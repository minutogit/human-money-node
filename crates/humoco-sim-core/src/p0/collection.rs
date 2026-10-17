//! Gateway collection state with an injected monotonic clock and a fixed roster.
//!
//! This model handles reply timing and neutral no-vote outcomes. It performs no
//! transport retries and does not claim that a packet arrived over real QUIC.

use super::{Approval, Error, Intent, Key, Receipt, Registry, View};
use std::collections::{BTreeMap, BTreeSet};

pub const COLLECTION_BUDGET_MS: u64 = 800;

/// One bounded attempt; changing the view requires constructing another attempt.
pub struct TimedCollection {
    intent: Intent,
    view: View,
    threshold: usize,
    deadline: u64,
    last_event: u64,
    answered: BTreeSet<Key>,
    approvals: BTreeMap<Key, Approval>,
    failed: bool,
}

impl TimedCollection {
    pub fn new(
        registry: &Registry,
        intent: &Intent,
        view: &View,
        started_at: u64,
    ) -> Result<Self, Error> {
        registry.validate_intent(intent, started_at)?;
        registry.context.verify_view(view)?;
        if !view.live(started_at) || view.shard != intent.slot.shard() {
            return Err(Error::WrongView);
        }
        Ok(Self {
            intent: intent.clone(),
            view: view.clone(),
            threshold: view.threshold()?,
            deadline: started_at.saturating_add(COLLECTION_BUDGET_MS),
            last_event: started_at,
            answered: BTreeSet::new(),
            approvals: BTreeMap::new(),
            failed: false,
        })
    }

    pub fn is_complete(&self) -> bool {
        self.approvals.len() >= self.threshold
    }

    fn advance(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last_event {
            return Err(Error::TimeRollback);
        }
        self.last_event = now;
        if self.failed {
            return Err(Error::Quorum);
        }
        if now >= self.deadline && !self.is_complete() {
            self.failed = true;
            return Err(Error::Quorum);
        }
        Ok(())
    }

    fn check_attainable(&mut self) -> Result<(), Error> {
        let remaining = self.view.roster.len().saturating_sub(self.answered.len());
        if self.approvals.len() + remaining < self.threshold {
            self.failed = true;
            return Err(Error::Quorum);
        }
        Ok(())
    }

    /// Valid replies count once; after fast exit stragglers are neutral.
    pub fn submit(&mut self, approval: Approval, received_at: u64) -> Result<bool, Error> {
        self.advance(received_at)?;
        if self.is_complete() {
            return Ok(true);
        }
        if !self.view.roster.contains(&approval.node)
            || approval.slot != self.intent.slot
            || approval.spend != self.intent.id()
            || approval.root_valid_until != self.intent.root_valid_until
            || approval.view_id != self.view.id
            || approval.mode != self.view.mode
        {
            return Err(Error::WrongView);
        }
        if !self.view.live(approval.issued_at)
            || approval.issued_at > received_at
            || approval.issued_at >= self.intent.root_valid_until
        {
            return Err(Error::Expired);
        }
        approval.verify()?;
        if self.answered.contains(&approval.node) {
            return Err(Error::Duplicate);
        }
        self.answered.insert(approval.node);
        self.approvals.insert(approval.node, approval);
        self.check_attainable()?;
        Ok(self.is_complete())
    }

    /// NOT_READY/capacity/cancellation supplies no signature and no fraud evidence.
    pub fn no_vote(&mut self, member: Key, now: u64) -> Result<(), Error> {
        self.advance(now)?;
        if self.is_complete() {
            return Ok(());
        }
        if !self.view.roster.contains(&member) {
            return Err(Error::WrongView);
        }
        if !self.answered.insert(member) {
            return Err(Error::Duplicate);
        }
        self.check_attainable()
    }

    pub fn finish(&mut self, now: u64) -> Result<Receipt, Error> {
        self.advance(now)?;
        if now >= self.intent.root_valid_until {
            return Err(Error::Expired);
        }
        if !self.is_complete() {
            return Err(Error::NotReady);
        }
        Ok(Receipt {
            intent: self.intent.clone(),
            view: self.view.clone(),
            approvals: self.approvals.values().cloned().collect(),
        })
    }
}
