use super::{
    hash, Approval, Context, Error, Id, Intent, Key, Mode, Observation, Receipt, Slot, View,
};
use ed25519_dalek::SigningKey;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceStatus {
    RegionalConfirmed,
    Provisional,
    Unknown,
    Rejected,
    Void,
}

#[derive(Clone, Debug)]
struct Candidate {
    intent: Intent,
    support: u8,
    receipts: Vec<Receipt>,
}

#[derive(Clone, Debug)]
pub struct Registry {
    pub context: Context,
    candidates: BTreeMap<Id, Candidate>,
    creations: BTreeMap<Id, (Id, usize)>,
}

impl Registry {
    pub fn new(context: Context) -> Self {
        Self {
            context,
            candidates: BTreeMap::new(),
            creations: BTreeMap::new(),
        }
    }

    pub fn validate_intent(&self, intent: &Intent, now: u64) -> Result<(), Error> {
        intent.verify()?;
        if intent.slot.network != self.context.network {
            return Err(Error::WrongNetwork);
        }
        let root = self
            .context
            .roots
            .get(&intent.slot.root)
            .ok_or(Error::UnknownRoot)?;
        root.verify()?;
        if intent.root_valid_until != root.valid_until {
            return Err(Error::InvalidIntent);
        }
        if now >= root.valid_until {
            return Err(Error::Expired);
        }
        let owner = if intent.slot.output == root.id() {
            root.owner
        } else {
            let (parent, index) = self
                .creations
                .get(&intent.slot.output)
                .ok_or(Error::UnknownAncestry)?;
            let p = self.candidates.get(parent).ok_or(Error::UnknownAncestry)?;
            if p.intent.slot.root != intent.slot.root {
                return Err(Error::UnknownAncestry);
            }
            p.intent
                .children
                .get(*index)
                .ok_or(Error::UnknownAncestry)?
                .owner
        };
        if owner != intent.owner {
            return Err(Error::InvalidOwner);
        }
        Ok(())
    }

    pub fn verify_receipt(&self, receipt: &Receipt, now: u64) -> Result<u8, Error> {
        self.validate_intent(&receipt.intent, now)?;
        self.context.verify_view(&receipt.view)?;
        if receipt.view.shard != receipt.intent.slot.shard() {
            return Err(Error::WrongView);
        }
        let threshold = receipt.view.threshold()?;
        if receipt.approvals.len() < threshold
            || receipt.approvals.len() > receipt.view.roster.len()
        {
            return Err(Error::Quorum);
        }
        let mut signers = BTreeSet::new();
        for a in &receipt.approvals {
            if !signers.insert(a.node) {
                return Err(Error::Duplicate);
            }
            if !receipt.view.roster.contains(&a.node)
                || a.slot != receipt.intent.slot
                || a.spend != receipt.intent.id()
                || a.root_valid_until != receipt.intent.root_valid_until
                || a.mode != receipt.view.mode
                || a.view_id != receipt.view.id
            {
                return Err(Error::WrongView);
            }
            if !receipt.view.live(a.issued_at)
                || a.issued_at >= receipt.intent.root_valid_until
                || a.issued_at > now
            {
                return Err(Error::Expired);
            }
            a.verify()?;
        }
        Ok(if receipt.view.mode == Mode::Regional {
            2
        } else {
            1
        })
    }

    pub fn import(&mut self, receipt: Receipt, now: u64) -> Result<EvidenceStatus, Error> {
        let support = self.verify_receipt(&receipt, now)?;
        let id = receipt.intent.id();
        if let Some(old) = self.candidates.get_mut(&id) {
            if old.intent.body() != receipt.intent.body() {
                return Err(Error::InvalidEvidence);
            }
            old.support = old.support.max(support);
            if !old.receipts.contains(&receipt) {
                old.receipts.push(receipt);
            }
        } else {
            for index in 0..receipt.intent.children.len() {
                let output = receipt.intent.output(index)?;
                if self.creations.contains_key(&output) {
                    return Err(Error::InvalidEvidence);
                }
            }
            for index in 0..receipt.intent.children.len() {
                self.creations
                    .insert(receipt.intent.output(index)?, (id, index));
            }
            self.candidates.insert(
                id,
                Candidate {
                    intent: receipt.intent.clone(),
                    support,
                    receipts: vec![receipt],
                },
            );
        }
        Ok(self.status(id, now))
    }

    pub fn winner(&self, slot: &Slot) -> Option<Id> {
        self.candidates
            .iter()
            .filter(|(_, c)| &c.intent.slot == slot)
            .max_by(|(ia, a), (ib, b)| a.support.cmp(&b.support).then_with(|| ib.cmp(ia)))
            .map(|(id, _)| *id)
    }

    fn path_live(&self, mut id: Id, now: u64, visited: &mut BTreeSet<Id>) -> bool {
        loop {
            if !visited.insert(id) {
                return false;
            }
            let Some(c) = self.candidates.get(&id) else {
                return false;
            };
            let Some(root) = self.context.roots.get(&c.intent.slot.root) else {
                return false;
            };
            if now >= root.valid_until || self.winner(&c.intent.slot) != Some(id) {
                return false;
            }
            if c.intent.slot.output == root.id() {
                return true;
            }
            let Some((parent, _)) = self.creations.get(&c.intent.slot.output) else {
                return false;
            };
            id = *parent;
        }
    }

    pub fn status(&self, id: Id, now: u64) -> EvidenceStatus {
        let Some(c) = self.candidates.get(&id) else {
            return EvidenceStatus::Unknown;
        };
        if !self.path_live(id, now, &mut BTreeSet::new()) {
            return EvidenceStatus::Void;
        }
        if c.support == 2 {
            EvidenceStatus::RegionalConfirmed
        } else {
            EvidenceStatus::Provisional
        }
    }

    /// Whether an output is on a usable canonical causal path. A consumed output
    /// is still an authenticated path node; `output_unspent` distinguishes spendability.
    pub fn usable_output(&self, root: Id, output: Id, now: u64) -> bool {
        let Some(anchor) = self.context.roots.get(&root) else {
            return false;
        };
        if now >= anchor.valid_until {
            return false;
        }
        if output == root {
            return true;
        }
        self.creations.get(&output).is_some_and(|(tx, _)| {
            self.candidates
                .get(tx)
                .is_some_and(|c| c.intent.slot.root == root)
                && self.path_live(*tx, now, &mut BTreeSet::new())
        })
    }

    pub fn output_unspent(&self, root: Id, output: Id, now: u64) -> bool {
        self.usable_output(root, output, now)
            && self
                .winner(&Slot {
                    network: self.context.network,
                    root,
                    output,
                })
                .is_none()
    }

    pub fn receipt(&self, id: Id) -> Option<&Receipt> {
        self.candidates.get(&id)?.receipts.iter().max_by_key(|r| {
            if r.view.mode == Mode::Regional {
                2
            } else {
                1
            }
        })
    }

    pub fn support(&self, id: Id) -> u8 {
        self.candidates.get(&id).map_or(0, |c| c.support)
    }

    /// Dependency-ordered evidence union. Authority is not imported: callers must
    /// independently recognize historical cuts/root anchors in `context` first.
    pub fn merge_from(&mut self, other: &Registry, now: u64) -> Result<(), Error> {
        let mut pending: Vec<Receipt> = other
            .candidates
            .values()
            .flat_map(|c| c.receipts.clone())
            .collect();
        while !pending.is_empty() {
            let old_len = pending.len();
            let mut next = Vec::new();
            for receipt in pending {
                match self.import(receipt.clone(), now) {
                    Ok(_) => (),
                    Err(Error::UnknownAncestry) => next.push(receipt),
                    Err(e) => return Err(e),
                }
            }
            if next.len() == old_len {
                return Err(Error::UnknownAncestry);
            }
            pending = next;
        }
        Ok(())
    }

    /// Normalized semantic digest; witness ordering/subsets cannot change it.
    pub fn digest(&self) -> Id {
        let mut b = Vec::new();
        for (id, c) in &self.candidates {
            b.extend_from_slice(id);
            b.push(c.support);
        }
        hash(b"HUMOCO_P0_SIM_NORMALIZED_STATE", &b)
    }

    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    pub fn prune(&mut self, now: u64) {
        let expired: BTreeSet<Id> = self
            .context
            .roots
            .iter()
            .filter(|(_, root)| now >= root.valid_until.saturating_add(30_000))
            .map(|(id, _)| *id)
            .collect();
        self.candidates
            .retain(|_, c| !expired.contains(&c.intent.slot.root));
        self.creations
            .retain(|_, (id, _)| self.candidates.contains_key(id));
        self.context.roots.retain(|id, _| !expired.contains(id));
    }
}

/// A serialized simulated durability decision. No signature exists before commit.
#[derive(Clone, Debug)]
pub struct PendingApproval {
    node: Key,
    intent: Intent,
    view: View,
    started_at: u64,
}

pub struct Signer {
    key: SigningKey,
    choices: BTreeMap<Slot, Id>,
    choice_expiry: BTreeMap<Slot, u64>,
    pending: BTreeMap<Slot, Id>,
    history_intact: bool,
    pub ready: bool,
    pub queue_capacity: usize,
}

impl Signer {
    pub fn new(key: SigningKey) -> Self {
        Self {
            key,
            choices: BTreeMap::new(),
            choice_expiry: BTreeMap::new(),
            pending: BTreeMap::new(),
            history_intact: true,
            ready: true,
            queue_capacity: 64,
        }
    }
    pub fn node(&self) -> Key {
        self.key.verifying_key().to_bytes()
    }
    pub fn own_choice(&self, slot: &Slot) -> Option<Id> {
        self.choices.get(slot).copied()
    }

    pub fn begin_approval(
        &mut self,
        registry: &Registry,
        intent: &Intent,
        view: &View,
        now: u64,
    ) -> Result<PendingApproval, Error> {
        if !self.ready || !self.history_intact || !registry.context.ready {
            return Err(Error::NotReady);
        }
        registry.context.verify_view(view)?;
        if !view.live(now) {
            return Err(Error::Expired);
        }
        if !registry.context.admitted(self.node(), now) {
            return Err(Error::UnknownAdmission);
        }
        if view.shard != intent.slot.shard() || !view.roster.contains(&self.node()) {
            return Err(Error::WrongView);
        }
        registry.validate_intent(intent, now)?;
        if !registry.usable_output(intent.slot.root, intent.slot.output, now) {
            return Err(Error::Conflict);
        }
        if registry
            .winner(&intent.slot)
            .is_some_and(|id| id != intent.id())
        {
            return Err(Error::Conflict);
        }
        if self
            .choices
            .get(&intent.slot)
            .or(self.pending.get(&intent.slot))
            .is_some_and(|id| *id != intent.id())
        {
            return Err(Error::Conflict);
        }
        // Reserve before any simulated RAM choice or persistence mutation.
        if self.pending.len() >= self.queue_capacity {
            return Err(Error::Capacity);
        }
        self.pending.insert(intent.slot, intent.id());
        Ok(PendingApproval {
            node: self.node(),
            intent: intent.clone(),
            view: view.clone(),
            started_at: now,
        })
    }

    /// Models a successful durable acknowledgment at `commit_time`. Expiry after
    /// persistence retains the exclusion, but cannot release an expired signature.
    pub fn commit(
        &mut self,
        pending: PendingApproval,
        commit_time: u64,
    ) -> Result<Option<Approval>, Error> {
        if commit_time < pending.started_at {
            return Err(Error::TimeRollback);
        }
        if pending.node != self.node()
            || self.pending.get(&pending.intent.slot) != Some(&pending.intent.id())
        {
            return Err(Error::InvalidEvidence);
        }
        if !self.history_intact || !self.ready {
            return Err(Error::NotReady);
        }
        self.choices
            .insert(pending.intent.slot, pending.intent.id());
        self.choice_expiry.insert(
            pending.intent.slot,
            pending.intent.root_valid_until.saturating_add(30_000),
        );
        self.pending.remove(&pending.intent.slot);
        if !pending.view.live(commit_time) || commit_time >= pending.intent.root_valid_until {
            return Ok(None);
        }
        Ok(Some(Approval::issue_unchecked(
            &self.key,
            &pending.intent,
            &pending.view,
            commit_time,
        )))
    }

    pub fn approve(
        &mut self,
        registry: &Registry,
        intent: &Intent,
        view: &View,
        now: u64,
    ) -> Result<Approval, Error> {
        let pending = self.begin_approval(registry, intent, view, now)?;
        self.commit(pending, now)?.ok_or(Error::Expired)
    }

    /// Crash drops only unacknowledged work; durable choices remain intact.
    pub fn crash(&mut self) {
        self.pending.clear();
    }

    /// A stale/unknown rollback cannot be repaired by matching another node digest.
    /// The model intentionally supplies no API to declare hidden history recovered.
    pub fn lose_own_history(&mut self) {
        self.choices.clear();
        self.choice_expiry.clear();
        self.pending.clear();
        self.history_intact = false;
        self.ready = false;
    }

    /// Expiry comes only from the authenticated root carried through validation.
    pub fn prune(&mut self, now: u64) {
        self.choice_expiry.retain(|_, expiry| now < *expiry);
        self.choices
            .retain(|slot, _| self.choice_expiry.contains_key(slot));
    }

    pub fn observe(&self, registry: &Registry, slot: &Slot) -> Result<Observation, Error> {
        let winner = registry.winner(slot).ok_or(Error::NoWinner)?;
        Ok(Observation::issue(
            &self.key,
            *slot,
            winner,
            registry.support(winner),
            registry.digest(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p0::{Child, RootAnchor, Ticket, DAY_MS, HOUR_MS};

    fn pending_fixture() -> Result<(Signer, Registry, Intent, View), Error> {
        let key = SigningKey::from_bytes(&[91; 32]);
        let node = key.verifying_key().to_bytes();
        let mut ctx = Context::new([7; 32], node, [node].into_iter().collect());
        ctx.learn(Ticket::issue(&key, 1, 0, 1), node, 0, true)?;
        for h in 0..=24 {
            ctx.observe_heartbeat(node, h * HOUR_MS)?;
        }
        ctx.refresh_reachability(node, DAY_MS)?;
        let root = RootAnchor::issue(&key, [7; 32], 1, DAY_MS + 100_000);
        ctx.register_root(root.clone())?;
        let slot = Slot {
            network: [7; 32],
            root: root.id(),
            output: root.id(),
        };
        let view = ctx.freeze_view(slot.shard(), DAY_MS)?;
        let intent = Intent::issue(
            &key,
            slot,
            root.valid_until,
            vec![Child {
                owner: node,
                commitment: [3; 32],
            }],
            1,
        );
        Ok((Signer::new(key), Registry::new(ctx), intent, view))
    }

    #[test]
    fn durable_choice_survives_expired_ack_and_prunes_only_after_root_grace() -> Result<(), Error> {
        let (mut signer, registry, intent, view) = pending_fixture()?;
        let pending = signer.begin_approval(&registry, &intent, &view, DAY_MS)?;
        assert_eq!(signer.commit(pending, view.valid_until)?, None);
        assert_eq!(signer.own_choice(&intent.slot), Some(intent.id()));
        signer.prune(intent.root_valid_until + 29_999);
        assert_eq!(signer.own_choice(&intent.slot), Some(intent.id()));
        signer.prune(intent.root_valid_until + 30_000);
        assert_eq!(signer.own_choice(&intent.slot), None);
        Ok(())
    }

    #[test]
    fn backdated_commit_cannot_release_or_persist_an_approval() -> Result<(), Error> {
        let (mut signer, registry, intent, view) = pending_fixture()?;
        let pending = signer.begin_approval(&registry, &intent, &view, DAY_MS + 10)?;
        assert_eq!(signer.commit(pending, DAY_MS), Err(Error::TimeRollback));
        assert_eq!(signer.own_choice(&intent.slot), None);
        Ok(())
    }
}
