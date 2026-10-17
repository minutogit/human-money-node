use super::{bytes, hash, Error, Id, Key, RootAnchor, DAY_MS, HOUR_MS, LEASE_MS, VIEW_MS};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub node: Key,
    pub nonce: u64,
    pub claimed_t0: u64,
    pub work: u64,
    pub routing_id: Id,
    pub signature: [u8; 64],
}

impl Ticket {
    pub fn issue(key: &SigningKey, nonce: u64, claimed_t0: u64, work: u64) -> Self {
        let node = key.verifying_key().to_bytes();
        let mut t = Self {
            node,
            nonce,
            claimed_t0,
            work,
            routing_id: [0; 32],
            signature: [0; 64],
        };
        t.routing_id = hash(b"HUMOCO_P0_SIM_TICKET_ID", &t.body());
        t.signature = key
            .sign(&bytes(b"HUMOCO_P0_SIM_TICKET", &t.body()))
            .to_bytes();
        t
    }

    fn body(&self) -> Vec<u8> {
        let mut b = self.node.to_vec();
        b.extend_from_slice(&self.nonce.to_le_bytes());
        b.extend_from_slice(&self.claimed_t0.to_le_bytes());
        b.extend_from_slice(&self.work.to_le_bytes());
        b
    }

    pub fn verify(&self) -> Result<(), Error> {
        if self.work == 0 || self.routing_id != hash(b"HUMOCO_P0_SIM_TICKET_ID", &self.body()) {
            return Err(Error::InvalidTicket);
        }
        verify(
            self.node,
            b"HUMOCO_P0_SIM_TICKET",
            &self.body(),
            self.signature,
        )
    }
}

pub(crate) fn verify(
    node: Key,
    domain: &[u8],
    body: &[u8],
    signature: [u8; 64],
) -> Result<(), Error> {
    VerifyingKey::from_bytes(&node)
        .map_err(|_| Error::Signature)?
        .verify_strict(&bytes(domain, body), &Signature::from_bytes(&signature))
        .map_err(|_| Error::Signature)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    Provisional,
    Regional,
}

impl Mode {
    pub fn threshold(self, n: usize) -> Result<usize, Error> {
        match (self, n) {
            (Self::Regional, 20) => Ok(14),
            (Self::Provisional, 1..=19) => Ok(2 * n / 3 + 1),
            _ => Err(Error::WrongView),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View {
    pub network: Id,
    pub shard: u16,
    pub cut_id: Id,
    pub mode: Mode,
    pub roster: Vec<Key>,
    pub tickets: Vec<Id>,
    pub created_at: u64,
    pub valid_until: u64,
    pub id: Id,
}

impl View {
    pub(crate) fn body(&self) -> Vec<u8> {
        let mut b = self.network.to_vec();
        b.extend_from_slice(&self.shard.to_le_bytes());
        b.extend_from_slice(&self.cut_id);
        b.push(self.mode as u8);
        b.extend_from_slice(&(self.roster.len() as u32).to_le_bytes());
        for (node, ticket) in self.roster.iter().zip(&self.tickets) {
            b.extend_from_slice(node);
            b.extend_from_slice(ticket);
        }
        b.extend_from_slice(&self.created_at.to_le_bytes());
        b.extend_from_slice(&self.valid_until.to_le_bytes());
        b
    }
    pub fn threshold(&self) -> Result<usize, Error> {
        self.mode.threshold(self.roster.len())
    }
    pub fn live(&self, now: u64) -> bool {
        self.created_at <= now && now < self.valid_until
    }
}

#[derive(Clone, Debug)]
struct Admission {
    ticket: Ticket,
    first_seen: u64,
    hours: BTreeSet<u64>,
    reachable_until: u64,
    pending: Option<(Ticket, u64, BTreeSet<u64>)>,
    revoked: bool,
}

/// An independently configured observer's knowledge, never a gateway roster.
#[derive(Clone, Debug)]
pub struct Context {
    pub network: Id,
    pub observer: Key,
    pub trusted_friends: BTreeSet<Key>,
    records: BTreeMap<Key, Admission>,
    cuts: BTreeMap<Id, View>,
    pub roots: BTreeMap<Id, RootAnchor>,
    trusted_observers: BTreeSet<Key>,
    stable_since: Option<u64>,
    population_covered_until: u64,
    last_population_update: u64,
    pub ready: bool,
}

impl Context {
    pub fn new(network: Id, observer: Key, trusted_friends: BTreeSet<Key>) -> Self {
        Self {
            network,
            observer,
            trusted_friends,
            records: BTreeMap::new(),
            cuts: BTreeMap::new(),
            roots: BTreeMap::new(),
            trusted_observers: BTreeSet::new(),
            stable_since: None,
            population_covered_until: 0,
            last_population_update: 0,
            ready: true,
        }
    }

    /// `work_verified` is an explicit simulation oracle for the real Argon verifier.
    /// `via` denotes delivery on an authenticated, configured F2F edge.
    pub fn learn(
        &mut self,
        ticket: Ticket,
        via: Key,
        now: u64,
        work_verified: bool,
    ) -> Result<(), Error> {
        if !self.trusted_friends.contains(&via) {
            return Err(Error::ForeignFriend);
        }
        ticket.verify()?;
        if !work_verified {
            return Err(Error::InvalidWork);
        }
        if let Some(a) = self.records.get_mut(&ticket.node) {
            if a.ticket == ticket {
                return Ok(());
            }
            let highest = a
                .pending
                .as_ref()
                .map_or(a.ticket.work, |(p, _, _)| p.work.max(a.ticket.work));
            if ticket.work <= highest {
                return Err(Error::InvalidTicket);
            }
            a.pending = Some((ticket, now, BTreeSet::new()));
        } else {
            self.records.insert(
                ticket.node,
                Admission {
                    ticket,
                    first_seen: now,
                    hours: BTreeSet::new(),
                    reachable_until: 0,
                    pending: None,
                    revoked: false,
                },
            );
        }
        Ok(())
    }

    /// Inject one authenticated delivery at the receiver's local observation hour.
    /// Claimed sender timestamps are not accepted by this interface.
    pub fn observe_heartbeat(&mut self, node: Key, now: u64) -> Result<(), Error> {
        let a = self.records.get_mut(&node).ok_or(Error::UnknownAdmission)?;
        if now < a.first_seen {
            return Err(Error::TimeRollback);
        }
        let hour = now / HOUR_MS;
        a.hours.insert(hour);
        a.hours.retain(|h| h.saturating_add(24) > hour);
        if let Some((_, _, hours)) = &mut a.pending {
            hours.insert(hour);
            hours.retain(|h| h.saturating_add(24) > hour);
        }
        if let Some((ticket, seen, hours)) = &a.pending {
            if now.saturating_sub(*seen) >= DAY_MS && hours.len() >= 8 {
                a.ticket = ticket.clone();
                a.first_seen = *seen;
                a.hours = hours.clone();
                a.pending = None;
            }
        }
        Ok(())
    }

    /// Inject a successfully authenticated *fresh challenge response* at local now.
    /// The caller models transport authentication; replay has a separate API which
    /// deliberately retains its original receipt time.
    pub fn refresh_reachability(&mut self, node: Key, now: u64) -> Result<(), Error> {
        self.record_reachability(node, now, now)
    }

    pub fn record_reachability(
        &mut self,
        node: Key,
        original_received_at: u64,
        now: u64,
    ) -> Result<(), Error> {
        let a = self.records.get_mut(&node).ok_or(Error::UnknownAdmission)?;
        if original_received_at > now || original_received_at < a.first_seen {
            return Err(Error::TimeRollback);
        }
        let expiry = original_received_at.saturating_add(LEASE_MS);
        if expiry <= now {
            return Err(Error::Stale);
        }
        a.reachable_until = a.reachable_until.max(expiry);
        Ok(())
    }

    pub fn revoke(
        &mut self,
        proof_a: &super::Approval,
        proof_b: &super::Approval,
    ) -> Result<(), Error> {
        let node = super::verify_node_equivocation(proof_a, proof_b)?;
        self.records
            .get_mut(&node)
            .ok_or(Error::UnknownAdmission)?
            .revoked = true;
        Ok(())
    }

    pub fn admitted(&self, node: Key, now: u64) -> bool {
        self.records.get(&node).is_some_and(|a| {
            let hour = now / HOUR_MS;
            !a.revoked
                && now
                    .checked_sub(a.first_seen)
                    .is_some_and(|age| age >= DAY_MS)
                && a.hours
                    .iter()
                    .filter(|h| **h <= hour && h.saturating_add(24) > hour)
                    .count()
                    >= 8
        })
    }

    pub fn selectable(&self, node: Key, now: u64) -> bool {
        self.admitted(node, now)
            && self
                .records
                .get(&node)
                .is_some_and(|a| a.reachable_until > now)
    }

    fn eligibility_until(&self, a: &Admission, now: u64) -> u64 {
        // The eighth most recent observed hour is the last presence observation
        // necessary to keep the minimum eight. Its expiry also bounds continuity.
        let hour = now / HOUR_MS;
        let presence_end = a
            .hours
            .iter()
            .rev()
            .filter(|h| **h <= hour && h.saturating_add(24) > hour)
            .nth(7)
            .map_or(now, |h| h.saturating_add(24).saturating_mul(HOUR_MS));
        a.reachable_until.min(presence_end)
    }

    pub fn update_population(&mut self, now: u64) {
        let expiries: Vec<u64> = self
            .records
            .iter()
            .filter(|(k, _)| self.selectable(**k, now))
            .map(|(_, a)| self.eligibility_until(a, now))
            .collect();
        if !self.ready || now < self.last_population_update || expiries.len() < 20 {
            self.stable_since = None;
            self.population_covered_until = 0;
        } else {
            if self.stable_since.is_none() || now > self.population_covered_until {
                self.stable_since = Some(now);
            }
            let mut sorted = expiries;
            sorted.sort_unstable_by(|a, b| b.cmp(a));
            self.population_covered_until = sorted.get(19).copied().unwrap_or(now);
        }
        self.last_population_update = now;
    }

    pub fn stability_anchor(&self) -> Option<u64> {
        self.stable_since
    }

    /// Independently configured observation delegation, never inferred from receipt.
    pub fn trust_observer(&mut self, provider: Key) {
        self.trusted_observers.insert(provider);
    }

    /// An in-process simulation capability for a trusted observer's historical cut.
    /// A gateway cannot supply a Context to a production verifier through this API.
    pub fn recognize_cut(&mut self, provider: &Context, view: &View) -> Result<(), Error> {
        if provider.network != self.network || !self.trusted_observers.contains(&provider.observer)
        {
            return Err(Error::UnknownView);
        }
        provider.verify_view(view)?;
        self.cuts.insert(view.cut_id, view.clone());
        Ok(())
    }

    pub fn freeze_view(&mut self, shard: u16, now: u64) -> Result<View, Error> {
        self.update_population(now);
        if !self.ready {
            return Err(Error::NotReady);
        }
        let mut candidates: Vec<(Id, Key, Id, u64)> = self
            .records
            .iter()
            .filter(|(k, _)| self.selectable(**k, now))
            .map(|(k, a)| {
                let mut b = a.ticket.routing_id.to_vec();
                b.extend_from_slice(&shard.to_le_bytes());
                (
                    hash(b"HUMOCO_P0_SIM_HRW", &b),
                    *k,
                    a.ticket.routing_id,
                    self.eligibility_until(a, now),
                )
            })
            .collect();
        if candidates.is_empty() {
            return Err(Error::UnknownAdmission);
        }
        let mode = if candidates.len() < 20 {
            Mode::Provisional
        } else {
            if self
                .stable_since
                .is_none_or(|s| now.checked_sub(s).is_none_or(|age| age < DAY_MS))
            {
                return Err(Error::NotStable);
            }
            Mode::Regional
        };
        candidates.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let mut cut_bytes = self.network.to_vec();
        cut_bytes.extend_from_slice(&now.to_le_bytes());
        cut_bytes.extend_from_slice(&shard.to_le_bytes());
        for (_, key, ticket, expiry) in &candidates {
            cut_bytes.extend_from_slice(key);
            cut_bytes.extend_from_slice(ticket);
            cut_bytes.extend_from_slice(&expiry.to_le_bytes());
        }
        let cut_id = hash(b"HUMOCO_P0_SIM_CATALOG", &cut_bytes);
        candidates.truncate(20);
        let valid_until = candidates
            .iter()
            .map(|x| x.3)
            .min()
            .unwrap_or(now)
            .min(now.saturating_add(VIEW_MS));
        let mut view = View {
            network: self.network,
            shard,
            cut_id,
            mode,
            roster: candidates.iter().map(|x| x.1).collect(),
            tickets: candidates.iter().map(|x| x.2).collect(),
            created_at: now,
            valid_until,
            id: [0; 32],
        };
        view.id = hash(b"HUMOCO_P0_SIM_VIEW", &view.body());
        self.cuts.insert(cut_id, view.clone());
        Ok(view)
    }

    pub fn verify_view(&self, view: &View) -> Result<(), Error> {
        if view.network != self.network {
            return Err(Error::WrongNetwork);
        }
        if view.roster.len() != view.tickets.len()
            || view.roster.iter().copied().collect::<BTreeSet<_>>().len() != view.roster.len()
        {
            return Err(Error::Duplicate);
        }
        view.threshold()?;
        if view.id != hash(b"HUMOCO_P0_SIM_VIEW", &view.body()) {
            return Err(Error::WrongView);
        }
        if self.cuts.get(&view.cut_id) != Some(view) {
            return Err(Error::UnknownView);
        }
        Ok(())
    }

    /// Root registration is an explicit independently trusted issuance boundary.
    pub fn register_root(&mut self, root: RootAnchor) -> Result<(), Error> {
        root.verify()?;
        if root.network != self.network {
            return Err(Error::WrongNetwork);
        }
        self.roots.insert(root.id(), root);
        Ok(())
    }
}
