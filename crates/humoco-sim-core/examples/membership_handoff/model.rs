//! Conditional handoff model. Statements carry unforgeable abstract identities;
//! no hash, signature, QUIC, disk engine or first-FINAL discovery is implemented.
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

type Id = u16;
type Slot = u32;
type Value = u32;
type State = BTreeMap<Slot, BTreeSet<u8>>;
// Ideal signature provenance is external to the adversarial certificate payload.
type ClosureRegistry = BTreeMap<(u32, State), BTreeSet<Id>>;
const Q: usize = 14;
const LIMIT: u64 = 500_000;

fn require(condition: bool, explanation: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(explanation.to_string())
    }
}
fn merge(target: &mut State, source: &State) {
    for (slot, values) in source {
        target.entry(*slot).or_default().extend(values);
    }
}
fn includes(target: &State, source: &State) -> bool {
    source
        .iter()
        .all(|(slot, values)| target.get(slot).is_some_and(|got| values.is_subset(got)))
}
fn singleton(slot: Slot, value: u8) -> State {
    BTreeMap::from([(slot, BTreeSet::from([value]))])
}

#[derive(Clone, Debug, Default)]
struct Replica {
    own: State,
    inherited: State,
    pending: State,
    active_epoch: u32,
    last_closed_epoch: Option<u32>,
    fenced: bool,
    online: bool,
    installed: bool,
}
impl Replica {
    fn fresh() -> Self {
        Self {
            online: true,
            installed: true,
            ..Self::default()
        }
    }
    fn obligations(&self) -> State {
        let mut state = self.own.clone();
        merge(&mut state, &self.inherited);
        state
    }
    fn vote(&mut self, slot: Slot, value: u8) -> bool {
        self.vote_at(self.active_epoch, slot, value)
    }
    fn vote_at(&mut self, epoch: u32, slot: Slot, value: u8) -> bool {
        if epoch != self.active_epoch
            || self.last_closed_epoch.is_some_and(|closed| epoch <= closed)
        {
            return false;
        }
        if !self.online || !self.installed || self.fenced {
            return false;
        }
        let state = self.obligations();
        if state
            .get(&slot)
            .is_some_and(|values| values != &BTreeSet::from([value]))
        {
            return false;
        }
        merge(&mut self.own, &singleton(slot, value));
        true
    }
    fn fence(&mut self) -> State {
        // One durable serialization point drains previously admitted choices.
        // A response is released only after that choice appears in this report.
        let pending = std::mem::take(&mut self.pending);
        merge(&mut self.own, &pending);
        self.fenced = true;
        self.last_closed_epoch = Some(
            self.last_closed_epoch
                .map_or(self.active_epoch, |old| old.max(self.active_epoch)),
        );
        self.obligations()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Package {
    epoch: u32,
    state: State,
    next: Vec<Id>,
    endorsers: BTreeSet<Id>,
    // Immutable authenticated inclusion statements: payload + signer-local effects.
    endorsed_state: State,
    inclusion: BTreeMap<Id, State>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Prepared {
    view: u32,
    value: Value,
    voters: BTreeSet<Id>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Change {
    sender: Id,
    next_view: u32,
    prepared: Option<Prepared>,
}
#[derive(Clone, Debug)]
enum Message {
    Proposal {
        view: u32,
        value: Value,
        changes: Vec<Change>,
    },
    Prepare {
        view: u32,
        value: Value,
    },
    Commit {
        view: u32,
        value: Value,
    },
    Change(Change),
}
#[derive(Clone, Debug)]
struct Event {
    at: u64,
    serial: u64,
    from: Id,
    to: Id,
    message: Message,
}
impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        (self.at, self.serial) == (other.at, other.serial)
    }
}
impl Eq for Event {}
impl Ord for Event {
    fn cmp(&self, other: &Self) -> Ordering {
        (other.at, other.serial).cmp(&(self.at, self.serial))
    }
}
impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
#[derive(Clone, Debug, Default)]
struct AgreementNode {
    view: u32,
    proposal: BTreeMap<u32, Value>,
    prepares: BTreeMap<(u32, Value), BTreeSet<Id>>,
    commits: BTreeMap<(u32, Value), BTreeSet<Id>>,
    sent_prepare: BTreeMap<u32, Value>,
    sent_commit: BTreeSet<(u32, Value)>,
    prepared: Option<Prepared>,
    changes: BTreeMap<u32, BTreeMap<Id, Change>>,
    proposed: BTreeSet<u32>,
    decided: Option<Value>,
}
struct Agreement {
    epoch: u32,
    quorum: usize,
    members: Vec<Id>,
    faulty: BTreeSet<Id>,
    packages: BTreeMap<Value, Package>,
    value_bindings: BTreeMap<Value, Package>,
    closure_registry: ClosureRegistry,
    nodes: BTreeMap<Id, AgreementNode>,
    events: BinaryHeap<Event>,
    now: u64,
    serial: u64,
    rng: u64,
    processed: u64,
    rejected: u64,
    trace: Vec<String>,
    decisions: BTreeMap<Value, BTreeSet<Id>>,
    committed: BTreeMap<Value, BTreeSet<Id>>,
    emitted_prepares: BTreeMap<(u32, Value), BTreeSet<Id>>,
    emitted_commits: BTreeMap<(u32, Value), BTreeSet<Id>>,
    emitted_changes: Vec<Change>,
}
impl Agreement {
    fn new(
        members: Vec<Id>,
        faulty: BTreeSet<Id>,
        packages: BTreeMap<Value, Package>,
        seed: u64,
        epoch: u32,
        closure_registry: ClosureRegistry,
    ) -> Self {
        let nodes = members
            .iter()
            .map(|id| (*id, AgreementNode::default()))
            .collect();
        Self {
            epoch,
            quorum: 2 * members.len() / 3 + 1,
            members,
            faulty,
            value_bindings: packages.clone(),
            packages,
            closure_registry,
            nodes,
            events: BinaryHeap::new(),
            now: 0,
            serial: 0,
            rng: seed.max(1),
            processed: 0,
            rejected: 0,
            trace: Vec::new(),
            decisions: BTreeMap::new(),
            committed: BTreeMap::new(),
            emitted_prepares: BTreeMap::new(),
            emitted_commits: BTreeMap::new(),
            emitted_changes: Vec::new(),
        }
    }
    fn leader(&self, view: u32) -> Id {
        self.members[view as usize % self.members.len()]
    }
    fn valid_package(&self, value: Value) -> bool {
        self.packages.get(&value).is_some_and(|package| {
            self.value_bindings.get(&value) == Some(package)
                && package.epoch == self.epoch
                && package.state == package.endorsed_state
                && package.endorsers.len() >= self.quorum
                && package.endorsers.iter().all(|id| {
                    self.members.contains(id)
                        && package.inclusion.get(id) == Some(&package.state)
                        && self
                            .closure_registry
                            .get(&(package.epoch, package.state.clone()))
                            .is_some_and(|issued| issued.contains(id))
                })
                && package.next.len() == 20
                && package.next.iter().copied().collect::<BTreeSet<_>>().len() == 20
        })
    }
    fn valid_prepared(&self, p: &Prepared) -> bool {
        self.valid_package(p.value)
            && p.voters.len() >= self.quorum
            && p.voters.iter().all(|id| {
                self.members.contains(id)
                    && self
                        .emitted_prepares
                        .get(&(p.view, p.value))
                        .is_some_and(|emitted| emitted.contains(id))
            })
    }
    fn chosen(&self, view: u32, changes: &[Change]) -> Result<Option<Value>, String> {
        if view == 0 {
            return if changes.is_empty() {
                Ok(None)
            } else {
                Err("view zero has unexpected change evidence".into())
            };
        }
        let senders: BTreeSet<_> = changes.iter().map(|c| c.sender).collect();
        require(
            senders.len() >= self.quorum && senders.len() == changes.len(),
            "invalid change quorum",
        )?;
        require(
            changes.iter().all(|c| {
                c.next_view == view
                    && self.members.contains(&c.sender)
                    && self.emitted_changes.contains(c)
                    && c.prepared
                        .as_ref()
                        .is_none_or(|p| p.view < view && self.valid_prepared(p))
            }),
            "invalid change statement",
        )?;
        let highest = changes
            .iter()
            .filter_map(|c| c.prepared.as_ref())
            .map(|p| p.view)
            .max();
        let values: BTreeSet<_> = changes
            .iter()
            .filter_map(|c| c.prepared.as_ref())
            .filter(|p| Some(p.view) == highest)
            .map(|p| p.value)
            .collect();
        require(values.len() <= 1, "conflicting highest prepared proofs")?;
        Ok(values.first().copied())
    }
    fn send(&mut self, from: Id, to: Id, message: Message) {
        match &message {
            Message::Prepare { view, value } => {
                self.emitted_prepares
                    .entry((*view, *value))
                    .or_default()
                    .insert(from);
            }
            Message::Commit { view, value } => {
                self.emitted_commits
                    .entry((*view, *value))
                    .or_default()
                    .insert(from);
            }
            Message::Change(change) => {
                if change.sender == from && !self.emitted_changes.contains(change) {
                    self.emitted_changes.push(change.clone());
                }
            }
            _ => {}
        }
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.serial += 1;
        self.events.push(Event {
            at: self.now + 1 + self.rng % 19,
            serial: self.serial,
            from,
            to,
            message,
        });
    }
    fn broadcast(&mut self, from: Id, message: Message) {
        for to in self.members.clone() {
            self.send(from, to, message.clone());
        }
    }
    fn note(&mut self, text: String) {
        if self.trace.len() < 100 {
            self.trace.push(format!("t={} {text}", self.now));
        }
    }
    fn timeout(&mut self, view: u32) {
        for id in self.members.clone() {
            if self.faulty.contains(&id) {
                continue;
            }
            let node = self.nodes.get_mut(&id).expect("model member");
            node.view = view;
            let change = Change {
                sender: id,
                next_view: view,
                prepared: node.prepared.clone(),
            };
            self.broadcast(id, Message::Change(change));
        }
    }
    fn progress(&mut self, id: Id, view: u32, value: Value) -> Result<(), String> {
        let node = self.nodes.get_mut(&id).ok_or("missing node")?;
        let key = (view, value);
        if node.view != view || node.proposal.get(&view) != Some(&value) {
            return Ok(());
        }
        let prepares = node.prepares.get(&key).cloned().unwrap_or_default();
        if prepares.len() >= self.quorum && !node.sent_commit.contains(&key) {
            let proof = Prepared {
                view,
                value,
                voters: prepares,
            };
            node.prepared = Some(proof);
            node.sent_commit.insert(key);
            self.note(format!("prepared node={id} view={view} value={value}"));
            self.broadcast(id, Message::Commit { view, value });
        }
        let node = self.nodes.get_mut(&id).ok_or("missing node")?;
        let commits = node.commits.get(&key).cloned().unwrap_or_default();
        if commits.len() >= self.quorum && node.sent_commit.contains(&key) {
            if node.decided.is_some_and(|previous| previous != value) {
                return Err("honest node decided conflicting values".into());
            }
            node.decided = Some(value);
            self.decisions.entry(value).or_default().insert(id);
            self.committed.entry(value).or_insert(commits);
            require(
                self.decisions.len() == 1,
                "conflicting membership decisions",
            )?;
        }
        Ok(())
    }
    fn deliver(&mut self, event: Event) -> Result<(), String> {
        if self.faulty.contains(&event.to) {
            return Ok(());
        } // adversaries may withhold forever
        if !self.members.contains(&event.from) {
            self.rejected += 1;
            return Ok(());
        }
        let id = event.to;
        match event.message {
            Message::Proposal {
                view,
                value,
                changes,
            } => {
                let chosen = self.chosen(view, &changes);
                if self.leader(view) != event.from
                    || !self.valid_package(value)
                    || chosen.is_err()
                    || chosen
                        .as_ref()
                        .ok()
                        .and_then(|v| *v)
                        .is_some_and(|v| v != value)
                {
                    self.rejected += 1;
                    return Ok(());
                }
                let node = self.nodes.get_mut(&id).ok_or("missing proposal node")?;
                if view < node.view
                    || node
                        .sent_prepare
                        .get(&view)
                        .is_some_and(|old| *old != value)
                {
                    return Ok(());
                }
                // A valid new-view certificate, rather than a local preferred package,
                // determines the safe carried value. Own payment choices remain intact.
                node.view = view;
                node.proposal.insert(view, value);
                if node.sent_prepare.insert(view, value).is_none() {
                    self.broadcast(id, Message::Prepare { view, value });
                }
                self.progress(id, view, value)?;
            }
            Message::Prepare { view, value } => {
                self.nodes
                    .get_mut(&id)
                    .ok_or("missing prepare node")?
                    .prepares
                    .entry((view, value))
                    .or_default()
                    .insert(event.from);
                self.progress(id, view, value)?;
            }
            Message::Commit { view, value } => {
                self.nodes
                    .get_mut(&id)
                    .ok_or("missing commit node")?
                    .commits
                    .entry((view, value))
                    .or_default()
                    .insert(event.from);
                self.progress(id, view, value)?;
            }
            Message::Change(change) => {
                if change.sender != event.from
                    || change
                        .prepared
                        .as_ref()
                        .is_some_and(|p| p.view >= change.next_view || !self.valid_prepared(p))
                {
                    self.rejected += 1;
                    return Ok(());
                }
                let view = change.next_view;
                let node = self.nodes.get_mut(&id).ok_or("missing change node")?;
                node.changes
                    .entry(view)
                    .or_default()
                    .insert(change.sender, change);
                if id == self.leader(view) {
                    let node = self.nodes.get_mut(&id).ok_or("missing leader")?;
                    let changes: Vec<_> = node.changes[&view].values().cloned().collect();
                    if changes.len() >= self.quorum && node.proposed.insert(view) {
                        let carried = self.chosen(view, &changes)?;
                        let value = carried
                            .or_else(|| self.packages.keys().next().copied())
                            .ok_or("no candidate")?;
                        self.broadcast(
                            id,
                            Message::Proposal {
                                view,
                                value,
                                changes,
                            },
                        );
                    }
                }
            }
        }
        Ok(())
    }
    fn run(&mut self) -> Result<(), String> {
        while let Some(event) = self.events.pop() {
            self.processed += 1;
            require(self.processed <= LIMIT, "INCONCLUSIVE: event bound reached")?;
            self.now = event.at;
            if let Err(error) = self.deliver(event) {
                return Err(format!(
                    "{error}; events={}; trace={:?}",
                    self.processed, self.trace
                ));
            }
        }
        Ok(())
    }
    fn decide(&mut self) -> Result<Value, String> {
        // Each completed model round delivers its queued messages fairly. The
        // next rotating leader is tried after a timeout, including faulty ones;
        // no scheduler lookup jumps directly to an honest leader.
        for view in 1..=self.members.len() as u32 + 1 {
            self.timeout(view);
            self.run()?;
            if self
                .decisions
                .values()
                .next()
                .is_some_and(|ids| ids.len() >= self.quorum)
            {
                return self
                    .decisions
                    .keys()
                    .next()
                    .copied()
                    .ok_or("no decision".into());
            }
        }
        Err("INCONCLUSIVE: stable model rounds exhausted without decision".into())
    }
}

#[derive(Clone)]
struct PaymentCert {
    epoch: u32,
    slot: Slot,
    value: u8,
    voters: BTreeSet<Id>,
}
#[derive(Clone)]
struct InstallReceipt {
    epoch: u32,
    value: Value,
    signer: Id,
}
fn install_quorum(
    epoch: u32,
    value: Value,
    next: &[Id],
    state: &State,
    receipts: &[InstallReceipt],
    emitted: &BTreeMap<(u32, Value, Id), State>,
) -> bool {
    let mut unique = BTreeSet::new();
    receipts.iter().all(|receipt| {
        receipt.epoch == epoch
            && receipt.value == value
            && next.contains(&receipt.signer)
            && unique.insert(receipt.signer)
            && emitted.get(&(epoch, value, receipt.signer)) == Some(state)
    }) && unique.len() >= Q
}

/// Exact outputs of the executed ideal-authentication model for cryptographic refinement.
/// This carries data and actual emitted signer sets, never an admission boolean.
#[allow(dead_code)]
#[derive(Clone)]
pub struct RecognitionTransition {
    pub epoch: u32,
    pub old_members: Vec<u16>,
    pub next_members: Vec<u16>,
    pub state: BTreeMap<u32, BTreeSet<u8>>,
    pub closure_signers: BTreeSet<u16>,
    pub commit_signers: BTreeSet<u16>,
    pub install_signers: BTreeSet<u16>,
}
#[allow(dead_code)]
pub struct RecognitionPayment {
    pub epoch: u32,
    pub slot: u32,
    pub value: u8,
    pub voters: BTreeSet<u16>,
}
#[allow(dead_code)]
pub struct RecognitionTrace {
    pub transitions: Vec<RecognitionTransition>,
    pub payments: Vec<RecognitionPayment>,
    pub events: u64,
}

struct Lab {
    replicas: BTreeMap<Id, Replica>,
    members: Vec<Id>,
    faulty: BTreeSet<Id>,
    accepted: BTreeMap<Slot, u8>,
    epoch: u32,
    events: u64,
    contexts: BTreeMap<u32, Vec<Id>>,
    emitted_votes: BTreeMap<(u32, Slot, u8), BTreeSet<Id>>,
    closure_registry: ClosureRegistry,
    final_enabled: bool,
    recognition_audit: Vec<RecognitionTransition>,
}
impl Lab {
    fn new() -> Self {
        Self {
            replicas: (0..20).map(|id| (id, Replica::fresh())).collect(),
            members: (0..20).collect(),
            faulty: (0..6).collect(),
            accepted: BTreeMap::new(),
            epoch: 0,
            events: 0,
            contexts: BTreeMap::from([(0, (0..20).collect())]),
            emitted_votes: BTreeMap::new(),
            closure_registry: BTreeMap::new(),
            final_enabled: true,
            recognition_audit: Vec::new(),
        }
    }
    fn collect(&mut self, slot: Slot, value: u8, voters: &[Id]) -> Result<bool, String> {
        if !self.final_enabled {
            return Ok(false);
        }
        let distinct: BTreeSet<_> = voters.iter().copied().collect();
        require(
            distinct.len() == voters.len(),
            "duplicate signer in fixture",
        )?;
        let mut signers = BTreeSet::new();
        for id in distinct {
            if !self.members.contains(&id) {
                continue;
            }
            self.events += 1;
            let node = self.replicas.get_mut(&id).ok_or("missing voter")?;
            if node.online && (self.faulty.contains(&id) || node.vote_at(self.epoch, slot, value)) {
                signers.insert(id);
            }
        }
        self.emitted_votes
            .entry((self.epoch, slot, value))
            .or_default()
            .extend(&signers);
        if signers.len() >= Q {
            self.submit_certificate(&PaymentCert {
                epoch: self.epoch,
                slot,
                value,
                voters: signers,
            })?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn valid_certificate(&self, certificate: &PaymentCert) -> bool {
        certificate.voters.len() >= Q
            && self
                .contexts
                .get(&certificate.epoch)
                .is_some_and(|members| certificate.voters.iter().all(|id| members.contains(id)))
            && self
                .emitted_votes
                .get(&(certificate.epoch, certificate.slot, certificate.value))
                .is_some_and(|emitted| certificate.voters.is_subset(emitted))
    }
    fn submit_certificate(&mut self, certificate: &PaymentCert) -> Result<(), String> {
        require(
            self.valid_certificate(certificate),
            "invalid historical payment certificate",
        )?;
        require(
            self.accepted
                .get(&certificate.slot)
                .is_none_or(|old| *old == certificate.value),
            "double FINAL in safe model",
        )?;
        // Monitor only: learning an external outcome does not inform replicas.
        self.accepted.insert(certificate.slot, certificate.value);
        Ok(())
    }
    fn present_certificate(
        &mut self,
        certificate: &PaymentCert,
        recipients: &[Id],
    ) -> Result<(), String> {
        require(
            self.valid_certificate(certificate),
            "client presented invalid historical evidence",
        )?;
        // Explicit client/request-carried evidence delivery, never lock gossip.
        // Undelivered/offline replicas do not gain knowledge from the monitor.
        for id in recipients {
            let node = self.replicas.get_mut(id).ok_or("unknown proof recipient")?;
            if !node.online {
                continue;
            }
            self.events += 1;
            if node.inherited.contains_key(&certificate.slot) {
                node.inherited
                    .insert(certificate.slot, BTreeSet::from([certificate.value]));
            }
        }
        Ok(())
    }
    fn package(
        &mut self,
        next: Vec<Id>,
        reports: &[Id],
        omit: Option<Slot>,
    ) -> Result<Package, String> {
        let mut state = State::new();
        for id in reports {
            let report = self.replicas.get_mut(id).ok_or("missing reporter")?.fence();
            merge(&mut state, &report);
        }
        if let Some(slot) = omit {
            state.remove(&slot);
        }
        let endorsers: BTreeSet<Id> = self
            .members
            .iter()
            .copied()
            .filter(|id| {
                if !self.replicas[id].online {
                    return false;
                }
                if self.faulty.contains(id) {
                    return true;
                }
                let node = &self.replicas[id];
                node.fenced && includes(&state, &node.obligations())
            })
            .collect();
        self.closure_registry
            .entry((self.epoch, state.clone()))
            .or_default()
            .extend(endorsers.iter().copied());
        let inclusion = endorsers.iter().map(|id| (*id, state.clone())).collect();
        Ok(Package {
            epoch: self.epoch,
            endorsed_state: state.clone(),
            state,
            next,
            endorsers,
            inclusion,
        })
    }
    fn handoff(&mut self, next: Vec<Id>, seed: u64) -> Result<(), String> {
        self.handoff_inner(next, None, seed)
    }
    fn handoff_inner(
        &mut self,
        next: Vec<Id>,
        competing: Option<Vec<Id>>,
        seed: u64,
    ) -> Result<(), String> {
        // Actual delivered reports only. Unavailable sources cannot be read by
        // the state-transfer procedure, even though the harness stores replicas.
        let reports: Vec<_> = self
            .members
            .iter()
            .copied()
            .filter(|id| self.replicas[id].online)
            .collect();
        let package = self.package(next.clone(), &reports, None)?;
        require(
            package.endorsers.len() > 2 * self.members.len() / 3,
            "no closure certificate",
        )?;
        let mut packages = BTreeMap::from([(1, package.clone())]);
        if let Some(alternate) = competing.as_ref() {
            let mut other = package;
            other.next = alternate.clone();
            packages.insert(2, other);
        }
        let mut agreement = Agreement::new(
            self.members.clone(),
            self.faulty.clone(),
            packages,
            seed,
            self.epoch,
            self.closure_registry.clone(),
        );
        if competing.is_some() {
            // A faulty leader sends conflicting, genuinely valid packages. Neither
            // honest half can prepare; ordinary scheduled view change must recover.
            let faulty_leader = self
                .members
                .iter()
                .copied()
                .find(|id| self.faulty.contains(id))
                .ok_or("competing fixture requires a faulty leader")?;
            for (index, id) in self.members.iter().enumerate() {
                agreement.send(
                    faulty_leader,
                    *id,
                    Message::Proposal {
                        view: 0,
                        value: if index < 13 { 1 } else { 2 },
                        changes: Vec::new(),
                    },
                );
            }
            agreement.run()?;
            require(
                agreement.decisions.is_empty(),
                "competing prefix unexpectedly decided",
            )?;
        }
        let chosen = agreement.decide()?;
        self.events += agreement.processed;
        let package = agreement
            .packages
            .get(&chosen)
            .ok_or("missing decided package")?
            .clone();
        require(
            agreement
                .committed
                .get(&chosen)
                .is_some_and(|votes| votes.len() >= agreement.quorum),
            "missing commit certificate",
        )?;
        let next = package.next.clone();
        // Every install receipt follows an individual verified durable install;
        // a quorum of receipts does not permit an uninstalled node to vote.
        let mut receipts = Vec::new();
        let mut emitted_receipts = BTreeMap::new();
        for id in &next {
            let node = self.replicas.entry(*id).or_insert_with(Replica::fresh);
            if !node.online {
                continue;
            }
            node.installed = false;
            node.inherited = package.state.clone();
            node.active_epoch = self.epoch + 1;
            node.fenced = false;
            node.installed = true;
            receipts.push(InstallReceipt {
                epoch: self.epoch,
                value: chosen,
                signer: *id,
            });
            emitted_receipts.insert((self.epoch, chosen, *id), package.state.clone());
            self.events += 1;
        }
        require(
            install_quorum(
                self.epoch,
                chosen,
                &next,
                &package.state,
                &receipts,
                &emitted_receipts,
            ),
            "invalid installation receipts",
        )?;
        self.recognition_audit.push(RecognitionTransition {
            epoch: self.epoch,
            old_members: self.members.clone(),
            next_members: next.clone(),
            state: package.state.clone(),
            closure_signers: package.endorsers.clone(),
            commit_signers: agreement
                .committed
                .get(&chosen)
                .cloned()
                .ok_or("missing decided commits")?,
            install_signers: receipts.iter().map(|receipt| receipt.signer).collect(),
        });
        self.members = next;
        self.epoch += 1;
        self.contexts.insert(self.epoch, self.members.clone());
        Ok(())
    }
}

/// Execute three complete turnovers including a split-proposal BFT recovery in
/// each epoch, exporting only concrete chosen/installed outputs and actual votes.
#[allow(dead_code)]
pub fn exercise_recognition_trace(seed: u64) -> Result<RecognitionTrace, String> {
    let mut lab = Lab::new();
    lab.faulty = (0..4)
        .flat_map(|generation| {
            (generation * 20..generation * 20 + 6)
                .chain(1000 + generation * 20..1000 + generation * 20 + 6)
        })
        .collect();
    for id in 0..6 {
        lab.replicas
            .get_mut(&id)
            .ok_or("missing initial faulty node")?
            .online = false;
    }
    let first: Vec<_> = lab
        .members
        .iter()
        .copied()
        .filter(|id| !lab.faulty.contains(id))
        .collect();
    require(
        lab.collect(10, 1, &first)?,
        "initial honest-only payment failed",
    )?;
    for generation in 1..=3 {
        let next: Vec<_> = (generation * 20..generation * 20 + 20).collect();
        let alternate: Vec<_> = (1000 + generation * 20..1000 + generation * 20 + 20).collect();
        for id in next
            .iter()
            .chain(&alternate)
            .filter(|id| lab.faulty.contains(id))
        {
            let mut node = Replica::fresh();
            node.online = false;
            lab.replicas.insert(*id, node);
        }
        lab.handoff_inner(next, Some(alternate), seed + u64::from(generation))?;
        let honest: Vec<_> = lab
            .members
            .iter()
            .copied()
            .filter(|id| !lab.faulty.contains(id))
            .collect();
        require(
            !lab.collect(10, 2, &honest)?,
            "old exclusion lost after certified transition",
        )?;
        require(
            lab.collect(10 + u32::from(generation), 1, &honest)?,
            "fresh honest-only payment stalled",
        )?;
    }
    let payments = lab
        .emitted_votes
        .iter()
        .filter(|(_, voters)| voters.len() >= Q)
        .map(|((epoch, slot, value), voters)| RecognitionPayment {
            epoch: *epoch,
            slot: *slot,
            value: *value,
            voters: voters.clone(),
        })
        .collect();
    Ok(RecognitionTrace {
        transitions: lab.recognition_audit,
        payments,
        events: lab.events,
    })
}

/// Exercise the first-FINAL path from locally verifiable discovery evidence.
/// The caller's global graph/fault premises are explicit experiment assumptions;
/// this function obtains the roster from the transcript, not the faulty set.
/// Earlier PROVISIONAL certificates are not promoted into FINAL by this model.
pub fn exercise_initial_final(
    evidence: &crate::bootstrap::AdmissionEvidence,
    faulty: &BTreeSet<Id>,
    seed: u64,
) -> Result<u64, String> {
    let members = evidence.members()?;
    require(
        (20..=64).contains(&members.len()),
        "initial model needs twenty to sixty-four discovered IDs",
    )?;
    let mut lab = Lab::new();
    lab.members = members.clone();
    lab.contexts = BTreeMap::from([(0, members.clone())]);
    lab.replicas = members.iter().map(|id| (*id, Replica::fresh())).collect();
    lab.faulty = faulty.clone();
    lab.final_enabled = false;
    for id in faulty {
        lab.replicas
            .get_mut(id)
            .ok_or("unknown faulty experiment ID")?
            .online = false;
    }
    // Provisional observations are authentic durable choices, not FINAL. Import
    // their conservative union rather than selecting the largest replica digest.
    lab.replicas
        .get_mut(&0)
        .ok_or("missing provisional witness")?
        .own = singleton(100, 1);
    lab.replicas
        .get_mut(&1)
        .ok_or("missing conflicting witness")?
        .own = singleton(100, 2);
    lab.replicas
        .get_mut(&2)
        .ok_or("missing consistent witness")?
        .own = singleton(101, 1);
    require(
        !lab.collect(102, 1, &members)?,
        "FINAL before initial activation",
    )?;
    // The agreement electorate is the discovered candidate universe. Its
    // decided value names the ordinary twenty HRW shard voters. Synthetic model
    // tickets stand in for already authenticated, mature ticket evidence.
    let eligible: Vec<_> = members
        .iter()
        .map(|id| {
            let mut key = [0_u8; 32];
            key[..2].copy_from_slice(&id.to_le_bytes());
            humoco_sim_core::types::CommitteeMember {
                node_pubkey: key,
                hrw_routing_id: key,
            }
        })
        .collect();
    let first_committee: Vec<_> = humoco_sim_core::types::select_shard_committee(1, &eligible)
        .iter()
        .map(|member| u16::from_le_bytes([member.node_pubkey[0], member.node_pubkey[1]]))
        .collect();
    require(
        first_committee.len() == 20,
        "initial HRW committee size incorrect",
    )?;
    lab.handoff(first_committee.clone(), seed)?;
    require(
        lab.epoch == 1 && !lab.final_enabled,
        "initial closure bypassed stability gate",
    )?;
    // Virtual time is input to the readiness gate; no host clock is consulted.
    let stable_since_ms = 0_u64;
    let day_ms = 86_400_000_u64;
    let ready_at = |now: u64| now.saturating_sub(stable_since_ms) >= day_ms;
    require(!ready_at(day_ms - 1), "early first FINAL")?;
    lab.final_enabled = ready_at(day_ms);
    require(
        lab.collect(101, 1, &members)?,
        "imported consistent lock cannot reach FINAL",
    )?;
    require(
        !lab.collect(100, 1, &first_committee)? && !lab.collect(100, 2, &first_committee)?,
        "provisional ambiguity silently resolved",
    )?;
    require(
        lab.collect(102, 1, &members)?,
        "first fresh FINAL failed without Byzantine assistance",
    )?;
    require(
        !lab.collect(102, 2, &first_committee)?,
        "first FINAL conflicted",
    )?;
    // A full subsequent turnover needs no founder signature after installation.
    let next_start = members.iter().max().copied().ok_or("empty universe")? + 1;
    lab.handoff((next_start..next_start + 20).collect(), seed + 1)?;
    let next = lab.members.clone();
    require(
        lab.collect(103, 1, &next)?,
        "post-bootstrap full turnover stalled",
    )?;
    require(
        !lab.collect(102, 2, &next)?,
        "first FINAL forgotten after turnover",
    )?;
    Ok(lab.events)
}

fn baseline(seed: u64) -> Result<u64, String> {
    let mut lab = Lab::new();
    let voters = lab.members.clone();
    require(lab.collect(1, 1, &voters)?, "baseline payment failed")?;
    require(!lab.collect(1, 2, &voters)?, "baseline conflict accepted")?;
    let package = lab.package((20..40).collect(), &voters, None)?;
    let mut agreement = Agreement::new(
        voters,
        lab.faulty,
        BTreeMap::from([(1, package)]),
        seed,
        lab.epoch,
        lab.closure_registry.clone(),
    );
    agreement.decide()?;
    Ok(lab.events + agreement.processed)
}
fn unsafe_copy(_seed: u64) -> Result<u64, String> {
    let mut nodes: BTreeMap<Id, Replica> = (0..22).map(|id| (id, Replica::fresh())).collect();
    let faulty: BTreeSet<Id> = (0..6).collect();
    let old: Vec<Id> = (0..14).collect(); // B0..5 + H6..13
    let new: Vec<Id> = (0..6).chain(14..22).collect();
    let mut a = BTreeSet::new();
    let mut b = BTreeSet::new();
    for id in old {
        if faulty.contains(&id) || nodes.get_mut(&id).ok_or("missing unsafe voter")?.vote(1, 1) {
            a.insert(id);
        }
    }
    // IDs20,21 had copied EMPTY before the old request. No closure is checked.
    for id in new {
        if faulty.contains(&id) || nodes.get_mut(&id).ok_or("missing unsafe voter")?.vote(1, 2) {
            b.insert(id);
        }
    }
    require(
        a.len() == Q && b.len() == Q && a.intersection(&b).all(|id| faulty.contains(id)),
        "mutant failed to reproduce double FINAL",
    )?;
    println!(
        "  EXPECTED-UNSAFE copy_then_activate: two 14-vote outcomes; only six faulty double-voters"
    );
    Ok(28)
}
fn generations(seed: u64) -> Result<u64, String> {
    let mut lab = Lab::new();
    lab.faulty = (0..4)
        .flat_map(|generation| generation * 20..generation * 20 + 6)
        .collect();
    let first = lab.members.clone();
    require(lab.collect(10, 1, &first)?, "initial payment failed")?;
    for generation in 1..=3 {
        let next: Vec<Id> = (generation * 20..generation * 20 + 20).collect();
        lab.handoff(next.clone(), seed + u64::from(generation))?;
        require(
            !lab.collect(10, 2, &next)?,
            "inherited payment exclusion lost",
        )?;
        require(
            lab.collect(10 + u32::from(generation), 1, &next)?,
            "fresh post-handoff payment failed",
        )?;
    }
    require(
        lab.members.iter().all(|id| *id >= 60),
        "full replacement not exercised",
    )?;
    Ok(lab.events)
}
fn minority(seed: u64) -> Result<u64, String> {
    let mut lab = Lab::new();
    let votes: Vec<_> = (0..14).collect();
    require(
        lab.collect(1, 1, &votes)?,
        "historical certificate not established",
    )?;
    // Create the concrete two-A/twelve-B report split. B has twelve genuine
    // signatures (six honest plus the equivocating faulty six), not FINAL.
    let partial_b: Vec<_> = (0..6).chain(14..20).collect();
    require(
        !lab.collect(1, 2, &partial_b)?,
        "partial B unexpectedly FINAL",
    )?;
    for id in 0..6 {
        lab.replicas
            .get_mut(&id)
            .ok_or("missing faulty reporter")?
            .own = singleton(1, 2);
    }
    // Fourteen closure endorsers intersect those14 payment voters in at least8,
    // including at least2 honest. The payload cannot erase their decision.
    let reports: Vec<_> = (0..6).chain(12..20).collect();
    require(
        reports
            .iter()
            .filter(|id| lab.replicas[id].own.get(&1) == Some(&BTreeSet::from([1])))
            .count()
            == 2,
        "minority fixture does not have two A reports",
    )?;
    require(
        reports
            .iter()
            .filter(|id| lab.replicas[id].own.get(&1) == Some(&BTreeSet::from([2])))
            .count()
            == 12,
        "minority fixture does not have twelve B reports",
    )?;
    let omitted = lab.package((20..40).collect(), &reports, Some(1))?;
    require(
        omitted.endorsers.len() < Q,
        "omitted minority witness obtained closure quorum",
    )?;
    let package = lab.package((20..40).collect(), &reports, None)?;
    require(
        package.endorsers.len() >= Q,
        "proper minority package failed",
    )?;
    require(
        package.state.get(&1) == Some(&BTreeSet::from([1, 2])),
        "minority binding was discarded in favor of twelve B reports",
    )?;
    let mut agreement = Agreement::new(
        lab.members.clone(),
        lab.faulty.clone(),
        BTreeMap::from([(1, package)]),
        seed,
        lab.epoch,
        lab.closure_registry.clone(),
    );
    agreement.decide()?;
    // Withhold the assembled certificate from the verifier until after transfer.
    let late = PaymentCert {
        epoch: 0,
        slot: 1,
        value: 1,
        voters: votes.into_iter().collect(),
    };
    lab.accepted.remove(&1);
    lab.handoff((20..40).collect(), seed)?;
    let now = lab.members.clone();
    require(!lab.collect(1, 2, &now)?, "late certificate exclusion lost")?;
    lab.submit_certificate(&late)?;
    require(
        lab.accepted.get(&1) == Some(&1),
        "old certificate invalidated",
    )?;
    Ok(lab.events + agreement.processed)
}
fn durability(_seed: u64) -> Result<u64, String> {
    let mut node = Replica::fresh();
    merge(&mut node.pending, &singleton(1, 1));
    // Crash before persistence: pending data is gone and no response escaped.
    node.pending.clear();
    require(
        node.own.is_empty(),
        "volatile choice survived modeled precommit crash",
    )?;
    require(
        node.vote(1, 2),
        "precommit crash prevented legitimate retry",
    )?;
    // Crash after persistence, before response: immutable decision survives restart.
    node.online = false;
    node.online = true;
    require(!node.vote(1, 1), "durable choice forgotten after restart")?;
    let mut draining = Replica::fresh();
    merge(&mut draining.pending, &singleton(2, 1));
    let report = draining.fence();
    require(
        report.get(&2) == Some(&BTreeSet::from([1])),
        "pending choice omitted by fence",
    )?;
    require(!draining.vote(3, 1), "old vote after closure")?;
    draining.online = false;
    draining.online = true;
    require(draining.fenced, "restart reopened closed epoch")?;
    let mut newcomer = Replica::fresh();
    newcomer.installed = false;
    newcomer.inherited = singleton(2, 1);
    newcomer.online = false;
    newcomer.online = true;
    require(
        !newcomer.vote(3, 1),
        "download-before-install crash permitted vote",
    )?;
    newcomer.installed = true;
    require(
        newcomer.vote(3, 1),
        "durably installed node cannot progress",
    )?;
    let receipts: Vec<_> = (20..34)
        .map(|signer| InstallReceipt {
            epoch: 1,
            value: 1,
            signer,
        })
        .collect();
    let emitted: BTreeMap<_, _> = (20..34).map(|id| ((1, 1, id), singleton(2, 1))).collect();
    require(
        install_quorum(
            1,
            1,
            &(20..40).collect::<Vec<_>>(),
            &singleton(2, 1),
            &receipts,
            &emitted,
        ),
        "valid install quorum rejected",
    )?;
    let mut duplicate = receipts.clone();
    duplicate[13] = duplicate[0].clone();
    require(
        !install_quorum(
            1,
            1,
            &(20..40).collect::<Vec<_>>(),
            &singleton(2, 1),
            &duplicate,
            &emitted,
        ),
        "duplicate installation counted",
    )?;
    let mut stale = receipts.clone();
    stale[0].epoch = 0;
    require(
        !install_quorum(
            1,
            1,
            &(20..40).collect::<Vec<_>>(),
            &singleton(2, 1),
            &stale,
            &emitted,
        ),
        "stale install receipt counted",
    )?;
    let mut outsider = receipts;
    outsider[0].signer = 99;
    require(
        !install_quorum(
            1,
            1,
            &(20..40).collect::<Vec<_>>(),
            &singleton(2, 1),
            &outsider,
            &emitted,
        ),
        "nonmember installation counted",
    )?;
    Ok(12)
}
fn conflicts(seed: u64) -> Result<u64, String> {
    let mut lab = Lab::new();
    lab.replicas.get_mut(&6).ok_or("missing witness")?.own = singleton(1, 1);
    lab.replicas.get_mut(&7).ok_or("missing witness")?.own = singleton(1, 2);
    for generation in 1..=3 {
        let next: Vec<Id> = (generation * 20..generation * 20 + 20).collect();
        lab.handoff(next.clone(), seed + u64::from(generation))?;
        require(
            !lab.collect(1, 1, &next)? && !lab.collect(1, 2, &next)?,
            "partial-conflict slot became signable",
        )?;
        require(
            lab.collect(100 + u32::from(generation), 1, &next)?,
            "unrelated payment blocked",
        )?;
    }
    require(
        lab.replicas[&60].inherited.get(&1) == Some(&BTreeSet::from([1, 2])),
        "repeated inherited conflict forgotten",
    )?;
    println!(
        "  SCOPE: exact bounded effect sets; conflict compression and root TTL are not modeled"
    );
    Ok(lab.events)
}
fn late_conflict_resolution(seed: u64) -> Result<u64, String> {
    let mut lab = Lab::new();
    let actual: Vec<Id> = (0..14).collect();
    require(
        lab.collect(1, 1, &actual)?,
        "late-proof fixture lacks full A",
    )?;
    let late = PaymentCert {
        epoch: 0,
        slot: 1,
        value: 1,
        voters: actual.into_iter().collect(),
    };
    lab.accepted.remove(&1);
    // Authentic conflicting partial intents are idealized owner-authorized input;
    // this does not assume a faulty node can fabricate somebody else's lock.
    lab.replicas.get_mut(&14).ok_or("missing B witness")?.own = singleton(1, 2);
    lab.replicas.get_mut(&15).ok_or("missing C witness")?.own = singleton(1, 3);
    lab.handoff((20..40).collect(), seed)?;
    lab.handoff((40..60).collect(), seed + 1)?;
    let voters = lab.members.clone();
    require(
        !lab.collect(1, 1, &voters)? && !lab.collect(1, 2, &voters)?,
        "partial conflict was not blocked",
    )?;
    require(
        lab.replicas[&40].inherited.get(&1) == Some(&BTreeSet::from([1, 2, 3])),
        "third candidate disappeared",
    )?;
    let forged = PaymentCert {
        epoch: 0,
        slot: 1,
        value: 2,
        voters: (0..14).collect(),
    };
    require(!lab.valid_certificate(&forged), "unsupported B certified")?;
    lab.submit_certificate(&late)?;
    require(
        lab.replicas[&40].inherited.get(&1) == Some(&BTreeSet::from([1, 2, 3])),
        "monitor leaked certificate to replica",
    )?;
    lab.present_certificate(&late, &voters)?;
    require(
        lab.replicas[&40].inherited.get(&1) == Some(&BTreeSet::from([1])),
        "valid late full A failed to resolve ambiguity",
    )?;
    require(
        lab.collect(1, 1, &voters)?,
        "proven A retry blocked after late proof",
    )?;
    require(
        !lab.collect(1, 2, &voters)?,
        "conflicting B accepted after late proof",
    )?;
    require(
        lab.replicas[&14].own == singleton(1, 2),
        "old private B choice erased by late A proof",
    )?;
    Ok(lab.events)
}

fn split_recovery(seed: u64) -> Result<u64, String> {
    let mut lab = Lab::new();
    let members = lab.members.clone();
    let package = lab.package((20..40).collect(), &members, None)?;
    let mut other = package.clone();
    other.next = (40..60).collect();
    let mut agreement = Agreement::new(
        members.clone(),
        lab.faulty.clone(),
        BTreeMap::from([(1, package), (2, other)]),
        seed,
        lab.epoch,
        lab.closure_registry.clone(),
    );
    // Byzantine view-zero leader equivocates:13 recipients prefer P,7 prefer Q.
    // Correct replicas issue at most one prepare per view; neither value gets14.
    for (index, id) in members.iter().enumerate() {
        agreement.send(
            0,
            *id,
            Message::Proposal {
                view: 0,
                value: if index < 13 { 1 } else { 2 },
                changes: Vec::new(),
            },
        );
    }
    agreement.run()?;
    require(agreement.decisions.is_empty(), "split unexpectedly decided")?;
    agreement.decide()?;
    require(
        agreement
            .nodes
            .values()
            .filter(|node| node.decided.is_some())
            .count()
            >= Q,
        "view-change failed to recover",
    )?;
    Ok(agreement.processed)
}
fn prepared_recovery(seed: u64) -> Result<u64, String> {
    let mut lab = Lab::new();
    for id in 14..20 {
        lab.replicas
            .get_mut(&id)
            .ok_or("missing omitted voter")?
            .own = singleton(100 + u32::from(id), 1);
    }
    let reports: Vec<_> = (0..14).collect();
    let carried = lab.package((20..40).collect(), &reports, None)?;
    require(
        carried.endorsers.len() >= Q,
        "partial closure package invalid",
    )?;
    require(
        !includes(&carried.state, &lab.replicas[&14].obligations()),
        "private-omission regression not exercised",
    )?;
    let all = lab.members.clone();
    let alternative = lab.package((40..60).collect(), &all, None)?;
    // Value1 is the leader's fresh default. Prepared value2 MUST override it.
    let mut agreement = Agreement::new(
        all,
        lab.faulty.clone(),
        BTreeMap::from([(1, alternative), (2, carried)]),
        seed,
        lab.epoch,
        lab.closure_registry.clone(),
    );
    for to in 6..14 {
        agreement.send(
            0,
            to,
            Message::Proposal {
                view: 0,
                value: 2,
                changes: Vec::new(),
            },
        );
        for from in 0..6 {
            agreement.send(from, to, Message::Prepare { view: 0, value: 2 });
        }
    }
    agreement.run()?;
    require(
        agreement
            .nodes
            .values()
            .filter(|node| node.prepared.as_ref().is_some_and(|p| p.value == 2))
            .count()
            == 8,
        "prepared carryover fixture did not prepare at8 honest nodes",
    )?;
    require(
        agreement.decisions.is_empty(),
        "withheld Byzantine commits unexpectedly decided",
    )?;
    let value = agreement.decide()?;
    require(value == 2, "view change discarded highest prepared value")?;
    require(
        agreement.nodes[&14].decided == Some(2),
        "publicly valid closure rejected due to private singleton omission",
    )?;
    require(
        lab.replicas[&14].own == singleton(114, 1),
        "private immutable choice was erased",
    )?;
    Ok(agreement.processed)
}
fn invalid_evidence(seed: u64) -> Result<u64, String> {
    let mut lab = Lab::new();
    let all = lab.members.clone();
    require(lab.collect(1, 1, &all)?, "fixture payment failed")?;
    let package = lab.package((20..40).collect(), &all, None)?;
    let mut agreement = Agreement::new(
        all,
        lab.faulty,
        BTreeMap::from([(1, package)]),
        seed,
        lab.epoch,
        lab.closure_registry.clone(),
    );
    require(agreement.valid_package(1), "valid evidence baseline failed")?;
    agreement
        .packages
        .get_mut(&1)
        .ok_or("missing payload")?
        .state
        .remove(&1);
    require(
        !agreement.valid_package(1),
        "incomplete snapshot authenticated as complete",
    )?;
    agreement.broadcast(
        0,
        Message::Proposal {
            view: 0,
            value: 1,
            changes: Vec::new(),
        },
    );
    agreement.run()?;
    require(
        agreement.decisions.is_empty() && agreement.rejected == 14,
        "incomplete proposal was not rejected by every honest replica",
    )?;
    // Restore the valid payload before testing prepare provenance: otherwise
    // package invalidity would make this check vacuous.
    agreement
        .packages
        .get_mut(&1)
        .ok_or("missing package")?
        .state = singleton(1, 1);
    require(
        agreement.valid_package(1),
        "forged-prepare fixture package invalid",
    )?;
    let authentic = agreement
        .packages
        .get(&1)
        .ok_or("missing authentic package")?
        .clone();
    let mut forged_package = authentic.clone();
    forged_package.state.clear();
    forged_package.endorsed_state.clear();
    for evidence in forged_package.inclusion.values_mut() {
        evidence.clear();
    }
    // Rebinding a fresh value does not confer signatures for a different state.
    agreement.packages.insert(77, forged_package.clone());
    agreement.value_bindings.insert(77, forged_package);
    require(
        !agreement.valid_package(77),
        "self-consistent forged closure signatures accepted",
    )?;
    agreement
        .packages
        .get_mut(&1)
        .ok_or("missing original value")?
        .next = (60..80).collect();
    require(
        !agreement.valid_package(1),
        "agreement value retargeted to another successor",
    )?;
    agreement.packages.insert(1, authentic);
    let fabricated = Prepared {
        view: 0,
        value: 1,
        voters: (0..14).collect(),
    };
    require(
        !agreement.valid_prepared(&fabricated),
        "fabricated prepared signatures accepted",
    )?;
    let fabricated_changes: Vec<_> = (0..14)
        .map(|sender| Change {
            sender,
            next_view: 6,
            prepared: None,
        })
        .collect();
    require(
        agreement.chosen(6, &fabricated_changes).is_err(),
        "fabricated nested change signatures accepted",
    )?;
    agreement.epoch += 1;
    require(
        !agreement.valid_package(1),
        "old-epoch closure replay accepted",
    )?;
    Ok(agreement.processed)
}

fn stalled(seed: u64) -> Result<u64, String> {
    let mut lab = Lab::new();
    let members = lab.members.clone();
    let package = lab.package((20..40).collect(), &members, None)?;
    let mut faulty = lab.faulty.clone();
    faulty.insert(6); // six Byzantine plus one unavailable honest
    let mut agreement = Agreement::new(
        members,
        faulty,
        BTreeMap::from([(1, package)]),
        seed,
        lab.epoch,
        lab.closure_registry.clone(),
    );
    agreement.timeout(7);
    agreement.run()?;
    require(
        agreement.decisions.is_empty(),
        "thirteen available participants decided",
    )?;
    println!(
        "  EXPECTED-STALL: 13 available identities cannot produce14 votes; liveness premise absent"
    );
    Ok(agreement.processed)
}
fn old_new_split(seed: u64) -> Result<u64, String> {
    let mut lab = Lab::new();
    let old = lab.members.clone();
    require(lab.collect(1, 1, &old)?, "old payment failed")?;
    lab.handoff((20..40).collect(), seed)?;
    for id in old {
        require(
            !lab.replicas
                .get_mut(&id)
                .ok_or("missing old replica")?
                .vote(2, 1),
            "retired honest replica signs",
        )?;
    }
    let next = lab.members.clone();
    require(lab.collect(2, 1, &next)?, "successor cannot progress")?;
    lab.handoff((30..50).collect(), seed + 1)?;
    for id in 30..40 {
        let reused = lab.replicas.get_mut(&id).ok_or("missing reused signer")?;
        require(
            !reused.vote_at(1, 3, 1),
            "reused identity reopened an old epoch",
        )?;
        reused.online = false;
        reused.online = true;
        require(
            !reused.vote_at(1, 3, 1),
            "restart erased historical epoch fence",
        )?;
    }
    let overlapping_next = lab.members.clone();
    require(
        lab.collect(3, 1, &overlapping_next)?,
        "overlapping successor failed to vote in new epoch",
    )?;
    Ok(lab.events)
}

pub fn run_cli() -> Result<(), String> {
    let mut seed = 1u64;
    let mut scenario = "all".to_string();
    let mut seed_count = 1_u64;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seed" => {
                seed = args
                    .next()
                    .ok_or("missing --seed value")?
                    .parse()
                    .map_err(|_| "invalid seed")?
            }
            "--scenario" => scenario = args.next().ok_or("missing --scenario value")?,
            "--seed-count" => {
                seed_count = args
                    .next()
                    .ok_or("missing --seed-count value")?
                    .parse()
                    .map_err(|_| "invalid seed count")?;
            }
            "--help" | "-h" => {
                println!("Usage: cargo run -p humoco-sim-core --example membership_handoff_model -- [--seed N] [--seed-count N] [--scenario all|handoff|bootstrap|capacity|lifecycle|baseline|unsafe-copy|generations|minority|durability|conflicts|split-recovery|late-conflict-resolution|prepared-recovery|invalid-evidence|stalled|old-new-split]");
                return Ok(());
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    require(
        (1..=10_000).contains(&seed_count),
        "seed count outside bounded model range 1..=10000",
    )?;
    println!("CONDITIONAL MODEL: recognized initial20 for handoff fixtures, q14, static fault identities, <=6 in each configuration throughout its evidence lifetime; authenticated statements, durable nonrollback storage; first-FINAL discovery additionally requires the explicit bootstrap graph/identity premises");
    println!("MODEL v1 seed={seed} rng=xorshift64 scheduler=(virtual_us,serial); agreement identity/signature abstraction; no QUIC or production proof");
    println!("SCOPE: agreement uses scheduled message events; durable/fence/install checks use explicit scripted state transitions, not exhaustive interleavings");
    type Scenario = (&'static str, fn(u64) -> Result<u64, String>);
    let cases: [Scenario; 12] = [
        ("baseline", baseline),
        ("unsafe-copy", unsafe_copy),
        ("generations", generations),
        ("minority", minority),
        ("durability", durability),
        ("conflicts", conflicts),
        ("split-recovery", split_recovery),
        ("late-conflict-resolution", late_conflict_resolution),
        ("prepared-recovery", prepared_recovery),
        ("invalid-evidence", invalid_evidence),
        ("stalled", stalled),
        ("old-new-split", old_new_split),
    ];
    let mut count = 0;
    let mut events = 0;
    for offset in 0..seed_count {
        let current_seed = seed.checked_add(offset).ok_or("seed range overflow")?;
        for (name, run) in cases {
            if scenario == "all" || scenario == "handoff" || scenario == name {
                let processed = run(current_seed)
                    .map_err(|error| format!("scenario={name} seed={current_seed}: {error}"))?;
                println!("PASS {name} model_steps={processed} seed={current_seed}");
                count += 1;
                events += processed;
            }
        }
    }
    if scenario == "all" || scenario == "bootstrap" {
        let checked = crate::bootstrap::run_checks()?;
        count += checked;
    }
    if scenario == "all" || scenario == "lifecycle" {
        count += crate::lifecycle::run_checks()?;
    }
    if scenario == "all" || scenario == "capacity" {
        let checked = crate::capacity::run_checks()?;
        count += checked;
    }
    require(count > 0, "unknown scenario")?;
    println!("PASS summary scenarios={count} handoff_model_steps={events} seed_count={seed_count}; bootstrap/capacity counts printed separately; seeded bounded execution, not exhaustive verification");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_unsafe_copy_is_detected() {
        assert!(unsafe_copy(1).is_ok());
    }
    #[test]
    fn honest_quorum_recovers_split() {
        for seed in [1, 7, 42] {
            assert!(split_recovery(seed).is_ok());
        }
    }
    #[test]
    fn complete_turnover_preserves_effects() {
        assert!(generations(42).is_ok());
    }
    #[test]
    fn minority_and_durability() {
        assert!(minority(7).is_ok());
        assert!(durability(1).is_ok());
    }
    #[test]
    fn blocked_slot_does_not_block_others() {
        assert!(conflicts(42).is_ok());
    }
    #[test]
    fn late_full_certificate_resolves_three_way_partial_conflict() {
        assert!(late_conflict_resolution(7).is_ok());
    }
    #[test]
    fn prepared_value_survives_and_public_validity_recovers() {
        assert!(prepared_recovery(42).is_ok());
    }
    #[test]
    fn incomplete_and_fabricated_evidence_rejected() {
        assert!(invalid_evidence(1).is_ok());
    }
    #[test]
    fn unavailable_quorum_does_not_decide() {
        assert!(stalled(1).is_ok());
    }
}
