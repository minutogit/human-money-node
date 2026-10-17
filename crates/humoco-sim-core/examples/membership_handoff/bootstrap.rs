//! Bounded local-message study of authenticated participant discovery.
//!
//! This deliberately implements the **literal source-boundary** P3 printed in
//! Heydari et al., arXiv:2405.06055v2, Theorem 3 / Algorithm 2. It reproduces a
//! liveness discrepancy on a complete 20-node graph with six silent nodes. It is
//! NOT a repaired implementation, a bootstrap safety proof, or value consensus.
//! https://arxiv.org/html/2405.06055v2
//!
//! Authentication is an ideal unforgeable-identity primitive. This is not real
//! cryptography, QUIC, a performance benchmark, or the production learned-peer
//! authorization policy. Queries additionally require mutual learned identities;
//! real F2F presence gossip, incubation and resource budgets remain out of scope.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

type Id = usize;
type Set = BTreeSet<Id>;
const F: usize = 6;
const INSTANCE: u64 = 1;
const DAY_MS: u64 = 86_400_000;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Pd {
    instance: u64,
    issuer: Id,
    // An ideal authentication oracle supplies this identity. It is not wire data.
    authenticated_as: Id,
    neighbors: Set,
    // Ideal signed presence proofs belonging to each named neighbor, bound to
    // this instance. Bare invented public keys are insufficient eligibility.
    authenticated_neighbors: Set,
}

impl Pd {
    fn ideal_signed(issuer: Id, neighbors: Set) -> Self {
        Self {
            instance: INSTANCE,
            issuer,
            authenticated_as: issuer,
            authenticated_neighbors: neighbors.clone(),
            neighbors,
        }
    }
}

#[derive(Clone, Debug)]
struct Local {
    known: Set,
    received: BTreeMap<Id, Pd>,
    equivocators: Set,
    rejected: usize,
}

impl Local {
    fn new(own: Pd) -> Self {
        let mut known = own.neighbors.clone();
        known.insert(own.issuer);
        Self {
            known,
            received: BTreeMap::from([(own.issuer, own)]),
            equivocators: Set::new(),
            rejected: 0,
        }
    }

    fn receive(&mut self, pd: Pd) {
        if pd.instance != INSTANCE
            || pd.issuer != pd.authenticated_as
            || !pd.neighbors.is_subset(&pd.authenticated_neighbors)
        {
            self.rejected += 1;
            return;
        }
        if self.equivocators.contains(&pd.issuer) {
            return;
        }
        if let Some(old) = self.received.get(&pd.issuer) {
            if old != &pd {
                // Do not silently substitute the latest claimed immutable PD.
                // Quarantine is conservative; no liveness claim is made for it.
                self.equivocators.insert(pd.issuer);
                self.received.remove(&pd.issuer);
            }
            return;
        }
        self.known.insert(pd.issuer);
        self.known.extend(pd.neighbors.iter().copied());
        self.received.insert(pd.issuer, pd);
    }

    // Independent stronger candidate; NOT a correction attributed to the paper.
    // Global conditional premise: all correct instance participants form a
    // 7-vertex-strongly-connected knowledge graph; at most six Byzantine eligible
    // identities in the fixed bootstrap instance. The admission predicate sees only rows.
    fn closed_candidate(&self) -> Option<ClosedWitness> {
        let received: Set = self.received.keys().copied().collect();
        if received.len() < 2 * F + 1 {
            return None;
        }
        let mut universe = received.clone();
        for pd in self.received.values() {
            universe.extend(pd.neighbors.iter().copied());
        }
        if universe.difference(&received).count() > F {
            return None;
        }
        Some(ClosedWitness { universe, received })
    }

    fn literal_witness(&self, members: &Set) -> Option<Set> {
        if members.len() < 2 * F + 1 || !members.iter().all(|id| self.received.contains_key(id)) {
            return None;
        }
        // P3 counts sources, NOT distinct outside target identities. This is the
        // wording in both the HTML and PDF; changing it would be a new algorithm.
        let outgoing_sources = members
            .iter()
            .filter(|id| {
                self.received
                    .get(id)
                    .is_some_and(|pd| pd.neighbors.iter().any(|v| !members.contains(v)))
            })
            .count();
        if outgoing_sources > F || !vertex_connected(members, &self.received, F + 1) {
            return None;
        }
        let mut result = members.clone();
        for outside in self.known.difference(members) {
            let incoming = members
                .iter()
                .filter(|id| {
                    self.received
                        .get(id)
                        .is_some_and(|pd| pd.neighbors.contains(outside))
                })
                .count();
            if incoming > F {
                result.insert(*outside);
            }
        }
        Some(result)
    }

    fn literal_sink(&self) -> Option<Set> {
        let received: Vec<_> = self.received.keys().copied().collect();
        // Bounded research model only, never allocate/exponentiate on wire input.
        if received.len() < 2 * F + 1 || received.len() > 22 {
            return None;
        }
        let all: Set = received.iter().copied().collect();
        if let Some(sink) = self.literal_witness(&all) {
            return Some(sink);
        }
        // Enumerate every available S1, including partial candidates. P3 is cheap
        // and runs before max-flow, so the silent-node discrepancy is inexpensive.
        for bits in 0u64..(1u64 << received.len()) {
            if bits.count_ones() < (2 * F + 1) as u32
                || bits.count_ones() as usize == received.len()
            {
                continue;
            }
            let members = received
                .iter()
                .enumerate()
                .filter_map(|(i, id)| {
                    if bits & (1u64 << i) != 0 {
                        Some(*id)
                    } else {
                        None
                    }
                })
                .collect();
            if let Some(sink) = self.literal_witness(&members) {
                return Some(sink);
            }
        }
        None
    }
}

#[derive(Debug)]
struct ClosedWitness {
    universe: Set,
    received: Set,
}

/// A verifiable local transcript, not a trusted list of actual participants.
/// Completeness still depends on the explicitly stated global graph premise.
#[derive(Clone)]
pub struct AdmissionEvidence {
    rows: Vec<Pd>,
}

impl AdmissionEvidence {
    pub fn members(&self) -> Result<Vec<u16>, String> {
        let mut verifier = Local {
            known: Set::new(),
            received: BTreeMap::new(),
            equivocators: Set::new(),
            rejected: 0,
        };
        for row in &self.rows {
            verifier.receive(row.clone());
        }
        require(
            verifier.rejected == 0 && verifier.equivocators.is_empty(),
            "invalid discovery transcript",
        )?;
        let witness = verifier
            .closed_candidate()
            .ok_or("incomplete closed-knowledge transcript")?;
        require(
            (20..=64).contains(&witness.universe.len()),
            "integrated initial-FINAL fixture requires twenty to sixty-four discovered identities",
        )?;
        witness
            .universe
            .into_iter()
            .map(|id| u16::try_from(id).map_err(|_| "model identity out of range".to_string()))
            .collect()
    }
}

// Unit vertex capacities with split in/out vertices; source/destination are not
// counted as internal vertices. Every original edge has capacity one, including
// the direct source->destination path. Stop once the required flow is reached.
fn disjoint_paths(
    ids: &[Id],
    pds: &BTreeMap<Id, Pd>,
    source: usize,
    target: usize,
    required: usize,
) -> usize {
    let n = ids.len();
    let mut residual = vec![vec![0usize; 2 * n]; 2 * n];
    for i in 0..n {
        residual[2 * i][2 * i + 1] = if i == source || i == target {
            required
        } else {
            1
        };
        for j in 0..n {
            if i != j
                && pds
                    .get(&ids[i])
                    .is_some_and(|pd| pd.neighbors.contains(&ids[j]))
            {
                residual[2 * i + 1][2 * j] = 1;
            }
        }
    }
    let start = 2 * source + 1;
    let end = 2 * target;
    let mut flow = 0;
    while flow < required {
        let mut parent = vec![None; 2 * n];
        parent[start] = Some(start);
        let mut queue = VecDeque::from([start]);
        while let Some(u) = queue.pop_front() {
            for v in 0..2 * n {
                if residual[u][v] > 0 && parent[v].is_none() {
                    parent[v] = Some(u);
                    queue.push_back(v);
                }
            }
        }
        if parent[end].is_none() {
            break;
        }
        let mut v = end;
        while v != start {
            let Some(u) = parent[v] else {
                return flow;
            };
            residual[u][v] -= 1;
            residual[v][u] += 1;
            v = u;
        }
        flow += 1;
    }
    flow
}

fn vertex_connected(members: &Set, pds: &BTreeMap<Id, Pd>, required: usize) -> bool {
    if members.len() <= required {
        return false;
    }
    let ids: Vec<_> = members.iter().copied().collect();
    for i in 0..ids.len() {
        for j in 0..ids.len() {
            if i != j && disjoint_paths(&ids, pds, i, j, required) < required {
                return false;
            }
        }
    }
    true
}

#[derive(Clone)]
enum Message {
    Query { from: Id, to: Id },
    Reply { to: Id, statements: Vec<Pd> },
}

struct Harness {
    locals: BTreeMap<Id, Local>,
    // Scheduler-only fault behavior; Local/Sink never receive this set.
    silent: Set,
    messages: usize,
}

impl Harness {
    fn new(pds: Vec<Pd>, silent: Set) -> Self {
        Self {
            locals: pds
                .into_iter()
                .map(|pd| (pd.issuer, Local::new(pd)))
                .collect(),
            silent,
            messages: 0,
        }
    }

    fn fair_round(&mut self, deliver: bool) {
        let queries: Vec<_> = self
            .locals
            .iter()
            .flat_map(|(from, local)| {
                local.known.iter().map(move |to| Message::Query {
                    from: *from,
                    to: *to,
                })
            })
            .collect();
        let mut replies = Vec::new();
        for msg in queries {
            self.messages += 1;
            if !deliver {
                continue;
            }
            if let Message::Query { from, to } = msg {
                if self.silent.contains(&to) {
                    continue;
                }
                if let Some(local) = self.locals.get(&to) {
                    // A learned destination is insufficient when that receiver
                    // has not learned the sender. This models mutual direct-RPC
                    // admission; full F2F presence gossip/TTL remains out of scope.
                    if !local.known.contains(&from) {
                        continue;
                    }
                    replies.push(Message::Reply {
                        to: from,
                        statements: local.received.values().cloned().collect(),
                    });
                }
            }
        }
        for msg in replies {
            self.messages += 1;
            if let Message::Reply { to, statements } = msg {
                if let Some(local) = self.locals.get_mut(&to) {
                    for pd in statements {
                        local.receive(pd);
                    }
                }
            }
        }
    }

    fn converge(&mut self) {
        self.fair_round(false); // arbitrary pre-GST loss/delay
        for _ in 0..8 {
            self.fair_round(true);
        } // fair after GST, bounded fixture
    }
}

fn complete(n: usize) -> Vec<Pd> {
    (0..n)
        .map(|id| Pd::ideal_signed(id, (0..n).filter(|j| *j != id).collect()))
        .collect()
}

fn require(ok: bool, message: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

// Sink discovery is deliberately not value agreement. A separate BFT completion
// must choose the initial membership AND a justified provisional-state import.
#[derive(Default)]
struct InitialGate {
    stable_since_ms: Option<u64>,
    membership_decided: bool,
    provisional_import_justified: bool,
}
impl InitialGate {
    fn final_ready(&self, now_ms: u64, roster: &Set) -> bool {
        roster.len() == 20
            && self.membership_decided
            && self.provisional_import_justified
            && self
                .stable_since_ms
                .is_some_and(|t| now_ms.saturating_sub(t) >= DAY_MS)
    }
}

/// Returns the number of bounded checks, including explicitly expected failures
/// of the literal candidate. A successful run does NOT mean bootstrap is solved.
pub fn run_checks() -> Result<usize, String> {
    let all: Set = (0..20).collect();
    let mut checks = 0;

    // Cooperating fault-capable nodes: the literal predicate can find a sink.
    let mut cooperating = Harness::new(complete(20), Set::new());
    cooperating.converge();
    for local in cooperating.locals.values() {
        require(
            local.literal_sink() == Some(all.clone()),
            "cooperating discovery failed",
        )?;
    }
    checks += 1;

    // Fully connected physical/knowledge fixture, actual f=6 static silent nodes.
    // The honest induced graph is a complete 14-vertex digraph (kappa=13>=7).
    // Thus the graph premise is strong enough; literal P3 still never succeeds.
    let silent: Set = (14..20).collect();
    let mut stopped = Harness::new(complete(20), silent.clone());
    stopped.converge();
    let honest: Set = (0..14).collect();
    let honest_pds = stopped
        .locals
        .get(&0)
        .ok_or("missing fixture node")?
        .received
        .clone();
    require(
        vertex_connected(&honest, &honest_pds, F + 1),
        "honest fixture connectivity invalid",
    )?;
    for id in &honest {
        let local = stopped.locals.get(id).ok_or("missing honest node")?;
        require(
            local.received.len() == 14,
            "silent nodes unexpectedly replied",
        )?;
        require(
            local.literal_sink().is_none(),
            "literal P3 discrepancy disappeared",
        )?;
    }
    println!("  EXPECTED LIVENESS COUNTEREXAMPLE: literal CUP P3, complete20, six silent, honest kappa>=7; no sink");
    checks += 1;

    // A separate, stronger closed-knowledge candidate avoids the literal P3
    // discrepancy, under explicitly stronger graph/eligibility premises. It
    // does not secretly read the actual population or scheduler fault set.
    for id in &honest {
        let candidate = stopped
            .locals
            .get(id)
            .ok_or("missing honest node")?
            .closed_candidate()
            .ok_or("closed candidate did not discover silent fixture")?;
        require(
            candidate.universe == all && candidate.received == honest,
            "closed candidate inferred wrong fixture universe",
        )?;
    }
    println!("  CONDITIONAL CANDIDATE: closed authenticated rows discover20 despite six silent; requires globally 7-connected correct graph and a static six-identity bound in this bootstrap instance");
    checks += 1;

    let transcript = AdmissionEvidence {
        rows: stopped
            .locals
            .get(&0)
            .ok_or("missing transcript source")?
            .received
            .values()
            .cloned()
            .collect(),
    };
    require(
        transcript.members()?.len() == 20,
        "valid transcript rejected",
    )?;
    let mut invalid_transcript = transcript.clone();
    invalid_transcript.rows.truncate(12);
    require(
        invalid_transcript.members().is_err(),
        "undersized transcript admitted",
    )?;
    let events = crate::model::exercise_initial_final(&transcript, &(14_u16..20).collect(), 41)?;
    println!("  INTEGRATED CONDITIONAL FIXTURE: transcript verification -> closure -> membership agreement -> 24h gate -> first FINAL; {events} model steps (strong graph premise)");
    checks += 1;

    for population in [21, 22] {
        let mut growing = Harness::new(complete(population), silent.clone());
        growing.converge();
        let local = growing.locals.get(&0).ok_or("missing growth observer")?;
        let evidence = AdmissionEvidence {
            rows: local.received.values().cloned().collect(),
        };
        require(
            evidence.members()?.len() == population,
            "concurrent admission omitted discovered identity",
        )?;
        let events = crate::model::exercise_initial_final(
            &evidence,
            &(14_u16..20).collect(),
            population as u64,
        )?;
        println!("  CONDITIONAL GROWTH population={population}: adaptive bootstrap agreement -> fixed HRW14/20 -> full turnover; {events} model steps");
        checks += 1;
    }

    // A threshold property over all small h/b combinations; this is arithmetic,
    // not a claim that a variable-roster BFT agreement protocol is implemented.
    for h in 13..=64 {
        for b in 0..=F {
            let n = h + b;
            let q = 2 * n / 3 + 1;
            require(
                q <= h && 2 * (q - b) > h,
                "closed-candidate quorum lacks honest majority or availability",
            )?;
        }
    }
    checks += 1;

    // Sparse honest knowledge: 14-node circulant with +/-1..4 edges has vertex
    // connectivity >=7; six additional nodes are globally known and cooperate.
    // Initial catalogs differ; replies carry previously authenticated PDs.
    let sparse_pds: Vec<_> = (0..20)
        .map(|id| {
            let neighbors = if id < 14 {
                let mut s: Set = (14..20).collect();
                for delta in 1..=4 {
                    s.insert((id + delta) % 14);
                    s.insert((id + 14 - delta) % 14);
                }
                s
            } else {
                (0..20).filter(|j| *j != id).collect()
            };
            Pd::ideal_signed(id, neighbors)
        })
        .collect();
    let sparse_map = sparse_pds
        .iter()
        .map(|pd| (pd.issuer, pd.clone()))
        .collect();
    require(
        vertex_connected(&honest, &sparse_map, 7),
        "sparse honest graph not sufficiently connected",
    )?;
    let mut sparse = Harness::new(sparse_pds.clone(), Set::new());
    sparse.converge();
    for local in sparse.locals.values() {
        require(
            local.literal_sink() == Some(all.clone()),
            "sparse cooperating discovery failed",
        )?;
    }
    checks += 1;

    let mut sparse_silent = Harness::new(sparse_pds, silent.clone());
    sparse_silent.converge();
    for id in &honest {
        let witness = sparse_silent
            .locals
            .get(id)
            .ok_or("missing sparse node")?
            .closed_candidate()
            .ok_or("sparse silent closed discovery failed")?;
        require(
            witness.universe == all && witness.received == honest,
            "sparse closed witness omitted honest identity",
        )?;
    }
    checks += 1;

    // Byzantine participants can lie about their own PDs without forging honest
    // rows. All correct complete rows still force the closed candidate's U20.
    let lying_pds = complete(20)
        .into_iter()
        .map(|pd| {
            if silent.contains(&pd.issuer) {
                Pd::ideal_signed(pd.issuer, Set::new())
            } else {
                pd
            }
        })
        .collect();
    let mut lying = Harness::new(lying_pds, Set::new());
    lying.converge();
    for id in &honest {
        let witness = lying
            .locals
            .get(id)
            .ok_or("missing lying-case node")?
            .closed_candidate()
            .ok_or("lying PDs stalled closed discovery")?;
        require(
            witness.universe == all,
            "lying PDs excluded honest identity",
        )?;
    }
    checks += 1;

    // Authentication, duplicate and immutable-instance checks.
    let mut receiver = Local::new(Pd::ideal_signed(100, Set::from([0])));
    let statement = Pd::ideal_signed(0, Set::from([1, 2]));
    receiver.receive(statement.clone());
    receiver.receive(statement.clone());
    require(receiver.received.len() == 2, "duplicate grew PD store")?;
    let mut forged = statement.clone();
    forged.issuer = 77;
    receiver.receive(forged);
    require(
        !receiver.known.contains(&77) && receiver.rejected == 1,
        "forged identity accepted",
    )?;
    let mut phantom = Pd::ideal_signed(5, Set::from([6]));
    phantom.neighbors.insert(9999); // no genuine first-party eligibility proof
    receiver.receive(phantom);
    require(
        !receiver.known.contains(&9999) && receiver.rejected == 2,
        "unproven neighbor identity accepted",
    )?;
    let mut foreign = statement;
    foreign.instance += 1;
    receiver.receive(foreign);
    require(
        receiver.rejected == 3,
        "foreign bootstrap instance accepted",
    )?;
    receiver.receive(Pd::ideal_signed(0, Set::from([999])));
    require(
        receiver.equivocators.contains(&0)
            && !receiver.received.contains_key(&0)
            && !receiver.known.contains(&999),
        "equivocating PD silently replaced",
    )?;
    checks += 1;

    // Out-of-assumptions graph: two closed communities. Locally valid witnesses
    // can disagree. The harness labels the violated global premise; Local does
    // not inspect a global graph or grant authority based on its own assertion.
    let split_pds: Vec<_> = (0..28)
        .map(|id| {
            let start = if id < 14 { 0 } else { 14 };
            Pd::ideal_signed(id, (start..start + 14).filter(|j| *j != id).collect())
        })
        .collect();
    let mut split = Harness::new(split_pds, Set::new());
    split.converge();
    let left = split
        .locals
        .get(&0)
        .ok_or("missing split node")?
        .literal_sink();
    let right = split
        .locals
        .get(&14)
        .ok_or("missing split node")?
        .literal_sink();
    require(
        left.is_some() && right.is_some() && left != right,
        "split-graph witness missing",
    )?;
    println!("  OUT OF ASSUMPTIONS: disconnected knowledge communities yield different local sink witnesses");
    checks += 1;

    // Different actual worlds, identical received prefixes. The extra nodes
    // initially know the original twenty, whose frozen PDs do not name them.
    // Their outgoing queries do not magically disclose them to the old nodes.
    // This is compatible with a common discovered sink: sink != full population.
    let mut extended_pds = complete(20);
    extended_pds.push(Pd::ideal_signed(20, (0..20).collect()));
    extended_pds.push(Pd::ideal_signed(21, (0..20).collect()));
    let mut hidden_world = Harness::new(extended_pds, Set::new());
    hidden_world.converge();
    let observed = cooperating.locals.get(&0).ok_or("missing observer")?;
    let hidden_world_observer = hidden_world
        .locals
        .get(&0)
        .ok_or("missing extended observer")?;
    require(
        hidden_world.locals.len() == 22 && cooperating.locals.len() == 20,
        "hidden-world populations are not distinct",
    )?;
    require(
        observed.known == hidden_world_observer.known
            && observed.received == hidden_world_observer.received,
        "indistinguishable-prefix fixture differs",
    )?;
    require(
        hidden_world_observer.literal_sink() == observed.literal_sink(),
        "common sink changed despite identical evidence",
    )?;
    require(
        hidden_world_observer.closed_candidate().is_some(),
        "closed candidate unexpectedly detects unseen outside participant",
    )?;
    let entire_extended_correct: Set = (0..22).collect();
    let extended_rows: BTreeMap<_, _> = hidden_world
        .locals
        .iter()
        .filter_map(|(id, local)| local.received.get(id).cloned().map(|pd| (*id, pd)))
        .collect();
    require(
        !vertex_connected(&entire_extended_correct, &extended_rows, F + 1),
        "hidden outside nodes unexpectedly meet stronger closed-knowledge premise",
    )?;
    println!("  LIMIT: actual20/22 prefixes match; closed-candidate completeness fails outside its global strong-connectivity premise, while a common CUP sink may exist");
    checks += 1;

    let mut nineteen = Harness::new(complete(19), Set::new());
    nineteen.converge();
    let sink19 = nineteen
        .locals
        .get(&0)
        .ok_or("missing nineteen node")?
        .literal_sink()
        .ok_or("nineteen sink not discovered")?;
    require(sink19.len() == 19, "unexpected sink size")?;
    let gate = InitialGate::default();
    require(
        !gate.final_ready(2 * DAY_MS, &sink19),
        "nineteen sink authorized FINAL",
    )?;
    require(
        !gate.final_ready(2 * DAY_MS, &all),
        "discovery alone authorized FINAL",
    )?;
    let decided_but_unimported = InitialGate {
        stable_since_ms: Some(0),
        membership_decided: true,
        provisional_import_justified: false,
    };
    require(
        !decided_but_unimported.final_ready(2 * DAY_MS, &all),
        "unimported provisional state authorized FINAL",
    )?;
    // This is an isolated gate unit check with explicit supplied premises, NOT
    // a fabricated BFT/provisional-import end-to-end implementation.
    let fixture = InitialGate {
        stable_since_ms: Some(0),
        membership_decided: true,
        provisional_import_justified: true,
    };
    require(
        !fixture.final_ready(DAY_MS - 1, &all) && fixture.final_ready(DAY_MS, &all),
        "24h virtual stability gate invalid",
    )?;
    checks += 1;

    println!("  Bootstrap study: {checks} checks; 20/21/22-node integrations are conditional; general dynamic bootstrap/provisional semantics remain OPEN; {} query/reply events in cooperating fixture", cooperating.messages);
    Ok(checks)
}

#[cfg(test)]
mod tests {
    #[test]
    fn discovery_admission_and_first_final_checks() -> Result<(), String> {
        super::run_checks().map(|_| ())
    }
}
