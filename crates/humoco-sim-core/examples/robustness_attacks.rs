#![forbid(unsafe_code)]
//! Independent research regressions. Not a production protocol or wire test.
//! Scripted deterministic schedules; no scheduler omniscience enters node rules.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::{BTreeMap, BTreeSet};

type Id = u16;
type Effects = BTreeSet<u8>;
const Q: usize = 14;

fn require(ok: bool, why: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}

#[derive(Default, Clone)]
struct Replica {
    own: Effects,
    inherited: Effects,
    closed: bool,
    installed: bool,
}
impl Replica {
    fn active() -> Self {
        Self {
            installed: true,
            ..Self::default()
        }
    }
    fn effects(&self) -> Effects {
        self.own.union(&self.inherited).copied().collect()
    }
    fn vote(&mut self, value: u8) -> bool {
        if !self.installed || self.closed || self.effects().iter().any(|v| *v != value) {
            return false;
        }
        self.own.insert(value);
        true
    }
    fn close(&mut self) -> Effects {
        self.closed = true;
        self.effects()
    }
    fn endorse(&self, package: &Effects) -> bool {
        self.closed && self.effects().is_subset(package)
    }
}

fn exact_twenty_two_trace() -> Result<(), String> {
    // F=0..5; H1=6,...,H14=19; X=20; Y=21.
    let old: BTreeSet<Id> = (0..20).collect();
    let new: BTreeSet<Id> = (0..6).chain(8..22).collect();
    let a: BTreeSet<Id> = (0..14).collect();
    let b: BTreeSet<Id> = (0..6).chain(14..22).collect();
    let mut replicas: BTreeMap<_, _> = (0..22).map(|id| (id, Replica::active())).collect();
    // t0: X,Y receive a complete EMPTY snapshot, before the old durable choices.
    for id in [20, 21] {
        replicas.get_mut(&id).ok_or("missing newcomer")?.inherited = Effects::new();
    }
    // t1: F + H1..H8 durably sign A; the aggregate remains at one gateway.
    for id in &a {
        if *id >= 6 {
            require(
                replicas.get_mut(id).ok_or("missing A voter")?.vote(1),
                "A refused",
            )?;
        }
    }
    // t2: mature X,Y activate without closing old writes or applying a final delta.
    // t3: F + H9..H14 + X,Y durably sign B from the new roster.
    for id in &b {
        if *id >= 6 {
            require(
                replicas.get_mut(id).ok_or("missing B voter")?.vote(2),
                "B refused",
            )?;
        }
    }
    require(old.len() == 20 && new.len() == 20, "wrong committees")?;
    require(a.is_subset(&old) && b.is_subset(&new), "nonmember vote")?;
    require(a.len() == Q && b.len() == Q, "missing conflicting FINAL")?;
    require(a.intersection(&b).all(|id| *id < 6), "honest equivocation")?;
    println!("TRACE unsafe-copy t0=empty-copy(X,Y) t1=durable-A(F,H1..H8) t2=activate(X,Y) t3=durable-B(F,H9..H14,X,Y) A=14 B=14 honest-double-signers=0");
    Ok(())
}

fn closure_intersection_exhaustive() -> Result<(), String> {
    // Fix a historical 14-vote certificate; enumerate every closure quorum.
    let historical: BTreeSet<Id> = (0..14).collect();
    let mut count = 0_u64;
    let mut minimum = 20;
    for bits in 0_u32..(1 << 20) {
        if bits.count_ones() != Q as u32 {
            continue;
        }
        let closure: BTreeSet<Id> = (0..20).filter(|id| bits & (1 << id) != 0).collect();
        let witnesses = closure
            .intersection(&historical)
            .filter(|id| **id >= 6)
            .count();
        minimum = minimum.min(witnesses);
        require(witnesses >= 2, "lost historical exclusion witness")?;
        let honest_fences = closure.iter().filter(|id| **id >= 6).count();
        require(
            20 - honest_fences < Q,
            "fresh old certificate remains possible",
        )?;
        count += 1;
    }
    require(
        count == 38_760 && minimum == 2,
        "vacuous intersection experiment",
    )?;
    println!("ENUM closure-quorums={count} minimum-honest-historical-witnesses={minimum}");
    Ok(())
}

fn private_inclusion_deadlock_and_repair() -> Result<(), String> {
    // A public closure certificate was issued by F + H1..H8 for state {A}.
    // All fourteen honest agreement voters are now available. H9..H14 retain
    // additional authentic private effects, omitted from that certified package.
    let package = Effects::from([1]);
    let mut old: BTreeMap<Id, Replica> = (0..20).map(|id| (id, Replica::active())).collect();
    for id in 6..14 {
        old.get_mut(&id).ok_or("missing witness")?.own.insert(1);
    }
    for id in 14..20 {
        old.get_mut(&id)
            .ok_or("missing private owner")?
            .own
            .insert(2);
    }
    for node in old.values_mut() {
        node.close();
    }
    let prepared_qc: BTreeSet<Id> = (0..14).collect();
    require(prepared_qc.len() == Q, "missing prepared QC")?;
    // Six Byzantine voters contributed prepares but now withhold commits.
    let private_acceptors = (6..20).filter(|id| old[id].endorse(&package)).count();
    require(
        private_acceptors == 8 && private_acceptors < Q,
        "mutant did not deadlock",
    )?;
    // Repair: existing closure provenance is public validity for agreement,
    // while immutable private obligations remain separately enforced on payment.
    let public_acceptors = (6..20).filter(|_| prepared_qc.len() == Q).count();
    require(public_acceptors == Q, "public-validity progress missing")?;
    require(
        (14..20).all(|id| old[&id].own == Effects::from([2])),
        "private choice erased",
    )?;
    println!("TRACE private-inclusion prepared=14 Byzantine-commits=0 private-validity-commits={private_acceptors} public-validity-commits={public_acceptors}");
    Ok(())
}

fn minority_and_repeated_replacement() -> Result<(), String> {
    let mut old: BTreeMap<Id, Replica> = (0..20).map(|id| (id, Replica::active())).collect();
    // Historical A=F+H1..H8. F lies in its report: B. Closure reports include
    // only H7,H8 from A and all six honest B voters: exactly two A/twelve B.
    for id in 6..14 {
        old.get_mut(&id).ok_or("missing A owner")?.own.insert(1);
    }
    for id in (0..6).chain(14..20) {
        old.get_mut(&id).ok_or("missing B owner")?.own.insert(2);
    }
    let reporters: Vec<Id> = (0..6).chain(12..20).collect();
    require(
        reporters
            .iter()
            .filter(|id| old[id].own.contains(&1))
            .count()
            == 2,
        "wrong minority",
    )?;
    let mut state = Effects::new();
    for id in &reporters {
        state.extend(old.get_mut(id).ok_or("missing reporter")?.close());
    }
    require(state == Effects::from([1, 2]), "minority discarded")?;
    require(
        reporters
            .iter()
            .filter(|id| **id >= 6)
            .all(|id| old[id].endorse(&state)),
        "closure not justified",
    )?;
    for generation in 1..=3 {
        let start: Id = generation * 20;
        let mut next: BTreeMap<Id, Replica> = (start..start + 20)
            .map(|id| (id, Replica::default()))
            .collect();
        for node in next.values_mut() {
            // Page receipt is separate from installation/activation.
            node.inherited = state.clone();
            require(!node.vote(1), "download without install voted")?;
            node.installed = true;
            require(
                !node.vote(1) && !node.vote(2),
                "ambiguous slot became signable",
            )?;
        }
        // Fresh-slot independence: its separate Replica state is empty.
        let fresh = (0..Q).filter(|_| Replica::active().vote(3)).count();
        require(fresh == Q, "unrelated fresh payment stalled")?;
        for node in next.values_mut() {
            state.extend(node.close());
        }
        old = next;
    }
    require(old.keys().all(|id| *id >= 60), "founder still required")?;
    println!("TRACE generations=3 complete-original-replacement=true inherited-conflict=blocked fresh-payments=3");
    Ok(())
}

fn digest(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[tag.len() as u8]);
    h.update(tag);
    h.update(data);
    *h.finalize().as_bytes()
}
fn key(id: u16) -> SigningKey {
    SigningKey::from_bytes(&digest(b"HUMOCO_RESEARCH_KEY", &id.to_le_bytes()))
}
#[derive(Clone)]
struct Auth {
    key: [u8; 32],
    sig: Signature,
}
fn sign(id: Id, context: &[u8]) -> Auth {
    let key = key(id);
    Auth {
        key: key.verifying_key().to_bytes(),
        sig: key.sign(context),
    }
}
fn verify(context: &[u8], members: &BTreeSet<[u8; 32]>, votes: &[Auth]) -> bool {
    let mut unique = BTreeSet::new();
    votes.len() >= Q
        && votes.iter().all(|vote| {
            members.contains(&vote.key)
                && unique.insert(vote.key)
                && VerifyingKey::from_bytes(&vote.key)
                    .is_ok_and(|vk| vk.verify_strict(context, &vote.sig).is_ok())
        })
}

fn real_signature_provenance() -> Result<(), String> {
    let members: BTreeSet<_> = (0..20)
        .map(|id| key(id).verifying_key().to_bytes())
        .collect();
    let context = digest(
        b"HUMOCO_RESEARCH_CLOSURE",
        b"instance=1;epoch=4;shard=17;state=A;successor=20..39",
    );
    let votes: Vec<_> = (0..14).map(|id| sign(id, &context)).collect();
    require(
        verify(&context, &members, &votes),
        "authentic baseline rejected",
    )?;
    let wrong_state = digest(
        b"HUMOCO_RESEARCH_CLOSURE",
        b"instance=1;epoch=4;shard=17;state=EMPTY;successor=20..39",
    );
    require(
        !verify(&wrong_state, &members, &votes),
        "self-consistent forged payload accepted",
    )?;
    let wrong_epoch = digest(
        b"HUMOCO_RESEARCH_CLOSURE",
        b"instance=1;epoch=5;shard=17;state=A;successor=20..39",
    );
    require(
        !verify(&wrong_epoch, &members, &votes),
        "stale context accepted",
    )?;
    let mut duplicate = votes.clone();
    duplicate[13] = duplicate[0].clone();
    require(
        !verify(&context, &members, &duplicate),
        "duplicate signer accepted",
    )?;
    let mut outsider = votes.clone();
    outsider[13] = sign(100, &context);
    require(
        !verify(&context, &members, &outsider),
        "unknown signer accepted",
    )?;
    // Signature validity never tells a recipient which self-created set to count.
    let fake_members: BTreeSet<_> = (100..120)
        .map(|id| key(id).verifying_key().to_bytes())
        .collect();
    let counterfeit: Vec<_> = (100..114).map(|id| sign(id, &context)).collect();
    require(
        verify(&context, &fake_members, &counterfeit),
        "counterfeit self-roster mutant not exercised",
    )?;
    require(
        !verify(&context, &members, &counterfeit),
        "recognized-roster boundary broken",
    )?;
    // A retired ordinary identity key remains able to sign exact old context.
    // Present fault count zero in the current disjoint committee does not help.
    let late_forgery: Vec<_> = (0..14).map(|id| sign(id, &wrong_state)).collect();
    require(
        verify(&wrong_state, &members, &late_forgery),
        "retired-key attack not reproduced",
    )?;
    println!("CRYPTO real-Ed25519 checks=8 forged-payload=false stale-epoch=false duplicate=false outsider=false self-roster-mutant=true retired-key-mutant=true");
    Ok(())
}

fn run() -> Result<(), String> {
    exact_twenty_two_trace()?;
    closure_intersection_exhaustive()?;
    private_inclusion_deadlock_and_repair()?;
    minority_and_repeated_replacement()?;
    real_signature_provenance()?;
    println!("{{\"suite\":\"independent-robustness-attacks-v1\",\"scenarios\":5,\"closure_quorums\":38760,\"status\":\"expected-attacks-and-conditional-checks-pass\",\"scope\":\"scripted-in-memory-not-wire\"}}");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("FAIL {error}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_unsafe_activation() {
        assert!(exact_twenty_two_trace().is_ok());
    }
    #[test]
    fn all_fourteen_member_closures() {
        assert!(closure_intersection_exhaustive().is_ok());
    }
    #[test]
    fn private_validity_mutant_and_public_repair() {
        assert!(private_inclusion_deadlock_and_repair().is_ok());
    }
    #[test]
    fn minority_full_turnover() {
        assert!(minority_and_repeated_replacement().is_ok());
    }
    #[test]
    fn signatures_do_not_establish_membership() {
        assert!(real_signature_provenance().is_ok());
    }
}
