//! Isolated, real-signature recognition-predicate experiments. No network protocol.
//! Trust is explicit operator-pinned bytes; deterministic secrets are test fixtures.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "membership_handoff/bootstrap.rs"]
mod bootstrap;
#[allow(dead_code)]
#[path = "membership_handoff/capacity.rs"]
mod capacity;
#[allow(dead_code)]
#[path = "membership_handoff/lifecycle.rs"]
mod lifecycle;
#[allow(dead_code)]
#[path = "membership_handoff/model.rs"]
mod model;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::{BTreeMap, BTreeSet};

type Hash = [u8; 32];
const Q: usize = 14;
const MAX_LINKS: usize = 64;

#[derive(Clone, Debug)]
struct Member {
    identity: Hash,
    epoch_key: Hash,
}

#[derive(Clone, Debug)]
struct Configuration {
    instance: Hash,
    shard: u16,
    generation: u64,
    parent: Hash,
    state: Hash,
    members: Vec<Member>,
}

fn digest(domain: &[u8], payload: &[u8]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[domain.len() as u8]);
    h.update(domain);
    h.update(payload);
    *h.finalize().as_bytes()
}

impl Configuration {
    fn id(&self) -> Hash {
        let mut bytes = Vec::new();
        bytes.extend(self.instance);
        bytes.extend(self.shard.to_le_bytes());
        bytes.extend(self.generation.to_le_bytes());
        bytes.extend(self.parent);
        bytes.extend(self.state);
        bytes.extend((self.members.len() as u64).to_le_bytes());
        for m in &self.members {
            bytes.extend(m.identity);
            bytes.extend(m.epoch_key);
        }
        digest(b"RESEARCH_ONLY_ADMISSION_CONFIG", &bytes)
    }

    fn well_formed(&self) -> bool {
        self.members.len() == 20
            && self
                .members
                .iter()
                .map(|m| m.identity)
                .collect::<BTreeSet<_>>()
                .len()
                == 20
            && self
                .members
                .iter()
                .map(|m| m.epoch_key)
                .collect::<BTreeSet<_>>()
                .len()
                == 20
            && self
                .members
                .iter()
                .all(|m| VerifyingKey::from_bytes(&m.epoch_key).is_ok())
    }
}

#[derive(Clone)]
struct Link {
    child: Configuration,
    signatures: Vec<(Hash, Signature)>,
}

#[derive(Clone)]
struct Anchor {
    // These are supplied through authenticated operator onboarding, not the peer.
    digest: Hash,
    expires_at: u64,
}

fn link_message(child: &Configuration) -> Hash {
    digest(b"RESEARCH_ONLY_ADMISSION_SUCCESSOR", &child.id())
}

fn link_valid(parent: &Configuration, link: &Link) -> bool {
    let child = &link.child;
    if !child.well_formed()
        || child.instance != parent.instance
        || child.shard != parent.shard
        || parent.generation.checked_add(1) != Some(child.generation)
        || child.parent != parent.id()
        || link.signatures.len() > 20
    {
        return false;
    }
    let mut seen = BTreeSet::new();
    for (identity, signature) in &link.signatures {
        if !seen.insert(*identity) {
            return false;
        }
        let Some(member) = parent.members.iter().find(|m| &m.identity == identity) else {
            return false;
        };
        let Ok(key) = VerifyingKey::from_bytes(&member.epoch_key) else {
            return false;
        };
        if key.verify_strict(&link_message(child), signature).is_err() {
            return false;
        }
    }
    seen.len() >= Q
}

fn recognize(anchor: &Anchor, root: &Configuration, links: &[Link], trusted_now: u64) -> bool {
    // All cheap resource/context filters precede signature verification.
    if trusted_now >= anchor.expires_at
        || links.len() > MAX_LINKS
        || root.id() != anchor.digest
        || !root.well_formed()
    {
        return false;
    }
    let mut parent = root;
    for link in links {
        if !link_valid(parent, link) {
            return false;
        }
        parent = &link.child;
    }
    true
}

fn secret(n: u64, epoch: u64, identity_role: bool) -> SigningKey {
    let mut bytes = n.to_le_bytes().to_vec();
    bytes.extend(epoch.to_le_bytes());
    bytes.push(u8::from(identity_role));
    SigningKey::from_bytes(&digest(b"RESEARCH_ONLY_DETERMINISTIC_FIXTURE", &bytes))
}

fn configuration(generation: u64, first: u64, parent: Hash) -> Configuration {
    Configuration {
        instance: [7; 32],
        shard: 42,
        generation,
        parent,
        state: [0; 32],
        members: (first..first + 20)
            .map(|n| Member {
                identity: secret(n, 0, true).verifying_key().to_bytes(),
                epoch_key: secret(n, generation, false).verifying_key().to_bytes(),
            })
            .collect(),
    }
}

fn certify(
    child: Configuration,
    first_parent: u64,
    indices: &[u64],
    identity_mutant: bool,
) -> Link {
    let signatures = indices
        .iter()
        .map(|i| {
            let n = first_parent + i;
            let identity = secret(n, 0, true).verifying_key().to_bytes();
            let sk = secret(
                n,
                if identity_mutant {
                    0
                } else {
                    child.generation - 1
                },
                identity_mutant,
            );
            (identity, sk.sign(&link_message(&child)))
        })
        .collect();
    Link { child, signatures }
}

fn run() -> Result<usize, String> {
    let root = configuration(0, 0, [0; 32]);
    let anchor = Anchor {
        digest: root.id(),
        expires_at: 100,
    };
    let honest: Vec<_> = (6..20).collect();
    let mut checks = 0;
    macro_rules! check {
        ($condition:expr, $label:expr) => {{
            if !$condition {
                return Err($label.to_owned());
            }
            checks += 1;
        }};
    }
    check!(recognize(&anchor, &root, &[], 1), "authentic pinned root");
    // One organic instance with a Byzantine discovery bridge (identity 19).
    // Both self-described committees contain only one Byzantine identity.
    let other_root = configuration(0, 19, [0; 32]);
    let left_child = configuration(1, 100, root.id());
    let right_child = configuration(1, 200, other_root.id());
    let left_indices: Vec<_> = (0..13).chain([19]).collect();
    let right_indices: Vec<_> = (0..14).collect();
    let left_certificate = certify(left_child, 0, &left_indices, false);
    let right_certificate = certify(right_child, 19, &right_indices, false);
    check!(
        link_valid(&root, &left_certificate),
        "left local universe accepts real fourteen signatures"
    );
    check!(
        link_valid(&other_root, &right_certificate),
        "hidden right universe accepts real fourteen signatures"
    );
    let left_ids: BTreeSet<_> = left_certificate.signatures.iter().map(|s| s.0).collect();
    let right_ids: BTreeSet<_> = right_certificate.signatures.iter().map(|s| s.0).collect();
    check!(
        left_ids.intersection(&right_ids).count() == 1,
        "only bridge double-signs in thirty-nine-node universe"
    );
    check!(
        !recognize(&anchor, &other_root, &[right_certificate], 1),
        "pinned recognition rejects alternate universe"
    );
    let counterfeit = configuration(0, 1_000, [0; 32]);
    check!(
        counterfeit.well_formed(),
        "counterfeit has real valid public keys"
    );
    check!(
        !recognize(&anchor, &counterfeit, &[], 1),
        "counterfeit exact-anchor rejection"
    );
    // The unsafe mutant's only recognition predicate is a well-formed self-description.
    check!(
        counterfeit.well_formed() && root.well_formed(),
        "unanchored mutant accepts both"
    );

    let mut current = root.clone();
    let mut chain = Vec::new();
    for generation in 1..=4 {
        let child = configuration(generation, generation * 100, current.id());
        let link = certify(child.clone(), (generation - 1) * 100, &honest, false);
        check!(
            link_valid(&current, &link),
            "complete turnover from fourteen honest signers"
        );
        chain.push(link);
        current = child;
        check!(
            recognize(&anchor, &root, &chain, 2),
            "late recipient verifies full replacement"
        );
    }
    let first = &chain[0];
    let mut forged = first.clone();
    forged.child.state = [9; 32];
    check!(!link_valid(&root, &forged), "state mutation rejected");
    let mut replay = first.clone();
    replay.child.shard += 1;
    check!(!link_valid(&root, &replay), "cross shard replay rejected");
    let mut duplicate = first.clone();
    duplicate.signatures = vec![first.signatures[0]; 14];
    check!(!link_valid(&root, &duplicate), "duplicate signers rejected");
    let mut missing = first.clone();
    missing.signatures.pop();
    check!(!link_valid(&root, &missing), "thirteen signers refused");
    check!(
        !recognize(&anchor, &root, &chain[1..], 2),
        "omitted predecessor rejected"
    );
    check!(
        !recognize(&anchor, &root, &chain, 100),
        "expired onboarding refused"
    );
    check!(
        !recognize(&anchor, &root, &vec![first.clone(); 65], 2),
        "bounded proof refusal"
    );
    let mut wrong_identity = first.child.clone();
    wrong_identity.state = [8; 32];
    let delegated = certify(wrong_identity.clone(), 0, &honest, true);
    check!(
        !link_valid(&root, &delegated),
        "permanent identity cannot replace bound epoch key"
    );
    // Backups retain ALL deterministic fixture keys. This is deliberately outside
    // the erasure premise, and demonstrates exactly what ordinary signatures permit.
    let late_forgery = certify(wrong_identity, 0, &honest, false);
    check!(
        link_valid(&root, &late_forgery),
        "fourteen recovered old epoch secrets forge valid history"
    );
    check!(
        recognize(&anchor, &root, &[late_forgery], 2),
        "old anchor alone cannot detect late forgery"
    );

    // Competing arrivals choose different next rosters. Local durable exclusion is
    // deliberately a simple sign-once predicate, NOT a live BFT implementation.
    let left = configuration(1, 100, root.id());
    let right = configuration(1, 200, root.id());
    let mut durable_choices = BTreeMap::new();
    let mut left_votes = Vec::new();
    let mut right_votes = Vec::new();
    for i in 0..20u64 {
        for (child, votes) in [(&left, &mut left_votes), (&right, &mut right_votes)] {
            let id = secret(i, 0, true).verifying_key().to_bytes();
            let permit = i < 6 || durable_choices.entry(id).or_insert(child.id()) == &child.id();
            if permit {
                votes.push((id, secret(i, 0, false).sign(&link_message(child))));
            }
        }
    }
    check!(
        link_valid(
            &root,
            &Link {
                child: left,
                signatures: left_votes
            }
        ),
        "first contender progress"
    );
    check!(
        !link_valid(
            &root,
            &Link {
                child: right,
                signatures: right_votes
            }
        ),
        "second contender lacks quorum"
    );
    // Complete-20 graph, silent 0..5: enumerate every received-row subset S1.
    let mut qualifying = 0;
    for mask in 0u32..(1u32 << 14) {
        if mask.count_ones() >= 13 {
            qualifying += 1;
            let outgoing_sources = mask.count_ones(); // each sees all six silent targets
            check!(
                outgoing_sources > 6,
                "literal CUP P3 refuses every candidate"
            );
        }
    }
    check!(qualifying == 15, "all 13/14-row candidates enumerated");
    Ok(checks)
}

#[derive(Clone)]
struct ComposedLink {
    link: Link,
    // Actual full transferred effect set, not only a claimed digest.
    state: BTreeMap<u32, BTreeSet<u8>>,
    closure: Vec<(Hash, Signature)>,
    installs: Vec<(Hash, Signature)>,
}

#[derive(Clone)]
struct Payment {
    configuration: Hash,
    slot: u32,
    value: u8,
    signatures: Vec<(Hash, Signature)>,
}

fn state_digest(state: &BTreeMap<u32, BTreeSet<u8>>) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend((state.len() as u64).to_le_bytes());
    for (slot, values) in state {
        bytes.extend(slot.to_le_bytes());
        bytes.extend((values.len() as u64).to_le_bytes());
        bytes.extend(values);
    }
    digest(b"RESEARCH_ONLY_INSTALLED_EFFECTS", &bytes)
}

fn closure_message(parent: &Configuration, child: &Configuration) -> Hash {
    let mut bytes = parent.id().to_vec();
    bytes.extend(child.state);
    digest(b"RESEARCH_ONLY_FENCED_INCLUSION", &bytes)
}

fn install_message(child: &Configuration) -> Hash {
    digest(b"RESEARCH_ONLY_DURABLE_INSTALL", &child.id())
}

fn signatures_valid(members: &[Member], message: &Hash, signatures: &[(Hash, Signature)]) -> bool {
    if signatures.len() < Q || signatures.len() > 20 {
        return false;
    }
    let mut seen = BTreeSet::new();
    for (identity, signature) in signatures {
        if !seen.insert(*identity) {
            return false;
        }
        let Some(member) = members.iter().find(|m| &m.identity == identity) else {
            return false;
        };
        let Ok(key) = VerifyingKey::from_bytes(&member.epoch_key) else {
            return false;
        };
        if key.verify_strict(message, signature).is_err() {
            return false;
        }
    }
    true
}

fn composed_valid(parent: &Configuration, proof: &ComposedLink) -> bool {
    let child = &proof.link.child;
    child.state == state_digest(&proof.state)
        && link_valid(parent, &proof.link)
        && signatures_valid(
            &parent.members,
            &closure_message(parent, child),
            &proof.closure,
        )
        && signatures_valid(&child.members, &install_message(child), &proof.installs)
}

fn payment_message(payment: &Payment) -> Hash {
    let mut bytes = payment.configuration.to_vec();
    bytes.extend(payment.slot.to_le_bytes());
    bytes.push(payment.value);
    digest(b"RESEARCH_ONLY_PAYMENT_CONTEXT", &bytes)
}

fn payment_valid(configuration: &Configuration, payment: &Payment) -> bool {
    payment.configuration == configuration.id()
        && signatures_valid(
            &configuration.members,
            &payment_message(payment),
            &payment.signatures,
        )
}

/// Pure late-recipient boundary: authority and payment context are resolved
/// only from the operator-pinned root and fully checked supplied history.
/// No model trace, fault map, expected configuration or emission registry enters.
fn verify_payment_from_anchor(
    anchor: &Anchor,
    root: &Configuration,
    proofs: &[ComposedLink],
    payment: &Payment,
    trusted_now: u64,
) -> bool {
    if trusted_now >= anchor.expires_at
        || proofs.len() > MAX_LINKS
        || root.id() != anchor.digest
        || !root.well_formed()
    {
        return false;
    }
    let mut parent = root;
    let mut payment_context = (payment.configuration == root.id()).then_some((root, None));
    for proof in proofs {
        if !composed_valid(parent, proof) {
            return false;
        }
        parent = &proof.link.child;
        if parent.id() == payment.configuration {
            payment_context = Some((parent, Some(&proof.installs)));
        }
    }
    let Some((configuration, installations)) = payment_context else {
        return false;
    };
    if !payment_valid(configuration, payment) {
        return false;
    }
    // Root readiness is trusted in the provisioned manifest. Every later payment
    // signer must supply its own authenticated installation receipt as well.
    installations.is_none_or(|receipts| {
        let installed: BTreeSet<_> = receipts.iter().map(|receipt| receipt.0).collect();
        payment
            .signatures
            .iter()
            .all(|signature| installed.contains(&signature.0))
    })
}

fn emitted_signatures(ids: &BTreeSet<u16>, epoch: u32, message: Hash) -> Vec<(Hash, Signature)> {
    // Cryptographic refinement: sign ONLY actors exported as actual emitters by
    // the executed model, not a freshly picked quorum or a monitor's expected set.
    ids.iter()
        .map(|id| {
            let identity = secret(u64::from(*id), 0, true).verifying_key().to_bytes();
            (
                identity,
                secret(u64::from(*id), u64::from(epoch), false).sign(&message),
            )
        })
        .collect()
}

fn from_model(epoch: u32, ids: &[u16], parent: Hash, state: Hash) -> Configuration {
    let mut cfg = configuration(u64::from(epoch), 0, parent);
    cfg.state = state;
    cfg.members = ids
        .iter()
        .map(|id| Member {
            identity: secret(u64::from(*id), 0, true).verifying_key().to_bytes(),
            epoch_key: secret(u64::from(*id), u64::from(epoch), false)
                .verifying_key()
                .to_bytes(),
        })
        .collect();
    cfg
}

fn composition(seed: u64) -> Result<(u64, usize), String> {
    let trace = model::exercise_recognition_trace(seed)?;
    if trace.transitions.len() != 3 || trace.payments.len() != 4 {
        return Err("composition did not complete all required transitions/payments".into());
    }
    let initial_ids = &trace.transitions[0].old_members;
    let root = from_model(0, initial_ids, [0; 32], state_digest(&BTreeMap::new()));
    let anchor = Anchor {
        digest: root.id(),
        expires_at: 100,
    };
    let mut configurations = vec![root.clone()];
    let mut proofs = Vec::new();
    for event in &trace.transitions {
        let parent = configurations
            .last()
            .ok_or("missing previous configuration")?;
        if parent.generation != u64::from(event.epoch) {
            return Err("exported transition context mismatch".into());
        }
        let child = from_model(
            event.epoch + 1,
            &event.next_members,
            parent.id(),
            state_digest(&event.state),
        );
        let link = Link {
            child: child.clone(),
            signatures: emitted_signatures(
                &event.commit_signers,
                event.epoch,
                link_message(&child),
            ),
        };
        let proof = ComposedLink {
            link,
            state: event.state.clone(),
            closure: emitted_signatures(
                &event.closure_signers,
                event.epoch,
                closure_message(parent, &child),
            ),
            installs: emitted_signatures(
                &event.install_signers,
                event.epoch + 1,
                install_message(&child),
            ),
        };
        if !composed_valid(parent, &proof) {
            return Err("actual emitted transition proof refused".into());
        }
        proofs.push(proof);
        configurations.push(child);
    }
    let mut checks = 0;
    let mut actual_payments = Vec::new();
    for event in &trace.payments {
        // The producer signs its actual executed output. The receiving function
        // below is never passed this producer-side configuration or trace.
        let cfg = configurations
            .get(event.epoch as usize)
            .ok_or("missing payment context")?;
        let mut payment = Payment {
            configuration: cfg.id(),
            slot: event.slot,
            value: event.value,
            signatures: Vec::new(),
        };
        payment.signatures =
            emitted_signatures(&event.voters, event.epoch, payment_message(&payment));
        if !verify_payment_from_anchor(&anchor, &root, &proofs, &payment, 1) {
            return Err(
                "late recipient refused actual emitted payment from anchored evidence".into(),
            );
        }
        let mut altered = payment.clone();
        altered.value = 2;
        if verify_payment_from_anchor(&anchor, &root, &proofs, &altered, 1) {
            return Err("altered payment accepted by anchored receiver".into());
        }
        let mut outside = payment.clone();
        outside.configuration = [255; 32];
        if verify_payment_from_anchor(&anchor, &root, &proofs, &outside, 1) {
            return Err("out-of-ancestry payment accepted by anchored receiver".into());
        }
        actual_payments.push(payment);
        checks += 3;
    }
    let latest_payment = actual_payments
        .last()
        .ok_or("no actual payment to attack")?;
    let mut omitted = proofs.clone();
    omitted[0].state.clear();
    if verify_payment_from_anchor(&anchor, &root, &omitted, latest_payment, 1) {
        return Err("state omission accepted by anchored receiver".into());
    }
    let mut forged_roster = proofs.clone();
    forged_roster[0].link.child.members = configuration(1, 5_000, root.id()).members;
    if verify_payment_from_anchor(&anchor, &root, &forged_roster, latest_payment, 1) {
        return Err("new roster substituted after BFT accepted by anchored receiver".into());
    }
    let mut no_install = proofs.clone();
    no_install[0].installs.clear();
    if verify_payment_from_anchor(&anchor, &root, &no_install, latest_payment, 1) {
        return Err("missing install quorum accepted by anchored receiver".into());
    }
    let mut no_closure = proofs.clone();
    no_closure[0].closure.clear();
    if verify_payment_from_anchor(&anchor, &root, &no_closure, latest_payment, 1) {
        return Err("missing closure quorum accepted by anchored receiver".into());
    }
    let alternate = configuration(0, 500, [0; 32]);
    if verify_payment_from_anchor(&anchor, &alternate, &proofs, latest_payment, 1) {
        return Err("alternate genesis accepted by anchored receiver".into());
    }
    if verify_payment_from_anchor(&anchor, &root, &proofs[1..], latest_payment, 1) {
        return Err("missing predecessor accepted by anchored receiver".into());
    }
    if verify_payment_from_anchor(&anchor, &root, &proofs[..2], latest_payment, 1) {
        return Err("genuine payment outside supplied certified ancestry accepted".into());
    }
    if verify_payment_from_anchor(
        &anchor,
        &root,
        &vec![proofs[0].clone(); MAX_LINKS + 1],
        latest_payment,
        1,
    ) {
        return Err("over-bound ancestry accepted by anchored receiver".into());
    }
    let mut reordered = proofs.clone();
    reordered.swap(0, 1);
    if verify_payment_from_anchor(&anchor, &root, &reordered, latest_payment, 1) {
        return Err("reordered ancestry accepted by anchored receiver".into());
    }
    if verify_payment_from_anchor(&anchor, &root, &proofs, latest_payment, 100) {
        return Err("expired anchor accepted by late receiver".into());
    }
    // Keep a valid 14-receipt install quorum while hiding one actual payment
    // signer's individual receipt; an extra Byzantine member signs instead.
    let mut missing_own_receipt = proofs.clone();
    let final_proof = missing_own_receipt.last_mut().ok_or("missing last proof")?;
    final_proof
        .installs
        .pop()
        .ok_or("missing receipt to remove")?;
    let last_event = trace.transitions.last().ok_or("missing last event")?;
    let byzantine_id = *last_event.next_members.first().ok_or("empty successor")?;
    final_proof.installs.extend(emitted_signatures(
        &BTreeSet::from([byzantine_id]),
        last_event.epoch + 1,
        install_message(&final_proof.link.child),
    ));
    if !composed_valid(&configurations[configurations.len() - 2], final_proof) {
        return Err("individual-receipt mutant failed to retain valid install quorum".into());
    }
    if verify_payment_from_anchor(&anchor, &root, &missing_own_receipt, latest_payment, 1) {
        return Err("payment signer without individual install receipt accepted".into());
    }
    checks += 12;
    Ok((trace.events, checks))
}

fn main() -> Result<(), String> {
    let checks = run()?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    let seeds: Vec<u64> = if args.is_empty() {
        vec![1, 7, 42]
    } else if args.len() == 2 && args[0] == "--seed-count" {
        let count: u64 = args[1].parse().map_err(|_| "invalid seed count")?;
        if !(1..=10_000).contains(&count) {
            return Err("seed count outside 1..=10000".into());
        }
        (1..=count).collect()
    } else {
        return Err("usage: robustness_admission [--seed-count 1..10000]".into());
    };
    for seed in seeds {
        let (events, composed_checks) = composition(seed)?;
        println!("{{\"scenario\":\"scheduled_bft_signed_recognition\",\"seed\":{seed},\"model_events\":{events},\"checks\":{composed_checks},\"full_turnovers\":3,\"payments\":4,\"network_protocol\":false}}");
    }
    println!("{{\"scenario\":\"recognition_predicates\",\"checks\":{checks},\"crypto\":\"real_ed25519\",\"seed\":\"deterministic\",\"network_protocol\":false}}");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn recognition_and_expected_attacks() -> Result<(), String> {
        super::run().map(|_| ())
    }
    #[test]
    fn signed_scheduled_composition() -> Result<(), String> {
        for seed in [1, 7, 42] {
            super::composition(seed)?;
        }
        Ok(())
    }
}
