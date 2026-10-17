//! P0-T07..T12 executable adversarial scenarios.
//!
//! Admission work, durable storage and transport are explicit deterministic model
//! inputs. These tests do not execute Argon2, fsync, the real terminal or QUIC.

mod p0_support;

use std::collections::{BTreeMap, BTreeSet};

use humoco_sim_core::p0::{
    can_display_global, verify_node_equivocation, verify_observation, Approval, Context,
    EvidenceStatus, Intent, Registry, Signer, Ticket, View, DAY_MS, HOUR_MS, LEASE_MS, VIEW_MS,
};
use p0_support::Fixture;

fn recognize(registry: &mut Registry, provider: &Context, view: &View) {
    // Provider configuration is a test-owned trust capability, never a value
    // taken from a payer or a gateway receipt.
    registry.context.trust_observer(provider.observer);
    registry.context.recognize_cut(provider, view).unwrap();
}

fn ordered_intents(
    f: &Fixture,
    root: &humoco_sim_core::p0::RootAnchor,
    count: usize,
) -> Vec<Intent> {
    let mut intents: Vec<_> = (0..count).map(|n| f.intent(root, n as u64)).collect();
    intents.sort_by_key(Intent::id);
    intents
}

#[test]
fn p0_t07_honest_observation_preserves_choice_and_allows_winning_descendants() {
    let f = Fixture::new(40);
    let left: Vec<_> = (0..20).collect();
    let right: Vec<_> = (20..40).collect();
    let root = f.root(701);
    let candidates = ordered_intents(&f, &root, 2);
    let (b, a) = (&candidates[0], &candidates[1]);
    let mut lc = f.catalog(0, &left);
    let mut rc = f.catalog(20, &right);
    let av = lc.freeze_view(a.slot.shard(), f.now).unwrap();
    let bv = rc.freeze_view(b.slot.shard(), f.now).unwrap();
    let mut registry = f.registry(0, &left, std::slice::from_ref(&root));
    recognize(&mut registry, &lc, &av);
    recognize(&mut registry, &rc, &bv);
    let mut honest = Signer::new(f.keys[0].clone());
    let original = honest.approve(&registry, a, &av, f.now).unwrap();
    registry
        .import(f.receipt(&av, a, &(0..14).collect::<Vec<_>>()), f.now)
        .unwrap();
    registry
        .import(f.receipt(&bv, b, &(20..34).collect::<Vec<_>>()), f.now)
        .unwrap();
    assert_eq!(registry.winner(&a.slot), Some(b.id()));
    let observation = honest.observe(&registry, &a.slot).unwrap();
    assert!(verify_observation(&observation).is_ok());
    assert_eq!(observation.winner, b.id());
    assert_eq!(honest.own_choice(&a.slot), Some(a.id()));
    assert!(honest.approve(&registry, b, &av, f.now).is_err());

    let mut retyped = Approval::issue_unchecked(&f.keys[0], b, &av, f.now);
    retyped.signature = observation.signature;
    assert!(retyped.verify().is_err());
    assert!(verify_node_equivocation(&original, &retyped).is_err());
    let malicious = Approval::issue_unchecked(&f.keys[0], b, &av, f.now);
    assert_eq!(
        verify_node_equivocation(&original, &malicious).unwrap(),
        f.key(0)
    );
    assert!(verify_node_equivocation(&original, &original).is_err());

    let c = f.child_intent(&root, b, 0, 704);
    let cv = lc.freeze_view(c.slot.shard(), f.now).unwrap();
    recognize(&mut registry, &lc, &cv);
    let child_approval = honest.approve(&registry, &c, &cv, f.now).unwrap();
    assert!(child_approval.verify().is_ok());
    assert_eq!(honest.own_choice(&c.slot), Some(c.id()));
    let mut missing = f.registry(0, &left, std::slice::from_ref(&root));
    recognize(&mut missing, &lc, &cv);
    assert!(Signer::new(f.keys[0].clone())
        .approve(&missing, &c, &cv, f.now)
        .is_err());
    assert!(!can_display_global());
    println!(
        "P0-T07 honest_choice_preserved=1 observation_replay_rejected=1 \
         authentic_equivocation_positive=1 descendant_approval=1 honest_bans=0 global=false"
    );
}

/// Terminal-only state, deliberately absent from the blind registry model.
#[derive(Clone, Debug, Default)]
struct PurchaseJournal {
    exposure: u64,
    records: BTreeMap<u64, PurchaseRecord>,
    goods_releases: usize,
    payment_dispatches: usize,
}

#[derive(Clone, Debug)]
struct PurchaseRecord {
    intent: [u8; 32],
    amount: u64,
    state: PurchaseState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PurchaseState {
    Unknown,
    Released,
    Declined,
}

impl PurchaseJournal {
    fn begin(&mut self, purchase: u64, intent: [u8; 32], amount: u64) -> bool {
        if let Some(existing) = self.records.get(&purchase) {
            // A lost response never authorizes an alternative payment intent.
            return existing.intent == intent;
        }
        self.records.insert(
            purchase,
            PurchaseRecord {
                intent,
                amount,
                state: PurchaseState::Unknown,
            },
        );
        self.payment_dispatches += 1;
        true
    }

    /// One serialized durable transaction models the terminal's local counter.
    fn reconcile_regional(&mut self, purchase: u64, receipt: [u8; 32]) -> bool {
        let Some(record) = self.records.get_mut(&purchase) else {
            return false;
        };
        if record.intent != receipt {
            return false;
        }
        if record.state != PurchaseState::Unknown {
            return record.state == PurchaseState::Released;
        }
        if record.amount > 10 || self.exposure.saturating_add(record.amount) > 20 {
            record.state = PurchaseState::Declined;
            return false;
        }
        self.exposure += record.amount;
        record.state = PurchaseState::Released;
        self.goods_releases += 1;
        true
    }
}

/// Model of scoped anti-entropy bookkeeping, not an implementation of a wire RPC.
#[derive(Clone, Debug)]
struct ScopedRepair {
    expected: Vec<[u8; 32]>,
    committed: BTreeMap<usize, [u8; 32]>,
    durable_cursor: usize,
    max_batch: usize,
    transferred: usize,
}

impl ScopedRepair {
    fn new(expected: Vec<[u8; 32]>, max_batch: usize) -> Self {
        Self {
            expected,
            committed: BTreeMap::new(),
            durable_cursor: 0,
            max_batch,
            transferred: 0,
        }
    }

    fn commit_batch(&mut self, records: &[(usize, [u8; 32])], durable: bool) -> bool {
        if records.len() > self.max_batch
            || records.iter().any(|(index, id)| {
                self.expected
                    .get(*index)
                    .is_none_or(|expected| expected != id)
            })
        {
            return false;
        }
        self.transferred += records.len();
        if !durable {
            return false;
        }
        for (index, id) in records {
            self.committed.insert(*index, *id);
        }
        while self.committed.contains_key(&self.durable_cursor) {
            self.durable_cursor += 1;
        }
        true
    }

    fn ready(&self) -> bool {
        self.durable_cursor == self.expected.len()
    }
}

#[test]
fn p0_t08_admission_rejects_forgery_but_reports_the_real_capture_boundary() {
    let f = Fixture::new(20);
    let members: Vec<_> = (0..20).collect();
    let trusted = BTreeSet::from([f.key(0)]);
    let mut empty = Context::new(f.network, f.key(0), trusted.clone());
    assert!(empty.freeze_view(0, f.now).is_err());

    let mut invalid_work = empty.clone();
    let invalid_ticket = Ticket::issue(&f.keys[1], 71, 0, 0);
    assert!(invalid_work
        .learn(invalid_ticket, f.key(0), 0, false)
        .is_err());
    for index in &members {
        let signed_but_failed_work = Ticket::issue(&f.keys[*index], 72 + *index as u64, 0, 1);
        assert!(signed_but_failed_work.verify().is_ok());
        assert!(invalid_work
            .learn(signed_but_failed_work, f.key(0), 0, false)
            .is_err());
    }

    let mut fresh = empty.clone();
    let mut foreign = empty.clone();
    for index in &members {
        let ticket = Ticket::issue(&f.keys[*index], 100 + *index as u64, 0, 1);
        fresh.learn(ticket.clone(), f.key(0), f.now, true).unwrap();
        assert!(foreign.learn(ticket, f.key(1), 0, true).is_err());
        for _ in 0..8 {
            fresh.observe_heartbeat(f.key(*index), f.now).unwrap();
        }
        fresh.refresh_reachability(f.key(*index), f.now).unwrap();
    }
    fresh.update_population(f.now);
    assert!(fresh.freeze_view(0, f.now).is_err());
    // Claimed issue time zero did not manufacture receiver-owned observation age;
    // repeated signed-presence events at one reception hour did not create eight.
    fresh.update_population(f.now + DAY_MS);
    assert!(fresh.freeze_view(0, f.now + DAY_MS).is_err());

    let mut qualified = f.catalog(0, &members);
    let root = f.root(801);
    let intent = f.intent(&root, 1);
    let valid_view = qualified.freeze_view(intent.slot.shard(), f.now).unwrap();
    assert!(qualified.verify_view(&valid_view).is_ok());
    assert!(empty.verify_view(&valid_view).is_err());
    let mut free_key_roster = valid_view.clone();
    free_key_roster.tickets.fill([0; 32]);
    assert!(empty.verify_view(&free_key_roster).is_err());
    let receipt = f.receipt(&valid_view, &intent, &(0..14).collect::<Vec<_>>());
    let mut verifier = f.registry(0, &members, std::slice::from_ref(&root));
    recognize(&mut verifier, &qualified, &valid_view);
    assert_eq!(
        verifier.import(receipt.clone(), f.now).unwrap(),
        EvidenceStatus::RegionalConfirmed
    );

    // The same genuinely admitted keys may all be controlled by one attacker.
    // Admission establishes its actual predicates, not independent human control.
    let mut captured = f.catalog(0, &members);
    captured.freeze_view(intent.slot.shard(), f.now).unwrap();
    assert!(captured.verify_view(&valid_view).is_ok());
    assert_eq!(
        verifier.status(intent.id(), f.now),
        EvidenceStatus::RegionalConfirmed
    );
    assert!(!can_display_global());

    let mut expired_reachability = qualified.clone();
    expired_reachability.update_population(f.now + LEASE_MS + 1);
    assert!(expired_reachability
        .freeze_view(0, f.now + LEASE_MS + 1)
        .is_err());
    // An unchanged historical receipt is still a historical fact, not a fresh
    // challenge response; the test does not inject a new authenticated response.
    assert!(expired_reachability.verify_view(&valid_view).is_ok());
    assert!(expired_reachability
        .record_reachability(f.key(0), f.now, f.now + LEASE_MS + 1)
        .is_err());
    let mut pending = qualified.clone();
    let replacement = Ticket::issue(&f.keys[0], 8_888, 0, 2);
    let replacement_id = replacement.routing_id;
    pending.learn(replacement, f.key(0), f.now, true).unwrap();
    let pending_view = pending.freeze_view(intent.slot.shard(), f.now).unwrap();
    let position = pending_view
        .roster
        .iter()
        .position(|node| *node == f.key(0))
        .unwrap();
    assert_ne!(pending_view.tickets[position], replacement_id);
    println!(
        "P0-T08 rejected_free_keys=20 rejected_invalid_work=21 rejected_fresh=20 \
         rejected_foreign=20 gateway_only_mature_catalog=rejected admitted_capture=20 global=false \
         pending_replacement_age_not_inherited=1 replay_old_lease_rejected=1 \
         gaps=real_argon2,authenticated_challenge_wire"
    );
}

#[test]
fn p0_t09_validation_precedes_min_hash_and_only_a_real_receipt_promotes_support() {
    let f = Fixture::new(47);
    let left: Vec<_> = (0..20).collect();
    let right: Vec<_> = (20..40).collect();
    let small: Vec<_> = (40..47).collect();
    let root = f.root(901);
    let intents = ordered_intents(&f, &root, 3);
    let (b, c, a) = (&intents[0], &intents[1], &intents[2]);
    let mut lc = f.catalog(0, &left);
    let mut rc = f.catalog(20, &right);
    let mut pc = f.catalog(40, &small);
    let av = lc.freeze_view(a.slot.shard(), f.now).unwrap();
    let bv = rc.freeze_view(b.slot.shard(), f.now).unwrap();
    let pv = pc.freeze_view(b.slot.shard(), f.now).unwrap();
    let mut registry = f.registry(0, &left, std::slice::from_ref(&root));
    recognize(&mut registry, &lc, &av);
    recognize(&mut registry, &rc, &bv);
    recognize(&mut registry, &pc, &pv);
    let ar = f.receipt(&av, a, &(0..14).collect::<Vec<_>>());
    registry.import(ar.clone(), f.now).unwrap();

    let mut invalid_cases = Vec::new();
    let mut bad = ar.clone();
    bad.intent.signature[0] ^= 1;
    invalid_cases.push(("owner_signature", bad));
    let mut bad = ar.clone();
    bad.approvals[0].signature[0] ^= 1;
    invalid_cases.push(("node_signature", bad));
    let mut bad = ar.clone();
    bad.intent.children[0].commitment[0] ^= 1;
    invalid_cases.push(("whole_child_bundle", bad));
    let mut bad = ar.clone();
    bad.view.network[0] ^= 1;
    invalid_cases.push(("network", bad));
    let mut bad = ar.clone();
    bad.view.shard ^= 1;
    invalid_cases.push(("shard", bad));
    let mut bad = ar.clone();
    bad.approvals[13] = bad.approvals[0].clone();
    invalid_cases.push(("duplicate_signer", bad));
    let bad_ttl = Intent::issue(
        &f.owner,
        a.slot,
        a.root_valid_until + 1,
        a.children.clone(),
        92,
    );
    invalid_cases.push((
        "successor_chosen_expiry",
        f.receipt(&av, &bad_ttl, &(0..14).collect::<Vec<_>>()),
    ));
    let missing_parent = f.spend(&root, [0x73; 32], vec![9], 93);
    let missing_view = lc.freeze_view(missing_parent.slot.shard(), f.now).unwrap();
    recognize(&mut registry, &lc, &missing_view);
    invalid_cases.push((
        "missing_ancestry",
        f.receipt(&missing_view, &missing_parent, &(0..14).collect::<Vec<_>>()),
    ));
    for (name, receipt) in &invalid_cases {
        let before = registry.digest();
        assert!(registry.import(receipt.clone(), f.now).is_err(), "{name}");
        assert_eq!(
            registry.digest(),
            before,
            "invalid evidence mutated state: {name}"
        );
    }
    let mut without_origin = Registry::new(lc.clone());
    assert!(without_origin.import(ar.clone(), f.now).is_err());
    for count in [1, 13] {
        assert!(registry
            .import(
                f.receipt(&bv, b, &(20..20 + count).collect::<Vec<_>>()),
                f.now
            )
            .is_err());
        assert_eq!(registry.winner(&a.slot), Some(a.id()));
    }
    registry
        .import(f.receipt(&pv, b, &(40..45).collect::<Vec<_>>()), f.now)
        .unwrap();
    assert_eq!(registry.winner(&a.slot), Some(a.id()));
    assert_eq!(registry.status(b.id(), f.now), EvidenceStatus::Void);
    assert!(Signer::new(f.keys[0].clone())
        .approve(&registry, b, &av, f.now)
        .is_err());
    registry
        .import(f.receipt(&bv, b, &(20..34).collect::<Vec<_>>()), f.now)
        .unwrap();
    assert_eq!(registry.winner(&a.slot), Some(b.id()));
    assert_eq!(
        registry.status(b.id(), f.now),
        EvidenceStatus::RegionalConfirmed
    );
    assert_eq!(registry.status(a.id(), f.now), EvidenceStatus::Void);

    let mut provisional = f.registry(40, &small, std::slice::from_ref(&root));
    recognize(&mut provisional, &pc, &pv);
    provisional
        .import(f.receipt(&pv, c, &(40..45).collect::<Vec<_>>()), f.now)
        .unwrap();
    provisional
        .import(f.receipt(&pv, b, &(40..45).collect::<Vec<_>>()), f.now)
        .unwrap();
    assert_eq!(provisional.winner(&b.slot), Some(b.id()));
    assert_eq!(
        provisional.status(b.id(), f.now),
        EvidenceStatus::Provisional
    );

    let mut late = f.registry(0, &left, std::slice::from_ref(&root));
    recognize(&mut late, &lc, &av);
    assert!(late.import(ar.clone(), f.now + 31 * DAY_MS).is_ok());
    assert!(late.import(ar, root.valid_until + 1).is_err());
    assert_ne!(
        late.status(a.id(), root.valid_until + 1),
        EvidenceStatus::RegionalConfirmed
    );
    assert!(!can_display_global());
    println!(
        "P0-T09 invalid_variants={} partial_receipts_rejected=2 real_promotion=1 \
         provisional_takeover_prevented=1 live_31day_receipt=accepted expired=unusable global=false",
        invalid_cases.len() + 1
    );
}

#[test]
fn p0_t10_late_smaller_evidence_revises_winner_and_scoped_repair_is_not_readiness() {
    let f = Fixture::new(60);
    let groups: Vec<Vec<usize>> = (0..3)
        .map(|region| (region * 20..region * 20 + 20).collect())
        .collect();
    let root = f.root(1_001);
    let independent_root = f.root(1_002);
    let intents = ordered_intents(&f, &root, 3);
    let (a, b, c) = (&intents[0], &intents[1], &intents[2]);
    let u = f.intent(&independent_root, 9);
    let mut catalogs: Vec<_> = groups
        .iter()
        .enumerate()
        .map(|(i, members)| f.catalog(i * 20, members))
        .collect();
    let mut registry = f.registry(0, &groups[0], &[root.clone(), independent_root]);
    let mut receipts = Vec::new();
    for (index, intent) in [c, b, a].iter().enumerate() {
        let view = catalogs[index]
            .freeze_view(intent.slot.shard(), f.now)
            .unwrap();
        recognize(&mut registry, &catalogs[index], &view);
        receipts.push(f.receipt(&view, intent, &groups[index][..14]));
    }
    let uv = catalogs[0].freeze_view(u.slot.shard(), f.now).unwrap();
    recognize(&mut registry, &catalogs[0], &uv);
    registry
        .import(f.receipt(&uv, &u, &groups[0][..14]), f.now)
        .unwrap();
    registry.import(receipts[0].clone(), f.now).unwrap();
    assert_eq!(registry.winner(&a.slot), Some(c.id()));
    registry
        .import(receipts[1].clone(), f.now + DAY_MS)
        .unwrap();
    assert_eq!(registry.winner(&a.slot), Some(b.id()));
    let late_time = f.now + 40 * DAY_MS;
    registry.import(receipts[2].clone(), late_time).unwrap();
    assert_eq!(registry.winner(&a.slot), Some(a.id()));
    let converged = registry.digest();
    registry.import(receipts[2].clone(), late_time).unwrap();
    assert_eq!(registry.digest(), converged);
    assert_eq!(registry.candidate_count(), 4);
    assert_eq!(
        registry.status(u.id(), late_time),
        EvidenceStatus::RegionalConfirmed
    );
    assert_eq!(registry.status(c.id(), late_time), EvidenceStatus::Void);

    let ids = vec![c.id(), b.id(), a.id(), u.id()];
    let mut repair = ScopedRepair::new(ids.clone(), 2);
    assert!(!repair.commit_batch(&[(0, ids[0])], false));
    assert_eq!(repair.durable_cursor, 0);
    assert!(!repair.ready());
    assert!(!repair.commit_batch(&[(0, [0x88; 32])], true));
    assert!(!repair.commit_batch(&[(0, ids[0]), (1, ids[1]), (2, ids[2])], true));
    assert!(repair.commit_batch(&[(2, ids[2])], true));
    assert_eq!(repair.durable_cursor, 0);
    assert!(repair.commit_batch(&[(0, ids[0])], true));
    assert_eq!(repair.durable_cursor, 1);
    let mut restarted = repair.clone();
    assert!(restarted.commit_batch(&[(0, ids[0])], true));
    assert_eq!(restarted.durable_cursor, 1);
    assert!(restarted.commit_batch(&[(1, ids[1]), (3, ids[3])], true));
    assert!(restarted.ready());
    assert!(!can_display_global());
    println!(
        "P0-T10 revisions=C->B->A late_delay_simulated_ms={} candidates={} \
         repair_records_transferred={} durable_cursor={} independent_survivors=1 \
         lock_gossip_emissions=0 global=false gap=wire_scoped_repair",
        40 * DAY_MS,
        registry.candidate_count(),
        restarted.transferred,
        restarted.durable_cursor
    );
}

#[test]
fn p0_t11_correlated_loss_queue_crashes_and_honest_view_skew_fail_closed() {
    let f = Fixture::new(27);
    let original_members: Vec<_> = (0..20).collect();
    let replacements: Vec<_> = (0..13).chain(20..27).collect();
    let root = f.root(1_101);
    let other_root = f.root(1_102);
    let intents = ordered_intents(&f, &root, 2);
    let (a, b) = (&intents[0], &intents[1]);
    let other = f.intent(&other_root, 1);
    let mut original_catalog = f.catalog(0, &original_members);
    let old_view = original_catalog.freeze_view(a.slot.shard(), f.now).unwrap();
    let mut registry = f.registry(0, &original_members, &[root.clone(), other_root]);
    recognize(&mut registry, &original_catalog, &old_view);
    let mut signers: Vec<_> = f.keys.iter().cloned().map(Signer::new).collect();
    let thirteen: Vec<_> = signers[..13]
        .iter_mut()
        .map(|signer| signer.approve(&registry, a, &old_view, f.now).unwrap())
        .collect();
    let incomplete = humoco_sim_core::p0::Receipt {
        intent: a.clone(),
        view: old_view.clone(),
        approvals: thirteen,
    };
    assert!(registry.import(incomplete, f.now).is_err());
    assert_eq!(registry.status(a.id(), f.now), EvidenceStatus::Unknown);
    assert_eq!(old_view.roster.len(), 20);

    let mut replacement_catalog = f.catalog(20, &replacements);
    let new_view = replacement_catalog
        .freeze_view(a.slot.shard(), f.now)
        .unwrap();
    let mut replacement_registry = f.registry(20, &replacements, std::slice::from_ref(&root));
    recognize(&mut replacement_registry, &replacement_catalog, &new_view);
    let mut new_approvals = Vec::new();
    for &index in &replacements[..14] {
        new_approvals.push(
            signers[index]
                .approve(&replacement_registry, a, &new_view, f.now)
                .unwrap(),
        );
    }
    let reconstituted = humoco_sim_core::p0::Receipt {
        intent: a.clone(),
        view: new_view.clone(),
        approvals: new_approvals,
    };
    replacement_registry.import(reconstituted, f.now).unwrap();
    assert_eq!(
        replacement_registry.status(a.id(), f.now),
        EvidenceStatus::RegionalConfirmed
    );

    let mut full = Signer::new(f.keys[0].clone());
    full.queue_capacity = 0;
    assert!(full.begin_approval(&registry, a, &old_view, f.now).is_err());
    assert_eq!(full.own_choice(&a.slot), None);
    full.queue_capacity = 1;
    let pending = full.begin_approval(&registry, a, &old_view, f.now).unwrap();
    let other_view = original_catalog
        .freeze_view(other.slot.shard(), f.now)
        .unwrap();
    recognize(&mut registry, &original_catalog, &other_view);
    assert!(full
        .begin_approval(&registry, &other, &other_view, f.now)
        .is_err());
    assert_eq!(full.own_choice(&other.slot), None);
    assert_eq!(full.own_choice(&a.slot), None);
    assert!(full.begin_approval(&registry, b, &old_view, f.now).is_err());
    assert!(full.commit(pending, f.now + VIEW_MS + 1).unwrap().is_none());
    assert_eq!(full.own_choice(&a.slot), Some(a.id()));

    let mut before_commit = Signer::new(f.keys[1].clone());
    let pending = before_commit
        .begin_approval(&registry, a, &old_view, f.now)
        .unwrap();
    before_commit.crash();
    assert!(before_commit.commit(pending, f.now).is_err());
    assert_eq!(before_commit.own_choice(&a.slot), None);
    assert!(before_commit
        .approve(&registry, b, &old_view, f.now)
        .is_ok());
    let mut after_commit = Signer::new(f.keys[2].clone());
    let committed_approval = after_commit
        .approve(&registry, a, &old_view, f.now)
        .unwrap();
    after_commit.crash();
    assert!(committed_approval.verify().is_ok());
    assert_eq!(after_commit.own_choice(&a.slot), Some(a.id()));
    assert!(after_commit
        .approve(&registry, b, &old_view, f.now)
        .is_err());
    after_commit.lose_own_history();
    after_commit.ready = true; // A superficial matching-digest readiness toggle.
    let matching_digest = registry.digest();
    assert_eq!(registry.digest(), matching_digest);
    assert!(after_commit
        .approve(&registry, a, &old_view, f.now)
        .is_err());
    assert!(Signer::new(f.keys[3].clone())
        .approve(&registry, &other, &other_view, f.now)
        .is_ok());

    // Honest local cuts differing by one millisecond have identical rosters but
    // different manifest identities. No automatic global view agreement exists.
    let mut skew_catalog = f.catalog(1, &original_members);
    let skew_view = skew_catalog.freeze_view(a.slot.shard(), f.now + 1).unwrap();
    let mut skew_registry = f.registry(1, &original_members, std::slice::from_ref(&root));
    recognize(&mut skew_registry, &skew_catalog, &skew_view);
    assert_eq!(old_view.roster, skew_view.roster);
    assert_ne!(old_view.id, skew_view.id);
    assert!(Signer::new(f.keys[1].clone())
        .approve(&skew_registry, a, &old_view, f.now + 1)
        .is_err());
    assert!(Signer::new(f.keys[1].clone())
        .approve(&skew_registry, a, &skew_view, f.now + 1)
        .is_ok());
    let mut replay = original_catalog.clone();
    assert!(replay
        .record_reachability(f.key(0), f.now, f.now + LEASE_MS + 1)
        .is_err());
    assert!(replay
        .record_reachability(f.key(0), f.now + HOUR_MS, f.now)
        .is_err());
    assert!(!can_display_global());
    println!(
        "P0-T11 frozen_available=13 frozen_quorum=unavailable future_view_approvals=14 \
         queue_capacity=1 undurable_signatures=0 rollback_gate=passive \
         honest_identical_roster_cut_skew_ms=1 skew_result=UNKNOWN timeout_bans=0 \
         gaps=real_fsync,wire_flood_scheduling,clock_interval_uncertainty global=false"
    );
}

#[test]
fn p0_t12_coordinated_100_of_1000_attack_damage_and_terminal_journal_are_explicit() {
    let f = Fixture::new(40);
    let left: Vec<_> = (0..20).collect();
    let right: Vec<_> = (20..40).collect();
    let mut registry = Registry::new(f.catalog(0, &left));
    let mut regional_right = Registry::new(f.catalog(20, &right));
    let mut other_context = f.catalog(20, &right);
    let mut network = p0_support::SimNetwork::new(40, f.now);
    network.partition(&[&left, &right]);
    let mut original_ids = Vec::new();
    let mut dependent_ids = Vec::new();
    let mut sibling_outputs = Vec::new();
    let mut recipients = Vec::new();
    let mut verified_receipts = 0usize;
    let mut queued_proof_bytes = 0usize;
    println!("P0-T12 begin seed=deterministic-P0-SIM-1 regional_quorum=14/20 primary_inputs=1000 attacks=100");

    for index in 0..1_000u64 {
        let root = f.root(120_000 + index);
        registry.context.register_root(root.clone()).unwrap();
        let original;
        if index < 100 {
            let creation = f.spend(
                &root,
                root.id(),
                vec![10_000 + index, 20_000 + index],
                index,
            );
            let receipt = f.receipt_local(&mut registry, &creation, &left[..14]);
            regional_right.context.register_root(root.clone()).unwrap();
            recognize(&mut regional_right, &registry.context, &receipt.view);
            regional_right.import(receipt.clone(), f.now).unwrap();
            registry.import(receipt, f.now).unwrap();
            verified_receipts += 1;
            let mut contenders = [
                f.child_intent(&root, &creation, 0, 30_000 + index),
                f.child_intent(&root, &creation, 0, 40_000 + index),
            ];
            contenders.sort_by_key(Intent::id);
            let rival = contenders[0].clone();
            original = contenders[1].clone();
            let view = other_context
                .freeze_view(rival.slot.shard(), f.now)
                .unwrap();
            recognize(&mut registry, &other_context, &view);
            let rival_receipt = f.receipt(&view, &rival, &right[..14]);
            assert_eq!(registry.verify_receipt(&rival_receipt, f.now).unwrap(), 2);
            recognize(&mut regional_right, &other_context, &view);
            regional_right.import(rival_receipt.clone(), f.now).unwrap();
            assert_eq!(
                regional_right.status(rival.id(), f.now),
                EvidenceStatus::RegionalConfirmed
            );
            queued_proof_bytes += rival.body().len() + rival_receipt.approvals.len() * (32 + 64);
            assert!(network.send(20, 0, rival_receipt).is_none());
            let mut recipient = PurchaseJournal::default();
            assert!(recipient.begin(1_000 + index, rival.id(), 1));
            assert!(recipient.reconcile_regional(1_000 + index, rival.id()));
            recipients.push(recipient);

            let sibling = f.child_intent(&root, &creation, 1, 50_000 + index);
            let receipt = f.receipt_local(&mut registry, &sibling, &left[..14]);
            registry.import(receipt, f.now).unwrap();
            verified_receipts += 1;
            sibling_outputs.push((root.id(), creation.output(1).unwrap()));
            sibling_outputs.push((root.id(), sibling.output(0).unwrap()));
        } else {
            original = f.intent(&root, index);
        }
        let receipt = f.receipt_local(&mut registry, &original, &left[..14]);
        registry.import(receipt, f.now).unwrap();
        verified_receipts += 1;
        assert_eq!(
            registry.status(original.id(), f.now),
            EvidenceStatus::RegionalConfirmed
        );
        original_ids.push(original.id());
        let mut recipient = PurchaseJournal::default();
        assert!(recipient.begin(index, original.id(), 1));
        assert!(recipient.reconcile_regional(index, original.id()));
        recipients.push(recipient);
        if index < 100 {
            let mut parent = original;
            for depth in 0..2 {
                let descendant = f.child_intent(&root, &parent, 0, 60_000 + index * 2 + depth);
                let receipt = f.receipt_local(&mut registry, &descendant, &left[..14]);
                registry.import(receipt, f.now).unwrap();
                verified_receipts += 1;
                dependent_ids.push(descendant.id());
                parent = descendant;
            }
        }
        if (index + 1) % 250 == 0 {
            println!(
                "P0-T12 partition_progress primary_inputs={} retained_receipts={verified_receipts}",
                index + 1
            );
        }
    }
    assert_eq!(verified_receipts, 1_400);
    assert_eq!(registry.candidate_count(), 1_400);
    assert_eq!(recipients.len(), 1_100);
    assert_eq!(
        recipients
            .iter()
            .map(|journal| journal.goods_releases)
            .sum::<usize>(),
        1_100
    );
    assert_eq!(
        original_ids
            .iter()
            .filter(|id| registry.status(**id, f.now) == EvidenceStatus::RegionalConfirmed)
            .count(),
        1_000
    );
    network.advance(8 * HOUR_MS);
    let reconnect_deliveries = network.reconnect();
    assert_eq!(reconnect_deliveries.len(), 100);
    for (target, receipt) in reconnect_deliveries {
        assert_eq!(target, 0);
        registry.import(receipt, network.now).unwrap();
        verified_receipts += 1;
    }
    let losing_original_recipients = original_ids
        .iter()
        .filter(|id| registry.status(**id, network.now) == EvidenceStatus::Void)
        .count();
    let void_descendants = dependent_ids
        .iter()
        .filter(|id| registry.status(**id, network.now) == EvidenceStatus::Void)
        .count();
    let unaffected_primary = original_ids
        .iter()
        .filter(|id| registry.status(**id, network.now) == EvidenceStatus::RegionalConfirmed)
        .count();
    let usable_sibling_outputs = sibling_outputs
        .iter()
        .filter(|(root, output)| registry.usable_output(*root, *output, network.now))
        .count();
    assert_eq!(losing_original_recipients, 100);
    assert_eq!(void_descendants, 200);
    assert_eq!(unaffected_primary, 900);
    assert_eq!(usable_sibling_outputs, 200);
    assert_eq!(registry.candidate_count(), 1_500);

    let mut terminal = PurchaseJournal::default();
    let mut accepted = 0;
    for purchase in 0..4u64 {
        let id = original_ids[purchase as usize];
        assert!(terminal.begin(purchase, id, 6));
        accepted += usize::from(terminal.reconcile_regional(purchase, id));
    }
    assert_eq!(accepted, 3);
    assert_eq!(terminal.exposure, 18);
    assert!(terminal.begin(99, original_ids[99], 11));
    assert!(!terminal.reconcile_regional(99, original_ids[99]));
    assert_eq!(terminal.exposure, 18);
    let mut fresh_terminal = PurchaseJournal::default();
    assert!(fresh_terminal.begin(99, original_ids[99], 11));
    assert!(!fresh_terminal.reconcile_regional(99, original_ids[99]));
    assert_eq!(fresh_terminal.exposure, 0);
    let mut restarted = terminal.clone();
    assert!(restarted.begin(0, original_ids[0], 6));
    assert!(restarted.reconcile_regional(0, original_ids[0]));
    assert_eq!(restarted.goods_releases, 3);
    assert_eq!(restarted.payment_dispatches, 5);

    let mut uncertain = PurchaseJournal::default();
    assert!(uncertain.begin(777, original_ids[777], 6));
    assert_eq!(uncertain.records[&777].state, PurchaseState::Unknown);
    let mut restart_unknown = uncertain.clone();
    assert!(!restart_unknown.begin(777, original_ids[778], 6));
    assert!(restart_unknown.begin(777, original_ids[777], 6));
    assert_eq!(restart_unknown.payment_dispatches, 1);
    assert!(restart_unknown.reconcile_regional(777, original_ids[777]));
    assert!(restart_unknown.reconcile_regional(777, original_ids[777]));
    assert_eq!(restart_unknown.goods_releases, 1);
    assert!(!can_display_global());
    println!(
        "P0-T12 seed=deterministic-P0-SIM-1 primary_inputs=1000 coordinated_double_spends=100 \
         authentic_regional_receipts={verified_receipts} regional_goods_releases=1100 \
         losing_original_recipients={losing_original_recipients} void_dependent_transactions={void_descendants} \
         unaffected_primary={unaffected_primary} usable_sibling_outputs={usable_sibling_outputs} \
         final_candidates={} conflict_proof_lower_bound_bytes={queued_proof_bytes} \
         reconnect_delivery_events=100 partition_simulated_ms={} terminal_6unit_accepted={accepted} \
         terminal_6unit_rejected=1 terminal_11unit_rejected=1 UNKNOWN_alternative_dispatches=0 \
         p95=NOT_MEASURED p99=NOT_MEASURED network_throughput=NOT_MEASURED global=false \
         gaps=terminal_durable_storage,real_concurrent_terminal_races,proof_fetch_cpu_benchmark",
        registry.candidate_count(),
        8 * HOUR_MS,
    );
}
