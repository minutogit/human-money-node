#![forbid(unsafe_code)]

//! P0-T01..T06 executable model acceptance cases. Real Ed25519 signatures;
//! authenticated F2F ingress, ticket work and transport remain model boundaries.

mod p0_support;

use std::collections::BTreeSet;

use humoco_sim_core::p0::*;
use p0_support::{Fixture, SimNetwork};

fn live_receipt(fixture: &Fixture, registry: &Registry, view: &View, intent: &Intent) -> Receipt {
    let approvals = fixture
        .signer_indices(view)
        .into_iter()
        .take(view.threshold().expect("valid threshold"))
        .map(|index| {
            Signer::new(fixture.keys[index].clone())
                .approve(registry, intent, view, fixture.now)
                .expect("honest durable approval")
        })
        .collect();
    Receipt {
        intent: intent.clone(),
        view: view.clone(),
        approvals,
    }
}

fn refresh_local(fixture: &Fixture, registry: &mut Registry, indices: &[usize], now: u64) {
    for &index in indices {
        registry
            .context
            .refresh_reachability(fixture.key(index), now)
            .expect("reachable partition-local peer");
    }
    registry.context.update_population(now);
}

#[test]
fn p0_t01_balanced_partition_operates_and_reconnect_delivers_only_after_healing() {
    let mut fixture = Fixture::new(40);
    let all: Vec<_> = (0..40).collect();
    let root_left = fixture.root(1);
    let root_right = fixture.root(2);
    let roots = [root_left.clone(), root_right.clone()];
    let mut left = fixture.registry(0, &all, &roots);
    let mut right = fixture.registry(20, &all, &roots);
    let old = left
        .context
        .freeze_view(fixture.intent(&root_left, 11).slot.shard(), fixture.now)
        .expect("old view");
    let old_indices = fixture.signer_indices(&old);
    let outside: Vec<_> = all
        .iter()
        .copied()
        .filter(|index| !old_indices.contains(index))
        .collect();
    let left_members: Vec<_> = old_indices[..10]
        .iter()
        .chain(&outside[..10])
        .copied()
        .collect();
    let right_members: Vec<_> = old_indices[10..]
        .iter()
        .chain(&outside[10..])
        .copied()
        .collect();
    let left_keys: BTreeSet<_> = left_members
        .iter()
        .map(|&index| fixture.key(index))
        .collect();
    assert_eq!(
        old.roster
            .iter()
            .filter(|key| left_keys.contains(*key))
            .count(),
        10
    );
    assert!(
        10 < old.threshold().expect("valid threshold"),
        "requiring old14 would stall both regions"
    );
    let mut network = SimNetwork::new(40, fixture.now);
    network.partition(&[&left_members, &right_members]);
    for elapsed in [30_000, 30_000, 30_000, 30_000, 1] {
        network.advance(elapsed);
        fixture.now = network.now;
        refresh_local(&fixture, &mut left, &left_members, fixture.now);
        refresh_local(&fixture, &mut right, &right_members, fixture.now);
    }
    let lv = left
        .context
        .freeze_view(old.shard, fixture.now)
        .expect("left regional20");
    let rv = right
        .context
        .freeze_view(fixture.intent(&root_right, 12).slot.shard(), fixture.now)
        .expect("right regional20");
    assert_eq!(lv.mode, Mode::Regional);
    assert_eq!(rv.mode, Mode::Regional);
    assert!(lv.roster.iter().all(|key| left_keys.contains(key)));
    assert!(rv.roster.iter().all(|key| !left_keys.contains(key)));
    let a = live_receipt(&fixture, &left, &lv, &fixture.intent(&root_left, 11));
    let b = live_receipt(&fixture, &right, &rv, &fixture.intent(&root_right, 12));
    assert_eq!(
        left.import(a.clone(), fixture.now),
        Ok(EvidenceStatus::RegionalConfirmed)
    );
    assert_eq!(
        right.import(b.clone(), fixture.now),
        Ok(EvidenceStatus::RegionalConfirmed)
    );
    assert!(network
        .send(left_members[0], right_members[0], a.clone())
        .is_none());
    assert!(network
        .send(right_members[0], left_members[0], b.clone())
        .is_none());
    assert_eq!(
        left.status(b.intent.id(), fixture.now),
        EvidenceStatus::Unknown
    );
    fixture.recognize(&mut left, &right, &rv, 20);
    fixture.recognize(&mut right, &left, &lv, 0);
    for (destination, receipt) in network.reconnect() {
        if destination == left_members[0] {
            left.import(receipt, fixture.now)
                .expect("healed delivery left");
        } else {
            right
                .import(receipt, fixture.now)
                .expect("healed delivery right");
        }
    }
    assert_eq!(left.digest(), right.digest());
    assert!(!can_display_global());
    assert!(network
        .trace
        .iter()
        .any(|event| event.starts_with("withhold")));
    println!(
        "P0-T01 seed=P0-SIM-1 regions=20/20 prior=10/10 blue=2 global=false trace={:?}",
        network.trace
    );
}

#[test]
fn p0_t02_asymmetric_partition_rejects_cross_view_duplicate_and_rank21_votes() {
    let mut fixture = Fixture::new(100);
    let all: Vec<_> = (0..100).collect();
    let root = fixture.root(20);
    let mut left = fixture.registry(0, &all, std::slice::from_ref(&root));
    let mut right = fixture.registry(80, &all, std::slice::from_ref(&root));
    let old = left
        .context
        .freeze_view(fixture.intent(&root, 21).slot.shard(), fixture.now)
        .expect("old view");
    let old_indices = fixture.signer_indices(&old);
    let outside: Vec<_> = all
        .iter()
        .copied()
        .filter(|index| !old_indices.contains(index))
        .collect();
    let large: Vec<_> = old_indices[..7]
        .iter()
        .chain(&outside[..73])
        .copied()
        .collect();
    let small: Vec<_> = old_indices[7..]
        .iter()
        .chain(&outside[73..])
        .copied()
        .collect();
    assert_eq!(large.len(), 80);
    assert_eq!(small.len(), 20);
    let mut network = SimNetwork::new(100, fixture.now);
    network.partition(&[&large, &small]);
    for elapsed in [30_000, 30_000, 30_000, 30_000, 1] {
        network.advance(elapsed);
        fixture.now = network.now;
        refresh_local(&fixture, &mut left, &large, fixture.now);
        refresh_local(&fixture, &mut right, &small, fixture.now);
    }
    let lv = left
        .context
        .freeze_view(old.shard, fixture.now)
        .expect("large regional view");
    let rv = right
        .context
        .freeze_view(old.shard, fixture.now)
        .expect("small regional view");
    let intent = fixture.intent(&root, 21);
    let good = live_receipt(&fixture, &left, &lv, &intent);
    let other = live_receipt(&fixture, &right, &rv, &intent);
    assert_eq!(good.approvals.len(), 14);
    assert_eq!(other.approvals.len(), 14);
    let mut bounded =
        TimedCollection::new(&left, &intent, &lv, fixture.now).expect("frozen collection");
    for approval in good.approvals.iter().take(13) {
        assert!(!bounded
            .submit(approval.clone(), fixture.now + 799)
            .expect("timely response"));
    }
    assert!(
        bounded
            .submit(good.approvals[13].clone(), fixture.now + 800)
            .is_err(),
        "800ms deadline cannot acquire14th vote"
    );
    assert!(
        bounded.finish(fixture.now + 800).is_err(),
        "13 votes remain incomplete"
    );
    let later_view = left
        .context
        .freeze_view(intent.slot.shard(), fixture.now + 1)
        .expect("another view becomes available during attempt");
    assert_ne!(later_view.id, lv.id);
    let mut frozen =
        TimedCollection::new(&left, &intent, &lv, fixture.now).expect("second frozen attempt");
    for approval in good.approvals.iter().take(7) {
        assert!(!frozen
            .submit(approval.clone(), fixture.now + 2)
            .expect("original view vote"));
    }
    let later_vote = Approval::issue_unchecked(
        &fixture.keys[fixture.signer_indices(&later_view)[7]],
        &intent,
        &later_view,
        fixture.now + 1,
    );
    assert!(
        frozen.submit(later_vote, fixture.now + 2).is_err(),
        "newly available view cannot mutate running attempt"
    );
    assert_eq!(
        left.import(good.clone(), fixture.now),
        Ok(EvidenceStatus::RegionalConfirmed)
    );
    assert_eq!(
        right.import(other.clone(), fixture.now),
        Ok(EvidenceStatus::RegionalConfirmed)
    );
    let old_indices = fixture.signer_indices(&old);
    let old_receipt = fixture.receipt(&old, &intent, &old_indices[..7]);
    let mut mixed = good.clone();
    mixed.approvals.truncate(7);
    mixed.approvals.extend(old_receipt.approvals);
    assert!(
        left.import(mixed, fixture.now).is_err(),
        "7old+7new never equals14"
    );
    let mut duplicate = good.clone();
    duplicate.approvals[13] = duplicate.approvals[0].clone();
    assert!(
        left.import(duplicate, fixture.now).is_err(),
        "duplicate identity cannot supply member14"
    );
    let outsider = large
        .iter()
        .copied()
        .find(|&index| !lv.roster.contains(&fixture.key(index)))
        .expect("large component has ranks beyond20");
    let mut expanded = good.clone();
    expanded.approvals[13] =
        Approval::issue_unchecked(&fixture.keys[outsider], &intent, &lv, fixture.now);
    assert!(
        left.import(expanded, fixture.now).is_err(),
        "rank21 cannot join frozen attempt"
    );
    assert_eq!(good.view.id, lv.id);
    assert!(!can_display_global());
    println!("P0-T02 regions=80/20 prior=7/13 mixed_rejected=true duplicate_rejected=true rank21_rejected=true deadline_800ms_enforced=true global=false");
}

#[test]
fn p0_t03_small_components_require_adaptive_quorums_and_real_stability() {
    for (population, split) in [(100, 90), (27, 20), (20, 13)] {
        let fixture = Fixture::new(population);
        let root = fixture.root(population as u64);
        for group in [
            (0..split).collect::<Vec<_>>(),
            (split..population).collect(),
        ] {
            let observer = group[0];
            let mut registry = fixture.registry(observer, &group, std::slice::from_ref(&root));
            let view = registry
                .context
                .freeze_view(
                    fixture.intent(&root, observer as u64).slot.shard(),
                    fixture.now,
                )
                .expect("local mature view");
            let expected = if group.len() >= 20 {
                14
            } else {
                group.len() * 2 / 3 + 1
            };
            assert_eq!(view.threshold(), Ok(expected));
            let receipt = live_receipt(
                &fixture,
                &registry,
                &view,
                &fixture.intent(&root, observer as u64),
            );
            let class = if group.len() >= 20 {
                EvidenceStatus::RegionalConfirmed
            } else {
                EvidenceStatus::Provisional
            };
            assert_eq!(registry.import(receipt.clone(), fixture.now), Ok(class));
            let mut short = receipt;
            short.approvals.pop();
            assert!(registry.import(short, fixture.now).is_err());
        }
    }
    let fixture = Fixture::new(20);
    let first19: Vec<_> = (0..19).collect();
    let mut context = fixture.catalog(0, &first19);
    let newcomer = Ticket::issue(&fixture.keys[19], 19, 0, 1);
    context
        .learn(newcomer, fixture.key(0), fixture.now, true)
        .expect("new independently learned key");
    for hour in 0..24 {
        for index in 0..20 {
            context
                .observe_heartbeat(fixture.key(index), fixture.now + hour * HOUR_MS)
                .expect("observed newcomer hour");
        }
    }
    let almost = fixture.now + DAY_MS - 60_000;
    for index in 0..20 {
        context
            .refresh_reachability(fixture.key(index), almost)
            .expect("fresh reachability");
    }
    context.update_population(almost);
    assert_eq!(
        context
            .freeze_view(0, almost)
            .expect("new ticket still immature")
            .mode,
        Mode::Provisional
    );
    let mature = fixture.now + DAY_MS;
    for index in 0..20 {
        context
            .observe_heartbeat(fixture.key(index), mature)
            .expect("current presence");
        context
            .refresh_reachability(fixture.key(index), mature)
            .expect("fresh reachability");
    }
    context.update_population(mature);
    assert!(
        context.freeze_view(0, mature).is_err(),
        "first seeing20 must wait actual24h stability"
    );
    let mut now = mature;
    while now < mature + DAY_MS {
        now += 60_000;
        for index in 0..20 {
            if now.is_multiple_of(HOUR_MS) {
                context
                    .observe_heartbeat(fixture.key(index), now)
                    .expect("ongoing hour");
            }
            context
                .refresh_reachability(fixture.key(index), now)
                .expect("ongoing reachability");
        }
        context.update_population(now);
    }
    assert_eq!(
        context.freeze_view(0, now).expect("real continuity").mode,
        Mode::Regional
    );
    now += LEASE_MS + 1;
    for index in 0..19 {
        context
            .refresh_reachability(fixture.key(index), now)
            .expect("nineteen survive");
    }
    context.update_population(now);
    assert_eq!(
        context.freeze_view(0, now).expect("flap lowers mode").mode,
        Mode::Provisional
    );
    context
        .refresh_reachability(fixture.key(19), now)
        .expect("twentieth returns");
    context.update_population(now);
    assert!(
        context.freeze_view(0, now).is_err(),
        "flap resets stability anchor"
    );
    assert!(!can_display_global());
    println!("P0-T03 partitions=90/10,20/7,13/7 adaptive=7,5,9 maturity_23h59_rejected=true stability24h_required=true flap_resets=true global=false");
}

#[test]
fn p0_t04_union_permutations_duplicates_and_signer_subsets_preserve_disjoint_payments() {
    let fixture = Fixture::new(40);
    let left_indices: Vec<_> = (0..20).collect();
    let right_indices: Vec<_> = (20..40).collect();
    let roots: Vec<_> = (100..108).map(|tag| fixture.root(tag)).collect();
    let mut left = fixture.registry(0, &left_indices, &roots);
    let mut right = fixture.registry(20, &right_indices, &roots);
    let receipts: Vec<_> = roots
        .iter()
        .enumerate()
        .map(|(index, root)| {
            let intent = fixture.intent(root, index as u64);
            if index < 4 {
                fixture.receipt_local(&mut left, &intent, &left_indices[..14])
            } else {
                fixture.receipt_local(&mut right, &intent, &right_indices[..14])
            }
        })
        .collect();
    for (index, receipt) in receipts.iter().enumerate() {
        if index < 4 {
            fixture.recognize(&mut right, &left, &receipt.view, 0);
        } else {
            fixture.recognize(&mut left, &right, &receipt.view, 20);
        }
    }
    for receipt in &receipts {
        left.import(receipt.clone(), fixture.now)
            .expect("independent payment");
    }
    let expected = left.digest();
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let mut reordered = Registry::new(left.context.clone());
        for index in order.into_iter().chain(3..8).chain([0, 7, 0]) {
            reordered
                .import(receipts[index].clone(), fixture.now)
                .expect("order or duplicate evidence");
        }
        assert_eq!(
            reordered.digest(),
            expected,
            "delivery permutation and duplicates converge"
        );
        for receipt in &receipts {
            assert_eq!(
                reordered.status(receipt.intent.id(), fixture.now),
                EvidenceStatus::RegionalConfirmed
            );
        }
    }
    let mut a = Registry::new(left.context.clone());
    let mut b = Registry::new(left.context.clone());
    let mut c = Registry::new(left.context.clone());
    a.import(receipts[0].clone(), fixture.now).expect("A");
    b.import(receipts[1].clone(), fixture.now).expect("B");
    c.import(receipts[2].clone(), fixture.now).expect("C");
    let mut ab_then_c = a.clone();
    ab_then_c.merge_from(&b, fixture.now).expect("A union B");
    ab_then_c
        .merge_from(&c, fixture.now)
        .expect("(A union B) union C");
    b.merge_from(&c, fixture.now).expect("B union C");
    a.merge_from(&b, fixture.now).expect("A union (B union C)");
    assert_eq!(
        a.digest(),
        ab_then_c.digest(),
        "explicit merge associativity"
    );
    let alternative = fixture.receipt(&receipts[0].view, &receipts[0].intent, &left_indices[6..20]);
    assert_ne!(
        alternative.approvals[0].signature,
        receipts[0].approvals[0].signature
    );
    assert_eq!(
        alternative.intent.id(),
        receipts[0].intent.id(),
        "signer subset is not transaction entropy"
    );
    left.import(alternative, fixture.now)
        .expect("different14subset authenticates same intent");
    let other_view_receipt =
        fixture.receipt_local(&mut right, &receipts[0].intent, &right_indices[..14]);
    assert_ne!(other_view_receipt.view.id, receipts[0].view.id);
    assert_eq!(
        other_view_receipt.intent.id(),
        receipts[0].intent.id(),
        "different view cannot alter SpendId"
    );
    fixture.recognize(&mut left, &right, &other_view_receipt.view, 20);
    left.import(other_view_receipt, fixture.now)
        .expect("same intent in independently authorized second view");
    assert_eq!(
        left.winner(&receipts[0].intent.slot),
        Some(receipts[0].intent.id())
    );
    right
        .merge_from(&left, fixture.now)
        .expect("complete evidence union");
    assert_eq!(left.digest(), right.digest());
    assert!(!can_display_global());
    println!("P0-T04 independent_payments=8 delivery_permutations=6 associativity=true duplicates_idempotent=true signer_and_view_independent_hash=true global=false");
}

#[test]
fn p0_t05_original_bridge_and_newcomer_witnesses_identify_only_actual_double_signers() {
    for newcomer_case in [false, true] {
        let fixture = Fixture::new(if newcomer_case { 22 } else { 39 });
        let root = fixture.root(if newcomer_case { 202 } else { 201 });
        let (old, new, a_signers, b_signers, expected_fraud): (
            Vec<_>,
            Vec<_>,
            Vec<_>,
            Vec<_>,
            Vec<_>,
        ) = if newcomer_case {
            (
                (0..20).collect(),
                (0..6).chain(8..22).collect(),
                (0..14).collect(),
                (0..6).chain(14..22).collect(),
                (0..6).collect(),
            )
        } else {
            (
                (0..20).collect(),
                std::iter::once(0).chain(20..39).collect(),
                (0..14).collect(),
                std::iter::once(0).chain(20..33).collect(),
                vec![0],
            )
        };
        let mut left = fixture.registry(0, &old, std::slice::from_ref(&root));
        let observer = *new
            .iter()
            .find(|&&index| index != 0)
            .expect("other observer");
        let mut right = fixture.registry(observer, &new, std::slice::from_ref(&root));
        let lv = left
            .context
            .freeze_view(fixture.intent(&root, 1).slot.shard(), fixture.now)
            .expect("old local view");
        let rv = right
            .context
            .freeze_view(fixture.intent(&root, 2).slot.shard(), fixture.now)
            .expect("new local view");
        assert!(
            right.winner(&fixture.intent(&root, 0).slot).is_none(),
            "newcomers copied actually empty slot first"
        );
        let a = fixture.receipt(&lv, &fixture.intent(&root, 1), &a_signers);
        let b = fixture.receipt(&rv, &fixture.intent(&root, 2), &b_signers);
        left.import(a.clone(), fixture.now)
            .expect("old payment first");
        right
            .import(b.clone(), fixture.now)
            .expect("new payment after independent empty sync");
        fixture.recognize(&mut left, &right, &rv, observer);
        fixture.recognize(&mut right, &left, &lv, 0);
        left.import(b.clone(), fixture.now)
            .expect("rival authentic evidence");
        right
            .import(a.clone(), fixture.now)
            .expect("rival authentic evidence");
        assert_eq!(
            left.winner(&a.intent.slot),
            Some(a.intent.id().min(b.intent.id()))
        );
        assert_eq!(left.digest(), right.digest());
        let mut fraud = BTreeSet::new();
        for first in &a.approvals {
            for second in &b.approvals {
                if let Ok(identity) = verify_node_equivocation(first, second) {
                    fraud.insert(identity);
                }
            }
        }
        assert_eq!(
            fraud,
            expected_fraud
                .into_iter()
                .map(|index| fixture.key(index))
                .collect()
        );
        for index in a_signers.into_iter().chain(b_signers) {
            if !fraud.contains(&fixture.key(index)) {
                assert!(
                    a.approvals
                        .iter()
                        .filter(|vote| vote.node == fixture.key(index))
                        .count()
                        + b.approvals
                            .iter()
                            .filter(|vote| vote.node == fixture.key(index))
                            .count()
                        <= 1
                );
            }
        }
        assert!(!can_display_global());
        println!("P0-T05 case={} authentic_competing_receipts=2 personal_double_signers={} honest_loser_bans=0 global=false",if newcomer_case {"R02"} else {"R01"},fraud.len());
    }
}

#[test]
fn p0_t06_splits_preserve_unrelated_siblings_and_reject_losing_descendants() {
    let fixture = Fixture::new(40);
    let li: Vec<_> = (0..20).collect();
    let ri: Vec<_> = (20..40).collect();
    let root = fixture.root(300);
    let mut left = fixture.registry(0, &li, std::slice::from_ref(&root));
    let mut right = fixture.registry(20, &ri, std::slice::from_ref(&root));
    let split = fixture.spend(&root, root.id(), vec![301, 302], 300);
    let split_receipt = fixture.receipt_local(&mut left, &split, &li[..14]);
    fixture.recognize(&mut right, &left, &split_receipt.view, 0);
    left.import(split_receipt.clone(), fixture.now)
        .expect("origin split");
    right
        .import(split_receipt, fixture.now)
        .expect("origin split");
    let a = fixture.child_intent(&root, &split, 0, 303);
    let b = fixture.child_intent(&root, &split, 0, 304);
    let sibling = fixture.child_intent(&root, &split, 1, 305);
    let da = fixture.child_intent(&root, &a, 0, 306);
    let db = fixture.child_intent(&root, &b, 0, 307);
    let ds = fixture.child_intent(&root, &sibling, 0, 308);
    let candidates = [&a, &b, &sibling, &da, &db, &ds];
    let receipts: Vec<_> = candidates
        .iter()
        .enumerate()
        .map(|(index, intent)| {
            if index == 1 || index == 4 {
                fixture.receipt_local(&mut right, intent, &ri[..14])
            } else {
                fixture.receipt_local(&mut left, intent, &li[..14])
            }
        })
        .collect();
    for (index, receipt) in receipts.iter().enumerate() {
        if index == 1 || index == 4 {
            fixture.recognize(&mut left, &right, &receipt.view, 20);
        } else {
            fixture.recognize(&mut right, &left, &receipt.view, 0);
        }
    }
    for index in [0, 2, 3, 5, 1, 4] {
        left.import(receipts[index].clone(), fixture.now)
            .expect("complete causal evidence");
    }
    for index in [1, 4, 2, 5, 0, 3] {
        right
            .import(receipts[index].clone(), fixture.now)
            .expect("opposite delivery");
    }
    assert_eq!(left.digest(), right.digest());
    let (winner, loser, winner_descendant, loser_descendant) = if a.id() < b.id() {
        (&a, &b, &da, &db)
    } else {
        (&b, &a, &db, &da)
    };
    assert_eq!(
        left.status(winner.id(), fixture.now),
        EvidenceStatus::RegionalConfirmed
    );
    assert_eq!(left.status(loser.id(), fixture.now), EvidenceStatus::Void);
    assert_eq!(
        left.status(winner_descendant.id(), fixture.now),
        EvidenceStatus::RegionalConfirmed
    );
    assert_eq!(
        left.status(loser_descendant.id(), fixture.now),
        EvidenceStatus::Void
    );
    assert_eq!(
        left.status(sibling.id(), fixture.now),
        EvidenceStatus::RegionalConfirmed
    );
    assert_eq!(
        left.status(ds.id(), fixture.now),
        EvidenceStatus::RegionalConfirmed
    );
    let replay = fixture.child_intent(&root, loser_descendant, 0, 309);
    let mut honest = Signer::new(fixture.keys[0].clone());
    let replay_view = left
        .context
        .freeze_view(replay.slot.shard(), fixture.now)
        .expect("replayview");
    assert!(
        honest
            .approve(&left, &replay, &replay_view, fixture.now)
            .is_err(),
        "leaf replay cannot bypass losing ancestor"
    );
    // Rival root bundles must not union their equal-looking child commitments.
    let other_root = fixture.root(310);
    left.context
        .register_root(other_root.clone())
        .expect("independent root");
    let first_bundle = fixture.spend(&other_root, other_root.id(), vec![1, 2], 311);
    let second_bundle = fixture.spend(&other_root, other_root.id(), vec![1, 3], 312);
    right
        .context
        .register_root(other_root.clone())
        .expect("independent root");
    let first_receipt = fixture.receipt_local(&mut left, &first_bundle, &li[..14]);
    let second_receipt = fixture.receipt_local(&mut right, &second_bundle, &ri[..14]);
    fixture.recognize(&mut left, &right, &second_receipt.view, 20);
    left.import(first_receipt, fixture.now)
        .expect("first whole bundle");
    left.import(second_receipt, fixture.now)
        .expect("second whole bundle");
    let (winning_bundle, losing_bundle) = if first_bundle.id() < second_bundle.id() {
        (&first_bundle, &second_bundle)
    } else {
        (&second_bundle, &first_bundle)
    };
    for index in 0..2 {
        assert!(left.usable_output(
            other_root.id(),
            winning_bundle.output(index).expect("winning child"),
            fixture.now
        ));
        assert!(!left.usable_output(
            other_root.id(),
            losing_bundle.output(index).expect("losing child"),
            fixture.now
        ));
    }
    assert!(!can_display_global());
    println!("P0-T06 fork_losing_transactions=1 fork_losing_descendants=1 sibling_branch_survives=true losing_ancestor_replay_rejected=true atomic_bundle_union=false global=false");
}
