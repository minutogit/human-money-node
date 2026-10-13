use humoco_sim_core::types::{hrw_rank_nodes, hrw_score_normalized, order_statistics_threshold, verify_order_statistics_quorum, select_shard_candidates};

#[test]
fn exact_quorum_preserves_provisional_and_final_thresholds() {
    for n in [1usize, 2, 3, 10, 19, 20, 1000] {
        let active: Vec<u16> = (0..n as u16).collect();
        let committee = select_shard_candidates(&active, 42, 20);
        let (q, finality) = humoco_sim_core::types::required_quorum(n);
        assert_eq!(verify_order_statistics_quorum(&committee[..q], &committee), (true, finality));
        assert_eq!(verify_order_statistics_quorum(&committee[..q-1], &committee), (false, false));
    }
}

#[test]
fn rank21_and_duplicates_fail_even_with_fourteen_signatures() {
    let active: Vec<u16> = (0..1000).collect();
    let ranked = hrw_rank_nodes(&active, 42);
    let committee: Vec<_> = ranked[..20].iter().map(|m| m.0).collect();
    let mut signers = committee[..14].to_vec();
    signers[13] = ranked[20].0;
    assert_eq!(verify_order_statistics_quorum(&signers, &committee), (false, false));
    signers[13] = signers[0];
    assert_eq!(verify_order_statistics_quorum(&signers, &committee), (false, false));
    let mut poisoned = committee.clone();
    poisoned.push(ranked[20].0);
    assert_eq!(verify_order_statistics_quorum(&poisoned, &committee), (false, false));
}

#[test]
fn rank21_can_pass_statistical_threshold_but_never_exact_membership() {
    let active: Vec<u16> = (0..1000).collect();
    for shard in 0..100 {
        let ranked = hrw_rank_nodes(&active, shard);
        if hrw_score_normalized(ranked[20].0, shard) >= order_statistics_threshold(1000, 20.0) {
            let committee: Vec<_> = ranked[..20].iter().map(|m| m.0).collect();
            let mut signers = committee[..13].to_vec();
            signers.push(ranked[20].0);
            assert_eq!(verify_order_statistics_quorum(&signers, &committee), (false, false));
            return;
        }
    }
    panic!("fixture must contain a rank-21 score above the statistical threshold");
}

#[test]
fn cryptographic_committee_is_bounded_unique_and_permutation_invariant() {
    use humoco_sim_core::types::{CommitteeMember, select_shard_committee, hrw_score_32};
    let mut active: Vec<_> = (0..40u8).map(|i| CommitteeMember {
        node_pubkey: [i;32], hrw_routing_id: [40-i;32]
    }).collect();
    let original = select_shard_committee(42,&active);
    assert_eq!(original.len(),20);
    for pair in original.windows(2) {
        assert!(hrw_score_32(&pair[0].hrw_routing_id,42) >= hrw_score_32(&pair[1].hrw_routing_id,42));
    }
    active.reverse(); active.extend(active.clone());
    assert_eq!(original,select_shard_committee(42,&active));
    let tied: Vec<_> = (0..21u8).rev().map(|i| CommitteeMember {node_pubkey:[i;32],hrw_routing_id:[0;32]}).collect();
    let committee = select_shard_committee(42,&tied);
    assert_eq!(committee.len(),20);
    assert_eq!(committee[0].node_pubkey,[0;32]);
    assert_eq!(committee[19].node_pubkey,[19;32]);
    assert_eq!(select_shard_committee(42,&tied[..5]).len(),5);
    let duplicate_tickets = [CommitteeMember {node_pubkey:[0;32],hrw_routing_id:[1;32]},
        CommitteeMember {node_pubkey:[0;32],hrw_routing_id:[2;32]}];
    assert_eq!(select_shard_committee(42,&duplicate_tickets),vec![duplicate_tickets[0]]);
}
