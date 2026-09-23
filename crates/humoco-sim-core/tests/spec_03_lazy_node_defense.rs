use humoco_sim_core::sim::{SimNetwork, SimNode};
use humoco_sim_core::types::{
    bitmask_has_bit, bitmask_count, hrw_rank_nodes, required_quorum,
    select_quorum_with_backup, LockRecord, NodeId, ShardId, SignersBitmask,
    SimTime,
};
use humoco_sim_core::crypto::sign_lock_attestation;
use humoco_sim_core::state_machine::apply_attestation;
use humoco_sim_core::types::LockId;

const SHARD_ID: ShardId = 42;
const NUM_NODES: usize = 25;
const MISSING_THRESHOLD: u32 = 3;

fn create_lock() -> (LockRecord, LockId) {
    let parent = [0x11u8; 32];
    let receiver = [0x22u8; 32];
    let nonce = b"test_salt".to_vec();
    let created = SimTime(0);
    let valid_until = SimTime(10_000);

    let lock = LockRecord::new(parent, receiver, nonce, created, valid_until);
    let lock_id = lock.id;
    (lock, lock_id)
}

#[test]
fn test_spec_03_top20_shard_and_rank21_backup() {
    let node_ids: Vec<NodeId> = (0..NUM_NODES as NodeId).collect();
    let ranked = hrw_rank_nodes(&node_ids, SHARD_ID);
    let (top20, rank21) = select_quorum_with_backup(&node_ids, SHARD_ID);

    assert_eq!(top20.len(), 20, "Top-20 should have exactly 20 candidates");
    assert!(rank21.is_some(), "Rank 21 must exist with >= 21 nodes");

    let rank7_id = ranked[6].0;
    let rank21_id = rank21.unwrap();

    assert!(
        top20.contains(&rank7_id),
        "Rank 7 node must be in Top-20"
    );
    assert!(
        !top20.contains(&rank21_id),
        "Rank 21 node should NOT be in Top-20"
    );
    assert_eq!(ranked[20].0, rank21_id, "Rank 21 must be the 21st node in HRW order");
}

#[test]
fn test_spec_03_lazy_node_defense_suspend_and_promote() {
    let mut network = SimNetwork::new();

    for i in 0..NUM_NODES as NodeId {
        let mut node = SimNode::new(i, NUM_NODES);
        for j in 0..NUM_NODES as NodeId {
            if i != j {
                node.add_peer(j);
            }
        }
        network.add_node(node);
    }

    let node_ids: Vec<NodeId> = (0..NUM_NODES as NodeId).collect();
    let ranked = hrw_rank_nodes(&node_ids, SHARD_ID);
    let (_top20, rank21_opt) = select_quorum_with_backup(&node_ids, SHARD_ID);

    let rank7_id = ranked[6].0;
    let rank21_id = rank21_opt.expect("Rank 21 must exist");

    for node in network.nodes.values_mut() {
        let top20: Vec<NodeId> = ranked.iter().take(20).map(|(nid, _)| *nid).collect();
        node.set_shard_candidates(SHARD_ID, top20);
    }

    let (mut lock, lock_id) = create_lock();

    for (i, (nid, _)) in ranked.iter().take(20).enumerate() {
        if i == 6 {
            continue;
        }
        let att = sign_lock_attestation(*nid, &lock_id, &lock.parent_lock, SimTime(100 + i as u64));
        let status = apply_attestation(&mut lock, att, NUM_NODES).unwrap();
        if lock.signers.len() >= 14 {
            assert!(status.is_active(), "Attestation should make lock active at >= 14 sigs");
        }
    }

    assert_eq!(lock.signers.len(), 19, "Should have 19 signers (top-20 minus rank 7)");

    let mut bitmask: SignersBitmask = 0;
    for i in 0..20 {
        if i != 6 {
            bitmask |= 1u32 << i;
        }
    }

    assert!(
        !bitmask_has_bit(bitmask, 6),
        "Bit 6 (rank 7) should be unset in bitmask"
    );
    assert_eq!(
        bitmask_count(bitmask),
        19,
        "Bitmask should have 19 bits set"
    );

    let mut promoted_node = None;
    for call in 0..MISSING_THRESHOLD {
        for node in network.nodes.values_mut() {
            let result = node.handle_stream_close(SHARD_ID, bitmask, lock_id);
            if call == MISSING_THRESHOLD - 1 {
                if let Some(promoted) = result {
                    promoted_node = Some(promoted);
                }
            }
        }
    }

    for node in network.nodes.values() {
        assert!(
            node.is_suspended(rank7_id),
            "Node should have rank 7 (ID={}) suspended locally",
            rank7_id
        );
    }

    assert!(
        !lock.signers.contains(&rank7_id),
        "Rank 7 should not have signed"
    );

    let promoted_id = promoted_node.expect("Rank 21 should have been promoted");
    assert_eq!(
        promoted_id, rank21_id,
        "Promoted node should be the HRW rank 21 node"
    );

    let att_rank21 = sign_lock_attestation(rank21_id, &lock_id, &lock.parent_lock, SimTime(500));
    let status = apply_attestation(&mut lock, att_rank21, NUM_NODES).unwrap();

    assert!(
        lock.signers.len() >= 14,
        "Should have at least 14 signers after rank 21 promotion (got {})",
        lock.signers.len()
    );
    assert!(
        lock.signers.contains(&rank21_id),
        "Rank 21 node should be among signers"
    );
    assert!(
        status.is_final() || status.is_active(),
        "Lock should be active or final with 14+ signatures"
    );

    let (required, is_final) = required_quorum(NUM_NODES);
    assert_eq!(required, 14, "Required quorum for N>=20 should be 14");
    assert!(is_final, "Should be in FINAL threshold");
    assert!(
        lock.signers.len() >= required,
        "Signers ({}) should meet required quorum ({})",
        lock.signers.len(),
        required
    );
}

#[test]
fn test_spec_03_transient_missing_count_suspension_and_autonomous_decay() {
    use humoco_sim_core::types::{PeerPresenceEntry, PeerPresenceState, FLAG_INBOUND_ACTIVE, FLAG_LAST_FAILED};

    let mut peer = PeerPresenceEntry::new(0xABCD_EF01, 100);

    // Initial 24h Aktivierung
    for ep in 101..=124 {
        peer.record_hour(ep, true);
    }
    assert_eq!(peer.evaluate_state(), PeerPresenceState::Active);
    assert_eq!(peer.malus_score, 0);
    assert_eq!(peer.backoff_level, 0);
    assert!(peer.is_hrw_eligible());
    assert!(peer.should_forward_gossip());

    // +2/-2 Tit-for-Tat: inbound + failure -> malus +2, backoff 1, choked
    peer.record_inbound_activity();
    assert!(peer.flags & FLAG_INBOUND_ACTIVE != 0);
    let bl = peer.record_outbound_failure();
    assert_eq!(bl, 1);
    assert_eq!(peer.malus_score, 2);
    assert_eq!(peer.backoff_level, 1);
    assert!(peer.is_suspended(), "Choked after failure");
    assert!(!peer.is_hrw_eligible(), "Choked peer not HRW eligible (gateway skips to rank 21)");
    assert!(!peer.should_forward_gossip(), "Gossip is suppressed while service is choked");

    // Eskalationssperre: ohne inbound keine weitere Eskalation (offline/DDoS Schutz)
    let bl2 = peer.record_outbound_failure();
    assert_eq!(bl2, 1, "No escalation without inbound");
    assert_eq!(peer.malus_score, 2);
    assert_eq!(peer.backoff_level, 1);
    assert!(peer.is_suspended());

    // Service-basiertes Heilen: 1 Stunde ohne Arbeit vergeht -> Malus bleibt bestehen (kein Zeit-Ablasshandel)
    peer.record_hour(125, true);
    assert_eq!(peer.backoff_level, 1, "No automatic hourly decay (anti-free-rider)");
    assert_eq!(peer.malus_score, 2, "Malus persists until worked off via successful interactions");
    assert!(peer.is_suspended());
    assert!(!peer.is_hrw_eligible());
    assert!(!peer.should_forward_gossip());

    // Erneuter Ausfall mit inbound -> weitere Eskalation (malus 2 + 2 = 4, backoff 2)
    peer.record_inbound_activity();
    let bl3 = peer.record_outbound_failure();
    assert_eq!(bl3, 2);
    assert_eq!(peer.malus_score, 4);
    assert_eq!(peer.backoff_level, 2);
    assert!(peer.is_suspended());
    assert!(!peer.is_hrw_eligible());
    assert!(!peer.should_forward_gossip());

    // Dritter Ausfall mit inbound -> malus 6, backoff 3
    peer.record_inbound_activity();
    let bl4 = peer.record_outbound_failure();
    assert_eq!(bl4, 3);
    assert_eq!(peer.malus_score, 6);
    assert_eq!(peer.backoff_level, 3);

    // Erfolg: FLAG_LAST_FAILED cleared, malus -2 (symmetrisch +2/-2)
    peer.record_outbound_success();
    assert_eq!(peer.malus_score, 4);
    assert_eq!(peer.backoff_level, 2);
    assert_eq!(peer.flags & FLAG_LAST_FAILED, 0);
    assert!(!peer.is_suspended(), "Not choked after success (flag cleared)");
    assert!(peer.should_forward_gossip());
    assert!(peer.is_hrw_eligible());

    // 2 weitere Erfolge -> malus 0, backoff 0
    peer.record_outbound_success();
    assert_eq!(peer.malus_score, 2);
    assert_eq!(peer.backoff_level, 1);
    peer.record_outbound_success();
    assert_eq!(peer.malus_score, 0);
    assert_eq!(peer.backoff_level, 0);
    assert!(!peer.is_suspended());

    // Dormant-Reset: inbound+failure to re-choke, then 23h offline -> DORMANT clears backoff, malus & flags
    peer.record_inbound_activity();
    peer.record_outbound_failure();
    assert_eq!(peer.malus_score, 2);
    assert_eq!(peer.backoff_level, 1);
    for ep in 126..=148 {
        peer.record_hour(ep, false);
    }
    assert_eq!(peer.evaluate_state(), PeerPresenceState::Dormant);
    assert_eq!(peer.backoff_level, 0, "Dormant resets backoff for clean re-entry");
    assert_eq!(peer.malus_score, 0, "Dormant resets malus for clean re-entry");
    assert_eq!(peer.flags, 0, "Dormant clears flags");
    assert!(!peer.is_suspended());

    // Fast Re-Entry nach Wochen: 2 Stunden reichen für Reaktivierung zur Probe
    peer.record_hour(149, true);
    assert_eq!(peer.evaluate_state(), PeerPresenceState::Dormant);
    peer.record_hour(150, true);
    assert_eq!(peer.evaluate_state(), PeerPresenceState::Active);
    assert_eq!(peer.backoff_level, 0);
    assert!(peer.is_hrw_eligible(), "Eligible for probation probe immediately upon re-entry");
    assert!(peer.should_forward_gossip());

    // Alias roundtrip
    peer.record_inbound_activity();
    let alias_bl = peer.record_missing();
    assert_eq!(alias_bl, peer.backoff_level);
    peer.record_success();
    assert_eq!(peer.flags & FLAG_LAST_FAILED, 0);
}