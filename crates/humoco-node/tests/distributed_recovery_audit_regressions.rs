//! Integration tests for Distributed Recovery, Shard Sync & Fragmented Consensus States.
//! Verifies fixes for Audit Findings F04, F05, F10b (Prompt 21).

use humoco_node::{network::framing::SyncPayload, storage::db::install::ShardStage};
use humoco_sim_core::types::{LockRecord, SimTime};

#[test]
fn test_readiness_manager_mark_sync_failed_does_not_clear_ready() {
    let mgr = humoco_node::daemon::ShardReadinessManager::new();
    let shard_id = 42u16;

    // 1. Mark ready
    mgr.mark_shard_ready(shard_id);
    assert!(mgr.is_shard_ready(shard_id));

    // 2. A lagging background sync task reporting failure must NEVER overwrite Ready
    mgr.mark_sync_failed(shard_id);
    assert!(
        mgr.is_shard_ready(shard_id),
        "mark_sync_failed must not clear Ready status for a converged shard"
    );
}

#[test]
fn test_readiness_manager_syncing_preserves_dedup() {
    let mgr = humoco_node::daemon::ShardReadinessManager::new();
    let shard_id = 42u16;

    assert!(mgr.request_sync(shard_id));
    // While syncing, concurrent request must be rejected (deduplicated)
    assert!(!mgr.request_sync(shard_id));

    // In demand sync, while syncing, triggering again must return false (already active)
    assert!(!mgr.try_trigger_demand_sync(shard_id));
}

#[test]
fn test_stage_rejects_cumulative_overflow_beyond_capacity() {
    let shard = 7u16;
    let now = 1_000u64;
    let stage = ShardStage::new(shard, now).unwrap();

    // Try to append 130 pages of 400 records each = 52,000 records.
    // Max stage entry capacity must be capped (at 50,000 records).
    let mut exceeded = false;
    for page_idx in 0..130 {
        let mut locks = Vec::new();
        for i in 0..400 {
            let mut parent = [0u8; 32];
            parent[..2].copy_from_slice(&shard.to_be_bytes());
            let offset = (page_idx * 400 + i) as u64;
            parent[2..10].copy_from_slice(&offset.to_le_bytes());
            let row = LockRecord::new(
                parent,
                [1u8; 32],
                vec![2],
                SimTime(now),
                SimTime(now + 60_000),
            );
            locks.push((row, now + 60_000));
        }
        let payload = SyncPayload {
            locks,
            hmc_locks: Vec::new(),
            support: Vec::new(),
        };
        if stage.append(payload).is_err() {
            exceeded = true;
            break;
        }
    }

    assert!(
        exceeded,
        "ShardStage must enforce cumulative capacity limits to prevent disk exhaustion attacks"
    );
}
