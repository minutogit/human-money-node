//! Integration tests for Distributed Recovery, Shard Sync & Fragmented Consensus States.
//! Verifies fixes for Audit Findings F04, F05, F10b (Prompt 21).

use humoco_node::{network::framing::SyncPayload, storage::db::install::ShardStage};

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

    // Try to append 130 pages of 400 support records each = 52,000 records.
    // Max stage entry capacity must be capped (at 50,000 records).
    let mut exceeded = false;
    for page_idx in 0..130 {
        let mut support = Vec::new();
        for i in 0..400 {
            let offset = (page_idx * 400 + i) as u64;
            let key = format!("tag-{}-{}", shard, offset);
            let fact = humoco_node::storage::db::support::ConfirmationSupport {
                parent: [1u8; 32],
                child: [2u8; 32],
                class: 1,
                root_valid_until_ms: now + 60_000,
                verified_context: [3u8; 32],
            };
            support.push((1u8, key, fact));
        }
        let payload = SyncPayload {
            hmc_locks: Vec::new(),
            support,
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
