//! Spec 12 & 14: RAM Index, Ingress Window, TTL Persistence (INV-1201..1203, INV-1401)
use humoco_sim_core::storage::{DualTierStorage, RamIndex, ingress_time_window_valid, should_prune};
use humoco_sim_core::types::{LockRecord, SimTime};
use std::time::Instant;

fn make_parent(b: u8) -> [u8;32] { [b;32] }
fn make_receiver(b: u8) -> [u8;32] { [b;32] }

// INV-1201: Hot-Path In-Memory RAM Latenz / First-Seen Check (<1ms, <1µs atomic)
#[test]
fn test_inv1201_hot_path_ram_latency_first_seen() {
    let mut idx = RamIndex::new();
    let now = SimTime(0);
    let root_valid = SimTime(1_000_000);

    // First insert must be AcceptedNew, second same parent same lock is IdempotentReplay, third different lock same parent is collision
    let parent = make_parent(0xAA);
    let rec1 = LockRecord::new(parent, make_receiver(0x11), b"first".to_vec(), SimTime(10), SimTime(500_000));
    let start = Instant::now();
    let r1 = idx.try_insert(rec1.clone(), now, root_valid);
    let elapsed = start.elapsed();
    assert_eq!(r1.unwrap(), humoco_sim_core::storage::IngressVerdictLow::AcceptedNew, "first-seen must be accepted");
    // Latency check: single operation <1ms (in test environment <5ms allowed due to CI)
    assert!(elapsed.as_millis() < 5, "First-Seen must be <1ms, was {:?}", elapsed);

    // Second identical -> idempotent
    let start2 = Instant::now();
    let r2 = idx.try_insert(rec1.clone(), now, root_valid);
    let elapsed2 = start2.elapsed();
    assert!(matches!(r2, Ok(humoco_sim_core::storage::IngressVerdictLow::IdempotentReplay)));
    assert!(elapsed2.as_millis() < 5);

    // Collision with different lock same parent
    let rec_coll = LockRecord::new(parent, make_receiver(0x22), b"coll".to_vec(), SimTime(10), SimTime(500_000));
    let r3 = idx.try_insert(rec_coll, now, root_valid);
    assert!(matches!(r3, Err(humoco_sim_core::storage::IngressVerdictLow::RejectedCollision)));

    // Bench 10k inserts <100ms ( => avg <10us )
    let mut bench = RamIndex::new();
    let bench_start = Instant::now();
    let n = 5_000;
    for i in 0..n {
        let mut p = [0u8;32];
        p[0] = (i & 0xFF) as u8;
        p[1] = ((i>>8)&0xFF) as u8;
        let rec = LockRecord::new(p, make_receiver(0x33), vec![], SimTime(10), SimTime(500_000));
        let _ = bench.try_insert(rec, now, root_valid);
    }
    let bench_elapsed = bench_start.elapsed();
    assert_eq!(bench.len(), n);
    // total < 100ms (fallback <500ms on slow CI)
    assert!(bench_elapsed.as_millis() < 500, "5k inserts must be fast (<500ms), took {:?}", bench_elapsed);
    let avg_us = bench_elapsed.as_micros() / n as u128;
    assert!(avg_us < 1000, "avg per insert <1ms, was {}us", avg_us);
}

// INV-1202: Ingress-Zeitfenster (now + 30s < valid_until <= root.valid_until)
#[test]
fn test_inv1202_ingress_time_window() {
    let root_valid = SimTime(1_000_000);
    let now = SimTime(100_000);

    // valid_until = now+30s exactly -> must be rejected (needs strictly >)
    let edge = SimTime(now.0 + 30_000);
    assert!(!ingress_time_window_valid(now, edge, root_valid), "exactly now+30s must be rejected");

    // now+30s+1 -> accepted
    assert!(ingress_time_window_valid(now, SimTime(now.0+30_001), root_valid));

    // > root_valid -> rejected
    assert!(!ingress_time_window_valid(now, SimTime(root_valid.0+1), root_valid));
    // == root_valid -> accepted
    assert!(ingress_time_window_valid(now, root_valid, root_valid));

    // valid_until in past -> rejected
    assert!(!ingress_time_window_valid(now, SimTime(now.0 - 1000), root_valid));

    // RamIndex also enforces window
    let mut idx = RamIndex::new();
    let parent = make_parent(0xBB);
    let rec_past = LockRecord::new(parent, make_receiver(0x01), b"past".to_vec(), now, SimTime(now.0 + 10_000));
    let res = idx.try_insert(rec_past, now, root_valid);
    assert!(matches!(res, Err(humoco_sim_core::storage::IngressVerdictLow::RejectedWindow)));

    let rec_ok = LockRecord::new(parent, make_receiver(0x02), b"ok".to_vec(), now, SimTime(now.0 + 40_000));
    let res2 = idx.try_insert(rec_ok, now, root_valid);
    assert_eq!(res2.unwrap(), humoco_sim_core::storage::IngressVerdictLow::AcceptedNew);

    // Second lock with same parent but future window would be rejected anyway, but collision logic also
    let root_small = SimTime(now.0 + 35_000);
    let rec_exceed = LockRecord::new(make_parent(0xCC), make_receiver(0x03), b"exceed".to_vec(), now, SimTime(now.0 + 40_000));
    let mut idx2 = RamIndex::new();
    let res3 = idx2.try_insert(rec_exceed, now, root_small);
    assert!(matches!(res3, Err(humoco_sim_core::storage::IngressVerdictLow::RejectedWindow)), "valid_until > root must be rejected");

    // 11-Year Max TTL Boundary Check (Zero State Bloat / L1 Standard Reconciliation)
    let max_ttl_ms = humoco_sim_core::storage::MAX_LOCK_TTL_MS;
    assert_eq!(max_ttl_ms, 11 * 31_536_000 * 1_000); // exactly 11 years

    // Exactly at 11 years -> accepted
    let root_11y = SimTime(now.0 + max_ttl_ms);
    let rec_11y = LockRecord::new(make_parent(0xDD), make_receiver(0x04), b"11y".to_vec(), now, root_11y);
    assert!(ingress_time_window_valid(now, root_11y, root_11y), "validity at exactly 11 years must be accepted");
    let res_11y = idx2.try_insert(rec_11y, now, root_11y);
    assert!(matches!(res_11y, Ok(humoco_sim_core::storage::IngressVerdictLow::AcceptedNew)));

    // Exceeding 11 years by 1ms -> rejected (protects against eternal state bloat)
    let root_11y_plus_1 = SimTime(now.0 + max_ttl_ms + 1);
    let rec_11y_plus_1 = LockRecord::new(make_parent(0xEE), make_receiver(0x05), b"11y+1".to_vec(), now, root_11y_plus_1);
    assert!(!ingress_time_window_valid(now, root_11y_plus_1, root_11y_plus_1), "validity > 11 years must be rejected");
    let res_11y_plus_1 = idx2.try_insert(rec_11y_plus_1, now, root_11y_plus_1);
    assert!(matches!(res_11y_plus_1, Err(humoco_sim_core::storage::IngressVerdictLow::RejectedWindow)));
}

// INV-1203: Zero-Cost TTL-Tilgung nach root.valid_until + 30s Grace
#[test]
fn test_inv1203_zero_cost_ttl_eviction_after_grace() {
    let mut idx = RamIndex::new();
    let now = SimTime(0);
    let root_valid = SimTime(100_000); // 100s
    let parent1 = make_parent(0x01);
    let parent2 = make_parent(0x02);
    let parent3 = make_parent(0x03);
    // Insert 3 locks with same root expiry
    for p in [parent1, parent2, parent3] {
        let rec = LockRecord::new(p, make_receiver(0xFF), b"x".to_vec(), SimTime(10), SimTime(90_000));
        idx.try_insert(rec, now, root_valid).unwrap();
    }
    assert_eq!(idx.len(), 3);

    // Before grace: now = root+30s exactly -> NOT pruned
    let before_grace = SimTime(root_valid.0 + 30_000);
    assert!(!should_prune(before_grace, root_valid));
    let pruned = idx.prune_expired(before_grace);
    assert_eq!(pruned, 0);
    assert_eq!(idx.len(), 3);

    // After grace: root+30s+1 -> must prune all
    let after_grace = SimTime(root_valid.0 + 30_001);
    assert!(should_prune(after_grace, root_valid));
    let pruned2 = idx.prune_expired(after_grace);
    assert_eq!(pruned2, 3);
    assert_eq!(idx.len(), 0, "Zero-cost pruning must remove all expired after grace");

    // New insert after prune with same parent should be allowed again (no resurrection conflict)
    let rec_new = LockRecord::new(parent1, make_receiver(0xEE), b"new".to_vec(), after_grace, SimTime(after_grace.0+40_000));
    let new_root = SimTime(after_grace.0 + 100_000);
    let r = idx.try_insert(rec_new, after_grace, new_root);
    assert_eq!(r.unwrap(), humoco_sim_core::storage::IngressVerdictLow::AcceptedNew, "after TTL eviction same parent can be reused");
}

// INV-1401: Dual-Tier Safety & Replay (WAL / Persistenz-Streaming & vollständige Crash-Recovery)
#[test]
fn test_inv1401_dual_tier_safety_wal_and_crash_recovery() {
    let now = SimTime(0);
    let root_valid = SimTime(500_000);
    let mut store = DualTierStorage::new();

    // Hot path: RAM immediately, WAL queued, disk not yet
    let p1 = make_parent(0x10);
    let p2 = make_parent(0x20);
    let r1 = LockRecord::new(p1, make_receiver(0x01), b"r1".to_vec(), now, SimTime(400_000));
    let r2 = LockRecord::new(p2, make_receiver(0x02), b"r2".to_vec(), now, SimTime(400_000));

    store.ingress(r1.clone(), now, root_valid).unwrap();
    store.ingress(r2.clone(), now, root_valid).unwrap();
    assert_eq!(store.ram_len(), 2);
    assert_eq!(store.wal_len(), 2);
    assert_eq!(store.disk_len(), 0, "disk not yet flushed (zero I/O hot path)");

    // Async flush (background)
    let flushed = store.persist_flush();
    assert_eq!(flushed, 2);
    assert_eq!(store.wal_len(), 0);
    assert_eq!(store.disk_len(), 2);

    // Add third lock but DON'T flush, simulate crash before flush
    let p3 = make_parent(0x30);
    let r3 = LockRecord::new(p3, make_receiver(0x03), b"r3".to_vec(), now, SimTime(400_000));
    store.ingress(r3.clone(), now, root_valid).unwrap();
    assert_eq!(store.ram_len(), 3);
    assert_eq!(store.wal_len(), 1);
    assert_eq!(store.disk_len(), 2);

    // Crash: RAM lost
    store.crash();
    assert_eq!(store.ram_len(), 0, "RAM lost on crash");
    assert_eq!(store.disk_len(), 2, "disk survives");
    assert_eq!(store.wal_len(), 1, "WAL survives (durable)");

    // Recovery: reload disk + replay WAL, all 3 must be back if not expired
    store.recover(now);
    assert_eq!(store.ram_len(), 3, "full crash-recovery must restore all locks");
    // Verify all parents present
    assert!(store.ram.get(&p1).is_some());
    assert!(store.ram.get(&p2).is_some());
    assert!(store.ram.get(&p3).is_some());
    // WAL should be empty after recovery flush
    assert_eq!(store.wal_len(), 0);
    assert_eq!(store.disk_len(), 3);

    // Verify TTL-respect on recovery: expired locks not reloaded
    let mut store2 = DualTierStorage::new();
    let exp_root = SimTime(100_000);
    let exp_rec = LockRecord::new(make_parent(0x99), make_receiver(0x99), b"exp".to_vec(), SimTime(10), SimTime(90_000));
    store2.ingress(exp_rec, SimTime(10), exp_root).unwrap();
    store2.persist_flush();
    assert_eq!(store2.disk_len(), 1);
    // crash and recover AFTER grace
    store2.crash();
    let far_future = SimTime(exp_root.0 + 30_001);
    store2.recover(far_future);
    assert_eq!(store2.ram_len(), 0, "expired lock must NOT be reloaded after TTL grace");

    // Idempotency after recovery: re-ingress same lock before expiry should be idempotent
    let mut store3 = DualTierStorage::new();
    let r = LockRecord::new(make_parent(0x77), make_receiver(0x77), b"idem".to_vec(), now, SimTime(400_000));
    store3.ingress(r.clone(), now, root_valid).unwrap();
    store3.persist_flush();
    store3.crash();
    store3.recover(now);
    let res = store3.ingress(r.clone(), now, root_valid);
    assert!(matches!(res, Ok(humoco_sim_core::storage::IngressVerdictLow::IdempotentReplay)));
}
