//! Spec 15: P2P Transport & Connection Lifecycle (INV-1501..1503)
use humoco_sim_core::transport::{compute_backoff, ConnectionPool, ConnState, Connection};
use humoco_sim_core::types::SimTime;

#[test]
fn test_inv1501_three_phase_connection_lifecycle_connected_degrading_suspended() {
    let now0 = SimTime(0);
    let mut conn = Connection::new(10, now0);
    assert_eq!(conn.state, ConnState::Connected);

    // 1 miss -> Degrading
    conn.on_miss(SimTime(10_000));
    assert_eq!(conn.state, ConnState::Degrading);
    assert_eq!(conn.missing_count, 1);

    // 2nd miss -> still Degrading
    conn.on_miss(SimTime(20_000));
    assert_eq!(conn.state, ConnState::Degrading);
    assert_eq!(conn.missing_count, 2);

    // 3rd miss -> Suspended (threshold 3)
    conn.on_miss(SimTime(30_000));
    assert_eq!(conn.state, ConnState::Suspended);
    assert!(conn.is_suspended());
    assert!(conn.next_retry_at.0 > 30_000, "backoff must set future retry");

    // Heartbeat after suspension restores Connected
    conn.on_heartbeat(SimTime(40_000));
    assert_eq!(conn.state, ConnState::Connected);
    assert_eq!(conn.missing_count, 0);

    // Idle timeout 30s -> Degrading, 60s -> Suspended
    let mut conn2 = Connection::new(20, SimTime(0));
    conn2.check_idle(SimTime(31_000));
    assert_eq!(conn2.state, ConnState::Degrading);
    conn2.check_idle(SimTime(61_000));
    assert_eq!(conn2.state, ConnState::Suspended);

    // Fresh heartbeat resets idle
    conn2.on_heartbeat(SimTime(62_000));
    assert_eq!(conn2.state, ConnState::Connected);
    conn2.check_idle(SimTime(92_000)); // idle 30s -> degrading
    assert_eq!(conn2.state, ConnState::Degrading);
}

#[test]
fn test_inv1502_exponentielles_backoff_mit_jitter() {
    let base = 1000;
    let cap = 60_000;
    // Attempt 1: ~1000ms +/-25%
    let b1 = compute_backoff(1, base, cap, 42);
    assert!((750..=1250).contains(&b1), "b1 {} out of 750..1250", b1);

    // Attempt 2: ~2000ms +/-25%
    let b2 = compute_backoff(2, base, cap, 42);
    assert!((1500..=2500).contains(&b2), "b2 {} out of 1500..2500", b2);

    // Attempt 3: ~4000ms
    let b3 = compute_backoff(3, base, cap, 42);
    assert!((3000..=5000).contains(&b3), "b3 {} out of 3000..5000", b3);

    // Attempt 6: 32s -> ~32000ms but cap 60s
    let b6 = compute_backoff(6, base, cap, 42);
    assert!((24000..=40000).contains(&b6), "b6 {} out of 24000..40000", b6);

    // Attempt high: capped at 60s
    let b10 = compute_backoff(10, base, cap, 42);
    assert!(b10 <= cap);
    assert!(b10 >= (cap as f64 * 0.75) as u64);

    // Deterministic with same seed
    let b1_a = compute_backoff(1, base, cap, 12345);
    let b1_b = compute_backoff(1, base, cap, 12345);
    assert_eq!(b1_a, b1_b, "same seed must be deterministic");

    // Different seed gives different jitter (probabilistically)
    let b_seed1 = compute_backoff(1, base, cap, 1);
    let b_seed2 = compute_backoff(1, base, cap, 2);
    // Not guaranteed different but likely, we just check both in bounds
    assert!((750..=1250).contains(&b_seed1));
    assert!((750..=1250).contains(&b_seed2));

    // Jitter doesn't exceed bounds even for many attempts
    for attempt in 1..10 {
        for seed in [0, 1, 999, 0xDEADBEEF] {
            let b = compute_backoff(attempt, base, cap, seed);
            let exp = 1u64 << (attempt-1).min(10);
            let base_exp = (base * exp).min(cap);
            let lo = (base_exp as f64 * 0.75) as u64;
            let hi = (base_exp as f64 * 1.25) as u64;
            assert!(b >= lo && b <= hi, "attempt {} seed {} got {} not in {}..{}", attempt, seed, b, lo, hi);
        }
    }

    // Backoff grows exponentially but respects jitter
    let b_at1 = compute_backoff(1, base, cap, 999);
    let b_at2 = compute_backoff(2, base, cap, 999);
    // b2 should be approx 2x b1 (allow jitter overlap but generally larger)
    // We check b2 > b1 *0.5 to avoid flaky due to jitter
    assert!(b_at2 > b_at1 / 2, "backoff should generally grow");
}

#[test]
fn test_inv1503_connection_pool_limits_and_dunbar_eviction() {
    let mut pool = ConnectionPool::new();
    let now = SimTime(0);

    // Fill to Dunbar 150
    for i in 0..150 {
        let ev = pool.add(i as u16, now);
        assert!(ev.is_none(), "no eviction before Dunbar");
    }
    assert_eq!(pool.len(), 150);
    assert!(pool.len() <= humoco_sim_core::transport::DUNBAR_MAX);
    assert!(pool.len() <= humoco_sim_core::transport::POOL_HARD_LIMIT);

    // Add one more -> evicts LRU tail (least useful)
    let evicted = pool.add(150, now).expect("must evict at Dunbar");
    assert_eq!(pool.len(), 150);
    assert!(pool.contains(150));
    assert!(!pool.contains(evicted), "evicted node must be gone");

    // Prefer evicting Suspended nodes first
    let mut pool2 = ConnectionPool::new();
    for i in 0..150 {
        pool2.add(i as u16, now);
    }
    // Suspend node 10
    pool2.on_miss(10, SimTime(1000));
    pool2.on_miss(10, SimTime(2000));
    pool2.on_miss(10, SimTime(3000));
    assert!(pool2.conns[&10].is_suspended());
    // Add new node should evict suspended node 10 before LRU
    let ev2 = pool2.add(999, now).unwrap();
    assert_eq!(ev2, 10, "suspended node should be evicted first (Dunbar-Verdrängung)");
    assert!(!pool2.contains(10));
    assert!(pool2.contains(999));

    // LRU touch: recently used nodes not evicted
    let mut pool3 = ConnectionPool::new();
    for i in 0..150 {
        pool3.add(i as u16, now);
    }
    // Touch node 0 (make it MRU)
    pool3.on_heartbeat(0, SimTime(5000));
    // Add many new nodes, 0 should survive longer than never-touched nodes
    for i in 151..160 {
        pool3.add(i as u16, now);
    }
    assert!(pool3.contains(0), "recently used node must survive Dunbar eviction");

    // Hard limit never exceeded
    assert!(pool3.len() <= humoco_sim_core::transport::POOL_HARD_LIMIT);
}

// Additional test: QUIC keep-alive intervals and idle timeout interaction
#[test]
fn test_transport_keepalive_and_idle_interaction() {
    let mut c = Connection::new(77, SimTime(0));
    // Simulate P2P keep-alive every 10s (spec 15.5)
    for t in [10_000, 20_000, 30_000, 40_000] {
        c.on_heartbeat(SimTime(t));
        assert_eq!(c.state, ConnState::Connected);
    }
    // Stop heartbeats, idle 31s -> degrading
    c.check_idle(SimTime(71_000));
    assert_eq!(c.state, ConnState::Degrading);
    // Resume keep-alive -> back to connected
    c.on_heartbeat(SimTime(72_000));
    assert_eq!(c.state, ConnState::Connected);
}
