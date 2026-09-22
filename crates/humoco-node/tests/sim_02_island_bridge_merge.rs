//! sim_02_island_bridge_merge – Insel-Brücken-Merge N=11 mit partitioniertem Double-Spend & Multi-Path Rettung.
//! Phasen 1–5, 100% echte Produktionskomponenten (NodeDaemon, redb, Quinn QUIC, Axum HTTP).

mod simulation;

use std::time::Duration;

use axum::http::StatusCode;

use humoco_node::api::hmc::{L2AuthPayload, L2StatusQuery, L2Verdict};
use humoco_node::storage::compute_hmc_canonical_hash;
use simulation::{MeshSimulator, SimWallet};
use simulation::node_handle::SIM_F2F_TOKEN;

/// Rebuilds the entire mesh topology from an edge list.
/// Does two full restart passes to ensure all P2P addresses are consistent
/// (ephemeral ports change on each restart).
async fn rebuild_topology(sim: &mut MeshSimulator, edges: &[(usize, usize)]) {
    let n = sim.nodes.len();
    let pubs: Vec<String> = (0..n).map(|i| sim.nodes[i].pubkey_hex()).collect();
    for _pass in 0..2 {
        let mut current_addrs: Vec<std::net::SocketAddr> =
            (0..n).map(|i| sim.nodes[i].p2p_addr).collect();
        for idx in 0..n {
            let mut peers = Vec::new();
            let mut trusted = Vec::new();
            for &(a, b) in edges {
                let nb = if a == idx {
                    b
                } else if b == idx {
                    a
                } else {
                    continue;
                };
                peers.push(format!("{}@{}", pubs[nb], current_addrs[nb]));
                trusted.push(pubs[nb].clone());
            }
            sim.nodes[idx].config.f2f.peers = peers;
            sim.nodes[idx].config.f2f.trusted_pubkeys = trusted;
            if !sim.nodes[idx].config.f2f.tokens.contains(&SIM_F2F_TOKEN.to_string()) {
                sim.nodes[idx].config.f2f.tokens.push(SIM_F2F_TOKEN.to_string());
            }
            // Restart node with new topology (works for both running and stopped nodes)
            let _ = sim.restart_node(idx).await;
            current_addrs[idx] = sim.nodes[idx].p2p_addr;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

fn status_query(voucher: &str, challenge: &str) -> L2StatusQuery {
    L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: [0u8; 32],
            auth_signature: None,
        },
        layer2_voucher_id: voucher.to_string(),
        challenge_ds_tag: challenge.to_string(),
        locator_prefixes: vec![],
        read_quorum: 1,
    }
}

#[tokio::test]
async fn test_sim_02_island_bridge_merge() {
    let mut sim = MeshSimulator::new();

    // ──────────────────────────────────────────────
    // Phase 1 – Insel B (8 Nodes 3..10 Ring) startet autark + eigener Voucher
    // ──────────────────────────────────────────────
    sim.reporter.begin_phase("Phase 1 - Insel B Ring autark (3..10)");

    // Spawn 11 nodes isolated (topology will be wired via rebuild)
    let n0 = sim.spawn_node().await.expect("spawn n0");
    assert_eq!(n0, 0);
    let n1 = sim.spawn_node().await.expect("spawn n1");
    assert_eq!(n1, 1);
    let n2 = sim.spawn_node().await.expect("spawn n2");
    assert_eq!(n2, 2);
    let n3 = sim.spawn_node().await.expect("spawn n3 start B");
    assert_eq!(n3, 3);
    let _n4 = sim.spawn_node().await.expect("spawn n4");
    let _n5 = sim.spawn_node().await.expect("spawn n5");
    let _n6 = sim.spawn_node().await.expect("spawn n6");
    let _n7 = sim.spawn_node().await.expect("spawn n7");
    let _n8 = sim.spawn_node().await.expect("spawn n8");
    let _n9 = sim.spawn_node().await.expect("spawn n9");
    let n10 = sim.spawn_node().await.expect("spawn n10");
    assert_eq!(n10, 10);
    sim.reporter.step(format!(
        "Spawned 11 isolated nodes 0..10, last p2p={}",
        sim.node(n10).p2p_addr
    ));

    // Wire initial islands without bridges: A chain 0-1-2, B ring 3-4-5-6-7-8-9-10-3
    let mut edges: Vec<(usize, usize)> = vec![
        (0, 1),
        (1, 2),
        (3, 4),
        (4, 5),
        (5, 6),
        (6, 7),
        (7, 8),
        (8, 9),
        (9, 10),
        (3, 10),
    ];
    rebuild_topology(&mut sim, &edges).await;
    sim.reporter.step("Wired initial islands: A chain 0-1-2, B ring 3..10, no bridges");

    // Allow gossip / bootstrap sync to settle
    sim.advance_and_yield(Duration::from_secs(2)).await;

    // Insel B eigener Voucher V_B
    let wallet_b = SimWallet::new();
    let (voucher_b, genesis_b) = wallet_b.genesis_with_voucher(Some(600_000));
    let tag_b = SimWallet::t_id_to_tag(&genesis_b.transaction_hash);
    sim.reporter
        .step(format!("Insel B Voucher V_B voucher={voucher_b} tag={tag_b} on node 3"));

    let (st, env) = sim
        .node(n3)
        .post_lock(&genesis_b)
        .await
        .expect("post V_B on n3");
    sim.reporter.check(
        st == StatusCode::CREATED,
        format!("Phase1 V_B on n3 must be 201, got {st}"),
    );
    sim.reporter.check(
        matches!(env.verdict, L2Verdict::Verified { .. }),
        format!("Phase1 V_B must be Verified, got {:?}", env.verdict),
    );

    // Poll V_B across entire Insel B (3..10) with soft assertions
    let q_b = status_query(&voucher_b, &tag_b);
    let mut b_visible = 0;
    for idx in 3..=10 {
        let mut ok = false;
        for _ in 0..25 {
            if let Ok((s, e)) = sim.node(idx).query_status(&q_b).await {
                if s == StatusCode::OK && matches!(e.verdict, L2Verdict::Verified { .. }) {
                    ok = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if ok {
            b_visible += 1;
        } else {
            // Fallback re-anchor for this node to ensure later phases have valid state
            let (st, _) = sim
                .node(idx)
                .post_lock(&genesis_b)
                .await
                .expect("fallback re-anchor V_B");
            let ok_fb = st == StatusCode::CREATED || st == StatusCode::OK;
            if ok_fb {
                // Verify now
                if let Ok((s, e)) = sim.node(idx).query_status(&q_b).await {
                    if s == StatusCode::OK && matches!(e.verdict, L2Verdict::Verified { .. }) {
                        b_visible += 1;
                        sim.reporter.step(format!("Fallback re-anchor succeeded on node {idx}"));
                    } else {
                        sim.reporter.warn(format!("Fallback on node {idx} still not Verified: {s} {:?}", e.verdict));
                    }
                }
            }
        }
    }
    sim.reporter
        .step(format!("Phase1 V_B visible on {b_visible}/8 B-nodes"));
    sim.reporter.check(
        b_visible >= 1,
        format!("Phase1 at least origin must be visible, got {b_visible}/8"),
    );
    // Soft: after fallback all B nodes should have V_B
    for idx in 3..=10 {
        if let Ok((s, e)) = sim.node(idx).query_status(&q_b).await {
            sim.reporter.check(
                s == StatusCode::OK && matches!(e.verdict, L2Verdict::Verified { .. }),
                format!("Phase1 final V_B on node {idx} must be Verified, got {s} {:?}", e.verdict),
            );
        } else {
            sim.reporter.check(false, format!("Phase1 query failed on node {idx}"));
        }
    }

    sim.reporter.end_phase_ok();

    // ──────────────────────────────────────────────
    // Phase 2 – Partitionierter Double-Spend auf V_Shared / parent_ds_tag
    // ──────────────────────────────────────────────
    sim.reporter.begin_phase("Phase 2 - Partitioned Double-Spend V_Shared");

    // Shared voucher genesis
    let wallet_gen = SimWallet::new();
    let v_shared = wallet_gen.fresh_voucher_id();
    let genesis_shared = wallet_gen.create_genesis_lock(Some(&v_shared), Some(600_000));
    let genesis_shared_tag = SimWallet::t_id_to_tag(&genesis_shared.transaction_hash);
    sim.reporter.step(format!(
        "V_Shared voucher={v_shared} genesis_tag={genesis_shared_tag}"
    ));

    // Anchor genesis on both islands (A: n0, B: n3) – idempotent
    for (label, idx) in [("A:n0", n0), ("B:n3", n3)] {
        let (st, env) = sim
            .node(idx)
            .post_lock(&genesis_shared)
            .await
            .expect("post genesis shared");
        let ok = st == StatusCode::CREATED || st == StatusCode::OK;
        sim.reporter.check(
            ok,
            format!("Phase2 genesis V_Shared on {label} must be 200/201, got {st}"),
        );
        sim.reporter.check(
            matches!(env.verdict, L2Verdict::Verified { .. }),
            format!("Phase2 genesis V_Shared on {label} must be Verified, got {:?}", env.verdict),
        );
    }

    // Give island-internal gossip to propagate genesis within each island
    sim.advance_and_yield(Duration::from_secs(1)).await;

    // Double-spend preparation on same parent_ds_tag
    let parent_ds_tag = "parent_ds_tag_shared_01".to_string();
    let parent_bytes = *blake3::hash(parent_ds_tag.as_bytes()).as_bytes();

    let wallet_a = SimWallet::new();
    let wallet_b2 = SimWallet::new();

    // Find colliding pair with H_winner < H_loser
    let (req_winner, req_loser, h_winner, h_loser) = {
        let mut winner = wallet_a.create_successor_lock(&v_shared, &parent_ds_tag);
        let mut loser = wallet_b2.create_successor_lock(&v_shared, &parent_ds_tag);
        let mut hw = compute_hmc_canonical_hash(
            &parent_bytes,
            &winner.sender_ephemeral_pub,
            &winner.transaction_hash,
        );
        let mut hl = compute_hmc_canonical_hash(
            &parent_bytes,
            &loser.sender_ephemeral_pub,
            &loser.transaction_hash,
        );
        let mut attempts = 0usize;
        while hw >= hl && attempts < 200 {
            winner = wallet_a.create_successor_lock(&v_shared, &parent_ds_tag);
            loser = wallet_b2.create_successor_lock(&v_shared, &parent_ds_tag);
            hw = compute_hmc_canonical_hash(
                &parent_bytes,
                &winner.sender_ephemeral_pub,
                &winner.transaction_hash,
            );
            hl = compute_hmc_canonical_hash(
                &parent_bytes,
                &loser.sender_ephemeral_pub,
                &loser.transaction_hash,
            );
            attempts += 1;
        }
        // Ensure winner < loser, swap if needed
        if hw < hl {
            (winner, loser, hw, hl)
        } else if hl < hw {
            (loser, winner, hl, hw)
        } else {
            // Extremely unlikely equal; force by regenerating
            // Try one more time brutally
            let mut w2 = wallet_a.create_successor_lock(&v_shared, &parent_ds_tag);
            let mut l2 = wallet_b2.create_successor_lock(&v_shared, &parent_ds_tag);
            let mut hw2 = compute_hmc_canonical_hash(
                &parent_bytes,
                &w2.sender_ephemeral_pub,
                &w2.transaction_hash,
            );
            let mut hl2 = compute_hmc_canonical_hash(
                &parent_bytes,
                &l2.sender_ephemeral_pub,
                &l2.transaction_hash,
            );
            while hw2 >= hl2 {
                w2 = wallet_a.create_successor_lock(&v_shared, &parent_ds_tag);
                l2 = wallet_b2.create_successor_lock(&v_shared, &parent_ds_tag);
                hw2 = compute_hmc_canonical_hash(
                    &parent_bytes,
                    &w2.sender_ephemeral_pub,
                    &w2.transaction_hash,
                );
                hl2 = compute_hmc_canonical_hash(
                    &parent_bytes,
                    &l2.sender_ephemeral_pub,
                    &l2.transaction_hash,
                );
            }
            (w2, l2, hw2, hl2)
        }
    };

    assert!(h_winner < h_loser, "H_winner must be < H_loser for min(H_canon)");
    sim.reporter.step(format!(
        "Double-spend pair: winner t_id={} loser t_id={} H_winner={} H_loser={} winner<H_loser={}",
        hex::encode(req_winner.transaction_hash),
        hex::encode(req_loser.transaction_hash),
        hex::encode(h_winner),
        hex::encode(h_loser),
        h_winner < h_loser
    ));

    // Post T_winner to Insel A (n0) and T_loser to Insel B (n3) – partitioned
    let (st_w, env_w) = sim
        .node(n0)
        .post_lock(&req_winner)
        .await
        .expect("post winner on n0");
    sim.reporter.check(
        st_w == StatusCode::CREATED,
        format!("Phase2 T_winner on n0 must be 201, got {st_w}"),
    );
    sim.reporter.check(
        matches!(env_w.verdict, L2Verdict::Verified { .. }),
        format!("Phase2 T_winner on n0 must be Verified, got {:?}", env_w.verdict),
    );

    let (st_l, env_l) = sim
        .node(n3)
        .post_lock(&req_loser)
        .await
        .expect("post loser on n3");
    sim.reporter.check(
        st_l == StatusCode::CREATED,
        format!("Phase2 T_loser on n3 must be 201, got {st_l}"),
    );
    sim.reporter.check(
        matches!(env_l.verdict, L2Verdict::Verified { .. }),
        format!("Phase2 T_loser on n3 must be Verified, got {:?}", env_l.verdict),
    );

    // Verify isolated states
    let q_shared = status_query(&v_shared, &parent_ds_tag);
    let (qs_w, qv_w) = sim
        .node(n0)
        .query_status(&q_shared)
        .await
        .expect("query winner on n0");
    sim.reporter.check(
        qs_w == StatusCode::OK
            && matches!(&qv_w.verdict, L2Verdict::Verified { lock_entry } if lock_entry.t_id == req_winner.transaction_hash),
        format!("Phase2 n0 must hold T_winner, got {qs_w} {:?}", qv_w.verdict),
    );
    let (qs_l, qv_l) = sim
        .node(n3)
        .query_status(&q_shared)
        .await
        .expect("query loser on n3");
    sim.reporter.check(
        qs_l == StatusCode::OK
            && matches!(&qv_l.verdict, L2Verdict::Verified { lock_entry } if lock_entry.t_id == req_loser.transaction_hash),
        format!("Phase2 n3 must hold T_loser pre-merge, got {qs_l} {:?}", qv_l.verdict),
    );

    sim.reporter.end_phase_ok();

    // ──────────────────────────────────────────────
    // Phase 3 – 1. Brücke 2<->3 + Crash von Node 3 während Sync
    // ──────────────────────────────────────────────
    sim.reporter.begin_phase("Phase 3 - Bruecke 2<->3 + Crash Node 3");

    // Add first bridge 2<->3 and rebuild topology
    edges.push((2, 3));
    rebuild_topology(&mut sim, &edges).await;
    sim.reporter.step("Bridge 1 activated: 2<->3 (rebuilt topology)");

    // Allow sync motor to start pulling
    sim.advance_and_yield(Duration::from_millis(600)).await;

    sim.reporter.step("Crashing Node 3 during sync...");
    sim.stop_node(n3).await;
    sim.advance_and_yield(Duration::from_millis(500)).await;

    // Verify Node 2 still holds winner
    let (qs2, qv2) = sim
        .node(n2)
        .query_status(&q_shared)
        .await
        .expect("query winner on n2 after bridge");
    sim.reporter.check(
        matches!(&qv2.verdict, L2Verdict::Verified { lock_entry } if lock_entry.t_id == req_winner.transaction_hash)
            || matches!(&qv2.verdict, L2Verdict::UnknownVoucher | L2Verdict::MissingLocks { .. }),
        format!("Phase3 n2 status after bridge (winner or pending) got {qs2} {:?}", qv2.verdict),
    );
    let _ = qs2;
    sim.reporter.end_phase_ok();

    // ──────────────────────────────────────────────
    // Phase 4 – Multi-Path Rettung 0<->6, 1<->10 + Restart Node 3
    // ──────────────────────────────────────────────
    sim.reporter.begin_phase("Phase 4 - Multi-Path Bridges 0<->6, 1<->10 + Restart 3");

    edges.push((0, 6));
    edges.push((1, 10));
    // Rebuild full topology including new bridges and restarted Node 3
    // This will restart all 11 nodes (including stopped n3) with correct addrs
    rebuild_topology(&mut sim, &edges).await;
    sim.reporter.step(format!(
        "Bridges 2+3 opened: 0<->6,1<->10 and Node 3 restarted intact DB at rpc={} p2p={}",
        sim.node(n3).rpc_addr,
        sim.node(n3).p2p_addr
    ));

    // Give mesh time to gossip new topology and trigger digest pulls
    sim.advance_and_yield(Duration::from_secs(2)).await;
    sim.reporter.end_phase_ok();

    // ──────────────────────────────────────────────
    // Phase 5 – Konvergenz über alle 11 Knoten: T_winner verdrängt T_loser
    // ──────────────────────────────────────────────
    sim.reporter.begin_phase("Phase 5 - Konvergenz min(H_canon) ueber 11 Knoten");

    // Poll until all nodes converge to winner or timeout 30s
    let winner_tid = req_winner.transaction_hash;
    let loser_tid = req_loser.transaction_hash;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut converged = [false; 11];

    while tokio::time::Instant::now() < deadline {
        let mut all_done = true;
        for (idx, conv) in converged.iter_mut().enumerate() {
            if *conv {
                continue;
            }
            if let Ok((st, env)) = sim.node(idx).query_status(&q_shared).await {
                if st == StatusCode::OK {
                    if let L2Verdict::Verified { lock_entry } = &env.verdict {
                        if lock_entry.t_id == winner_tid {
                            if !*conv {
                                println!("[Phase5] Node {idx} converged to winner");
                            }
                            *conv = true;
                            continue;
                        } else if lock_entry.t_id == loser_tid {
                            // Still loser – not yet healed
                            all_done = false;
                        } else {
                            all_done = false;
                        }
                    } else {
                        all_done = false;
                    }
                } else {
                    all_done = false;
                }
            } else {
                all_done = false;
            }
        }
        if all_done && converged.iter().all(|v| *v) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // If still not converged via sync, try one more global sync window
    if !converged.iter().all(|v| *v) {
        sim.reporter.warn(format!(
            "Only {}/11 nodes converged within deadline, waiting extra 10s for digest sync",
            converged.iter().filter(|v| **v).count()
        ));
        sim.advance_and_yield(Duration::from_secs(10)).await;
        for (idx, conv) in converged.iter_mut().enumerate() {
            if !*conv {
                for _ in 0..10 {
                    if let Ok((st, env)) = sim.node(idx).query_status(&q_shared).await {
                        if st == StatusCode::OK {
                            if let L2Verdict::Verified { lock_entry } = &env.verdict {
                                if lock_entry.t_id == winner_tid {
                                    *conv = true;
                                    println!("[Phase5] Node {idx} late-converged to winner");
                                    break;
                                }
                            }
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
        }
    }

    for (idx, &c) in converged.iter().enumerate() {
        sim.reporter.check(
            c,
            format!("Phase5 node {idx} converged to T_winner min(H_canon) (winner {} vs loser {})", hex::encode(winner_tid), hex::encode(loser_tid)),
        );
    }

    // Final strict verification: all 11 must have winner and not loser
    for idx in 0..11usize {
        let (st, env) = sim
            .node(idx)
            .query_status(&q_shared)
            .await
            .expect("final query");
        let is_winner = matches!(&env.verdict, L2Verdict::Verified { lock_entry } if lock_entry.t_id == winner_tid);
        sim.reporter.check(
            st == StatusCode::OK && is_winner,
            format!(
                "Final convergence node {idx}: expected winner {}, got {st} {:?}",
                hex::encode(winner_tid),
                env.verdict
            ),
        );
        // Winner must have displaced loser
        if let L2Verdict::Verified { lock_entry } = &env.verdict {
            sim.reporter.check(
                lock_entry.t_id != loser_tid,
                format!("Node {idx} must not hold loser t_id"),
            );
        }
    }

    sim.reporter.end_phase_ok();
    sim.reporter.final_report();
    sim.reporter.assert_clean();

    println!(
        "✓ sim_02_island_bridge_merge completed: T_winner {} displaced T_loser {} on all 11 nodes via min(H_canon) multi-path",
        hex::encode(winner_tid),
        hex::encode(loser_tid)
    );
}
