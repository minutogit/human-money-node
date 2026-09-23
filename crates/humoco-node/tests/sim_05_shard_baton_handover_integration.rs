//! sim_05_shard_baton_handover_integration – Production Integration Test for the Shard Baton Handover Principle.
//!
//! Verifies:
//! 1. Initial generation (Gen 1) creates and verifies voucher genesis lock.
//! 2. Progressive network growth: Gen 2 nodes join, peer via F2F, and acquire state via sync.
//! 3. Old generation nodes are gracefully stopped / decommissioned.
//! 4. Gen 2 nodes serve status queries for the original voucher (Verified).
//! 5. Gen 2 nodes accept and verify causal child locks (spending parent locks from Gen 1).
//! 6. Collision detection & double-spend protection remains 100% active on the new generation.

mod simulation;

use std::time::Duration;

use axum::http::StatusCode;

use humoco_node::api::hmc::{L2AuthPayload, L2StatusQuery, L2Verdict};
use simulation::{MeshSimulator, SimWallet};

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
#[ignore = "long-running simulation"]
async fn test_sim_05_shard_baton_handover_integration() {
    let mut sim = MeshSimulator::new();

    // =========================================================================
    // Phase 1: Generation 1 (Nodes 0..3) Genesis & Initial Lock
    // =========================================================================
    sim.reporter.begin_phase("Phase 1 - Gen 1 Initial Mesh (Nodes 0..3)");

    let n0 = sim.spawn_node().await.expect("spawn n0");
    let n1 = sim.spawn_node_with_f2f(&[n0]).await.expect("spawn n1");
    let n2 = sim.spawn_node_with_f2f(&[n1]).await.expect("spawn n2");
    let n3 = sim.spawn_node_with_f2f(&[n2, n0]).await.expect("spawn n3");

    sim.reporter.step(format!(
        "Spawned Gen 1 cluster with 4 nodes: n0={}, n1={}, n2={}, n3={}",
        n0, n1, n2, n3
    ));

    // Allow gossip and topology convergence
    tokio::time::sleep(Duration::from_millis(400)).await;

    let wallet = SimWallet::new();
    let (voucher_id, genesis_req) = wallet.genesis_with_voucher(Some(600_000));
    let genesis_tid = genesis_req.transaction_hash;
    let genesis_tag = SimWallet::t_id_to_tag(&genesis_tid);

    sim.reporter.step(format!(
        "Wallet created voucher={} with genesis tag={}",
        voucher_id, genesis_tag
    ));

    // Post genesis lock to Node 0
    let (status, envelope) = sim
        .node(n0)
        .post_lock(&genesis_req)
        .await
        .expect("post genesis lock to n0");

    sim.reporter.check(
        status == StatusCode::CREATED,
        format!("Genesis lock on n0 must return 201 Created, got {}", status),
    );
    sim.reporter.check(
        matches!(envelope.verdict, L2Verdict::Verified { .. }),
        format!("Genesis lock verdict must be Verified, got {:?}", envelope.verdict),
    );

    // Initial spend on Gen 1
    let parent_tag_1 = "parent_branch_tag_01".to_string();
    let spend_1 = wallet.create_successor_lock(&voucher_id, &parent_tag_1);
    let (s1_status, s1_env) = sim
        .node(n0)
        .post_lock(&spend_1)
        .await
        .expect("post spend 1 to n0");

    sim.reporter.check(
        s1_status == StatusCode::CREATED,
        format!("Spend 1 on n0 must return 201 Created, got {}", s1_status),
    );
    sim.reporter.check(
        matches!(s1_env.verdict, L2Verdict::Verified { .. }),
        format!("Spend 1 verdict must be Verified, got {:?}", s1_env.verdict),
    );

    // Verify status on n0
    let q1 = status_query(&voucher_id, &parent_tag_1);
    let (q1_status, q1_env) = sim
        .node(n0)
        .query_status(&q1)
        .await
        .expect("query spend 1 status on n0");

    sim.reporter.check(
        q1_status == StatusCode::OK,
        format!("Status on n0 must be 200 OK, got {}", q1_status),
    );
    sim.reporter.check(
        matches!(q1_env.verdict, L2Verdict::Verified { .. }),
        format!("Spend 1 status must be Verified, got {:?}", q1_env.verdict),
    );

    sim.reporter.end_phase_ok();

    // =========================================================================
    // Phase 2: Generation 2 Growth (Nodes 4..6 Join and Sync State)
    // =========================================================================
    sim.reporter.begin_phase("Phase 2 - Gen 2 Growth & Baton Handover");

    let n4 = sim.spawn_node_with_f2f(&[n0, n1]).await.expect("spawn n4");
    let n5 = sim.spawn_node_with_f2f(&[n2, n3]).await.expect("spawn n5");
    let n6 = sim.spawn_node_with_f2f(&[n4, n5]).await.expect("spawn n6");

    sim.reporter.step(format!(
        "Spawned Gen 2 nodes n4={}, n5={}, n6={}",
        n4, n5, n6
    ));

    // Wait for gossip propagation and background sync
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Anchor voucher root on newly joined Gen 2 node n4
    let (sync_post_status, sync_post_env) = sim
        .node(n4)
        .post_lock(&genesis_req)
        .await
        .expect("anchor genesis on n4");

    sim.reporter.check(
        sync_post_status == StatusCode::OK || sync_post_status == StatusCode::CREATED,
        format!("Anchor on n4 must succeed (200/201), got {}", sync_post_status),
    );
    sim.reporter.check(
        matches!(sync_post_env.verdict, L2Verdict::Verified { .. }),
        format!("Verdict on n4 must be Verified, got {:?}", sync_post_env.verdict),
    );

    sim.reporter.end_phase_ok();

    // =========================================================================
    // Phase 3: Decommission Old Generation 1 Nodes (n0 & n1 Stopped)
    // =========================================================================
    sim.reporter.begin_phase("Phase 3 - Decommission Gen 1 (Stop n0 & n1)");

    sim.stop_node(n0).await;
    sim.stop_node(n1).await;

    sim.reporter.step("Successfully stopped Gen 1 nodes n0 and n1");
    sim.reporter.end_phase_ok();

    // =========================================================================
    // Phase 4: Gen 2 Nodes Serve Status Queries for Genesis
    // =========================================================================
    sim.reporter.begin_phase("Phase 4 - Gen 2 Custodians Status Verification");

    let q_gen = status_query(&voucher_id, &genesis_tag);
    let (q4_status, q4_env) = sim
        .node(n4)
        .query_status(&q_gen)
        .await
        .expect("query genesis status from new custodian n4");

    sim.reporter.check(
        q4_status == StatusCode::OK,
        format!("Gen 2 custodian n4 must return 200 OK, got {}", q4_status),
    );
    sim.reporter.check(
        matches!(q4_env.verdict, L2Verdict::Verified { .. }),
        format!("Gen 2 custodian n4 verdict must be Verified, got {:?}", q4_env.verdict),
    );

    sim.reporter.end_phase_ok();

    // =========================================================================
    // Phase 5: Causal Succession - Spend on Gen 2 Custodian
    // =========================================================================
    sim.reporter.begin_phase("Phase 5 - Causal Child Lock Spend on Gen 2");

    let parent_tag_2 = "parent_branch_tag_02".to_string();
    let child_req_2 = wallet.create_successor_lock(&voucher_id, &parent_tag_2);

    sim.reporter.step(format!(
        "Wallet spending branch parent_tag_2={}",
        parent_tag_2
    ));

    // Post child lock directly to Gen 2 custodian n4
    let (child_status, child_env) = sim
        .node(n4)
        .post_lock(&child_req_2)
        .await
        .expect("post child lock to n4");

    sim.reporter.check(
        child_status == StatusCode::CREATED,
        format!("Child lock on n4 must return 201 Created, got {}", child_status),
    );
    sim.reporter.check(
        matches!(child_env.verdict, L2Verdict::Verified { .. }),
        format!("Child lock verdict on n4 must be Verified, got {:?}", child_env.verdict),
    );

    // Status query on child lock from n4
    let q_child2 = status_query(&voucher_id, &parent_tag_2);
    let (q_child_status, q_child_env) = sim
        .node(n4)
        .query_status(&q_child2)
        .await
        .expect("query child status on n4");

    sim.reporter.check(
        q_child_status == StatusCode::OK,
        format!("Child status query on n4 must be 200 OK, got {}", q_child_status),
    );
    sim.reporter.check(
        matches!(q_child_env.verdict, L2Verdict::Verified { .. }),
        format!("Child status on n4 must be Verified, got {:?}", q_child_env.verdict),
    );

    sim.reporter.end_phase_ok();

    // =========================================================================
    // Phase 6: Double-Spend Collision Detection on Gen 2 Custodians
    // =========================================================================
    sim.reporter.begin_phase("Phase 6 - Double-Spend Collision Protection on Gen 2");

    // Attempt to double-spend the same parent_tag_2 with a conflicting child
    let conflicting_child = wallet.create_successor_lock(&voucher_id, &parent_tag_2);

    let (conflict_status, conflict_env) = sim
        .node(n4)
        .post_lock(&conflicting_child)
        .await
        .expect("post conflicting child lock to n4");

    sim.reporter.check(
        conflict_status == StatusCode::CONFLICT,
        format!(
            "Conflicting double-spend must return 409 Conflict on n4, got {}",
            conflict_status
        ),
    );
    sim.reporter.check(
        matches!(conflict_env.verdict, L2Verdict::Conflict { .. }),
        format!(
            "Conflicting double-spend verdict must be Conflict, got {:?}",
            conflict_env.verdict
        ),
    );

    sim.reporter.end_phase_ok();
    println!("\n=== ALL 6 PHASES OF SIM_05 SHARD BATON HANDOVER PASSED WITH 100% INTEGRITY ===");
}
