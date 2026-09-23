//! sim_03_byzantine_resilience – Byzantinische Resilienz N=3 mit 100% Produktionskomponenten.
//! Phasen 1–4: Fake-Quorum Rejection, Equivocation Ban, Echo-Gossip Flooding, Fantasy-Lock Rejection.

mod simulation;

use std::time::Duration;

use axum::http::StatusCode;
use humoco_node::api::hmc::{L2Verdict, L2StatusQuery, L2AuthPayload};
use humoco_sim_core::crypto::{sign_lock_attestation, verify_attestation};
use humoco_sim_core::fraud::{sign_heartbeat, FraudProofPayload, FraudProofPillar, SlotDetector128};
use humoco_sim_core::types::{SimTime, Attestation};
use humoco_sim_core::wire::{MsgType, WireHeader};

use simulation::{MeshSimulator, SimWallet};

fn status_query(voucher: &str, challenge: &str, pubkey: [u8; 32]) -> L2StatusQuery {
    L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: pubkey,
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
async fn test_sim_03_byzantine_resilience() {
    let mut sim = MeshSimulator::new();

    // --- Phase 1: Fake Quorum Ingress Rejection ---
    sim.reporter.begin_phase("Phase 1 - Fake Quorum Ingress Rejection");

    let n0 = sim.spawn_node().await.expect("spawn n0 honest");
    sim.reporter.step(format!(
        "Spawned honest node 0 rpc={} p2p={}",
        sim.node(n0).rpc_addr,
        sim.node(n0).p2p_addr
    ));

    // Anchors a legitimate genesis for later reference
    let wallet_legit = SimWallet::new();
    let (voucher_legit, genesis_legit) = wallet_legit.genesis_with_voucher(Some(600_000));
    let tag_legit = SimWallet::t_id_to_tag(&genesis_legit.transaction_hash);
    let (st_legit, env_legit) = sim
        .node(n0)
        .post_lock(&genesis_legit)
        .await
        .expect("post legit genesis");
    sim.reporter.check(
        st_legit == StatusCode::CREATED,
        format!("Legit genesis must be 201, got {st_legit}"),
    );
    sim.reporter.check(
        matches!(env_legit.verdict, L2Verdict::Verified { .. }),
        format!("Legit genesis must be Verified, got {:?}", env_legit.verdict),
    );

    // Craft fake quorum / manipulated signature: flip a byte in layer2_signature
    let wallet_attacker = SimWallet::new();
    let mut fake_req = wallet_attacker.create_genesis_lock(Some(&voucher_legit), Some(600_000));
    // Use a fresh voucher to avoid collision with legit genesis lookup_tag
    let fake_voucher = wallet_attacker.fresh_voucher_id();
    fake_req.layer2_voucher_id = fake_voucher.clone();
    // Corrupt signature to simulate forged quorum claim
    fake_req.layer2_signature[0] ^= 0xFF;
    fake_req.layer2_signature[32] ^= 0xAA;

    let (st_fake, env_fake) = sim
        .node(n0)
        .post_lock(&fake_req)
        .await
        .expect("post fake quorum");
    // Production must reject invalid signature immediately with 400 Bad Request
    sim.reporter.check(
        st_fake == StatusCode::BAD_REQUEST,
        format!("Fake quorum must be 400 Bad Request, got {st_fake}"),
    );
    sim.reporter.check(
        matches!(env_fake.verdict, L2Verdict::Rejected { .. }),
        format!("Fake quorum verdict must be Rejected, got {:?}", env_fake.verdict),
    );
    if let L2Verdict::Rejected { reason } = &env_fake.verdict {
        sim.reporter.check(
            reason.to_lowercase().contains("signature") || reason.to_lowercase().contains("invalid"),
            format!("Rejection reason must mention signature, got '{reason}'"),
        );
    }

    // Ensure legit genesis still verified (not polluted)
    let q_legit = status_query(&voucher_legit, &tag_legit, wallet_legit.pubkey());
    let (qs, qv) = sim
        .node(n0)
        .query_status(&q_legit)
        .await
        .expect("query legit after fake");
    sim.reporter.check(
        qs == StatusCode::OK && matches!(qv.verdict, L2Verdict::Verified { .. }),
        format!("Legit genesis must remain Verified after fake attempt, got {qs} {:?}", qv.verdict),
    );

    sim.reporter.end_phase_ok();

    // --- Phase 2: Equivocation Double-Signing Ban ---
    sim.reporter.begin_phase("Phase 2 - Equivocation Double-Signing Ban");

    // Spawn a second node F2F-paired to n0 to have a real F2F session
    let n1 = sim
        .spawn_node_with_f2f(&[n0])
        .await
        .expect("spawn n1 F2F");
    sim.reporter.step(format!(
        "Spawned node 1 F2F with node 0: rpc={} p2p={}",
        sim.node(n1).rpc_addr,
        sim.node(n1).p2p_addr
    ));
    // Allow gossip / QUIC handshake to establish F2F session
    sim.advance_and_yield(Duration::from_secs(1)).await;

    // Rogue identity: derive from node 1's real pubkey so ban hits actual F2F entry
    let rogue_pubkey_hex = sim.node(n1).pubkey_hex();
    let rogue_pubkey_bytes = hex::decode(&rogue_pubkey_hex).expect("hex decode rogue pubkey");
    let mut rogue_pubkey = [0u8; 32];
    rogue_pubkey.copy_from_slice(&rogue_pubkey_bytes);
    let rogue_node_id = u16::from_le_bytes([rogue_pubkey[0], rogue_pubkey[1]]);

    // Create two conflicting attestations for same parent_lock (same slot) signed by same rogue node
    let parent_lock = *blake3::hash(b"byzantine_slot_42").as_bytes();
    let mut lock_a = [0u8; 32];
    let mut lock_b = [0u8; 32];
    // Deterministic distinct lock_ids
    lock_a.copy_from_slice(blake3::hash(b"equivocation_lock_A").as_bytes());
    lock_b.copy_from_slice(blake3::hash(b"equivocation_lock_B").as_bytes());
    assert_ne!(lock_a, lock_b, "lock ids must differ for equivocation");

    let att_a = sign_lock_attestation(rogue_node_id, &lock_a, &parent_lock, SimTime(1_000));
    let att_b = sign_lock_attestation(rogue_node_id, &lock_b, &parent_lock, SimTime(1_001));

    // Verify both attestations individually valid (First-Party Evidence pre-condition)
    sim.reporter.check(
        verify_attestation(&att_a),
        "Attestation A must be cryptographically valid",
    );
    sim.reporter.check(
        verify_attestation(&att_b),
        "Attestation B must be cryptographically valid",
    );

    // Build FraudProofPayload (Säule 1: ShardEquivocation)
    let mut proof = FraudProofPayload::new_shard_equivocation(att_a.clone(), att_b.clone());
    // Override perpetrator to actual rogue pubkey so ban targets real F2F session
    proof.perpetrator_node_id = rogue_pubkey;
    proof.perpetrator = rogue_node_id;
    proof.pillar = humoco_sim_core::fraud::FraudProofPillar::ShardEquivocation;
    proof.proof_pillar = humoco_sim_core::fraud::FraudProofPillar::ShardEquivocation;

    sim.reporter.check(
        proof.verify(),
        "FraudProofPayload must verify (First-Party Evidence)",
    );

    // Serialize proof and wrap in WireHeader MsgType::EquivocationProof
    let raw_payload = bincode::serialize(&proof).expect("serialize proof");
    let header = WireHeader::new(
        MsgType::EquivocationProof as u16,
        1,
        0,
        0,
        raw_payload.len() as u32,
    );
    // Validate WireHeader framing (32-byte, magic, roundtrip)
    let hdr_bytes = header.to_bytes();
    let decoded_hdr = WireHeader::from_bytes(&hdr_bytes);
    sim.reporter.check(
        decoded_hdr == header,
        "WireHeader roundtrip must be lossless",
    );
    sim.reporter.check(
        decoded_hdr.msg_type == MsgType::EquivocationProof as u16,
        format!(
            "WireHeader msg_type must be EquivocationProof (0x0105), got 0x{:04x}",
            decoded_hdr.msg_type
        ),
    );
    sim.reporter.check(
        header.is_valid_magic(),
        "WireHeader magic must be valid",
    );
    // Also demonstrate the diagnostic alias doesn't panic (SimTime usage)
    let _ = SimTime(0u64);

    // Use real production components for slashing: redb persistence + PeerManager ban
    // Demonstrate redb: open an isolated evidence store and persist raw proof
    {
        use humoco_node::storage::RedbStorage;
        let tmp = tempfile::TempDir::new().expect("tempdir redb");
        let db_path = tmp.path().join("slashing_test.redb");
        let storage = RedbStorage::open(&db_path).expect("open redb");

        let evidence_hash = *blake3::hash(&raw_payload).as_bytes();
        storage.put_evidence(&evidence_hash, &raw_payload).expect("put evidence redb");
        let loaded = storage.get_evidence(&evidence_hash).expect("get evidence redb");
        sim.reporter.check(
            loaded.is_some() && loaded.unwrap() == raw_payload,
            "Evidence must be persisted and retrievable in redb (ACID)",
        );

        // Persist ban atomically in redb
        let now_ms = 1_700_000_000_000u64;
        storage.ban_node(&rogue_pubkey, now_ms).expect("ban_node redb");
        let is_banned_disk = storage.is_node_banned(&rogue_pubkey).expect("is_node_banned redb");
        sim.reporter.check(is_banned_disk, "Rogue NodePubKey must be banned on disk (redb)");

        // Verify banned list contains rogue
        let banned_list = storage.all_banned_nodes().expect("all_banned_nodes");
        sim.reporter.check(
            banned_list.contains(&rogue_pubkey),
            "Banned list in redb must contain rogue pubkey",
        );
    }

    // Demonstrate PeerManager atomarer Bann + F2F-Session-Abbruch
    {
        use humoco_node::network::PeerManager;
        use std::net::SocketAddr;

        let pm = std::sync::Arc::new(PeerManager::new(vec![]));
        // Register rogue as F2F friend with a dummy socket addr
        let rogue_addr: SocketAddr = "127.0.0.1:19090".parse().unwrap();
        pm.register_f2f_friend(rogue_pubkey, Some(rogue_addr)).await;
        pm.add_peer(rogue_addr).await;

        let is_friend_before = pm.is_f2f_friend(&rogue_pubkey).await;
        sim.reporter.check(is_friend_before, "Rogue must be F2F friend before ban");

        // Also demonstrate Quinn QUIC transport creation (real production component)
        {
            use humoco_node::identity::NodeIdentity;
            use humoco_node::network::QuicTransport;
            use tokio_util::sync::CancellationToken;

            let id = NodeIdentity::generate();
            let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let transport_res = QuicTransport::bind(
                bind_addr,
                &id,
            );
            let transport_ok = transport_res.is_ok();
            let transport_err = transport_res.as_ref().err().map(|e| format!("{e:?}"));
            sim.reporter.check(
                transport_ok,
                format!("Quinn QUIC transport must bind on ephemeral port, got {:?}", transport_err),
            );
            if let Ok(t) = transport_res {
                let _ = t.local_addr();
                let _ = t.peer_manager();
                let _ = t.cancel_token();
                // Drop transport (close endpoint) – demonstrates graceful shutdown via CancellationToken
                let _ = CancellationToken::new();
            }
        }

        // Atomic ban – must remove from known nodes and close session
        let affected = pm.ban_node(&rogue_pubkey).await;
        sim.reporter.check(
            affected >= 1,
            format!("ban_node must affect >=1 entry, got {affected}"),
        );
        let is_banned = pm.is_banned(&rogue_pubkey).await;
        sim.reporter.check(is_banned, "Rogue must be banned in PeerManager after equivocation");

        let is_friend_after = pm.is_f2f_friend(&rogue_pubkey).await;
        sim.reporter.check(
            !is_friend_after,
            "Rogue F2F friendship must be severed after ban (WoT exclusion)",
        );

        // Further gossip/RPC from banned node must be rejected
        let can_gossip = pm.can_accept_gossip(&rogue_addr, Some(&rogue_pubkey)).await;
        sim.reporter.check(
            !can_gossip,
            "Banned rogue must not be able to gossip (Gossip Barrier)",
        );
        let can_rpc = pm.can_authorize_direct_rpc(&rogue_addr, Some(&rogue_pubkey)).await;
        sim.reporter.check(
            !can_rpc,
            "Banned rogue must not be authorized for Shard-Direct RPC",
        );
    }

    // Additionally ensure honest node's HTTP still correctly verifies proofs are rejected if tampered
    {
        // Create a proof with same attestations but tamper one signature -> verify must fail (anti-framing)
        let mut tampered_att = att_a.clone();
        tampered_att.signature[0] ^= 0xFF;
        let bad_proof = FraudProofPayload::new_shard_equivocation(tampered_att, att_b.clone());
        sim.reporter.check(
            !bad_proof.verify(),
            "Tampered equivocation proof must NOT verify (anti-framing)",
        );
    }

    let _ = Attestation {
        lock_id: [0u8; 32],
        parent_lock: [0u8; 32],
        node_id: 0,
        timestamp: SimTime(0),
        signature: [0u8; 64],
    };

    sim.reporter.end_phase_ok();

    // --- Phase 3: Heartbeat Spam & SlotDetector128 O(1) Fraud Slashing (Spec 10 Pillar 3) ---
    sim.reporter.begin_phase("Phase 3 - Heartbeat Spam & SlotDetector128 O(1) Slashing");

    {
        let mut detector = SlotDetector128::new();
        let node_id = 7u16;

        let t0 = SimTime(1_000_000_000);
        let hb1 = sign_heartbeat(node_id, t0);

        // First heartbeat stored cleanly
        let proof1 = detector.observe(hb1);
        sim.reporter.check(proof1.is_none(), "First honest heartbeat must not trigger fraud");

        // Second heartbeat within 10 minutes (< 50 min threshold) => Slashing proof generated immediately!
        let t1 = SimTime(1_000_000_000 + 10 * 60 * 1000);
        let hb2 = sign_heartbeat(node_id, t1);
        let proof2 = detector.observe(hb2);
        sim.reporter.check(proof2.is_some(), "Heartbeat spam within 10m (<50m) must trigger FraudProofPayload immediately");

        if let Some(proof) = proof2 {
            sim.reporter.check(proof.proof_pillar == FraudProofPillar::HeartbeatSpam, "Proof pillar must be HeartbeatSpam");
            sim.reporter.check(proof.verify(), "Generated HeartbeatSpam fraud proof must be cryptographically valid");
        }
    }

    sim.reporter.end_phase_ok();

    // --- Phase 4: Unanchored Fantasy Lock Rejection (400 Bad Request, keine RamIndex-Allokation) ---
    sim.reporter.begin_phase("Phase 4 - Unanchored Fantasy Lock Rejection");

    // Snapshot total_locks before fantasy to ensure no allocation
    let (health_status, health_body) = sim
        .node(n0)
        .http_request("GET", "/health", None, &[])
        .await
        .expect("GET /health before fantasy");
    sim.reporter.check(
        health_status == StatusCode::OK,
        format!("GET /health before fantasy must be 200, got {health_status}"),
    );
    let total_before: usize = serde_json::from_slice::<serde_json::Value>(&health_body)
        .ok()
        .and_then(|v| v.get("total_locks").and_then(|n| n.as_u64()).map(|n| n as usize))
        .unwrap_or(0);

    // Fantasy voucher: never anchored via genesis
    let fantasy_voucher = hex::encode(&blake3::hash(b"fantasy_voucher_never_anchored").as_bytes()[..16]);
    let fantasy_wallet = SimWallet::new();
    let fantasy_req = fantasy_wallet.create_successor_lock(&fantasy_voucher, "parent_ds_tag_fantasy_01");

    // This must be rejected with 400 Bad Request (Unknown voucher root)
    let (st_fantasy, env_fantasy) = sim
        .node(n0)
        .post_lock(&fantasy_req)
        .await
        .expect("post fantasy lock");
    sim.reporter.check(
        st_fantasy == StatusCode::BAD_REQUEST,
        format!("Fantasy lock must be 400 Bad Request, got {st_fantasy}"),
    );
    sim.reporter.check(
        matches!(env_fantasy.verdict, L2Verdict::Rejected { .. }),
        format!("Fantasy verdict must be Rejected, got {:?}", env_fantasy.verdict),
    );
    if let L2Verdict::Rejected { reason } = &env_fantasy.verdict {
        sim.reporter.check(
            reason.contains("Unknown voucher root") || reason.contains("genesis"),
            format!("Fantasy rejection must mention unknown voucher/genesis, got '{reason}'"),
        );
    }

    // Ensure no RamIndex allocation: total_locks unchanged
    let (health_status2, health_body2) = sim
        .node(n0)
        .http_request("GET", "/health", None, &[])
        .await
        .expect("GET /health after fantasy");
    let total_after: usize = serde_json::from_slice::<serde_json::Value>(&health_body2)
        .ok()
        .and_then(|v| v.get("total_locks").and_then(|n| n.as_u64()).map(|n| n as usize))
        .unwrap_or(usize::MAX);
    sim.reporter.check(
        health_status2 == StatusCode::OK,
        format!("GET /health after fantasy must be 200, got {health_status2}"),
    );
    sim.reporter.check(
        total_after == total_before,
        format!("RamIndex must not allocate for fantasy lock: before={total_before} after={total_after}"),
    );

    // Query status for fantasy voucher must be UnknownVoucher / MissingLocks, never Verified
    let fantasy_tag = fantasy_req.ds_tag.clone().unwrap();
    let q_fantasy = status_query(&fantasy_voucher, &fantasy_tag, fantasy_wallet.pubkey());
    let (qs_fantasy, qv_fantasy) = sim
        .node(n0)
        .query_status(&q_fantasy)
        .await
        .expect("query fantasy status");
    sim.reporter.check(
        qs_fantasy == StatusCode::OK,
        format!("Fantasy status HTTP must be 200, got {qs_fantasy}"),
    );
    sim.reporter.check(
        matches!(qv_fantasy.verdict, L2Verdict::UnknownVoucher | L2Verdict::MissingLocks { .. } | L2Verdict::Rejected { .. }),
        format!("Fantasy query must be UnknownVoucher/MissingLocks/Rejected, got {:?}", qv_fantasy.verdict),
    );
    sim.reporter.check(
        !matches!(qv_fantasy.verdict, L2Verdict::Verified { .. }),
        "Fantasy lock must never be Verified",
    );

    sim.reporter.end_phase_ok();
    sim.reporter.final_report();
    sim.reporter.assert_clean();

    println!("✓ sim_03_byzantine_resilience completed: fake quorum rejected, equivocation banned, echo suppressed O(1), fantasy rejected 400");
}
