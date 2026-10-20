//! Real HTTP isolation and full cryptographic live-proof negative cases.
use ed25519_dalek::{Signer, SigningKey};
use humoco_node::{
    api::{
        routes::{build_operator_router, build_router},
        AppState,
    },
    identity::NodeIdentity,
    ingress::{PowEngine, TierController},
    storage::{DualTierEngine, RedbStorage},
};
use humoco_proto::{
    live::{live_state_digest, verify_live_state_proof, LiveStateContext, LiveStateProof},
    AttestationVote,
};
use std::sync::Arc;

fn context() -> (LiveStateContext, Vec<SigningKey>) {
    let keys: Vec<_> = (1..=20).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
    let tag = "parent-output";
    (
        LiveStateContext {
            version: 1,
            network: 0,
            shard_id: 9,
            voucher_id: "voucher".into(),
            lookup_tag: tag.into(),
            parent_lock: *blake3::hash(tag.as_bytes()).as_bytes(),
            child_lock: [2; 32],
            root_valid_until: 9999999999999,
            state_digest: [3; 32],
            recipient_nonce: [4; 32],
            committee: keys.iter().map(|k| k.verifying_key().to_bytes()).collect(),
        },
        keys,
    )
}

#[test]
fn recipient_context_full_keys_and_exact_fourteen_are_required() {
    let (expected, keys) = context();
    let digest = live_state_digest(&expected).unwrap();
    let proof = LiveStateProof {
        context: expected.clone(),
        votes: keys
            .iter()
            .take(14)
            .map(|k| AttestationVote {
                signer_pubkey: k.verifying_key().to_bytes(),
                signature: k.sign(&digest).to_bytes(),
            })
            .collect(),
    };
    assert!(verify_live_state_proof(&proof, &expected).is_ok());
    let mut changed = proof.clone();
    changed.votes.pop();
    assert!(verify_live_state_proof(&changed, &expected).is_err());
    let mut changed = proof.clone();
    changed.votes[13] = changed.votes[0].clone();
    assert!(verify_live_state_proof(&changed, &expected).is_err());
    let rogue = SigningKey::from_bytes(&[99; 32]);
    let mut changed = proof.clone();
    changed.votes[13] = AttestationVote {
        signer_pubkey: rogue.verifying_key().to_bytes(),
        signature: rogue.sign(&digest).to_bytes(),
    };
    assert!(verify_live_state_proof(&changed, &expected).is_err());
    for field in 0..7 {
        let mut replay = expected.clone();
        match field {
            0 => replay.recipient_nonce[0] ^= 1,
            1 => replay.network = 1,
            2 => replay.child_lock[0] ^= 1,
            3 => replay.state_digest[0] ^= 1,
            4 => replay.root_valid_until += 1,
            5 => replay.committee.swap(0, 1),
            _ => replay.shard_id += 1,
        }
        assert!(verify_live_state_proof(&proof, &replay).is_err());
    }
    let write = humoco_sim_core::crypto::compute_sig_digest(
        humoco_sim_core::crypto::domain_approve_final(humoco_sim_core::types::NetworkId::Mainnet),
        0,
        0,
        0,
        expected.shard_id,
        1,
        &humoco_sim_core::crypto::compute_attestation_payload_digest(
            &expected.parent_lock,
            &expected.child_lock,
        ),
    );
    let mut transplanted = proof.clone();
    for (vote, key) in transplanted.votes.iter_mut().zip(keys.iter()) {
        vote.signature = key.sign(&write).to_bytes();
    }
    assert!(verify_live_state_proof(&transplanted, &expected).is_err());
}

#[tokio::test]
async fn actual_public_http_never_serves_operator_aliases_or_fake_strong_lookup() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Arc::new(RedbStorage::open(&temp.path().join("http.redb")).unwrap());
    let (engine, _flush) = DualTierEngine::new(storage.clone());
    let id = NodeIdentity::generate();
    let pow = Arc::new(PowEngine::new(*id.node_id(), 8));
    let tier = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let state = AppState::new(engine, storage, id, tier, pow);
    let public = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_addr = public.local_addr().unwrap();
    let private = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let private_addr = private.local_addr().unwrap();
    let pub_job = tokio::spawn(async move {
        axum::serve(public, build_router(state.clone()))
            .await
            .unwrap()
    });
    // Build a separate private state to prove operator functionality survives routing separation.
    let storage = Arc::new(RedbStorage::open(&temp.path().join("private.redb")).unwrap());
    let (engine, _flush) = DualTierEngine::new(storage.clone());
    let id = NodeIdentity::generate();
    let pow = Arc::new(PowEngine::new(*id.node_id(), 8));
    let tier = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let private_state = AppState::new(engine, storage, id, tier, pow);
    let priv_job = tokio::spawn(async move {
        axum::serve(private, build_operator_router(private_state))
            .await
            .unwrap()
    });
    let client = reqwest::Client::new();
    for route in [
        "/metrics",
        "/peers",
        "/api/v1/network/peers",
        "/dashboard",
        "/dashboard/data",
        "/dashboard/history",
        "/dashboard/events",
        "/health/ready",
        "/dashboard/vouchers",
    ] {
        assert_eq!(
            client
                .get(format!("http://{public_addr}{route}"))
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::NOT_FOUND,
            "{route}"
        );
    }
    assert_eq!(
        client
            .get(format!("http://{private_addr}/dashboard"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    let metadata: serde_json::Value = client
        .get(format!("http://{public_addr}/v1/node-status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(metadata.as_object().unwrap().len(), 2);
    let response=client.post(format!("http://{public_addr}/v1/status")).json(&serde_json::json!({"auth":{"ephemeral_pubkey":bs58::encode([0u8;32]).into_string()},"layer2_voucher_id":"v","challenge_ds_tag":"t","locator_prefixes":[],"read_quorum":14})).send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let invalid: serde_json::Value = response.json().await.unwrap();
    assert_eq!(invalid["error"], "RecipientChallengeRequired");
    let (live, _) = context();
    assert_eq!(
        client
            .post(format!("http://{public_addr}/v1/verify-current"))
            .json(&live)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    pub_job.abort();
    priv_job.abort();
}

#[tokio::test]
async fn live_state_signature_over_quic_requires_exact_ready_state() {
    use humoco_node::{
        api::hmc::L2LockEntry,
        daemon::ShardReadinessManager,
        network::{DefaultRequestHandler, NodeRequestHandler, PeerManager, QuicTransport},
    };
    use humoco_sim_core::wire::{MsgType, WireHeader, FLAG_NOT_READY};
    use std::time::{Duration, Instant};
    use tokio_util::sync::CancellationToken;
    let temp = tempfile::tempdir().unwrap();
    let storage = Arc::new(RedbStorage::open(&temp.path().join("live.redb")).unwrap());
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let server = NodeIdentity::generate();
    let client = NodeIdentity::generate();
    let pm = Arc::new(PeerManager::new(Vec::new()));
    let cm = Arc::new(PeerManager::new(Vec::new()));
    let cancel = CancellationToken::new();
    let readiness = Arc::new(ShardReadinessManager::with_cancel_token(cancel.clone()));
    let handler = Arc::new(
        NodeRequestHandler::with_peer_manager(engine.clone(), storage, server.clone(), pm.clone())
            .with_readiness_manager(readiness.clone()),
    );
    let receiver = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        pm.clone(),
        handler,
        cancel.clone(),
    )
    .unwrap();
    let sender = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &client,
        cm.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    pm.register_f2f_friend(*client.node_pubkey(), Some(sender.local_addr().unwrap()))
        .await;
    cm.register_f2f_friend(*server.node_pubkey(), Some(receiver.local_addr().unwrap()))
        .await;
    // Explicit readiness/eligibility fixture, not evidence for source-complete recovery.
    for identity in std::iter::once(server.clone()).chain((0..19).map(|_| NodeIdentity::generate()))
    {
        pm.learn_node_from_gossip_with_hrw(
            *identity.node_pubkey(),
            *identity.hrw_routing_id(),
            receiver.local_addr().unwrap(),
            0,
            None,
        )
        .await;
        pm.set_first_seen_for_test(
            identity.node_pubkey(),
            Instant::now() - Duration::from_secs(25 * 3600),
        )
        .await;
    }
    let (mut expected, _) = context();
    expected.shard_id = 9;
    expected.root_valid_until = pm.net_time_ms() + 600_000;
    let entry = L2LockEntry {
        layer2_voucher_id: expected.voucher_id.clone(),
        t_id: expected.child_lock,
        sender_ephemeral_pub: [8; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: None,
        privacy_guard: None,
    };
    {
        let mut ram = engine.hmc_ram.write().await;
        ram.locks.insert(expected.lookup_tag.clone(), entry.clone());
        ram.voucher_roots
            .insert(expected.voucher_id.clone(), expected.root_valid_until);
    }
    let mut anchor = [0; 32];
    anchor[..2].copy_from_slice(&expected.shard_id.to_be_bytes());
    engine
        .record_hmc_voucher_genesis_parent(&expected.voucher_id, anchor)
        .await;
    expected.state_digest = *blake3::hash(&serde_json::to_vec(&entry).unwrap()).as_bytes();
    expected.committee = pm
        .shard_committee(*server.node_pubkey(), *server.hrw_routing_id(), 9)
        .await
        .0
        .iter()
        .map(|m| m.node_pubkey)
        .collect();
    assert_eq!(expected.committee.len(), 20);
    pm.set_local_sync_ready(true);
    pm.set_ge20_anchor_for_test(pm.net_time_ms() - 86_400_001);
    receiver.spawn_accept_loop();
    sender.spawn_accept_loop();
    let conn = sender
        .connect_peer(receiver.local_addr().unwrap())
        .await
        .unwrap();
    let payload = serde_json::to_vec(&expected).unwrap();
    let header = WireHeader::new(
        MsgType::LiveStateRequest as u16,
        1,
        0,
        0,
        payload.len() as u32,
    );
    let (reply, _) = sender.send_request(&conn, &header, &payload).await.unwrap();
    assert_eq!(reply.flags, FLAG_NOT_READY);
    readiness.mark_shard_ready(9);
    // RAM presence alone is insufficient even with an explicitly ready shard.
    let (pending, _) = sender.send_request(&conn, &header, &payload).await.unwrap();
    assert_eq!(pending.flags, FLAG_NOT_READY);
    engine
        .persist_original_approval(
            expected.lookup_tag.clone(),
            entry.clone(),
            *server.node_pubkey(),
            b"fixture-original".to_vec(),
            0,
            pm.net_time_ms(),
        )
        .await
        .unwrap();
    let (reply, bytes) = sender.send_request(&conn, &header, &payload).await.unwrap();
    assert_eq!(reply.flags, 0);
    let vote: AttestationVote = bincode::deserialize(&bytes).unwrap();
    let key = ed25519_dalek::VerifyingKey::from_bytes(&vote.signer_pubkey).unwrap();
    key.verify_strict(
        &live_state_digest(&expected).unwrap(),
        &ed25519_dalek::Signature::from_bytes(&vote.signature),
    )
    .unwrap();
    let mut replay = expected.clone();
    replay.recipient_nonce[0] ^= 1;
    assert!(key
        .verify_strict(
            &live_state_digest(&replay).unwrap(),
            &ed25519_dalek::Signature::from_bytes(&vote.signature)
        )
        .is_err());
    readiness.invalidate_shard(9);
    let (reply, _) = sender.send_request(&conn, &header, &payload).await.unwrap();
    assert_eq!(reply.flags, FLAG_NOT_READY);
    cancel.cancel();
    receiver.close();
    sender.close();
    receiver.drain_tasks().await;
    sender.drain_tasks().await;
}
