use ed25519_dalek::{Signer, SigningKey};
use humoco_node::{
    api::hmc::{calculate_l2_payload_hash_for_entry, L2LockEntry, L2Verdict},
    storage::{DualTierEngine, HmcRamIndex, IngressOrigin, RedbStorage},
};
use humoco_proto::causal::CausalOutputProof;
use std::{
    future::Future,
    sync::Arc,
    task::{Context, Poll, Waker},
};
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;

#[path = "common/recovery.rs"]
mod recovery;

#[tokio::test]
async fn real_quic_root_rejection_preserves_signing_health() {
    use humoco_node::{
        api::{
            dto::AttestationDto,
            hmc::{L2AuthPayload, L2LockRequest},
        },
        network::framing::LockWirePayload,
    };
    use humoco_sim_core::wire::{MsgType, WireHeader};
    let peers = recovery::recovery_peers(2).await;
    let source = &peers[0];
    let target = &peers[1];
    let now = source.manager.net_time_ms();
    let expiry = now + 600_000;
    let key = SigningKey::from_bytes(&[1; 32]);
    let mut root = row(&key, 1, true);
    root.deletable_at = Some(expiry.to_string());
    let tag = bs58::encode(root.t_id).into_string();
    root.layer2_signature = key
        .sign(&calculate_l2_payload_hash_for_entry(&root, &tag))
        .to_bytes();
    let shard = humoco_sim_core::types::canonical_voucher_shard(
        &humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag),
    );
    target.readiness.mark_shard_ready(shard);
    let (verdict, _) = target
        .engine
        .ingress_hmc_lock_durable(
            tag,
            root,
            IngressOrigin::ClientApi,
            Some(now),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(verdict, L2Verdict::Verified { .. }));
    let mut entry = row(&key, 2, false);
    entry.created_at_ms = now;
    entry.layer2_signature = key
        .sign(&calculate_l2_payload_hash_for_entry(&entry, "parent"))
        .to_bytes();
    let req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: entry.sender_ephemeral_pub,
            auth_signature: None,
        },
        layer2_voucher_id: entry.layer2_voucher_id.clone(),
        ds_tag: Some("parent".into()),
        transaction_hash: entry.t_id,
        is_genesis: false,
        sender_ephemeral_pub: entry.sender_ephemeral_pub,
        layer2_signature: entry.layer2_signature,
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: now,
        deletable_at: None,
        privacy_guard: None,
    };
    let footprint =
        humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds((expiry - now) / 1_000);
    let sender = *source.identity.node_pubkey();
    let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        &sender,
        0,
        1,
        now,
        0,
        0,
        footprint,
        false,
        &entry.t_id,
    );
    let mut wire = LockWirePayload::Hmc {
        req,
        chain: None,
        root_valid_until: expiry,
        epoch_day: 0,
        epoch_seq: 1,
        cumulative_micro_byte_years: footprint,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        sender_pubkey: sender,
        sender_signature: source.identity.signing_key().sign(&digest).to_bytes(),
        timestamp_ms: now,
    };
    let payload = bincode::serialize(&wire).unwrap();
    let conn = source
        .network
        .connect_peer(target.network.local_addr().unwrap())
        .await
        .unwrap();
    let header = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        1,
        0,
        0,
        payload.len() as u32,
    );
    let reply = source.network.send_request(&conn, &header, &payload).await;
    let committed = target.db.get_hmc_lock("parent").unwrap();
    let valid_reply = reply.as_ref().is_ok_and(|(header, bytes)| {
        header.flags == 0 && AttestationDto::from_wire_bytes(bytes).is_some()
    });
    let attacker = SigningKey::from_bytes(&[2; 32]);
    let mut conflict = row(&attacker, 3, true);
    conflict.created_at_ms = now;
    conflict.deletable_at = Some(expiry.to_string());
    let mut proof = CausalOutputProof {
        version: 1,
        voucher_id: conflict.layer2_voucher_id.clone(),
        transaction_id: conflict.t_id,
        state_hash: [3; 32],
        sender_pubkey: conflict.sender_ephemeral_pub,
        receiver_pubkey_hash: None,
        change_pubkey_hash: None,
        root_valid_until_ms: expiry,
        is_root: true,
        signature: [0; 64],
    };
    proof.signature = attacker.sign(&proof.digest().unwrap()).to_bytes();
    conflict.causal_output = Some(proof);
    let conflict_tag = bs58::encode(conflict.t_id).into_string();
    conflict.layer2_signature = attacker
        .sign(&calculate_l2_payload_hash_for_entry(
            &conflict,
            &conflict_tag,
        ))
        .to_bytes();
    let LockWirePayload::Hmc {
        req,
        epoch_seq,
        cumulative_micro_byte_years,
        sender_signature,
        ..
    } = &mut wire;
        req.causal_output = conflict.causal_output.clone();
        req.auth.ephemeral_pubkey = conflict.sender_ephemeral_pub;
        req.transaction_hash = conflict.t_id;
        req.is_genesis = true;
        req.ds_tag = None;
        req.sender_ephemeral_pub = conflict.sender_ephemeral_pub;
        req.layer2_signature = conflict.layer2_signature;
        req.deletable_at = conflict.deletable_at.clone();
        *epoch_seq = 2;
        *cumulative_micro_byte_years = footprint * 2;
        let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
            &sender,
            0,
            2,
            now,
            0,
            0,
            footprint,
            false,
            &conflict.t_id,
        );
        *sender_signature = source.identity.signing_key().sign(&digest).to_bytes();
    let payload = bincode::serialize(&wire).unwrap();
    let header = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        2,
        0,
        0,
        payload.len() as u32,
    );
    let rejected = source.network.send_request(&conn, &header, &payload).await;
    let health = target.engine.stats.clone();
    recovery::stop_recovery_peers(peers).await;
    assert!(
        rejected.as_ref().is_ok_and(|(_, bytes)| matches!(
            serde_json::from_slice::<L2Verdict>(bytes),
            Ok(L2Verdict::Rejected { .. })
        )),
        "conflicting root must be rejected: {rejected:?}"
    );
    assert!(
        !health
            .signing_failed
            .load(std::sync::atomic::Ordering::Acquire),
        "rejected QUIC root upgrade must not disable the node"
    );
    assert!(
        valid_reply && committed == Some(entry),
        "valid checkout failed over QUIC: {reply:?}"
    );
}

#[test]
fn optional_request_fields_must_roundtrip_over_quic() {
    use humoco_node::{
        api::hmc::{L2AuthPayload, L2LockRequest},
        network::framing::LockWirePayload,
    };
    let key = SigningKey::from_bytes(&[1; 32]);
    let entry = row(&key, 2, false);
    let req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: entry.sender_ephemeral_pub,
            auth_signature: None,
        },
        layer2_voucher_id: entry.layer2_voucher_id,
        ds_tag: Some("parent".into()),
        transaction_hash: entry.t_id,
        is_genesis: false,
        sender_ephemeral_pub: entry.sender_ephemeral_pub,
        layer2_signature: entry.layer2_signature,
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 1_000,
        deletable_at: None,
        privacy_guard: None,
    };
    let json = serde_json::to_vec(&req).unwrap();
    let req: L2LockRequest = serde_json::from_slice(&json).unwrap();
    let wire = LockWirePayload::Hmc {
        req,
        chain: None,
        root_valid_until: 600_000,
        epoch_day: 0,
        epoch_seq: 1,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        sender_pubkey: [0; 32],
        sender_signature: [0; 64],
        timestamp_ms: 1_000,
    };
    let bytes = bincode::serialize(&wire).unwrap();
    assert!(bincode::deserialize::<LockWirePayload>(&bytes).is_ok());
}

fn row(key: &SigningKey, child: u8, root: bool) -> L2LockEntry {
    let mut entry = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: "review-root".into(),
        t_id: [child; 32],
        sender_ephemeral_pub: key.verifying_key().to_bytes(),
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 1_000,
        deletable_at: root.then(|| "600000".into()),
        privacy_guard: None,
    };
    let tag = if root {
        bs58::encode(entry.t_id).into_string()
    } else {
        "parent".into()
    };
    entry.layer2_signature = key
        .sign(&calculate_l2_payload_hash_for_entry(&entry, &tag))
        .to_bytes();
    entry
}

#[tokio::test]
async fn rejected_root_upgrade_must_not_disable_all_signing() {
    let temp = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&temp.path().join("node.redb")).unwrap());
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let key = SigningKey::from_bytes(&[1; 32]);
    let root = row(&key, 1, true);
    let root_tag = bs58::encode(root.t_id).into_string();
    let (verdict, _) = engine
        .ingress_hmc_lock_durable(
            root_tag,
            root.clone(),
            IngressOrigin::ClientApi,
            Some(1_000),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(verdict, L2Verdict::Verified { .. }));

    let attacker = SigningKey::from_bytes(&[2; 32]);
    let mut conflict = row(&attacker, 2, true);
    let mut proof = CausalOutputProof {
        version: 1,
        voucher_id: conflict.layer2_voucher_id.clone(),
        transaction_id: conflict.t_id,
        state_hash: [3; 32],
        sender_pubkey: conflict.sender_ephemeral_pub,
        receiver_pubkey_hash: None,
        change_pubkey_hash: None,
        root_valid_until_ms: 600_000,
        is_root: true,
        signature: [0; 64],
    };
    proof.signature = attacker.sign(&proof.digest().unwrap()).to_bytes();
    conflict.causal_output = Some(proof);
    let tag = bs58::encode(conflict.t_id).into_string();
    assert!(humoco_node::api::hmc::verify_l2_lock_entry_signature(
        &conflict, &tag
    ));
    let (verdict, _) = engine
        .ingress_hmc_lock_durable(
            tag,
            conflict,
            IngressOrigin::ClientApi,
            Some(1_000),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(verdict, L2Verdict::Rejected { .. }));
    cancel.cancel();
    worker.await.unwrap();
    assert_eq!(db.voucher_root("review-root").unwrap(), Some(root));
    assert!(db.is_signing_history_healthy());
    assert!(
        !engine
            .stats
            .signing_failed
            .load(std::sync::atomic::Ordering::Acquire),
        "a rejected root must not poison the persistence worker"
    );
}

#[tokio::test]
async fn cancelled_hmc_ingress_must_not_leave_unqueued_ram_state() {
    let temp = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&temp.path().join("node.redb")).unwrap());
    let key = SigningKey::from_bytes(&[1; 32]);
    let root = row(&key, 1, true);
    let root_tag = bs58::encode(root.t_id).into_string();
    db.put_hmc_lock(&root_tag, &root).unwrap();
    let ram = Arc::new(RwLock::new(HmcRamIndex::new()));
    ram.write().await.insert_recovered(root_tag, root);
    let (tx, mut rx) = mpsc::channel(4);
    let engine = DualTierEngine::from_parts(
        ram.clone(),
        db.clone(),
        tx,
    );
    let initial_read = ram.read().await;
    let mut op = Box::pin(engine.ingress_hmc_lock_durable(
        "parent".into(),
        row(&key, 2, false),
        IngressOrigin::ClientApi,
        Some(1_000),
        None,
        None,
        None,
    ));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(op.as_mut().poll(&mut cx), Poll::Pending));
    let mut queued_writer = Box::pin(ram.write());
    assert!(matches!(
        queued_writer.as_mut().poll(&mut cx),
        Poll::Pending
    ));
    drop(initial_read);
    assert!(matches!(op.as_mut().poll(&mut cx), Poll::Pending));
    let guard = queued_writer.await;
    assert!(guard.contains_lock("parent"));
    drop(op);
    drop(guard);
    assert!(db.get_hmc_lock("parent").unwrap().is_none());
    assert!(engine.is_signing_healthy());
    let queued = rx.try_recv().ok();
    assert!(
        queued.is_some() || engine.get_hmc_ram_lock("parent").await.is_none(),
        "accepted RAM state must be queued before the first cancellable await"
    );
}

#[tokio::test]
async fn successful_retry_after_cancelled_root_and_spend_survives_recovery() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use humoco_node::{
        api::{
            build_router,
            hmc::{L2AuthPayload, L2LockRequest},
            AppState,
        },
        identity::NodeIdentity,
        ingress::{PowEngine, TierController},
    };
    use humoco_sim_core::types::SimTime;
    use tower::ServiceExt;

    async fn cancel_after_mutation(
        engine: &DualTierEngine,
        tag: String,
        entry: L2LockEntry,
        now: u64,
    ) {
        let initial_read = engine.hmc_ram.read().await;
        let mut op = Box::pin(engine.ingress_hmc_lock_durable(
            tag,
            entry,
            IngressOrigin::ClientApi,
            Some(now),
            None,
            None,
            None,
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(op.as_mut().poll(&mut cx).is_pending());
        let mut writer = Box::pin(engine.hmc_ram.write());
        assert!(writer.as_mut().poll(&mut cx).is_pending());
        drop(initial_read);
        assert!(op.as_mut().poll(&mut cx).is_pending());
        let guard = writer.await;
        drop(op);
        drop(guard);
    }

    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&dir.path().join("node.redb")).unwrap());
    let (tx, rx) = mpsc::channel(16);
    let engine = DualTierEngine::from_parts(
        Arc::new(RwLock::new(HmcRamIndex::new())),
        db.clone(),
        tx,
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let key = SigningKey::from_bytes(&[1; 32]);
    let mut root = row(&key, 1, true);
    root.created_at_ms = now;
    root.deletable_at = Some((now + 600_000).to_string());
    let root_tag = bs58::encode(root.t_id).into_string();
    root.layer2_signature = key
        .sign(&calculate_l2_payload_hash_for_entry(&root, &root_tag))
        .to_bytes();
    cancel_after_mutation(&engine, root_tag.clone(), root, now).await;
    let mut spend = row(&key, 2, false);
    spend.created_at_ms = now;
    spend.layer2_signature = key
        .sign(&calculate_l2_payload_hash_for_entry(&spend, "parent"))
        .to_bytes();
    cancel_after_mutation(&engine, "parent".into(), spend.clone(), now).await;
    let cancel = CancellationToken::new();
    let worker =
        DualTierEngine::spawn_flush_worker(rx, db.clone(), engine.stats.clone(), cancel.clone());
    let identity = NodeIdentity::generate();
    let pow = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tiers = Arc::new(TierController::new(db.clone(), pow.clone()));
    tiers.register_f2f_client("retry", None);
    let state = AppState::new(engine.clone(), db.clone(), identity, tiers, pow);
    let shard = humoco_sim_core::types::canonical_voucher_shard(
        &humoco_sim_core::types::genesis_parent_bytes_from_tag(&root_tag),
    );
    state.readiness_manager.mark_shard_ready(shard);
    let request = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: spend.sender_ephemeral_pub,
            auth_signature: None,
        },
        layer2_voucher_id: spend.layer2_voucher_id.clone(),
        ds_tag: Some("parent".into()),
        transaction_hash: spend.t_id,
        is_genesis: false,
        sender_ephemeral_pub: spend.sender_ephemeral_pub,
        layer2_signature: spend.layer2_signature,
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: now,
        deletable_at: None,
        privacy_guard: None,
    };
    let response = build_router(state)
        .oneshot(
            Request::post("/v1/lock")
                .header("Content-Type", "application/json")
                .header("X-Peer-Token", "retry")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the retry is acknowledged as successful"
    );
    assert!(db.get_hmc_lock("parent").unwrap().is_some());
    cancel.cancel();
    worker.await.unwrap();
    let (recovered, recovery_worker) = DualTierEngine::new(db);
    recovered.recover_from_disk(SimTime(now)).await.unwrap();
    let recovered_entry = recovered.get_hmc_ram_lock("parent").await;
    drop(recovered);
    recovery_worker.await.unwrap();
    assert_eq!(
        recovered_entry,
        Some(spend),
        "HTTP 200 must survive storage recovery with its root anchor"
    );
}
