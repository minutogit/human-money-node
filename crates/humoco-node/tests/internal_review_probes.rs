use ed25519_dalek::{Signer, SigningKey};
use humoco_node::{
    api::{dto::QuorumCertificateDto, hmc::*, routes::create_attestation_for_network},
    identity::NodeIdentity,
    network::framing::SyncPayload,
    storage::{
        db::{install::ShardStage, support::VerifiedSupport},
        DualTierEngine, RedbStorage,
    },
};
use humoco_sim_core::types::NetworkId;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
#[path = "common/recovery.rs"]
mod recovery;

fn row(key: &SigningKey, voucher: &str, child: u8, root: bool) -> L2LockEntry {
    let mut e = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: voucher.into(),
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
        bs58::encode(e.t_id).into_string()
    } else {
        "parent".into()
    };
    e.layer2_signature = key
        .sign(&calculate_l2_payload_hash_for_entry(&e, &tag))
        .to_bytes();
    e
}
fn shard(root: &L2LockEntry) -> u16 {
    humoco_sim_core::types::canonical_voucher_shard(
        &humoco_sim_core::types::genesis_parent_bytes_from_tag(
            &bs58::encode(root.t_id).into_string(),
        ),
    )
}
fn request(e: &L2LockEntry) -> L2LockRequest {
    L2LockRequest {
        causal_output: e.causal_output.clone(),
        auth: L2AuthPayload {
            ephemeral_pubkey: e.sender_ephemeral_pub,
            auth_signature: None,
        },
        layer2_voucher_id: e.layer2_voucher_id.clone(),
        ds_tag: Some("parent".into()),
        transaction_hash: e.t_id,
        is_genesis: false,
        sender_ephemeral_pub: e.sender_ephemeral_pub,
        layer2_signature: e.layer2_signature,
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: e.encrypted_timestamp,
        created_at_ms: e.created_at_ms,
        deletable_at: None,
        privacy_guard: None,
    }
}
fn confirm(db: &RedbStorage, e: &L2LockEntry, sid: u16) {
    let keys: Vec<_> = (0..20).map(|_| NodeIdentity::generate()).collect();
    let parent = *blake3::hash(b"parent").as_bytes();
    let cert = QuorumCertificateDto {
        lock_id: hex::encode(e.t_id),
        shard_id: sid,
        status: 1,
        active_nodes_count: 20,
        signer_count: 14,
        signer_bitmap: (1 << 14) - 1,
        signatures: keys[..14]
            .iter()
            .map(|k| {
                create_attestation_for_network(k, e.t_id, parent, sid, 1, 1_000, NetworkId::Mainnet)
            })
            .collect(),
    };
    let committee: Vec<_> = keys.iter().map(|k| *k.node_pubkey()).collect();
    let root = db.voucher_root(&e.layer2_voucher_id).unwrap().unwrap();
    let expiry = humoco_node::storage::db::roots::root_valid_until(&root).unwrap();
    let verified = VerifiedSupport::verify(
        "parent".into(),
        e.t_id,
        expiry,
        &cert,
        &committee,
        14,
        true,
        NetworkId::Mainnet,
    )
    .unwrap();
    db.commit_confirmation_support(verified).unwrap();
}
async fn replacement_probe(foreign: bool) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&dir.path().join("node.redb")).unwrap());
    let a = SigningKey::from_bytes(&[1; 32]);
    let b = SigningKey::from_bytes(&[2; 32]);
    let root = row(&a, "review-a", 1, true);
    db.put_hmc_lock(&bs58::encode(root.t_id).into_string(), &root)
        .unwrap();
    let old = row(&a, "review-a", 2, false);
    db.put_hmc_lock("parent", &old).unwrap();
    confirm(&db, &old, shard(&root));
    let incoming_root = if foreign {
        row(&b, "review-b", 3, true)
    } else {
        root.clone()
    };
    let incoming = row(
        &b,
        &incoming_root.layer2_voucher_id,
        if foreign { 4 } else { 2 },
        false,
    );
    assert!(verify_l2_lock_entry_signature(&incoming, "parent"));
    if foreign {
        assert_ne!(shard(&root), shard(&incoming_root));
    }
    let stage = Arc::new(ShardStage::new(shard(&incoming_root), 1_000).unwrap());
    stage
        .append(SyncPayload {
            support: vec![],
            hmc_locks: vec![
                (
                    bs58::encode(incoming_root.t_id).into_string(),
                    incoming_root,
                ),
                ("parent".into(), incoming.clone()),
            ],
        })
        .unwrap();
    let digest = stage.digest().unwrap();
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    engine
        .recover_from_disk(humoco_sim_core::types::SimTime(1_000))
        .await
        .unwrap();
    assert_eq!(
        engine.hmc_ram.read().await.get_confirmation_class("parent"),
        2
    );
    let result = engine
        .install_shard_snapshot(stage, digest, 1, [7; 32], 1, None, None)
        .await;
    let disk = db.get_hmc_lock("parent").unwrap().unwrap();
    let ram = engine.get_hmc_ram_lock("parent").await.unwrap();
    let class = db.confirmation_support("parent").unwrap().unwrap().class;
    cancel.cancel();
    worker.await.unwrap();
    assert!(result.is_err(), "{result:?}");
    assert_eq!(disk, old);
    assert_eq!(ram, old);
    assert_eq!(class, 2);
}
#[tokio::test]
async fn foreign_shard_install_preserves_final_lock() {
    replacement_probe(true).await;
}
#[tokio::test]
async fn same_child_cannot_transfer_confirmation_to_another_sender() {
    replacement_probe(false).await;
}

#[test]
fn legacy_signature_cannot_authenticate_refreshed_timestamp() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let mut original = row(&key, "review-a", 2, false);
    original.created_at_ms = 0;
    original.layer2_signature = key
        .sign(&calculate_l2_payload_hash_for_entry(&original, "parent"))
        .to_bytes();
    let mut refreshed = original.clone();
    refreshed.created_at_ms = 100_000;
    assert!(!verify_l2_lock_signature(&request(&refreshed)));
    assert!(!verify_l2_lock_entry_signature(&refreshed, "parent"));
    refreshed.layer2_signature = key
        .sign(&calculate_l2_payload_hash_for_entry(&refreshed, "parent"))
        .to_bytes();
    assert!(verify_l2_lock_signature(&request(&refreshed)));
    assert!(verify_l2_lock_entry_signature(&refreshed, "parent"));
}

fn retime(key: &SigningKey, e: &mut L2LockEntry, tag: &str, now: u64) {
    e.created_at_ms = now;
    if e.deletable_at.is_some() {
        e.deletable_at = Some((now + 600_000).to_string());
    }
    e.layer2_signature = key
        .sign(&calculate_l2_payload_hash_for_entry(e, tag))
        .to_bytes();
}
fn canonical_root(key: &SigningKey, child: u8, now: u64) -> L2LockEntry {
    use sha2::Digest;
    let mut root = row(key, "", child, true);
    root.created_at_ms = now;
    root.deletable_at = Some((now + 600_000).to_string());
    let mut hash = sha2::Sha256::new();
    hash.update(root.t_id);
    hash.update(root.sender_ephemeral_pub);
    hash.update(root.deletable_at.as_ref().unwrap().as_bytes());
    root.layer2_voucher_id = hex::encode(hash.finalize());
    let mut proof = humoco_proto::causal::CausalOutputProof {
        version: 1,
        voucher_id: root.layer2_voucher_id.clone(),
        transaction_id: root.t_id,
        state_hash: [5; 32],
        sender_pubkey: root.sender_ephemeral_pub,
        receiver_pubkey_hash: None,
        change_pubkey_hash: None,
        root_valid_until_ms: now + 600_000,
        is_root: true,
        signature: [0; 64],
    };
    proof.signature = key.sign(&proof.digest().unwrap()).to_bytes();
    root.causal_output = Some(proof);
    let tag = bs58::encode(root.t_id).into_string();
    root.layer2_signature = key
        .sign(&calculate_l2_payload_hash_for_entry(&root, &tag))
        .to_bytes();
    root
}
#[tokio::test]
async fn real_quic_foreign_shard_install_preserves_final_lock() {
    real_quic_replacement(true).await;
}
#[tokio::test]
async fn real_quic_same_child_cannot_transfer_final_support() {
    real_quic_replacement(false).await;
}
async fn real_quic_replacement(foreign: bool) {
    let peers = recovery::recovery_peers(4).await;
    let target = &peers[0];
    let now = target.manager.net_time_ms();
    let a = SigningKey::from_bytes(&[1; 32]);
    let b = SigningKey::from_bytes(&[2; 32]);
    let root_a = canonical_root(&a, 1, now);
    let tag_a = bs58::encode(root_a.t_id).into_string();
    let mut old = row(&a, &root_a.layer2_voucher_id, 2, false);
    retime(&a, &mut old, "parent", now);
    target.db.put_hmc_lock(&tag_a, &root_a).unwrap();
    target.db.put_hmc_lock("parent", &old).unwrap();
    confirm(&target.db, &old, shard(&root_a));
    target
        .engine
        .recover_from_disk(humoco_sim_core::types::SimTime(now))
        .await
        .unwrap();
    let root_b = if foreign {
        canonical_root(&b, 3, now)
    } else {
        root_a.clone()
    };
    let tag_b = bs58::encode(root_b.t_id).into_string();
    let mut incoming = row(
        &b,
        &root_b.layer2_voucher_id,
        if foreign { 4 } else { 2 },
        false,
    );
    retime(&b, &mut incoming, "parent", now);
    let sid_b = shard(&root_b);
    if foreign {
        assert_ne!(shard(&root_a), sid_b);
    }
    for peer in &peers[1..] {
        peer.db.put_hmc_lock(&tag_b, &root_b).unwrap();
        peer.db.put_hmc_lock("parent", &incoming).unwrap();
        peer.engine
            .recover_from_disk(humoco_sim_core::types::SimTime(now))
            .await
            .unwrap();
        peer.readiness.mark_shard_ready(sid_b);
    }
    let synced = humoco_node::daemon::sync_single_shard(
        sid_b,
        &target.network,
        &target.manager,
        &target.engine,
        &target.db,
        &target.identity,
        &target.readiness,
        &target.cancel,
    )
    .await;
    let disk = target.db.get_hmc_lock("parent").unwrap();
    let ram = target.engine.get_hmc_ram_lock("parent").await;
    recovery::stop_recovery_peers(peers).await;
    assert!(!matches!(synced, Ok(true)), "{synced:?}");
    assert_eq!(disk, Some(old.clone()));
    assert_eq!(ram, Some(old));
}

#[tokio::test]
async fn real_quic_refreshed_legacy_timestamp_is_rejected() {
    use humoco_node::{api::dto::AttestationDto, network::framing::LockWirePayload};
    use humoco_sim_core::wire::{MsgType, WireHeader};
    let peers = recovery::recovery_peers(2).await;
    let source = &peers[0];
    let target = &peers[1];
    let now = target.manager.net_time_ms();
    let key = SigningKey::from_bytes(&[1; 32]);
    let root = canonical_root(&key, 1, now);
    let root_tag = bs58::encode(root.t_id).into_string();
    target.db.put_hmc_lock(&root_tag, &root).unwrap();
    target
        .engine
        .recover_from_disk(humoco_sim_core::types::SimTime(now))
        .await
        .unwrap();
    target.readiness.mark_shard_ready(shard(&root));
    let mut spend = row(&key, &root.layer2_voucher_id, 2, false);
    spend.created_at_ms = 0;
    spend.layer2_signature = key
        .sign(&calculate_l2_payload_hash_for_entry(&spend, "parent"))
        .to_bytes();
    spend.created_at_ms = now;
    let req = request(&spend);
    assert!(!verify_l2_lock_signature(&req));
    let expiry = now + 600_000;
    let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(600);
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
        &spend.t_id,
    );
    let wire = LockWirePayload::Hmc {
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
    let payload = wire.to_bytes().unwrap();
    let conn = source
        .network
        .connect_peer(target.network.local_addr().unwrap())
        .await
        .unwrap();
    let response = source
        .network
        .send_request(
            &conn,
            &WireHeader::new(
                MsgType::LockVerifyRequest as u16,
                1,
                0,
                0,
                payload.len() as u32,
            ),
            &payload,
        )
        .await;
    let retained = target
        .db
        .own_signing_choice(target.identity.node_pubkey(), "parent")
        .unwrap();
    recovery::stop_recovery_peers(peers).await;
    let (header, bytes) = response.unwrap();
    assert_ne!(header.flags, 0);
    assert!(AttestationDto::from_wire_bytes(&bytes).is_none());
    assert!(retained.is_none());
}
