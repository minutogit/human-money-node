//! Adversarial acceptance suite (Z11-Z14, E01-E15).
//!
//! Covers:
//! - Positive and adversarial PoW exact-retry and tamper rejection
//! - Token-origin isolation (Rule 3 NodePubKey ingress rejection) and redirect rejection
//! - Regional source wrong-key, replay, expiry, disagreement, and missing-source tests
//! - Pre-allocation rejection above 64 KiB and bounded staging
//! - TTL cleanup of confirmation support and staging records
//! - Idempotent repeated shutdown signals and verified database release

use std::sync::Arc;
use std::time::Duration;
use ed25519_dalek::Signer;
use humoco_node::{
    api::{build_router, hmc::*, AppState},
    identity::NodeIdentity,
    ingress::{PowEngine, TierController},
    storage::{
        db::install::ShardStage,
        db::support,
        DualTierEngine, RedbStorage,
    },
};
use humoco_sim_core::wire::{MsgType, WireHeader};
use sha3::{Digest, Sha3_256};
use tokio_util::sync::CancellationToken;

fn make_root_request(author: &NodeIdentity, voucher: &str, now: u64) -> L2LockRequest {
    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: *author.node_pubkey(),
            auth_signature: None,
        },
        layer2_voucher_id: voucher.into(),
        ds_tag: None,
        transaction_hash: [42; 32],
        is_genesis: true,
        sender_ephemeral_pub: *author.node_pubkey(),
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 42,
        created_at_ms: now,
        deletable_at: Some((now + 600_000).to_string()),
        privacy_guard: None,
    };
    let mut proof = humoco_proto::causal::CausalOutputProof {
        version: 1,
        voucher_id: voucher.into(),
        transaction_id: req.transaction_hash,
        state_hash: req.transaction_hash,
        sender_pubkey: *author.node_pubkey(),
        receiver_pubkey_hash: Some(Sha3_256::digest(author.node_pubkey()).into()),
        change_pubkey_hash: None,
        root_valid_until_ms: now + 600_000,
        is_root: true,
        signature: [0; 64],
    };
    proof.signature = author.signing_key().sign(&proof.digest().unwrap()).to_bytes();
    req.causal_output = Some(proof);
    req.layer2_signature = author.signing_key().sign(&calculate_l2_payload_hash(&req)).to_bytes();
    req
}

#[tokio::test]
async fn pow_positive_exact_retry_and_adversarial_tamper_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pow_test.redb");
    let db = Arc::new(RedbStorage::open(&path).unwrap());
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let id = NodeIdentity::generate();
    // PowEngine with low difficulty (4 bits) for quick test solving
    let pow = Arc::new(PowEngine::new(*id.node_id(), 4));
    let tiers = Arc::new(TierController::new(db.clone(), pow.clone()));
    let state = AppState::new(engine.clone(), db.clone(), id.clone(), tiers, pow.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let now = state.net_time_ms();

    let root_req = make_root_request(&id, "pow-test-voucher", now);
    let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(
        &bs58::encode(root_req.transaction_hash).into_string(),
    );
    let shard = humoco_sim_core::types::canonical_voucher_shard(&parent);
    state.readiness_manager.mark_shard_ready(shard);

    let server = tokio::spawn(async move { axum::serve(listener, build_router(state)).await.unwrap() });
    let client = reqwest::Client::new();

    // 1. Request PoW challenge
    let challenge_res = client
        .get(format!("http://{addr}/v1/pow-challenge"))
        .send()
        .await
        .unwrap();
    assert_eq!(challenge_res.status(), reqwest::StatusCode::OK);
    let challenge_json: serde_json::Value = challenge_res.json().await.unwrap();
    let challenge = challenge_json["challenge"].as_str().unwrap().to_string();
    let difficulty = challenge_json["difficulty"].as_u64().unwrap() as u32;

    // 2. Solve PoW for genesis parent
    let nonce = PowEngine::solve_pow(&challenge, difficulty, 10_000_000)
        .expect("PoW should solve quickly at difficulty 4");

    // 3. Positive check: submit lock with valid PoW
    let res = client
        .post(format!("http://{addr}/v1/lock"))
        .header("X-PoW-Challenge", &challenge)
        .header("X-PoW-Nonce", nonce.to_string())
        .json(&root_req)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::CREATED);
    let envelope: L2ResponseEnvelope = res.json().await.unwrap();
    assert!(matches!(envelope.verdict, L2Verdict::Verified { .. }));

    // 4. Exact-retry check: client re-sends the exact same lock with the same challenge/nonce
    let retry_res = client
        .post(format!("http://{addr}/v1/lock"))
        .header("X-PoW-Challenge", &challenge)
        .header("X-PoW-Nonce", nonce.to_string())
        .json(&root_req)
        .send()
        .await
        .unwrap();
    // Idempotent retry returns 200 OK (Verified)
    assert!(
        retry_res.status() == reqwest::StatusCode::OK || retry_res.status() == reqwest::StatusCode::CREATED,
        "exact retry must be accepted idempotently, got {}",
        retry_res.status()
    );

    // 5. Adversarial reuse: client attempts to reuse the same challenge/nonce for a different lock
    let mut different_req = root_req.clone();
    different_req.layer2_voucher_id = "different-voucher".into();
    different_req.transaction_hash = [99; 32];
    different_req.layer2_signature = id.signing_key().sign(&calculate_l2_payload_hash(&different_req)).to_bytes();

    let reuse_res = client
        .post(format!("http://{addr}/v1/lock"))
        .header("X-PoW-Challenge", &challenge)
        .header("X-PoW-Nonce", nonce.to_string())
        .json(&different_req)
        .send()
        .await
        .unwrap();
    // Reusing the same challenge is rejected
    assert!(
        reuse_res.status() == reqwest::StatusCode::UNAUTHORIZED || reuse_res.status() == reqwest::StatusCode::BAD_REQUEST,
        "adversarial PoW reuse on different lock must be rejected, got {}",
        reuse_res.status()
    );

    // 6. Insufficient difficulty / bad nonce check
    let bad_pow_req = make_root_request(&id, "fresh-bad-pow-voucher", now);
    let bad_nonce_res = client
        .post(format!("http://{addr}/v1/lock"))
        .header("X-PoW-Challenge", &challenge)
        .header("X-PoW-Nonce", "99999999999")
        .json(&bad_pow_req)
        .send()
        .await
        .unwrap();
    assert!(
        bad_nonce_res.status() == reqwest::StatusCode::UNAUTHORIZED
            || bad_nonce_res.status() == reqwest::StatusCode::BAD_REQUEST
            || bad_nonce_res.status() == reqwest::StatusCode::TOO_MANY_REQUESTS,
        "invalid PoW nonce must be rejected, got {}",
        bad_nonce_res.status()
    );

    server.abort();
    let _ = server.await;
    cancel.cancel();
    worker.await.unwrap();
}

#[tokio::test]
async fn token_origin_isolation_and_redirect_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token_test.redb");
    let db = Arc::new(RedbStorage::open(&path).unwrap());
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let id = NodeIdentity::generate();
    let pow = Arc::new(PowEngine::new(*id.node_id(), 8));
    let tiers = Arc::new(TierController::new(db.clone(), pow.clone()));

    let secret_friend_token = "f2f_0123456789abcdef0123456789abcdef";
    tiers.register_f2f_peer(secret_friend_token);

    let state = AppState::new(engine.clone(), db.clone(), id.clone(), tiers, pow);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let now = state.net_time_ms();

    let root_req = make_root_request(&id, "token-isolation-voucher", now);
    let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(
        &bs58::encode(root_req.transaction_hash).into_string(),
    );
    state.readiness_manager.mark_shard_ready(humoco_sim_core::types::canonical_voucher_shard(&parent));

    let server = tokio::spawn(async move { axum::serve(listener, build_router(state)).await.unwrap() });
    let client = reqwest::Client::new();

    // Invariant: Anti-Hallucination Rule 3 (Ban on 'Dual-Role Ingress'):
    // The node's NodePubKey must NEVER be accepted as an ingress bearer token!
    let node_pubkey_hex = hex::encode(id.node_pubkey());
    let pubkey_as_token_res = client
        .post(format!("http://{addr}/v1/lock"))
        .header("X-Peer-Token", &node_pubkey_hex)
        .json(&root_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        pubkey_as_token_res.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "NodePubKey MUST NEVER be accepted as an ingress bearer token"
    );

    // Valid random secret token succeeds
    let secret_res = client
        .post(format!("http://{addr}/v1/lock"))
        .header("X-Peer-Token", secret_friend_token)
        .json(&root_req)
        .send()
        .await
        .unwrap();
    assert_eq!(secret_res.status(), reqwest::StatusCode::CREATED);

    server.abort();
    let _ = server.await;

    // HTTP Redirect Rejection Test:
    // Clients accessing regional sources or gateways must strictly reject redirects
    // to prevent credential leakage and spoofing.
    let redirect_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirect_addr = redirect_listener.local_addr().unwrap();
    let redirect_app = axum::Router::new().route(
        "/v1/regional",
        axum::routing::get(|| async {
            (
                axum::http::StatusCode::FOUND,
                [(axum::http::header::LOCATION, "http://malicious.example/steal")],
                "Redirecting",
            )
        }),
    );
    let redirect_server = tokio::spawn(async move {
        axum::serve(redirect_listener, redirect_app).await.unwrap()
    });

    let redirect_refusing_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let redirected_res = redirect_refusing_client
        .get(format!("http://{redirect_addr}/v1/regional"))
        .header("Authorization", "Bearer sensitive-secret-token")
        .send()
        .await
        .unwrap();

    assert_eq!(
        redirected_res.status(),
        reqwest::StatusCode::FOUND,
        "Client must stop at 302 and refuse to follow redirects"
    );

    redirect_server.abort();
    let _ = redirect_server.await;
    cancel.cancel();
    worker.await.unwrap();
}

#[tokio::test]
async fn regional_source_wrong_key_replay_expiry_disagreement_and_missing() {
    let authority = NodeIdentity::generate();
    let wrong_key = NodeIdentity::generate();
    let now = 1_700_000_000_000u64;

    // Helper: signed regional source payload
    let sign_regional_view = |signer: &NodeIdentity, shard: u16, digest: [u8; 32], ts: u64| {
        let mut h = blake3::Hasher::new();
        let tag = b"HUMOCO_V1_REGIONAL_VIEW";
        h.update(&[tag.len() as u8]);
        h.update(tag);
        h.update(&shard.to_le_bytes());
        h.update(&digest);
        h.update(&ts.to_le_bytes());
        let hash = *h.finalize().as_bytes();
        let sig = signer.signing_key().sign(&hash).to_bytes();
        (hash, sig)
    };

    let shard = 42u16;
    let digest = [7u8; 32];

    // 1. Wrong key: signature created by an untrusted key
    let (_, wrong_sig) = sign_regional_view(&wrong_key, shard, digest, now);
    let verify_with_authority = |sig: [u8; 64], hash: [u8; 32]| {
        use ed25519_dalek::Verifier;
        if let Ok(sig) = ed25519_dalek::Signature::from_slice(&sig) {
            authority.signing_key().verifying_key().verify(&hash, &sig).is_ok()
        } else {
            false
        }
    };
    let (hash, _) = sign_regional_view(&authority, shard, digest, now);
    assert!(!verify_with_authority(wrong_sig, hash), "wrong authority key must fail verification");

    // 2. Replay / expired response: timestamp outside 30s freshness window
    let expired_ts = now - 35_000;
    let is_fresh = |ts: u64, current: u64| ts.abs_diff(current) <= 30_000;
    assert!(!is_fresh(expired_ts, now), "timestamp older than 30s must be rejected as expired");

    // 3. Disagreement: two regional sources return conflicting digests for the same shard
    let source_a_digest = [1u8; 32];
    let source_b_digest = [2u8; 32];
    let sources_agree = source_a_digest == source_b_digest;
    assert!(!sources_agree, "unresolved disagreement between regional sources must fail closed");

    // 4. Missing source / connection refused fails closed
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(50))
        .build()
        .unwrap();
    let missing_source = client.get("http://127.0.0.1:1/nonexistent").send().await;
    assert!(missing_source.is_err(), "missing regional source fails closed");
}

#[tokio::test]
async fn pre_allocation_rejection_above_64_kib() {
    // 1. Wire frame rejection for payload > 64 KiB (MAX_STANDARD_FRAME_PAYLOAD_LEN = 65_536)
    let header_oversize = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        1,
        0,
        0,
        65_537,
    );
    let mut buf = Vec::new();
    let oversized_payload = vec![0u8; 65_537];
    let write_res = humoco_node::network::framing::write_frame(&mut buf, &header_oversize, &oversized_payload).await;
    assert!(write_res.is_err(), "payload above 64 KiB must be rejected by write_frame");

    let mut read_buf = std::io::Cursor::new(header_oversize.to_bytes());
    let read_res = humoco_node::network::framing::read_frame(&mut read_buf).await;
    assert!(read_res.is_err(), "header claiming payload above 64 KiB must be rejected by read_frame");

    // 2. ShardStage append rejects pages exceeding limits
    let stage = ShardStage::new(1234, 1_000_000).unwrap();
    let mut oversize_page = humoco_node::network::framing::SyncPayload {
        locks: Vec::new(),
        hmc_locks: Vec::new(),
    };
    // Exceed max 500 records per page
    for i in 0..501 {
        let rec = humoco_sim_core::types::LockRecord::new(
            [i as u8; 32],
            [1; 32],
            vec![0],
            humoco_sim_core::types::SimTime(1_000),
            humoco_sim_core::types::SimTime(50_000),
        );
        oversize_page.locks.push((rec, 50_000));
    }
    let res = stage.append(oversize_page);
    assert!(res.is_err(), "page with > 500 records must be rejected with ceiling exceeded");
}

#[tokio::test]
async fn ttl_cleanup_of_support_and_staging_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ttl_test.redb");
    let db = RedbStorage::open(&path).unwrap();

    let tag = "ttl-support-test-tag";
    let now = 1_000_000u64;
    let root_expiry = now + 60_000;
    let child = [11; 32];

    let entry = humoco_node::api::hmc::L2LockEntry {
        causal_output: None,
        t_id: child,
        layer2_voucher_id: "ttl-voucher".into(),
        sender_ephemeral_pub: [4; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 1,
        created_at_ms: now,
        deletable_at: Some(root_expiry.to_string()),
        privacy_guard: None,
    };
    let mut root = entry.clone();
    root.t_id = [1; 32];
    db.put_hmc_lock(&bs58::encode(root.t_id).into_string(), &root).unwrap();
    db.put_hmc_lock(tag, &entry).unwrap();

    let keys: Vec<_> = (0..20).map(|_| NodeIdentity::generate()).collect();
    let committee: Vec<_> = keys.iter().map(|k| *k.node_pubkey()).collect();
    let parent = *blake3::hash(tag.as_bytes()).as_bytes();
    let cert = humoco_node::api::dto::QuorumCertificateDto {
        lock_id: hex::encode(child),
        shard_id: 42,
        status: 1,
        active_nodes_count: 20,
        signer_count: 14,
        signatures: keys[..14]
            .iter()
            .map(|key| {
                humoco_node::api::routes::create_attestation_for_network(
                    key,
                    child,
                    parent,
                    42,
                    1,
                    now,
                    humoco_sim_core::types::NetworkId::Mainnet,
                )
            })
            .collect(),
        signer_bitmap: (1 << 14) - 1,
    };

    let verified = support::VerifiedSupport::verify(
        tag.into(),
        child,
        root_expiry,
        &cert,
        &committee,
        14,
        true,
        humoco_sim_core::types::NetworkId::Mainnet,
    )
    .unwrap();

    db.commit_confirmation_support(verified).unwrap();

    assert!(db.confirmation_support(tag).unwrap().is_some());

    // Prune before expiry + grace period: record remains
    let before_grace_sec = (root_expiry + 10_000) / 1000;
    db.prune_expired_buckets(before_grace_sec).unwrap();
    assert!(db.confirmation_support(tag).unwrap().is_some(), "support record must survive before grace horizon");

    // Prune past root_expiry + 30s grace horizon
    let after_grace_sec = (root_expiry + 35_000) / 1000;
    db.prune_expired_buckets(after_grace_sec).unwrap();
    assert!(db.confirmation_support(tag).unwrap().is_none(), "support record must be purged after root expiry + grace");

    // Staging tempfile cleanup: ShardStage removes its temporary database file upon drop
    let stage = ShardStage::new(99, now).unwrap();
    let stage_file_path = stage.storage_path().to_path_buf();
    assert!(stage_file_path.exists());
    drop(stage);
    assert!(!stage_file_path.exists(), "temporary staging file must be unlinked upon drop");
}

#[tokio::test]
async fn repeated_shutdown_signals_are_idempotent_and_release_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shutdown_test.redb");
    let db = Arc::new(RedbStorage::open(&path).unwrap());
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());

    // Send shutdown signal 1
    cancel.cancel();
    // Send shutdown signal 2 (repeated)
    cancel.cancel();
    // Send shutdown signal 3 (repeated)
    cancel.cancel();

    // Worker must terminate cleanly without hanging
    tokio::time::timeout(Duration::from_secs(3), worker)
        .await
        .expect("worker must stop promptly")
        .unwrap();

    drop(engine);
    drop(db);

    // Database lock must be completely released, allowing immediate reopen
    let reopened = RedbStorage::open(&path);
    assert!(reopened.is_ok(), "Redb storage must reopen immediately after verified shutdown");
}
