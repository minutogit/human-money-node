//! Real HTTP and QUIC regression for exact causality and durable valid prefixes.
use ed25519_dalek::Signer;
use humoco_node::{
    api::{build_router, hmc::*, AppState},
    daemon::ShardReadinessManager,
    identity::NodeIdentity,
    ingress::{PowEngine, TierController},
    network::{
        framing::LockWirePayload, DefaultRequestHandler, NodeRequestHandler, PeerManager,
        QuicTransport,
    },
    storage::{DualTierEngine, RedbStorage},
};
use humoco_sim_core::wire::{MsgType, WireHeader, FLAG_UNAUTHORIZED};
use sha3::{Digest, Sha3_256};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

fn hop(
    key: &NodeIdentity,
    voucher: &str,
    id: u8,
    prev: Option<[u8; 32]>,
    now: u64,
) -> L2LockRequest {
    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: *key.node_pubkey(),
            auth_signature: None,
        },
        layer2_voucher_id: voucher.into(),
        ds_tag: prev.map(|p| {
            let mut h = Sha3_256::new();
            h.update(32u32.to_le_bytes());
            h.update(p);
            h.update(32u32.to_le_bytes());
            h.update(key.node_pubkey());
            bs58::encode(h.finalize()).into_string()
        }),
        transaction_hash: [id; 32],
        is_genesis: prev.is_none(),
        sender_ephemeral_pub: *key.node_pubkey(),
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: u128::from(id),
        created_at_ms: now,
        deletable_at: prev.is_none().then(|| (now + 600_000).to_string()),
        privacy_guard: None,
    };
    let mut proof = humoco_proto::causal::CausalOutputProof {
        version: 1,
        voucher_id: voucher.into(),
        transaction_id: req.transaction_hash,
        state_hash: req.transaction_hash,
        sender_pubkey: *key.node_pubkey(),
        receiver_pubkey_hash: Some(Sha3_256::digest(key.node_pubkey()).into()),
        change_pubkey_hash: None,
        root_valid_until_ms: now + 600_000,
        is_root: req.is_genesis,
        signature: [0; 64],
    };
    proof.signature = key.signing_key().sign(&proof.digest().unwrap()).to_bytes();
    req.causal_output = Some(proof);
    req.layer2_signature = key
        .signing_key()
        .sign(&calculate_l2_payload_hash(&req))
        .to_bytes();
    req
}
fn chain(key: &NodeIdentity, voucher: &str, now: u64, failure: usize) -> L2ChainLockRequest {
    let a = hop(key, voucher, 1, None, now);
    let b = hop(key, voucher, 2, Some(a.transaction_hash), now);
    let mut c = hop(key, voucher, 3, Some(b.transaction_hash), now);
    match failure {
        0 => {}
        1 => {
            c.ds_tag = Some(bs58::encode([99; 32]).into_string());
        }
        2 => {
            c.created_at_ms = now - 30_001;
        }
        3 => {
            c.layer2_signature = [0; 64];
        }
        _ => unreachable!(),
    }
    if failure == 1 || failure == 2 {
        c.layer2_signature = key
            .signing_key()
            .sign(&calculate_l2_payload_hash(&c))
            .to_bytes();
    }
    L2ChainLockRequest {
        auth: a.auth.clone(),
        layer2_voucher_id: voucher.into(),
        chain: vec![a, b, c],
    }
}
fn assert_prefix(db: &RedbStorage, chain: &L2ChainLockRequest, complete: bool) {
    let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&bs58::encode(chain.chain[0].transaction_hash).into_string());
    let shard = humoco_sim_core::types::canonical_voucher_shard(&parent);
    let records = db.committed_shard_records(shard, chain.chain[0].created_at_ms).unwrap();
    assert_eq!(records.len(), if complete { 2 } else { 1 }, "root proof is not a spend; all SST slots belong to the root shard");
    assert!(db.committed_shard_records(shard.wrapping_add(1), chain.chain[0].created_at_ms).unwrap().is_empty());
    for (i, req) in chain.chain.iter().enumerate() {
        let tag = if req.is_genesis {
            bs58::encode(req.transaction_hash).into_string()
        } else {
            req.ds_tag.clone().unwrap()
        };
        let stored = db.get_hmc_lock(&tag).unwrap();
        if req.is_genesis {
            assert!(
                stored.is_none(),
                "genesis must never occupy a collision slot"
            );
            assert_eq!(
                db.voucher_root(&req.layer2_voucher_id)
                    .unwrap()
                    .unwrap()
                    .t_id,
                req.transaction_hash
            );
            continue;
        }
        if i < 2 || complete {
            assert_eq!(stored.unwrap().t_id, req.transaction_hash);
        } else {
            assert!(stored.is_none(), "bad suffix must never persist");
        }
    }
}

#[tokio::test]
async fn http_bad_suffix_retains_exact_durable_prefix_after_restart() {
    for failure in 0..=3 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.redb");
        let db = Arc::new(RedbStorage::open(&path).unwrap());
        let cancel = CancellationToken::new();
        let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
        let id = NodeIdentity::generate();
        let pow = Arc::new(PowEngine::new(*id.node_id(), 8));
        let tiers = Arc::new(TierController::new(db.clone(), pow.clone()));
        tiers.register_f2f_peer("prefix-test");
        let state = AppState::new(engine.clone(), db.clone(), id.clone(), tiers, pow);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let now = state.net_time_ms();
        let req = chain(&id, &format!("prefix-{failure}"), now, failure);
        // This fixture starts from a prepared source; recovery activation is
        // covered separately. Never bypass readiness in production collectors.
        let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(
            &bs58::encode(req.chain[0].transaction_hash).into_string(),
        );
        state
            .readiness_manager
            .mark_shard_ready(humoco_sim_core::types::canonical_voucher_shard(&parent));
        let server =
            tokio::spawn(async move { axum::serve(listener, build_router(state)).await.unwrap() });
        let res = reqwest::Client::new()
            .post(format!("http://{addr}/v1/lock/chain"))
            .header("X-Peer-Token", "prefix-test")
            .json(&req)
            .send()
            .await
            .unwrap();
        let status = res.status();
        let envelope: L2ResponseEnvelope = res.json().await.unwrap();
        if failure == 0 {
            assert_eq!(
                status,
                reqwest::StatusCode::CREATED,
                "{:?}",
                envelope.verdict
            );
            assert!(matches!(envelope.verdict, L2Verdict::Verified { .. }));
        } else {
            assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
            assert!(
                matches!(envelope.verdict,L2Verdict::Rejected{ref reason} if reason.contains("step 2")),
                "{:?}",
                envelope.verdict
            );
        }
        if failure == 0 {
            let mut alternate = req.clone();
            alternate.chain.truncate(2);
            let spend = &mut alternate.chain[1];
            spend.transaction_hash = [88; 32];
            let proof = spend.causal_output.as_mut().unwrap();
            proof.transaction_id = spend.transaction_hash;
            proof.state_hash = spend.transaction_hash;
            proof.signature = id.signing_key().sign(&proof.digest().unwrap()).to_bytes();
            spend.layer2_signature = id.signing_key().sign(&calculate_l2_payload_hash(spend)).to_bytes();
            let response = reqwest::Client::new().post(format!("http://{addr}/v1/lock/chain"))
                .header("X-Peer-Token", "prefix-test").json(&alternate).send().await.unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::CONFLICT, "a second genuine spend must collide");
        }
        assert_prefix(&db, &req, failure == 0);
        server.abort();
        let _ = server.await;
        cancel.cancel();
        worker.await.unwrap();
        drop(engine);
        drop(db);
        let reopened = RedbStorage::open(&path).unwrap();
        assert_prefix(&reopened, &req, failure == 0);
    }
}

#[tokio::test]
async fn quic_bad_suffix_reports_step_and_preserves_committed_prefix() {
    for failure in 1..=3 {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(RedbStorage::open(&dir.path().join("node.redb")).unwrap());
        let stop = CancellationToken::new();
        let (engine, worker) = DualTierEngine::new_with_token(db.clone(), stop.clone());
        let server = NodeIdentity::generate();
        let client = NodeIdentity::generate();
        let server_pm = Arc::new(PeerManager::with_f2f(vec![], vec![*client.node_pubkey()]));
        let client_pm = Arc::new(PeerManager::with_f2f(vec![], vec![*server.node_pubkey()]));
        let now = server_pm.net_time_ms();
        let req = chain(&client, &format!("wire-prefix-{failure}"), now, failure);
        let shard = humoco_sim_core::types::canonical_voucher_shard(
            &humoco_sim_core::types::genesis_parent_bytes_from_tag(
                &bs58::encode(req.chain[0].transaction_hash).into_string(),
            ),
        );
        let ready = Arc::new(ShardReadinessManager::new());
        ready.mark_shard_ready(shard);
        // Prepared source fixture: this verifies request semantics, not recovery activation.
        let handler = Arc::new(
            NodeRequestHandler::new(engine.clone(), db.clone(), server.clone())
                .with_readiness_manager(ready),
        );
        let server_net = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            &server,
            server_pm.clone(),
            handler,
            stop.clone(),
        )
        .unwrap();
        let client_net = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            &client,
            client_pm.clone(),
            Arc::new(DefaultRequestHandler),
            stop.clone(),
        )
        .unwrap();
        server_pm
            .register_f2f_friend(
                *client.node_pubkey(),
                Some(client_net.local_addr().unwrap()),
            )
            .await;
        client_pm
            .register_f2f_friend(
                *server.node_pubkey(),
                Some(server_net.local_addr().unwrap()),
            )
            .await;
        server_net.spawn_accept_loop();
        client_net.spawn_accept_loop();
        let conn = client_net
            .connect_peer(server_net.local_addr().unwrap())
            .await
            .unwrap();
        let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(600) * 3;
        let last = req.chain.last().unwrap().clone();
        let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
            client.node_pubkey(),
            0,
            0,
            now,
            0,
            0,
            footprint,
            false,
            &last.transaction_hash,
        );
        let wire = LockWirePayload::Hmc {
            req: last,
            chain: Some(req.clone()),
            root_valid_until: now + 600_000,
            epoch_day: 0,
            epoch_seq: 0,
            cumulative_micro_byte_years: 0,
            prev_day_final_bytes: 0,
            current_anl_24h: 0,
            declared_write_ema_micro_bj: 0,
            declared_read_ema_credits: 0,
            sender_pubkey: *client.node_pubkey(),
            sender_signature: client.signing_key().sign(&digest).to_bytes(),
            timestamp_ms: now,
        };
        let bytes = bincode::serialize(&wire).unwrap();
        let header = WireHeader::new(
            MsgType::LockVerifyRequest as u16,
            1,
            0,
            0,
            bytes.len() as u32,
        );
        let (reply, body) = client_net
            .send_request(&conn, &header, &bytes)
            .await
            .unwrap();
        assert_ne!(reply.flags & FLAG_UNAUTHORIZED, 0);
        let verdict: L2Verdict = serde_json::from_slice(&body).unwrap();
        assert!(
            matches!(verdict,L2Verdict::Rejected{ref reason} if reason.contains("step 2")),
            "{verdict:?}"
        );
        assert_prefix(&db, &req, false);
        stop.cancel();
        worker.await.unwrap();
    }
}

#[test]
fn receiver_and_change_consume_independent_sst_slots_and_sidecars_are_authenticated() {
    let author = NodeIdentity::generate();
    let receiver = NodeIdentity::generate();
    let change = NodeIdentity::generate();
    let now = 1_800_000_000_000;
    let mut root = hop(&author, "split-output", 11, None, now);
    let proof = root.causal_output.as_mut().unwrap();
    proof.receiver_pubkey_hash = Some(Sha3_256::digest(receiver.node_pubkey()).into());
    proof.change_pubkey_hash = Some(Sha3_256::digest(change.node_pubkey()).into());
    proof.signature = author
        .signing_key()
        .sign(&proof.digest().unwrap())
        .to_bytes();
    let receive_spend = hop(
        &receiver,
        "split-output",
        12,
        Some(root.transaction_hash),
        now,
    );
    let change_spend = hop(
        &change,
        "split-output",
        13,
        Some(root.transaction_hash),
        now,
    );
    assert_ne!(
        receive_spend.ds_tag, change_spend.ds_tag,
        "independent split branches must not collide"
    );
    let make = |next| L2ChainLockRequest {
        auth: root.auth.clone(),
        layer2_voucher_id: "split-output".into(),
        chain: vec![root.clone(), next],
    };
    assert!(DualTierEngine::verify_chain_causality(&make(receive_spend.clone())).is_ok());
    assert!(DualTierEngine::verify_chain_causality(&make(change_spend)).is_ok());
    let rogue = NodeIdentity::generate();
    assert!(DualTierEngine::verify_chain_causality(&make(hop(
        &rogue,
        "split-output",
        14,
        Some(root.transaction_hash),
        now
    )))
    .is_err());
    let mut forged = make(receive_spend);
    forged.chain[0].causal_output.as_mut().unwrap().state_hash = [99; 32];
    assert!(DualTierEngine::verify_chain_causality(&forged).is_err());
}
