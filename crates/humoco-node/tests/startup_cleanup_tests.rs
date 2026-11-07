//! Startup errors must release already-started operator, QUIC and storage resources.
use ed25519_dalek::{Signer, SigningKey};
use humoco_node::{
    api::{
        dto::QuorumCertificateDto,
        hmc::{
            calculate_l2_payload_hash, L2AuthPayload, L2LockEntry, L2LockRequest, L2Verdict,
        },
        routes::create_attestation_for_network,
    },
    config::NodeConfig,
    daemon::NodeDaemon,
    identity::NodeIdentity,
    storage::{IngressOrigin, RedbStorage},
};
use humoco_proto::causal::CausalOutputProof;
use humoco_sim_core::types::{canonical_voucher_shard, genesis_parent_bytes_from_tag, NetworkId};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn test_now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("valid timestamp")
            .as_millis(),
    )
    .expect("fits u64")
}

fn test_root(key: &SigningKey, seed: u8, now: u64) -> L2LockRequest {
    let sender = key.verifying_key().to_bytes();
    let transaction = [seed; 32];
    let expiry = (now + 600_000).to_string();
    let receiver: [u8; 32] = Sha3_256::digest(sender).into();
    let mut hash = Sha256::new();
    hash.update(transaction);
    hash.update(sender);
    hash.update(receiver);
    hash.update(expiry.as_bytes());
    let voucher = hex::encode(hash.finalize());
    let mut proof = CausalOutputProof {
        version: 1,
        voucher_id: voucher.clone(),
        transaction_id: transaction,
        state_hash: transaction,
        sender_pubkey: sender,
        receiver_pubkey_hash: Some(receiver),
        change_pubkey_hash: None,
        root_valid_until_ms: expiry.parse().expect("parse expiry"),
        is_root: true,
        signature: [0; 64],
    };
    proof.signature = key
        .sign(&proof.digest().expect("proof digest"))
        .to_bytes();
    let mut req = L2LockRequest {
        causal_output: Some(proof),
        auth: L2AuthPayload {
            ephemeral_pubkey: sender,
            auth_signature: None,
        },
        layer2_voucher_id: voucher,
        ds_tag: None,
        transaction_hash: transaction,
        is_genesis: true,
        sender_ephemeral_pub: sender,
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: u128::from(now),
        created_at_ms: now,
        deletable_at: Some(expiry),
        privacy_guard: None,
    };
    req.layer2_signature = key.sign(&calculate_l2_payload_hash(&req)).to_bytes();
    req
}

fn test_spend(root: &L2LockRequest, seed: u8, key: &SigningKey) -> L2LockRequest {
    let mut req = root.clone();
    let mut hash = Sha3_256::new();
    hash.update(32u32.to_le_bytes());
    hash.update(root.transaction_hash);
    hash.update(32u32.to_le_bytes());
    hash.update(key.verifying_key().as_bytes());
    req.ds_tag = Some(bs58::encode(hash.finalize()).into_string());
    req.transaction_hash = [seed; 32];
    req.is_genesis = false;
    req.deletable_at = None;
    let proof = req.causal_output.as_mut().expect("root proof missing");
    proof.transaction_id = req.transaction_hash;
    proof.state_hash = req.transaction_hash;
    proof.is_root = false;
    proof.signature = key
        .sign(&proof.digest().expect("proof digest"))
        .to_bytes();
    req.layer2_signature = key.sign(&calculate_l2_payload_hash(&req)).to_bytes();
    req
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_bind_failure_releases_operator_and_database_in_the_same_runtime() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let occupied_public = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("occupied public port");
    let reservation = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .expect("reservation socket");
    reservation
        .set_reuse_address(true)
        .expect("set reuse_address");
    #[cfg(unix)]
    let _ = reservation.set_reuse_port(true);
    reservation
        .bind(
            &"127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
        )
        .expect("reservation bind");
    let operator_address = reservation
        .local_addr()
        .expect("operator address")
        .as_socket()
        .expect("as_socket");
    drop(reservation);
    let mut config = NodeConfig::default();
    config.network.rpc_listen_addr = occupied_public.local_addr().expect("public address");
    config.network.p2p_listen_addr = "127.0.0.1:0".parse().expect("QUIC address");
    config.network.operator_listen_addr = Some(operator_address);
    config.network.shutdown_timeout_secs = 3;
    config.storage.data_dir = temporary.path().join("data");
    config.network.control_socket = Some(temporary.path().join("control.sock"));
    let database_path = config.storage.data_dir.join("humoco.redb");
    let cancel = CancellationToken::new();
    let daemon =
        NodeDaemon::with_cancel_token(config.clone(), NodeIdentity::generate(), cancel.clone());

    let result = tokio::time::timeout(Duration::from_secs(5), daemon.run())
        .await
        .expect("startup failure must return within its shutdown bound");
    assert!(
        result.is_err(),
        "occupied public listener must fail startup"
    );
    assert!(
        cancel.is_cancelled(),
        "every startup error cancels the per-run producers"
    );
    assert!(
        tokio::net::TcpStream::connect(operator_address)
            .await
            .is_err(),
        "operator listener released before run returns"
    );
    let database = RedbStorage::open(&database_path)
        .expect("all task-held database handles released before run returns");
    drop(database);
    let completion = std::fs::read(config.control_socket_path().with_extension("stop.json"))
        .expect("truthful completion record");
    let completion: serde_json::Value =
        serde_json::from_slice(&completion).expect("completion JSON");
    assert_eq!(
        completion["clean"], false,
        "failed startup must never advertise clean success"
    );
    // The Tokio runtime and the original failed daemon object remain alive here.
    assert!(occupied_public.local_addr().is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn occupied_quic_port_drains_the_earlier_persistence_worker() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let occupied = std::net::UdpSocket::bind("127.0.0.1:0").expect("occupied QUIC port");
    let mut config = NodeConfig::default();
    config.network.p2p_listen_addr = occupied.local_addr().expect("QUIC address");
    config.network.rpc_listen_addr = "127.0.0.1:0".parse().expect("HTTP address");
    config.network.shutdown_timeout_secs = 3;
    config.storage.data_dir = temporary.path().join("data");
    config.network.control_socket = Some(temporary.path().join("control.sock"));
    let database_path = config.storage.data_dir.join("humoco.redb");
    let daemon = NodeDaemon::new(config, NodeIdentity::generate());
    let result = tokio::time::timeout(Duration::from_secs(5), daemon.run())
        .await
        .expect("early startup failure bounded");
    assert!(result.is_err());
    let database = RedbStorage::open(&database_path)
        .expect("early startup worker releases redb without runtime shutdown");
    drop(database);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_shutdown_waits_for_timed_out_support_continuation_and_releases_database() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let mut config = NodeConfig::default();
    config.network.p2p_listen_addr = "127.0.0.1:0".parse().expect("QUIC address");
    config.network.rpc_listen_addr = "127.0.0.1:0".parse().expect("HTTP address");
    config.network.shutdown_timeout_secs = 3;
    config.storage.data_dir = temporary.path().join("data");
    config.network.control_socket = Some(temporary.path().join("control.sock"));
    let database_path = config.storage.data_dir.join("humoco.redb");

    let cancel = CancellationToken::new();
    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
    let (engine_tx, engine_rx) = tokio::sync::oneshot::channel();

    let identity = NodeIdentity::generate();
    let daemon = NodeDaemon::with_bound_sender(config.clone(), identity.clone(), cancel.clone(), bound_tx)
        .with_engine_sender(engine_tx);

    let daemon_handle = tokio::spawn(async move { daemon.run().await });
    let _bound = bound_rx.await.expect("daemon bound");
    let engine = engine_rx.await.expect("engine handle");

    // Ingress root lock and spend lock in engine
    let now = test_now_ms();
    let key = SigningKey::from_bytes(&[42; 32]);
    let root_req = test_root(&key, 0x61, now);
    let root_tag = bs58::encode(root_req.transaction_hash).into_string();
    let (v_root, _) = engine
        .ingress_hmc_lock_durable(
            root_tag.clone(),
            L2LockEntry::from(&root_req),
            IngressOrigin::ClientApi,
            Some(now),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_root, L2Verdict::Verified { .. }));

    let spend_req = test_spend(&root_req, 0x62, &key);
    let spend_tag = spend_req.ds_tag.clone().expect("ds_tag");
    let (v_spend, _) = engine
        .ingress_hmc_lock_durable(
            spend_tag.clone(),
            L2LockEntry::from(&spend_req),
            IngressOrigin::ClientApi,
            Some(now),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_spend, L2Verdict::Verified { .. }));

    // Prepare valid provisional support certificate (status = 0)
    let parent = *blake3::hash(spend_tag.as_bytes()).as_bytes();
    let genesis_parent = genesis_parent_bytes_from_tag(&root_tag);
    let shard = canonical_voucher_shard(&genesis_parent);
    let att = create_attestation_for_network(
        &identity,
        spend_req.transaction_hash,
        parent,
        shard,
        0,
        now,
        NetworkId::Mainnet,
    );
    let cert = QuorumCertificateDto {
        lock_id: hex::encode(spend_req.transaction_hash),
        shard_id: shard,
        status: 0,
        active_nodes_count: 1,
        signer_count: 1,
        signatures: vec![att],
        signer_bitmap: 1,
    };

    // Hold blocking redb write transaction to freeze support commit
    let blocking_txn = engine.db.raw_database_for_test().begin_write().expect("begin write");

    // Persist support with tight deadline (15ms)
    let res = engine
        .persist_confirmation_support_with_deadline(
            spend_tag.clone(),
            cert,
            &identity,
            now,
            NetworkId::Mainnet,
            None,
            Some(tokio::time::Instant::now() + Duration::from_millis(15)),
        )
        .await;
    assert!(res.is_err(), "Caller deadline must expire while redb writer is blocked");

    // Initiate daemon shutdown
    cancel.cancel();

    // Release blocking transaction after 100ms (well within 3s shutdown budget)
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(blocking_txn);
    });

    // Daemon run must wait for continuation to complete and then return Ok(())
    let run_result = tokio::time::timeout(Duration::from_secs(5), daemon_handle)
        .await
        .expect("join handle")
        .expect("run result");
    assert!(run_result.is_ok(), "daemon shutdown must complete cleanly: {run_result:?}");

    // Completion record must report clean = true
    let completion_raw = std::fs::read(config.control_socket_path().with_extension("stop.json"))
        .expect("stop.json");
    let completion: serde_json::Value = serde_json::from_slice(&completion_raw).expect("parse stop.json");
    assert_eq!(completion["clean"], true, "daemon shutdown must report clean completion");

    // Drop the test's own clone of engine so only daemon/task-held handles are being evaluated
    drop(engine);

    // Immediate redb::Database::open MUST succeed right after clean shutdown completes!
    let reopened = redb::Database::open(&database_path)
        .expect("immediate redb::Database::open must succeed right after clean shutdown");
    drop(reopened);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_support_continuation_exceeding_shutdown_deadline_reports_incomplete_shutdown() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let mut config = NodeConfig::default();
    config.network.p2p_listen_addr = "127.0.0.1:0".parse().expect("QUIC address");
    config.network.rpc_listen_addr = "127.0.0.1:0".parse().expect("HTTP address");
    config.network.shutdown_timeout_secs = 1; // 1 second shutdown budget
    config.storage.data_dir = temporary.path().join("data");
    config.network.control_socket = Some(temporary.path().join("control.sock"));

    let cancel = CancellationToken::new();
    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
    let (engine_tx, engine_rx) = tokio::sync::oneshot::channel();

    let identity = NodeIdentity::generate();
    let daemon = NodeDaemon::with_bound_sender(config.clone(), identity.clone(), cancel.clone(), bound_tx)
        .with_engine_sender(engine_tx);

    let daemon_handle = tokio::spawn(async move { daemon.run().await });
    let _bound = bound_rx.await.expect("daemon bound");
    let engine = engine_rx.await.expect("engine handle");

    // Ingress root lock and spend lock in engine
    let now = test_now_ms();
    let key = SigningKey::from_bytes(&[42; 32]);
    let root_req = test_root(&key, 0x71, now);
    let root_tag = bs58::encode(root_req.transaction_hash).into_string();
    let (v_root, _) = engine
        .ingress_hmc_lock_durable(
            root_tag.clone(),
            L2LockEntry::from(&root_req),
            IngressOrigin::ClientApi,
            Some(now),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_root, L2Verdict::Verified { .. }));

    let spend_req = test_spend(&root_req, 0x72, &key);
    let spend_tag = spend_req.ds_tag.clone().expect("ds_tag");
    let (v_spend, _) = engine
        .ingress_hmc_lock_durable(
            spend_tag.clone(),
            L2LockEntry::from(&spend_req),
            IngressOrigin::ClientApi,
            Some(now),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_spend, L2Verdict::Verified { .. }));

    // Prepare valid provisional support certificate (status = 0)
    let parent = *blake3::hash(spend_tag.as_bytes()).as_bytes();
    let genesis_parent = genesis_parent_bytes_from_tag(&root_tag);
    let shard = canonical_voucher_shard(&genesis_parent);
    let att = create_attestation_for_network(
        &identity,
        spend_req.transaction_hash,
        parent,
        shard,
        0,
        now,
        NetworkId::Mainnet,
    );
    let cert = QuorumCertificateDto {
        lock_id: hex::encode(spend_req.transaction_hash),
        shard_id: shard,
        status: 0,
        active_nodes_count: 1,
        signer_count: 1,
        signatures: vec![att],
        signer_bitmap: 1,
    };

    // Hold blocking redb write transaction to freeze support commit
    let blocking_txn = engine.db.raw_database_for_test().begin_write().expect("begin write");

    // Persist support with tight deadline (15ms)
    let res = engine
        .persist_confirmation_support_with_deadline(
            spend_tag.clone(),
            cert,
            &identity,
            now,
            NetworkId::Mainnet,
            None,
            Some(tokio::time::Instant::now() + Duration::from_millis(15)),
        )
        .await;
    assert!(res.is_err(), "Caller deadline must expire while redb writer is blocked");

    // Initiate daemon shutdown
    cancel.cancel();

    // Keep blocking transaction held for 1500ms (exceeding the 1s shutdown budget!)
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        drop(blocking_txn);
    });

    // Daemon run must time out and return an Err
    let run_result = tokio::time::timeout(Duration::from_secs(4), daemon_handle)
        .await
        .expect("join handle")
        .expect("run result");
    assert!(run_result.is_err(), "daemon shutdown must fail when budget exceeded: {run_result:?}");
    let err_msg = format!("{:?}", run_result.unwrap_err());
    assert!(
        err_msg.contains("shutdown deadline exceeded"),
        "error message must reflect shutdown deadline exceeded: {err_msg}"
    );

    // Completion record must report clean = false (truthful incomplete reporting)
    let completion_raw = std::fs::read(config.control_socket_path().with_extension("stop.json"))
        .expect("stop.json");
    let completion: serde_json::Value = serde_json::from_slice(&completion_raw).expect("parse stop.json");
    assert_eq!(
        completion["clean"], false,
        "shutdown exceeding deadline must report clean = false"
    );
}
