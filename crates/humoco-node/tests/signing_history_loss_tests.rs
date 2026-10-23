//! Real F2F QUIC delivery of first-party signing-history rollback evidence.
use humoco_node::error::NodeError;
use humoco_node::network::{
    framing::{HeartbeatWirePayload, SigningCheckpoint},
    transport::BoxFuture,
};
use humoco_node::{
    identity::NodeIdentity,
    network::{
        DefaultRequestHandler, NodeRequestHandler, PeerManager, QuicTransport, RequestHandler,
    },
    storage::{DualTierEngine, RedbStorage},
};
use humoco_sim_core::{
    types::{LockRecord, SimTime},
    wire::{MsgType, WireHeader},
};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

struct Observed {
    handler: NodeRequestHandler,
    completed: tokio::sync::mpsc::Sender<()>,
}
impl RequestHandler for Observed {
    fn handle_unidirectional_authenticated(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
        peer: Option<[u8; 32]>,
    ) -> BoxFuture<Result<(), NodeError>> {
        let handler = self.handler.clone();
        let completed = self.completed.clone();
        Box::pin(async move {
            handler
                .handle_unidirectional_authenticated(header, payload, peer)
                .await?;
            let _ = completed.send(()).await;
            Ok(())
        })
    }
}

#[tokio::test]
async fn real_quic_checkpoint_detects_restore_but_rejects_framing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("humoco_node=debug")
        .with_test_writer()
        .try_init();
    let dir = tempfile::tempdir().unwrap();
    let own = NodeIdentity::generate();
    let reporter = NodeIdentity::generate();
    let backup = dir.path().join("old.redb");
    let checkpoint = {
        let db = Arc::new(RedbStorage::open(&dir.path().join("source.redb")).unwrap());
        let record = |parent| {
            LockRecord::new(
                [parent; 32],
                [2; 32],
                vec![3],
                SimTime(1_000),
                SimTime(50_000),
            )
        };
        db.commit_original_record_approval(&record(1), 50_000, own.node_pubkey(), b"first", 0)
            .unwrap();
        db.create_backup(&backup).unwrap();
        db.commit_original_record_approval(&record(2), 50_000, own.node_pubkey(), b"second", 0)
            .unwrap();
        let (engine, worker) = DualTierEngine::new(db.clone());
        let handler = NodeRequestHandler::new(engine.clone(), db, own.clone());
        let state = handler.signing_checkpoint().await.unwrap().unwrap();
        drop(handler);
        drop(engine);
        worker.await.unwrap();
        state
    };
    let storage = Arc::new(RedbStorage::open(&backup).unwrap());
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(storage.clone(), cancel.clone());
    let pm = Arc::new(PeerManager::new(Vec::new()));
    let handler = NodeRequestHandler::with_peer_manager(
        engine.clone(),
        storage.clone(),
        own.clone(),
        pm.clone(),
    );
    let intact_checkpoint = handler.signing_checkpoint().await.unwrap().unwrap();
    let readiness = handler.readiness_manager.clone();
    readiness.mark_shard_ready(42);
    let (completed, mut observed) = tokio::sync::mpsc::channel(8);
    let server = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &own,
        pm.clone(),
        Arc::new(Observed { handler, completed }),
        cancel.clone(),
    )
    .unwrap();
    server.spawn_accept_loop();
    let client_pm = Arc::new(PeerManager::new(Vec::new()));
    let client = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &reporter,
        client_pm.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    client.spawn_accept_loop();
    pm.register_f2f_friend(*reporter.node_pubkey(), Some(client.local_addr().unwrap()))
        .await;
    client_pm
        .register_f2f_friend(*own.node_pubkey(), Some(server.local_addr().unwrap()))
        .await;
    let connection = client
        .connect_peer(server.local_addr().unwrap())
        .await
        .unwrap();
    let mut forged = checkpoint.clone();
    forged.generation += 1;
    let wrong_key =
        SigningCheckpoint::signed(&reporter, 0, checkpoint.generation, checkpoint.fingerprint);
    let wrong_network =
        SigningCheckpoint::signed(&own, 1, checkpoint.generation, checkpoint.fingerprint);
    let heartbeat_time = pm.net_time_ms();
    for (index, (evidence, corrupt)) in [
        (forged, false),
        (wrong_key, false),
        (wrong_network, false),
        (intact_checkpoint, false),
        (checkpoint, true),
    ]
    .into_iter()
    .enumerate()
    {
        let hb = HeartbeatWirePayload {
            node_id: *reporter.node_pubkey(),
            addr: client.local_addr().unwrap(),
            timestamp_ms: heartbeat_time + index as u64,
            declared_write_ema_micro_bj: 0,
            declared_read_ema_credits: 0,
            signature: [0; 64],
            supported_suites_mask: 0,
            piggyback_observations: Vec::new(),
            pow_nonce: 0,
            hrw_routing_id: *reporter.node_pubkey(),
            ticket_epoch_t0: 0,
            ttl: 16,
            signing_checkpoint: Some(evidence),
        };
        let bytes = bincode::serialize(&hb).unwrap();
        let header = WireHeader::new(
            MsgType::Heartbeat as u16,
            index as u64 + 1,
            0,
            0,
            bytes.len() as u32,
        );
        client
            .send_unidirectional(&connection, &header, &bytes)
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), observed.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            !storage.is_signing_history_healthy(),
            corrupt,
            "wire case {index}"
        );
        assert_eq!(!engine.is_signing_healthy(), corrupt);
        assert_eq!(readiness.is_shard_ready(42), !corrupt);
        assert!(
            !engine.is_node_banned(own.node_pubkey()).await,
            "local loss is not a network fraud sanction"
        );
    }
    let record = LockRecord::new([3; 32], [2; 32], vec![3], SimTime(1_000), SimTime(50_000));
    assert!(storage
        .commit_original_record_approval(&record, 50_000, own.node_pubkey(), b"unsafe", 0)
        .is_err());
    let corrupt_backup = dir.path().join("corrupt-backup.redb");
    storage.create_backup(&corrupt_backup).unwrap();
    assert!(!RedbStorage::open(&corrupt_backup)
        .unwrap()
        .is_signing_history_healthy());
    // Corruption is visible to the operator over the real UNIX control socket.
    let socket = dir.path().join("control.sock");
    let control = humoco_node::control::ControlServer::new(
        socket.clone(),
        storage.clone(),
        engine.clone(),
        pm,
        own,
        dir.path().to_path_buf(),
        cancel.clone(),
    );
    let control_task = tokio::spawn(async move {
        control.run().await.unwrap();
    });
    let control_client = humoco_node::control::ControlClient::new(socket);
    let status = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let Ok(status) = control_client.get_status().await {
                break status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        status,
        humoco_node::control::ControlResponse::Status {
            signing_history_corrupt: true,
            ..
        }
    ));
    cancel.cancel();
    server.close();
    client.close();
    control_task.await.unwrap();
    worker.await.unwrap();
}
