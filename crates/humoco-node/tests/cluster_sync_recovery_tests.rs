//! Wire-level immutable snapshot and resource-ceiling regressions.
use humoco_node::{
    identity::NodeIdentity,
    network::{DefaultRequestHandler, NodeRequestHandler, PeerManager, QuicTransport},
    storage::{DualTierEngine, RedbStorage},
};
use humoco_sim_core::{
    types::{LockRecord, SimTime},
    wire::{MsgType, WireHeader},
};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn fixed_snapshot_cursor_survives_concurrent_insert_delete_and_rejects_foreign_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&dir.path().join("node.redb")).unwrap());
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let source = NodeIdentity::generate();
    let reader = NodeIdentity::generate();
    let outsider = NodeIdentity::generate();
    let source_pm = Arc::new(PeerManager::with_f2f(
        vec![],
        vec![*reader.node_pubkey(), *outsider.node_pubkey()],
    ));
    let reader_pm = Arc::new(PeerManager::with_f2f(vec![], vec![*source.node_pubkey()]));
    let other_pm = Arc::new(PeerManager::with_f2f(vec![], vec![*source.node_pubkey()]));
    let source_net = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &source,
        source_pm.clone(),
        Arc::new(NodeRequestHandler::new(engine, db.clone(), source.clone())),
        cancel.clone(),
    )
    .unwrap();
    let reader_net = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &reader,
        reader_pm.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    let other_net = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &outsider,
        other_pm.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    for (key, addr) in [
        (*reader.node_pubkey(), reader_net.local_addr().unwrap()),
        (*outsider.node_pubkey(), other_net.local_addr().unwrap()),
    ] {
        source_pm.register_f2f_friend(key, Some(addr)).await;
    }
    for pm in [&reader_pm, &other_pm] {
        pm.register_f2f_friend(
            *source.node_pubkey(),
            Some(source_net.local_addr().unwrap()),
        )
        .await;
    }
    source_net.spawn_accept_loop();
    reader_net.spawn_accept_loop();
    other_net.spawn_accept_loop();
    let conn = reader_net
        .connect_peer(source_net.local_addr().unwrap())
        .await
        .unwrap();
    let other = other_net
        .connect_peer(source_net.local_addr().unwrap())
        .await
        .unwrap();
    let record =
        |i: u8| LockRecord::new([i; 32], [8; 32], vec![i], SimTime(1_000), SimTime(50_000));
    for i in 1..=3 {
        db.put_lock(&record(i), 50_000).unwrap();
    }
    let first = reader_net
        .request_active_sync_page(&conn, 1, 0, 1)
        .await
        .unwrap();
    assert_eq!(first.payload.locks[0].0.parent_lock, [1; 32]);
    let cursor = first.next_cursor.unwrap();
    db.prune_expired_buckets(81).unwrap();
    db.put_lock(&record(4), 50_000).unwrap();
    assert!(
        other_net
            .request_active_sync_page(&other, 2, cursor, 1)
            .await
            .is_err(),
        "an authenticated different peer cannot consume this cut"
    );
    let second = reader_net
        .request_active_sync_page(&conn, 3, cursor, 1)
        .await
        .unwrap();
    assert_eq!(second.payload.locks[0].0.parent_lock, [2; 32]);
    let third = reader_net
        .request_active_sync_page(&conn, 4, second.next_cursor.unwrap(), 1)
        .await
        .unwrap();
    assert_eq!(third.payload.locks[0].0.parent_lock, [3; 32]);
    assert!(!third.has_more);
    let fresh = reader_net
        .request_active_sync_page(&conn, 5, 0, 10)
        .await
        .unwrap();
    assert_eq!(fresh.payload.locks.len(), 1);
    assert_eq!(fresh.payload.locks[0].0.parent_lock, [4; 32]);
    // Send only the oversized header. Rejection must precede payload reads.
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&WireHeader::new(MsgType::ActiveSyncRequest as u16, 6, 0, 0, 65_537).to_bytes())
        .await
        .unwrap();
    let rejected = tokio::time::timeout(std::time::Duration::from_secs(1), recv.read_to_end(64))
        .await
        .expect("header rejection must not await the declared body");
    assert!(rejected.is_err() || rejected.unwrap().is_empty());
    cancel.cancel();
    worker.await.unwrap();
}

struct HoldSync {
    entered: tokio::sync::mpsc::Sender<()>,
    release: CancellationToken,
}
impl humoco_node::network::RequestHandler for HoldSync {
    fn handle(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
    ) -> humoco_node::network::BoxFuture<Result<(WireHeader, Vec<u8>), humoco_node::error::NodeError>>
    {
        let entered = self.entered.clone();
        let release = self.release.clone();
        Box::pin(async move {
            if header.msg_type == MsgType::ActiveSyncRequest as u16 {
                let _ = entered.send(()).await;
                release.cancelled().await;
            }
            humoco_node::network::RequestHandler::handle(&DefaultRequestHandler, header, payload)
                .await
        })
    }
}
#[tokio::test]
async fn thirty_two_stalled_sync_jobs_do_not_consume_reserved_shard_rpc_slots() {
    let source = NodeIdentity::generate();
    let reader = NodeIdentity::generate();
    let stop = CancellationToken::new();
    let release = CancellationToken::new();
    let source_pm = Arc::new(PeerManager::with_f2f(vec![], vec![*reader.node_pubkey()]));
    let reader_pm = Arc::new(PeerManager::with_f2f(vec![], vec![*source.node_pubkey()]));
    let (tx, mut rx) = tokio::sync::mpsc::channel(32);
    let server = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &source,
        source_pm.clone(),
        Arc::new(HoldSync {
            entered: tx,
            release: release.clone(),
        }),
        stop.clone(),
    )
    .unwrap();
    let client = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &reader,
        reader_pm.clone(),
        Arc::new(DefaultRequestHandler),
        stop.clone(),
    )
    .unwrap();
    source_pm
        .register_f2f_friend(*reader.node_pubkey(), Some(client.local_addr().unwrap()))
        .await;
    reader_pm
        .register_f2f_friend(*source.node_pubkey(), Some(server.local_addr().unwrap()))
        .await;
    server.spawn_accept_loop();
    client.spawn_accept_loop();
    let conn = client
        .connect_peer(server.local_addr().unwrap())
        .await
        .unwrap();
    let mut jobs = tokio::task::JoinSet::new();
    for seq in 0..32 {
        let client = client.clone();
        let conn = conn.clone();
        jobs.spawn(async move {
            client
                .send_request(
                    &conn,
                    &WireHeader::new(MsgType::ActiveSyncRequest as u16, seq, 0, 0, 0),
                    &[],
                )
                .await
        });
    }
    for _ in 0..32 {
        tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
    }
    assert!(client
        .send_request(
            &conn,
            &WireHeader::new(MsgType::ActiveSyncRequest as u16, 33, 0, 0, 0),
            &[]
        )
        .await
        .is_err());
    let (reply, _) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        client.send_request(
            &conn,
            &WireHeader::new(MsgType::StatusQuery as u16, 34, 0, 0, 0),
            &[],
        ),
    )
    .await
    .expect("shard RPC must progress while sync is stalled")
    .unwrap();
    assert_eq!(reply.msg_type, MsgType::StatusResponse as u16);
    release.cancel();
    while let Some(result) = jobs.join_next().await {
        assert!(result.unwrap().is_ok());
    }
    stop.cancel();
}
