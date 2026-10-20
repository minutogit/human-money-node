use humoco_node::network::{
    BoxFuture, DefaultRequestHandler, PeerManager, QuicTransport, RequestHandler,
};
use humoco_node::{NodeError, NodeIdentity};
use humoco_sim_core::wire::{MsgType, WireHeader};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

struct BlockingHandler {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}
impl RequestHandler for BlockingHandler {
    fn handle(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
    ) -> BoxFuture<Result<(WireHeader, Vec<u8>), NodeError>> {
        let entered = self.entered.clone();
        let release = self.release.clone();
        Box::pin(async move {
            entered.notify_one();
            release.notified().await;
            Ok((
                WireHeader::new(
                    MsgType::StatusResponse as u16,
                    header.session_seq + 1,
                    0,
                    0,
                    payload.len() as u32,
                ),
                payload,
            ))
        })
    }
}

/// Exercise the actual 256-session production pool over real QUIC, including a
/// reverse RPC on an outbound socket whose originating lease has been released.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shard_pool_capacity_idle_lru_and_inbound_busy_protection_are_neutral() {
    let cancel = CancellationToken::new();
    let client_identity = NodeIdentity::generate();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let client_manager = Arc::new(PeerManager::new(Vec::new()));
    let client = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &client_identity,
        client_manager.clone(),
        Arc::new(BlockingHandler {
            entered: entered.clone(),
            release: release.clone(),
        }),
        cancel.clone(),
    )
    .unwrap();
    let client_addr = client.local_addr().unwrap();
    client.spawn_accept_loop();
    let mut servers = Vec::new();
    let mut leases = Vec::new();
    for index in 0..258 {
        let server_identity = NodeIdentity::generate();
        let manager = Arc::new(PeerManager::new(Vec::new()));
        manager
            .register_f2f_friend(*client_identity.node_id(), Some(client_addr))
            .await;
        let server = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            &server_identity,
            manager,
            Arc::new(DefaultRequestHandler),
            cancel.clone(),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        client_manager
            .learn_node_from_gossip(*server_identity.node_pubkey(), addr, 0, None)
            .await;
        server.spawn_accept_loop();
        if index < 256 {
            leases.push(Some(client.connect_peer(addr).await.unwrap()));
        }
        servers.push(server);
    }
    let first = quinn::Connection::clone(leases[0].as_ref().unwrap());
    let oldest_idle = quinn::Connection::clone(leases[1].as_ref().unwrap());
    let inbound_busy = quinn::Connection::clone(leases[2].as_ref().unwrap());
    let next_idle = quinn::Connection::clone(leases[3].as_ref().unwrap());
    let remote_oldest = servers[1]
        .peer_manager()
        .get_connection(&client_addr)
        .await
        .unwrap();
    let extra_addr = servers[256].local_addr().unwrap();
    assert!(matches!(
        client.connect_peer(extra_addr).await,
        Err(NodeError::LocalCapacity(_))
    ));
    assert!(client_manager.get_peer(&extra_addr).await.is_none());

    // Dropping leases defines idle order; the first lease remains pinned even
    // though it has never opened an RPC stream.
    for lease in leases.iter_mut().skip(1) {
        drop(lease.take());
    }
    let extra = client.connect_peer(extra_addr).await.unwrap();
    assert_eq!(
        oldest_idle.closed().await,
        quinn::ConnectionError::LocallyClosed
    );
    assert!(first.close_reason().is_none());
    assert!(inbound_busy.close_reason().is_none());
    remote_oldest.closed().await;
    let header = WireHeader::new(MsgType::StatusQuery as u16, 10, 0, 0, 0);
    let turnover = servers[1]
        .send_request(&remote_oldest, &header, &[])
        .await
        .unwrap_err();
    assert!(
        turnover.is_local_capacity(),
        "remote pool turnover must remain neutral: {turnover}"
    );
    assert_eq!(
        client_manager
            .get_peer(&servers[1].local_addr().unwrap())
            .await
            .unwrap()
            .missing_count,
        0
    );

    // Use the same connection in the reverse direction. Its server task must
    // pin the socket after all originating client leases were dropped.
    let remote_connection = servers[2]
        .peer_manager()
        .get_connection(&client_addr)
        .await
        .unwrap();
    let server = servers[2].clone();
    let reverse_rpc = tokio::spawn(async move {
        let header = WireHeader::new(MsgType::StatusQuery as u16, 1, 0, 0, 0);
        server.send_request(&remote_connection, &header, &[]).await
    });
    tokio::time::timeout(Duration::from_secs(3), entered.notified())
        .await
        .unwrap();
    let another = client
        .connect_peer(servers[257].local_addr().unwrap())
        .await
        .unwrap();
    assert!(inbound_busy.close_reason().is_none());
    assert!(first.close_reason().is_none());
    assert_eq!(
        next_idle.closed().await,
        quinn::ConnectionError::LocallyClosed
    );
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(3), reverse_rpc)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    // An old handler's deferred close cannot erase a newly published session.
    let replacement_addr = servers[1].local_addr().unwrap();
    let replacement = client.connect_peer(replacement_addr).await.unwrap();
    client_manager
        .note_connection_closed(&replacement_addr, oldest_idle.stable_id())
        .await;
    assert_eq!(
        client_manager
            .get_connection(&replacement_addr)
            .await
            .unwrap()
            .stable_id(),
        replacement.stable_id()
    );
    assert_eq!(
        servers[1]
            .peer_manager()
            .get_peer(&client_addr)
            .await
            .unwrap()
            .missing_count,
        0
    );
    drop((extra, another, replacement, leases));
    cancel.cancel();
    client.endpoint().close(0u32.into(), b"test complete");
    for server in &servers {
        server.endpoint().close(0u32.into(), b"test complete");
    }
    client.drain_tasks().await;
    for server in &servers {
        server.drain_tasks().await;
    }
}
