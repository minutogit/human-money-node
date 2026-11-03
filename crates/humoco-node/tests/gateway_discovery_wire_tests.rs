//! Passive discovery is authenticated heartbeat data, never a third gossip stream.
use humoco_node::{
    api::{build_router, AppState},
    identity::NodeIdentity,
    ingress::{PowEngine, TierController},
    network::{
        framing::HeartbeatWirePayload, BoxFuture, NodeRequestHandler, PeerManager, QuicTransport,
        RequestHandler,
    },
    storage::{DualTierEngine, RedbStorage},
};
use humoco_sim_core::wire::{MsgType, WireHeader};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
struct Observed {
    inner: NodeRequestHandler,
    done: tokio::sync::mpsc::Sender<()>,
}
impl RequestHandler for Observed {
    fn handle(
        &self,
        h: WireHeader,
        p: Vec<u8>,
    ) -> BoxFuture<Result<(WireHeader, Vec<u8>), humoco_node::error::NodeError>> {
        self.inner.handle(h, p)
    }
    fn handle_unidirectional_authenticated(
        &self,
        h: WireHeader,
        p: Vec<u8>,
        peer: Option<[u8; 32]>,
    ) -> BoxFuture<Result<(), humoco_node::error::NodeError>> {
        let task = self.inner.handle_unidirectional_authenticated(h, p, peer);
        let done = self.done.clone();
        Box::pin(async move {
            let result = task.await;
            let _ = done.send(()).await;
            result
        })
    }
}
#[tokio::test]
async fn signed_passive_gateway_publication_arrives_over_quic_and_tampering_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let stop = CancellationToken::new();
    let source = NodeIdentity::generate();
    let receiver = NodeIdentity::generate();
    let source_db = Arc::new(RedbStorage::open(&dir.path().join("source.redb")).unwrap());
    let receiver_db = Arc::new(RedbStorage::open(&dir.path().join("receiver.redb")).unwrap());
    let (source_engine, source_worker) =
        DualTierEngine::new_with_token(source_db.clone(), stop.clone());
    let (engine, worker) = DualTierEngine::new_with_token(receiver_db.clone(), stop.clone());
    let source_pm = Arc::new(PeerManager::with_f2f(vec![], vec![*receiver.node_pubkey()]));
    source_pm.set_simulation_mode(true);
    let pm = Arc::new(PeerManager::with_f2f(vec![], vec![*source.node_pubkey()]));
    pm.set_simulation_mode(true);
    let publisher = Arc::new(
        NodeRequestHandler::with_peer_manager(
            source_engine,
            source_db,
            source.clone(),
            source_pm.clone(),
        )
        .with_gateway_urls(vec!["https://checkout.example".into()]),
    );
    let (tx, mut done) = tokio::sync::mpsc::channel(4);
    let handler = Arc::new(Observed {
        inner: NodeRequestHandler::with_peer_manager(
            engine.clone(),
            receiver_db.clone(),
            receiver.clone(),
            pm.clone(),
        ),
        done: tx,
    });
    let source_net = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &source,
        source_pm.clone(),
        publisher.clone(),
        stop.clone(),
    )
    .unwrap();
    let receiver_net = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &receiver,
        pm.clone(),
        handler,
        stop.clone(),
    )
    .unwrap();
    source_pm
        .register_f2f_friend(
            *receiver.node_pubkey(),
            Some(receiver_net.local_addr().unwrap()),
        )
        .await;
    pm.register_f2f_friend(
        *source.node_pubkey(),
        Some(source_net.local_addr().unwrap()),
    )
    .await;
    source_net.spawn_accept_loop();
    receiver_net.spawn_accept_loop();
    let now = source_pm.net_time_ms();
    source_net
        .send_heartbeat_to(
            receiver_net.local_addr().unwrap(),
            *source.node_pubkey(),
            source_net.local_addr().unwrap(),
            1,
            0,
            0,
            [0u8; 64],
            now,
            vec![],
        )
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), done.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pm.advertised_gateway_urls().await,
        vec!["https://checkout.example"]
    );
    let mut ad = publisher.gateway_advertisement().unwrap();
    ad.urls = vec!["https://forged.example".into()];
    let mut hb = HeartbeatWirePayload {
        node_id: *source.node_pubkey(),
        addr: source_net.local_addr().unwrap(),
        timestamp_ms: now + 1,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0; 64],
        supported_suites_mask: 1,
        piggyback_observations: vec![],
        pow_nonce: 0,
        hrw_routing_id: *source.node_pubkey(),
        ticket_epoch_t0: 0,
        ttl: 16,
        signing_checkpoint: None,
        gateway_advertisement: Some(ad),
    };
    hb.sign_origin(&source, hb.timestamp_ms);
    let bytes = bincode::serialize(&hb).unwrap();
    let conn = source_net
        .connect_peer(receiver_net.local_addr().unwrap())
        .await
        .unwrap();
    humoco_node::network::send_unidirectional_frame(
        &conn,
        &WireHeader::new(MsgType::Heartbeat as u16, 2, 0, 0, bytes.len() as u32),
        &bytes,
    )
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), done.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pm.advertised_gateway_urls().await,
        vec!["https://checkout.example"]
    );
    let pow = Arc::new(PowEngine::new(*receiver.node_id(), 8));
    let tiers = Arc::new(TierController::new(receiver_db.clone(), pow.clone()));
    let mut state = AppState::new(engine, receiver_db, receiver, tiers, pow);
    state.peer_manager = Some(pm);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let http =
        tokio::spawn(async move { axum::serve(listener, build_router(state)).await.unwrap() });
    let json: serde_json::Value = reqwest::get(format!("http://{address}/v1/gateways"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        json["gateways"],
        serde_json::json!(["https://checkout.example"])
    );
    http.abort();
    let _ = http.await;
    stop.cancel();
    source_worker.await.unwrap();
    worker.await.unwrap();
}
