//! Real QUIC fixtures shared by recovery and the multi-repository acceptance harness.
use humoco_node::{identity::NodeIdentity,network::{NodeRequestHandler,PeerManager,QuicTransport},storage::{DualTierEngine,RedbStorage}};
use humoco_sim_core::wire::{MsgType,WireHeader};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
pub(crate) struct RecoveryPeer {
    pub(crate) identity: NodeIdentity,
    pub(crate) manager: Arc<PeerManager>,
    pub(crate) engine: DualTierEngine,
    pub(crate) db: Arc<RedbStorage>,
    pub(crate) network: QuicTransport,
    pub(crate) readiness: Arc<humoco_node::daemon::ShardReadinessManager>,
    pub(crate) cancel: CancellationToken,
    pub(crate) worker: tokio::task::JoinHandle<()>,
    pub(crate) _dir: tempfile::TempDir,
}
/// Established source availability and mature tickets are explicit premises;
/// target readiness is NEVER set by this fixture or an automatic empty fallback.
pub(crate) async fn recovery_peers(count: usize) -> Vec<RecoveryPeer> { recovery_peers_mode(count,false).await }
pub(crate) async fn recovery_peers_mode(count: usize, corrupt: bool) -> Vec<RecoveryPeer> { recovery_peers_fault(count,corrupt,0).await }
#[allow(dead_code)]
pub(crate) async fn recovery_peers_fault(count: usize, corrupt: bool,support_fault:u8) -> Vec<RecoveryPeer> {
    let identities: Vec<_> = (0..count).map(|_|NodeIdentity::generate()).collect();
    let mut peers = Vec::new();
    for identity in &identities {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(RedbStorage::open(&dir.path().join("node.redb")).unwrap());
        let cancel = CancellationToken::new();
        let (engine,worker) = DualTierEngine::new_with_token(db.clone(),cancel.clone());
        let manager = Arc::new(PeerManager::new(vec![]));
        let readiness = Arc::new(humoco_node::daemon::ShardReadinessManager::new());
        let handler = Arc::new(NodeRequestHandler::with_peer_manager(engine.clone(),db.clone(),identity.clone(),manager.clone())
            .with_readiness_manager(readiness.clone()));
        let handler = Arc::new(CorruptSnapshot { inner: handler, corrupt, support_fault, identity:identity.clone(), pages: std::sync::atomic::AtomicUsize::new(0) });
        let network = QuicTransport::bind_with_options("127.0.0.1:0".parse().unwrap(),identity,manager.clone(),handler,cancel.clone()).unwrap();
        network.spawn_accept_loop();
        peers.push(RecoveryPeer { identity:identity.clone(),manager,engine,db,network,readiness,cancel,worker,_dir:dir });
    }
    for peer in &peers {
        for member in &peers {
            let addr = member.network.local_addr().unwrap();
            peer.manager.register_f2f_friend(*member.identity.node_pubkey(),Some(addr)).await;
            peer.manager.learn_node_from_gossip_with_hrw(*member.identity.node_pubkey(),*member.identity.hrw_routing_id(),addr,0,None).await;
            peer.manager.set_first_seen_for_test(member.identity.node_pubkey(),std::time::Instant::now()-std::time::Duration::from_secs(25*3600)).await;
        }
    }
    peers
}
pub(crate) async fn stop_recovery_peers(peers: Vec<RecoveryPeer>) {
    for peer in &peers { peer.cancel.cancel(); peer.network.close(); }
    for peer in peers { peer.worker.await.unwrap(); }
}

struct CorruptSnapshot {
    inner: Arc<NodeRequestHandler>,
    corrupt: bool,
    support_fault:u8,
    identity:NodeIdentity,
    pages: std::sync::atomic::AtomicUsize,
}
impl humoco_node::network::RequestHandler for CorruptSnapshot {
    fn handle(&self, header: WireHeader, payload: Vec<u8>) -> humoco_node::network::BoxFuture<Result<(WireHeader,Vec<u8>),humoco_node::error::NodeError>> {
        self.handle_authenticated(header,payload,None)
    }
    fn handle_unidirectional_authenticated(&self, header: WireHeader, payload: Vec<u8>, owner: Option<[u8; 32]>)
        -> humoco_node::network::BoxFuture<Result<(), humoco_node::error::NodeError>> {
        self.inner.handle_unidirectional_authenticated(header, payload, owner)
    }
    fn handle_authenticated(&self,header:WireHeader,payload:Vec<u8>,owner:Option<[u8;32]>)
        -> humoco_node::network::BoxFuture<Result<(WireHeader,Vec<u8>),humoco_node::error::NodeError>> {
        let corrupt = self.corrupt && header.msg_type == MsgType::ActiveSyncRequest as u16
            && self.pages.fetch_add(1,std::sync::atomic::Ordering::Relaxed) == 1;
        let support_fault = self.support_fault;
        let identity = self.identity.clone();
        let shard = if payload.len() >= 4 {u16::from_le_bytes([payload[2],payload[3]])} else {0};
        let freeze = header.msg_type == MsgType::ShardDigestRequest as u16 && payload.len() == 20 && payload[1] == 0;
        let active = header.msg_type == MsgType::ActiveSyncRequest as u16;
        let reply = self.inner.handle_authenticated(header,payload,owner);
        Box::pin(async move {
            let (mut header,mut bytes) = reply.await?;
            if freeze && support_fault > 0 && support_fault <= 4 && header.flags == 0 {
                use ed25519_dalek::Signer;
                let mut reply: humoco_node::network::framing::FrozenShardReply = bincode::deserialize(&bytes).unwrap();
                let network = if support_fault == 2 {humoco_sim_core::types::NetworkId::Testnet} else {humoco_sim_core::types::NetworkId::Mainnet};
                let shard = if support_fault == 3 {shard.wrapping_add(1)} else {shard};
                let receiver = if support_fault == 4 {[99;32]} else {owner.unwrap()};
                reply.signature = identity.signing_key().sign(&reply.signing_digest(network,shard,identity.node_pubkey(),&receiver)).to_bytes().to_vec();
                if support_fault == 1 {reply.signature[0] ^= 1;}
                bytes = bincode::serialize(&reply).unwrap(); header.payload_len=bytes.len() as u32;
            }
            if active && support_fault >= 5 {
                let mut page=humoco_node::network::framing::ActiveSyncResponse::from_bytes(&bytes).unwrap();
                if let Some((_,_,fact))=page.payload.support.first_mut() {
                    if support_fault == 5 {fact.class=2;} else if support_fault == 7 {fact.parent[0]^=1;} else {fact.root_valid_until_ms=1;}
                }
                bytes=page.to_bytes().unwrap(); header.payload_len=bytes.len() as u32;
            }
            if corrupt {
                let mut page = humoco_node::network::framing::ActiveSyncResponse::from_bytes(&bytes)
                    .map_err(|e|humoco_node::error::NodeError::Network(e.to_string()))?;
                if let Some((row,_)) = page.payload.locks.first_mut() { row.id[0] ^= 1; }
                bytes = page.to_bytes().map_err(|e|humoco_node::error::NodeError::Network(e.to_string()))?;
                header.payload_len = bytes.len() as u32;
            }
            Ok((header,bytes))
        })
    }
}

