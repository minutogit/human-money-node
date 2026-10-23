//! Operator sovereignty is the only empty-region bootstrap authority.
use std::{sync::Arc, time::Duration};
use humoco_node::{config::NodeConfig, daemon::NodeDaemon, identity::NodeIdentity,
    network::{DefaultRequestHandler, PeerManager, QuicTransport}};
use humoco_sim_core::wire::{MsgType, WireHeader, FLAG_NOT_READY};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn explicit_new_region_serves_committed_digest_but_restart_stays_closed() {
    let dir = tempfile::tempdir().unwrap();
    let server = NodeIdentity::generate();
    let client = NodeIdentity::generate();
    let mut config = NodeConfig::default();
    config.storage.data_dir = dir.path().join("data");
    config.network.p2p_listen_addr = "127.0.0.1:0".parse().unwrap();
    config.network.rpc_listen_addr = "127.0.0.1:0".parse().unwrap();
    config.f2f.trusted_pubkeys.push(client.public_key_hex());
    for bootstrap in [true, false] {
        let cancel = CancellationToken::new();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let daemon = NodeDaemon::with_bound_sender(config.clone(), server.clone(), cancel.clone(), tx);
        let daemon = if bootstrap { daemon.bootstrap_new_region() } else { daemon };
        let run = tokio::spawn(async move { daemon.run().await });
        let bound = tokio::time::timeout(Duration::from_secs(10), rx).await.unwrap().unwrap();
        let client_cancel = CancellationToken::new();
        let pm = Arc::new(PeerManager::with_f2f(vec![], vec![*server.node_pubkey()]));
        pm.register_f2f_friend(*server.node_pubkey(), Some(bound.p2p_addr)).await;
        let transport = QuicTransport::bind_with_options("127.0.0.1:0".parse().unwrap(),
            &client, pm, Arc::new(DefaultRequestHandler), client_cancel.clone()).unwrap();
        transport.spawn_accept_loop();
        let conn = transport.connect_peer(bound.p2p_addr).await.unwrap();
        let header = WireHeader::new(MsgType::ShardDigestRequest as u16, 1, 0, 0, 2);
        let (reply, payload) = transport.send_request(&conn, &header, &42u16.to_le_bytes()).await.unwrap();
        assert_eq!(reply.flags & FLAG_NOT_READY == 0, bootstrap);
        if bootstrap {
            let (_, count): ([u8;32], u64) = bincode::deserialize(&payload).unwrap();
            assert_eq!(count, 0);
        }
        client_cancel.cancel();
        drop(conn);
        drop(transport);
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(10), run).await.unwrap().unwrap().unwrap();
    }
    let daemon = NodeDaemon::new(config, server).bootstrap_new_region();
    let error = daemon.run().await.unwrap_err();
    assert!(error.to_string().contains("existing database"));
}
