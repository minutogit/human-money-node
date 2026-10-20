//! Startup errors must release already-started operator, QUIC and storage resources.
use humoco_node::{config::NodeConfig, daemon::NodeDaemon, identity::NodeIdentity, storage::RedbStorage};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_bind_failure_releases_operator_and_database_in_the_same_runtime() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let occupied_public = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("occupied public port");
    let operator_reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("operator port reservation");
    let operator_address = operator_reservation.local_addr().expect("operator address");
    drop(operator_reservation);
    let mut config = NodeConfig::default();
    config.network.rpc_listen_addr = occupied_public.local_addr().expect("public address");
    config.network.p2p_listen_addr = "127.0.0.1:0".parse().expect("QUIC address");
    config.network.operator_listen_addr = Some(operator_address);
    config.network.shutdown_timeout_secs = 3;
    config.storage.data_dir = temporary.path().join("data");
    config.network.control_socket = Some(temporary.path().join("control.sock"));
    let database_path = config.storage.data_dir.join("humoco.redb");
    let cancel = CancellationToken::new();
    let daemon = NodeDaemon::with_cancel_token(config.clone(), NodeIdentity::generate(), cancel.clone());

    let result = tokio::time::timeout(Duration::from_secs(5), daemon.run()).await.expect("startup failure must return within its shutdown bound");
    assert!(result.is_err(), "occupied public listener must fail startup");
    assert!(cancel.is_cancelled(), "every startup error cancels the per-run producers");
    let operator = tokio::net::TcpListener::bind(operator_address).await.expect("operator listener released before run returns");
    let database = RedbStorage::open(&database_path).expect("all task-held database handles released before run returns");
    drop(database);
    drop(operator);
    let completion = std::fs::read(config.control_socket_path().with_extension("stop.json")).expect("truthful completion record");
    let completion: serde_json::Value = serde_json::from_slice(&completion).expect("completion JSON");
    assert_eq!(completion["clean"], false, "failed startup must never advertise clean success");
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
    let result = tokio::time::timeout(Duration::from_secs(5), daemon.run()).await.expect("early startup failure bounded");
    assert!(result.is_err());
    let database = RedbStorage::open(&database_path).expect("early startup worker releases redb without runtime shutdown");
    drop(database);
}
