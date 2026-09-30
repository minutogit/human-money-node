use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use axum::http::StatusCode;
use ed25519_dalek::{Signer, SigningKey};
use rand::Rng;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use humoco_node::{
    api::hmc::{
        calculate_l2_payload_hash, L2AuthPayload, L2ChainLockRequest, L2LockRequest,
        L2ResponseEnvelope,
    },
    config::NodeConfig,
    daemon::{BoundAddrs, NodeDaemon},
    identity::NodeIdentity,
};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn make_hmc_genesis(
    voucher_id: &str,
    valid_until_ms: u64,
    timestamp_ms: u64,
    sender_key: &SigningKey,
) -> L2LockRequest {
    let sender_pub = sender_key.verifying_key().to_bytes();
    let tx_hash = *blake3::hash(voucher_id.as_bytes()).as_bytes();
    let del_str = valid_until_ms.to_string();

    let mut req = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: None,
        transaction_hash: tx_hash,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: timestamp_ms as u128,
        deletable_at: Some(del_str),
        privacy_guard: None,
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

fn make_hmc_spend(
    voucher_id: &str,
    ds_tag: &str,
    tx_hash: [u8; 32],
    timestamp_ms: u64,
    sender_key: &SigningKey,
) -> L2LockRequest {
    let sender_pub = sender_key.verifying_key().to_bytes();

    let mut req = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: Some(ds_tag.to_string()),
        transaction_hash: tx_hash,
        is_genesis: false,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: timestamp_ms as u128,
        deletable_at: None,
        privacy_guard: None,
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

#[derive(serde::Serialize)]
#[serde(untagged)]
enum IngressRequest {
    Chain(L2ChainLockRequest),
    Single(L2LockRequest),
}

async fn post_lock_http(
    rpc_addr: SocketAddr,
    req: &IngressRequest,
) -> Result<(StatusCode, Duration, L2ResponseEnvelope), Box<dyn std::error::Error + Send + Sync>> {
    let start = Instant::now();
    let json_body = serde_json::to_string(req)?;
    let mut stream = tokio::net::TcpStream::connect(rpc_addr).await?;
    let body_bytes = json_body.as_bytes();

    let req_str = format!(
        "POST /v1/lock HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nX-Peer-Token: cluster_sim_token\r\nContent-Length: {}\r\n\r\n",
        rpc_addr, body_bytes.len()
    );

    stream.write_all(req_str.as_bytes()).await?;
    stream.write_all(body_bytes).await?;
    stream.flush().await?;

    let mut response_buf = Vec::new();
    stream.read_to_end(&mut response_buf).await?;
    let elapsed = start.elapsed();

    let mut split_idx = None;
    for i in 0..response_buf.len().saturating_sub(3) {
        if &response_buf[i..i + 4] == b"\r\n\r\n" {
            split_idx = Some(i);
            break;
        }
    }

    let (header_part, body_part) = match split_idx {
        Some(idx) => (&response_buf[..idx], &response_buf[idx + 4..]),
        None => (&response_buf[..], &[][..]),
    };

    let header_str = String::from_utf8_lossy(header_part);
    let mut lines = header_str.lines();
    let status_line = lines.next().unwrap_or("");
    let status_code_u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(500);

    let status = StatusCode::from_u16(status_code_u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let envelope: L2ResponseEnvelope = serde_json::from_slice(body_part)?;

    Ok((status, elapsed, envelope))
}

struct NodeInstance {
    id: usize,
    identity: NodeIdentity,
    rpc_addr: SocketAddr,
    p2p_addr: SocketAddr,
    control_socket: std::path::PathBuf,
    _temp_dir: TempDir,
    cancel_token: CancellationToken,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("\x1b[1;36m╔══════════════════════════════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[1;36m║        HuMoCo Layer-2 Multi-Node Cluster & Live Dashboard Simulation         ║\x1b[0m");
    println!("\x1b[1;36m╚══════════════════════════════════════════════════════════════════════════════╝\x1b[0m\n");

    let num_nodes = 4;
    println!("\x1b[1;33m🚀 Initialisiere {} HuMoCo Knoten im echten F2F Mesh...\x1b[0m", num_nodes);

    // 1. Pre-generate all identities and storage directories
    let mut node_defs = Vec::with_capacity(num_nodes);
    for i in 0..num_nodes {
        let temp = TempDir::new()?;
        let identity = NodeIdentity::generate();
        let key_path = temp.path().join("node_key.bin");
        identity.save_to_file(&key_path)?;
        let control_socket = temp.path().join(format!("humoco_{}.sock", i));
        node_defs.push((i, identity, key_path, control_socket, temp));
    }

    let all_pubkeys: Vec<String> = node_defs.iter().map(|(_, id, _, _, _)| id.public_key_hex()).collect();

    // 2. Start daemons with full mutual trust
    let mut instances = Vec::with_capacity(num_nodes);
    let mut join_handles = Vec::new();

    for (i, identity, key_path, control_socket, temp) in node_defs {
        let mut config = NodeConfig::default();
        config.network.p2p_listen_addr = "127.0.0.1:0".parse().unwrap();
        config.network.rpc_listen_addr = "127.0.0.1:0".parse().unwrap();
        config.storage.data_dir = temp.path().join("data");
        config.identity.key_path = key_path;
        config.network.control_socket = Some(control_socket.clone());
        config.f2f.tokens.push("cluster_sim_token".into());

        // Every node trusts all other nodes' public keys
        for pk in &all_pubkeys {
            if pk != &identity.public_key_hex() {
                config.f2f.trusted_pubkeys.push(pk.clone());
            }
        }

        let cancel_token = CancellationToken::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<BoundAddrs>();

        let daemon = NodeDaemon::with_bound_sender(
            config.clone(),
            identity.clone(),
            cancel_token.clone(),
            tx,
        );

        let handle = tokio::spawn(async move {
            if let Err(e) = daemon.run().await {
                eprintln!("Daemon {} error: {:?}", i, e);
            }
        });
        join_handles.push(handle);

        let bound = tokio::time::timeout(Duration::from_secs(8), rx)
            .await
            .map_err(|_| format!("Knoten {} Bind-Timeout", i + 1))??;

        instances.push(NodeInstance {
            id: i,
            identity,
            rpc_addr: bound.rpc_addr,
            p2p_addr: bound.p2p_addr,
            control_socket,
            _temp_dir: temp,
            cancel_token,
        });
    }

    // 3. Connect all nodes via Control Client (bidirectional F2F peering)
    for (i, inst) in instances.iter().enumerate() {
        let client = humoco_node::control::ControlClient::new(inst.control_socket.clone());
        for (j, peer) in instances.iter().enumerate() {
            if i != j {
                let peer_str = format!("{}@{}", peer.identity.public_key_hex(), peer.p2p_addr);
                let _ = client.add_peer(&peer_str).await;
            }
        }
    }

    // Wait for QUIC connection establishment
    tokio::time::sleep(Duration::from_millis(800)).await;

    println!("\n\x1b[1;32m✅ Alle 4 Knoten sind erfolgreich gestartet und im F2F Mesh verbunden (ONLINE Mode)!\x1b[0m\n");
    println!("\x1b[1;37m📊 Klicke auf die folgenden Links, um die interaktiven Web-Dashboards zu öffnen:\x1b[0m\n");
    for inst in &instances {
        println!(
            "  • \x1b[1;34mKnoten {} Dashboard:\x1b[0m \x1b[4;32mhttp://{}/dashboard\x1b[0m  (NodeID: \x1b[90m{}\x1b[0m)",
            inst.id + 1,
            inst.rpc_addr,
            &inst.identity.node_id_hex()[..12]
        );
    }
    println!();
    println!("\x1b[1;33m⚡ Starte kontinuierlichen Client-Traffic (1 Transaktion pro Sekunde via wechselnde Gateways)...\x1b[0m");
    println!("\x1b[90m   (Drücke Strg+C zum Beenden)\x1b[0m\n");

    let client_key = SigningKey::from_bytes(&[42u8; 32]);
    let client_pub = client_key.verifying_key().to_bytes();
    let mut rng = rand::thread_rng();
    let mut active_vouchers: Vec<(String, L2LockRequest)> = Vec::new();
    let mut tx_counter: u64 = 0;

    let shutdown_signal = tokio::signal::ctrl_c();
    tokio::pin!(shutdown_signal);

    let mut ticker = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            _ = &mut shutdown_signal => {
                println!("\n\x1b[1;33m🛑 Beende Simulation und stoppe alle Knoten sauber...\x1b[0m");
                for inst in &instances {
                    inst.cancel_token.cancel();
                }
                break;
            }
            _ = ticker.tick() => {
                tx_counter += 1;
                let gateway_idx = rng.gen_range(0..instances.len());
                let gateway = &instances[gateway_idx];
                let current_time = now_ms();

                // Decide action: create new genesis voucher (~40%) or spend existing (~60%)
                let should_create_genesis = active_vouchers.is_empty() || rng.gen_bool(0.35);

                let (req, lock_type, tag_display) = if should_create_genesis {
                    let v_num: u64 = rng.gen_range(100000..999999);
                    let v_id = format!("v_{}_{}", v_num, tx_counter);
                    let valid_until = current_time + 3_600_000; // 1h validity
                    let genesis = make_hmc_genesis(&v_id, valid_until, current_time, &client_key);
                    active_vouchers.push((v_id.clone(), genesis.clone()));
                    if active_vouchers.len() > 50 {
                        active_vouchers.remove(0);
                    }
                    let tag_display = format!("Voucher: {}", v_id);
                    (IngressRequest::Single(genesis), "GENESIS LOCK", tag_display)
                } else {
                    let v_idx = rng.gen_range(0..active_vouchers.len());
                    let (v_id, genesis) = &active_vouchers[v_idx];
                    let ds_tag = format!("ds_{}_{}", tx_counter, rng.gen_range(1000..9999));
                    let mut tx_hash = [0u8; 32];
                    rng.fill(&mut tx_hash);
                    let spend = make_hmc_spend(v_id, &ds_tag, tx_hash, current_time + 1000, &client_key);
                    let chain_req = L2ChainLockRequest {
                        auth: L2AuthPayload {
                            ephemeral_pubkey: client_pub,
                            auth_signature: None,
                        },
                        layer2_voucher_id: v_id.clone(),
                        chain: vec![genesis.clone(), spend],
                    };
                    let tag_display = format!("Parent: {}...", &ds_tag[..8.min(ds_tag.len())]);
                    (IngressRequest::Chain(chain_req), "SPEND LOCK  ", tag_display)
                };

                match post_lock_http(gateway.rpc_addr, &req).await {
                    Ok((_status, duration, resp)) => {
                        let verdict_str = match &resp.verdict {
                            humoco_node::api::hmc::L2Verdict::Verified { .. } | humoco_node::api::hmc::L2Verdict::Ok { .. } => "\x1b[1;32mVerified (200 OK)\x1b[0m",
                            humoco_node::api::hmc::L2Verdict::Conflict { .. } => "\x1b[1;31mConflict (409)\x1b[0m",
                            humoco_node::api::hmc::L2Verdict::Rejected { .. } => "\x1b[1;33mRejected\x1b[0m",
                            _ => "\x1b[1;33mOther\x1b[0m",
                        };
                        let quorum_info = resp.quorum_certificate.as_ref().map(|q| {
                            format!("\x1b[1;36m[{}/{} Shard-Signaturen]\x1b[0m", q.signer_count, q.active_nodes_count)
                        }).unwrap_or_else(|| "\x1b[90m[Lokal]\x1b[0m".to_string());
                        println!(
                            "\x1b[1;37m[TX #{:04}]\x1b[0m Gateway \x1b[1;34mKnoten {} (: {})\x1b[0m | \x1b[1;35m{}\x1b[0m | {:<22} | {} {} | Latenz: \x1b[1;32m{:.2}ms\x1b[0m",
                            tx_counter,
                            gateway.id + 1,
                            gateway.rpc_addr.port(),
                            lock_type,
                            tag_display,
                            verdict_str,
                            quorum_info,
                            duration.as_secs_f64() * 1000.0,
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "\x1b[1;31m[TX #{:04}] Fehler beim Senden an Knoten {}: {}\x1b[0m",
                            tx_counter,
                            gateway.id + 1,
                            e
                        );
                    }
                }
            }
        }
    }

    println!("\x1b[1;32m✨ Simulation erfolgreich beendet.\x1b[0m");
    Ok(())
}
