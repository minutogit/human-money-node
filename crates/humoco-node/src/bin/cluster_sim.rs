#![forbid(unsafe_code)]

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
        L2ResponseEnvelope, L2StatusQuery, L2Verdict,
    },
    config::NodeConfig,
    daemon::{BoundAddrs, NodeDaemon},
    identity::NodeIdentity,
};
use humoco_sim_core::quota::ByteYears;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

struct UnspentOutput {
    ds_tag: String,
    owner_key: SigningKey,
    chain_history: Vec<L2LockRequest>,
    last_timestamp: u128,
}

struct SimVoucher {
    voucher_id: String,
    valid_until_ms: u64,
    unspent_outputs: Vec<UnspentOutput>,
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

#[derive(Debug, Clone)]
enum SimTier {
    F2F,
    Vip(&'static str),
    Free,
}

#[derive(serde::Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
enum IngressRequest {
    Chain(L2ChainLockRequest),
    Single(L2LockRequest),
}

async fn post_lock_http(
    rpc_addr: SocketAddr,
    req: &IngressRequest,
    tier: &SimTier,
) -> Result<(StatusCode, Duration, L2ResponseEnvelope), Box<dyn std::error::Error + Send + Sync>> {
    let start = Instant::now();
    let json_body = serde_json::to_string(req)?;
    let mut stream = tokio::net::TcpStream::connect(rpc_addr).await?;
    let body_bytes = json_body.as_bytes();

    let auth_header = match tier {
        SimTier::F2F => "X-Peer-Token: cluster_sim_token\r\n".to_string(),
        SimTier::Vip(token) => format!("Authorization: Bearer {}\r\n", token),
        SimTier::Free => {
            let parent_bytes = match req {
                IngressRequest::Single(single_req) if !single_req.is_genesis => {
                    let tag = single_req.ds_tag.as_deref().unwrap_or_default();
                    *blake3::hash(tag.as_bytes()).as_bytes()
                }
                IngressRequest::Chain(chain_req) => {
                    if let Some(last_hop) = chain_req.chain.last() {
                        let tag = last_hop.ds_tag.as_deref().unwrap_or_default();
                        *blake3::hash(tag.as_bytes()).as_bytes()
                    } else {
                        [0u8; 32]
                    }
                }
                _ => [0u8; 32],
            };
            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let slot = now_sec / 600;
            let challenge_bytes = humoco_node::ingress::pow::compute_stateless_challenge(&parent_bytes, slot);
            let challenge_hex = hex::encode(challenge_bytes);
            let start_nonce: u64 = rand::random::<u32>() as u64;
            let mut nonce = start_nonce;
            for n in start_nonce..(start_nonce + 200_000) {
                let hash = humoco_node::ingress::pow::compute_solution_hash(&challenge_bytes, n);
                if humoco_node::ingress::pow::check_difficulty(&hash, 8) {
                    nonce = n;
                    break;
                }
            }
            format!(
                "X-PoW-Challenge: {}\r\nX-PoW-Nonce: {}\r\n",
                challenge_hex, nonce
            )
        }
    };

    let req_str = format!(
        "POST /v1/lock HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n",
        rpc_addr, auth_header, body_bytes.len()
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

async fn post_status_http(
    rpc_addr: SocketAddr,
    req: &L2StatusQuery,
) -> Result<(StatusCode, Duration, L2ResponseEnvelope), Box<dyn std::error::Error + Send + Sync>> {
    let start = Instant::now();
    let json_body = serde_json::to_string(req)?;
    let mut stream = tokio::net::TcpStream::connect(rpc_addr).await?;
    let body_bytes = json_body.as_bytes();

    let req_str = format!(
        "POST /v1/status HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nX-Peer-Token: cluster_sim_token\r\nContent-Length: {}\r\n\r\n",
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

async fn get_status_http(
    rpc_addr: SocketAddr,
) -> Result<(StatusCode, Duration, serde_json::Value), Box<dyn std::error::Error + Send + Sync>> {
    let start = Instant::now();
    let mut stream = tokio::net::TcpStream::connect(rpc_addr).await?;

    let req_str = format!(
        "GET /v1/node-status HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        rpc_addr
    );

    stream.write_all(req_str.as_bytes()).await?;
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
    let body_json: serde_json::Value = serde_json::from_slice(body_part).unwrap_or_default();

    Ok((status, elapsed, body_json))
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

    // 2. Start daemons with full mutual trust and simulation mode
    let mut instances = Vec::with_capacity(num_nodes);
    let mut join_handles = Vec::new();

    for (i, identity, key_path, control_socket, temp) in node_defs {
        let mut config = NodeConfig::default();
        config.network.simulation_mode = true;
        config.network.fast_ticker_interval_secs = Some(5);
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

    // 3. Connect all nodes via Control Client (bidirectional F2F peering) and pre-seed VIP accounts
    for (i, inst) in instances.iter().enumerate() {
        let client = humoco_node::control::ControlClient::new(inst.control_socket.clone());
        for (j, peer) in instances.iter().enumerate() {
            if i != j {
                let peer_str = format!("{}@{}", peer.identity.public_key_hex(), peer.p2p_addr);
                let _ = client.add_peer(&peer_str).await;
            }
        }
        // Pre-seed 2 VIP accounts per node with 500,000 Byte-Years
        let _ = client.topup_quota("pos_terminal_vip_1", 500_000).await;
        let _ = client.topup_quota("merchant_checkout_vip_2", 500_000).await;
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
    println!("\x1b[1;33m⚡ Starte organischen 80:20 Read/Write Traffic (720x Zeitraffer: 5s Realzeit = 1h Simzeit)...\x1b[0m");
    println!("\x1b[90m   (Drücke Strg+C zum Beenden)\x1b[0m\n");

    let mut rng = rand::thread_rng();
    let mut active_vouchers: Vec<SimVoucher> = Vec::new();
    let mut spent_history: Vec<(String, UnspentOutput)> = Vec::new();
    let mut write_counter: u64 = 0;
    let mut total_reads_count: u64 = 0;
    let mut total_byte_years_consumed: u64 = 0;

    let start_instant = Instant::now();
    let sim_start_time = now_ms();

    let mut batch_reads_count: u64 = 0;
    let mut batch_reads_latency_sum: Duration = Duration::ZERO;
    let mut last_read_batch_print = Instant::now();

    let mut batch_writes_count: u64 = 0;
    let mut batch_writes_byte_years: u64 = 0;
    let mut batch_writes_f2f: u64 = 0;
    let mut batch_writes_vip: u64 = 0;
    let mut batch_writes_free: u64 = 0;
    let mut batch_writes_latency_sum: Duration = Duration::ZERO;
    let mut last_write_batch_print = Instant::now();

    let mut last_virtual_hour: u64 = 0;
    let mut node4_flapping_state: Option<Instant> = None;

    let shutdown_signal = tokio::signal::ctrl_c();
    tokio::pin!(shutdown_signal);

    let mut ticker = tokio::time::interval(Duration::from_millis(40));

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
                let elapsed_millis = start_instant.elapsed().as_millis() as u64;
                let sim_now_ms = sim_start_time + (elapsed_millis * 720);
                let elapsed_secs = start_instant.elapsed().as_secs_f64();

                // Clean up expired vouchers or vouchers with no unspent outputs
                active_vouchers.retain(|v| !v.unspent_outputs.is_empty() && v.valid_until_ms > sim_now_ms);

                // Hourly status printing (5 real seconds = 1 virtual hour)
                let current_virtual_hour = elapsed_millis / 5000;
                if current_virtual_hour > last_virtual_hour {
                    last_virtual_hour = current_virtual_hour;
                    let sim_day = (current_virtual_hour / 24) + 1;
                    let sim_hour = current_virtual_hour % 24;
                    let daily_quota = 960_000u64;
                    let quota_pct = ((total_byte_years_consumed as f64 / daily_quota as f64) * 100.0).min(100.0);

                    let mut cluster_active_byte_years = 0u64;
                    for inst in &instances {
                        if let Ok((status, _, json)) = get_status_http(inst.rpc_addr).await {
                            if status.is_success() {
                                if let Some(by) = json.get("active_byte_years").and_then(|v| v.as_u64()) {
                                    cluster_active_byte_years = cluster_active_byte_years.max(by);
                                }
                            }
                        }
                    }

                    println!(
                        "\x1b[1;33m⏱️  [Sim-Tag {}, {:02}:00 Uhr] {}h simuliert | Aktive Gutscheine: {} | Writes: {} ({} BY total, {} BY aktiv im Cluster / {:.1}% Tagesquote) | Reads: {}\x1b[0m",
                        sim_day,
                        sim_hour,
                        current_virtual_hour,
                        active_vouchers.len(),
                        write_counter,
                        total_byte_years_consumed,
                        cluster_active_byte_years,
                        quota_pct,
                        total_reads_count
                    );
                }

                // Node 4 transient flapping / self-healing demonstration (every ~25s real time)
                if node4_flapping_state.is_none() && write_counter > 20 && rng.gen_bool(0.003) {
                    let node4_peer_str = format!("{}@{}", instances[3].identity.public_key_hex(), instances[3].p2p_addr);
                    let client1 = humoco_node::control::ControlClient::new(instances[0].control_socket.clone());
                    let _ = client1.remove_peer(&node4_peer_str).await;
                    println!("  \x1b[90m⚡ [NODE FLAP SIM]\x1b[0m \x1b[1;33mSimuliere temporäre Trennung von Knoten 4 (Transient Degradation)...\x1b[0m");
                    node4_flapping_state = Some(Instant::now());
                } else if let Some(flap_start) = node4_flapping_state {
                    if flap_start.elapsed() >= Duration::from_secs(3) {
                        let node4_peer_str = format!("{}@{}", instances[3].identity.public_key_hex(), instances[3].p2p_addr);
                        let client1 = humoco_node::control::ControlClient::new(instances[0].control_socket.clone());
                        let _ = client1.add_peer(&node4_peer_str).await;
                        println!("  \x1b[90m💚 [NODE HEAL SIM]\x1b[0m \x1b[1;32mKnoten 4 wieder verbunden (Self-Healing ONLINE)...\x1b[0m");
                        node4_flapping_state = None;
                    }
                }

                // Periodic aggregated write batch output (every 1.5s)
                if last_write_batch_print.elapsed() >= Duration::from_millis(1500) {
                    if batch_writes_count > 0 {
                        let avg_ms = (batch_writes_latency_sum.as_secs_f64() * 1000.0) / (batch_writes_count as f64);
                        println!(
                            "  \x1b[90m✍️  [WRITE BATCH]\x1b[0m \x1b[1;32m{} Locks erstellt (200 OK)\x1b[0m | \x1b[1;35m{} Byte-Jahre\x1b[0m (F2F: {}, VIP: {}, Free: {}) | Avg Latenz: \x1b[1;32m{:.2}ms\x1b[0m",
                            batch_writes_count,
                            batch_writes_byte_years,
                            batch_writes_f2f,
                            batch_writes_vip,
                            batch_writes_free,
                            avg_ms
                        );
                        batch_writes_count = 0;
                        batch_writes_byte_years = 0;
                        batch_writes_f2f = 0;
                        batch_writes_vip = 0;
                        batch_writes_free = 0;
                        batch_writes_latency_sum = Duration::ZERO;
                    }
                    last_write_batch_print = Instant::now();
                }

                // Periodic aggregated read batch output (every 1.5s)
                if last_read_batch_print.elapsed() >= Duration::from_millis(1500) {
                    if batch_reads_count > 0 {
                        let avg_ms = (batch_reads_latency_sum.as_secs_f64() * 1000.0) / (batch_reads_count as f64);
                        println!(
                            "  \x1b[90m🔍 [READ BATCH]\x1b[0m \x1b[1;36m{} Status-Abfragen (200 OK)\x1b[0m | Avg Latenz: \x1b[1;32m{:.2}ms\x1b[0m",
                            batch_reads_count,
                            avg_ms
                        );
                        batch_reads_count = 0;
                        batch_reads_latency_sum = Duration::ZERO;
                    }
                    last_read_batch_print = Instant::now();
                }

                // Execute operations batch for this tick (6 to 12 ops ~= 200 ops/s ~= 1,000 ops/hour)
                let ops_this_tick = rng.gen_range(6..=12);
                for _ in 0..ops_this_tick {
                    // Organic traffic wave: ~20% writes, varying sinusoidally
                    let write_prob = (0.20 + 0.08 * (elapsed_secs / 10.0).sin()).clamp(0.08, 0.40);
                    let is_write = rng.gen_bool(write_prob);

                    let gateway_idx = rng.gen_range(0..instances.len());
                    let gateway = &instances[gateway_idx];

                    if is_write {
                        write_counter += 1;
                        // Check if we should inject an intentional double-spend collision (~2% probability)
                        let should_inject_collision = !spent_history.is_empty() && rng.gen_bool(0.02);

                        let (req, tag_display, byte_years_est) = if should_inject_collision {
                            let (voucher_id, prev_output) = &spent_history[rng.gen_range(0..spent_history.len())];
                            let fake_receiver_key = SigningKey::generate(&mut rng);
                            let fake_receiver_pub = fake_receiver_key.verifying_key().to_bytes();
                            let fake_receiver_ephemeral_pub_hash = Some(*blake3::hash(&fake_receiver_pub).as_bytes());

                            let timestamp = (sim_now_ms as u128).max(prev_output.last_timestamp + 2000);
                            let sender_pub = prev_output.owner_key.verifying_key().to_bytes();

                            let mut h = blake3::Hasher::new();
                            h.update(prev_output.ds_tag.as_bytes());
                            h.update(&timestamp.to_le_bytes());
                            h.update(&sender_pub);
                            let tx_hash = *h.finalize().as_bytes();

                            let mut conflicting_spend = L2LockRequest {
                                auth: L2AuthPayload {
                                    ephemeral_pubkey: sender_pub,
                                    auth_signature: None,
                                },
                                layer2_voucher_id: voucher_id.clone(),
                                ds_tag: Some(prev_output.ds_tag.clone()),
                                transaction_hash: tx_hash,
                                is_genesis: false,
                                sender_ephemeral_pub: sender_pub,
                                receiver_ephemeral_pub_hash: fake_receiver_ephemeral_pub_hash,
                                change_ephemeral_pub_hash: None,
                                layer2_signature: [0u8; 64],
                                trap_r: Some("none".into()),
                                trap_s: Some("none".into()),
                                encrypted_timestamp: timestamp,
                                deletable_at: None,
                                privacy_guard: None,
                            };
                            let payload_hash = calculate_l2_payload_hash(&conflicting_spend);
                            conflicting_spend.layer2_signature = prev_output.owner_key.sign(&payload_hash).to_bytes();

                            let mut conflicting_chain = prev_output.chain_history.clone();
                            conflicting_chain.push(conflicting_spend);

                            let chain_req = L2ChainLockRequest {
                                auth: L2AuthPayload {
                                    ephemeral_pubkey: sender_pub,
                                    auth_signature: None,
                                },
                                layer2_voucher_id: voucher_id.clone(),
                                chain: conflicting_chain,
                            };

                            let tag_display = format!("Parent: {}... (Collision 409)", &prev_output.ds_tag[..8.min(prev_output.ds_tag.len())]);
                            (IngressRequest::Chain(chain_req), tag_display, 0u64)
                        } else {
                            // Decide write action: Genesis Lock (~30%) or Spend / Split Lock (~70%)
                            let should_create_genesis = active_vouchers.is_empty() || rng.gen_bool(0.30);

                            if should_create_genesis {
                                let v_num: u64 = rng.gen_range(100000..999999);
                                let v_hash = *blake3::hash(format!("genesis_{}_{}", v_num, write_counter).as_bytes()).as_bytes();
                                let v_id = bs58::encode(&v_hash).into_string();

                                // Realistic multi-tier voucher validity (Spec 09 & HMC):
                                // 10% short/event vouchers (30–90 days: ~16–48 Byte-Years)
                                // 30% 1-year vouchers (365 days: 192 Byte-Years)
                                // 30% 2-to-3-year vouchers (730–1095 days: 384–576 Byte-Years)
                                // 30% 5-year long-term root vouchers (1825 days: 960 Byte-Years)
                                let r_ttl: f64 = rng.gen_range(0.0..1.0);
                                let duration_virtual_ms = if r_ttl < 0.10 {
                                    rng.gen_range(30 * 86_400_000..=90 * 86_400_000)
                                } else if r_ttl < 0.40 {
                                    365 * 86_400_000
                                } else if r_ttl < 0.70 {
                                    rng.gen_range(2 * 365 * 86_400_000..=3 * 365 * 86_400_000)
                                } else {
                                    5 * 365 * 86_400_000
                                };
                                let valid_until = sim_now_ms + duration_virtual_ms;
                                let by = ByteYears::from_ttl_seconds((duration_virtual_ms / 1000).max(1));

                                let issuer_key = SigningKey::generate(&mut rng);
                                let genesis = make_hmc_genesis(&v_id, valid_until, sim_now_ms, &issuer_key);
                                let genesis_tx_hash = genesis.transaction_hash;
                                let genesis_tag = bs58::encode(&genesis_tx_hash).into_string();
                                let genesis_spend_tag = bs58::encode(
                                    blake3::hash(format!("{}:out0", genesis_tag).as_bytes()).as_bytes(),
                                )
                                .into_string();

                                let unspent = UnspentOutput {
                                    ds_tag: genesis_spend_tag,
                                    owner_key: issuer_key,
                                    chain_history: vec![genesis.clone()],
                                    last_timestamp: sim_now_ms as u128,
                                };

                                active_vouchers.push(SimVoucher {
                                    voucher_id: v_id.clone(),
                                    valid_until_ms: valid_until,
                                    unspent_outputs: vec![unspent],
                                });

                                if active_vouchers.len() > 100 {
                                    active_vouchers.remove(0);
                                }

                                let tag_display = format!("Tag: {}...", &genesis_tag[..8.min(genesis_tag.len())]);
                                (IngressRequest::Single(genesis), tag_display, by)
                            } else {
                                let v_idx = rng.gen_range(0..active_vouchers.len());
                                let voucher = &mut active_vouchers[v_idx];
                                let out_idx = rng.gen_range(0..voucher.unspent_outputs.len());
                                let output = voucher.unspent_outputs.remove(out_idx);
                                let remaining_secs = voucher.valid_until_ms.saturating_sub(sim_now_ms) / 1000;
                                let by = ByteYears::from_ttl_seconds(remaining_secs.max(1));

                                // Save to spent history for potential double-spend collision injection
                                spent_history.push((voucher.voucher_id.clone(), UnspentOutput {
                                    ds_tag: output.ds_tag.clone(),
                                    owner_key: SigningKey::from_bytes(&output.owner_key.to_bytes()),
                                    chain_history: output.chain_history.clone(),
                                    last_timestamp: output.last_timestamp,
                                }));
                                if spent_history.len() > 50 {
                                    spent_history.remove(0);
                                }

                                let receiver_key = SigningKey::generate(&mut rng);
                                let receiver_pub = receiver_key.verifying_key().to_bytes();
                                let receiver_ephemeral_pub_hash = Some(*blake3::hash(&receiver_pub).as_bytes());

                                let is_split = rng.gen_bool(0.30);
                                let (change_key_opt, change_ephemeral_pub_hash) = if is_split {
                                    let change_key = SigningKey::generate(&mut rng);
                                    let change_pub = change_key.verifying_key().to_bytes();
                                    let change_hash = *blake3::hash(&change_pub).as_bytes();
                                    (Some(change_key), Some(change_hash))
                                } else {
                                    (None, None)
                                };

                                let timestamp = (sim_now_ms as u128).max(output.last_timestamp + 1000);
                                let sender_pub = output.owner_key.verifying_key().to_bytes();

                                let mut h = blake3::Hasher::new();
                                h.update(output.ds_tag.as_bytes());
                                h.update(&timestamp.to_le_bytes());
                                h.update(&sender_pub);
                                let tx_hash = *h.finalize().as_bytes();

                                let mut spend = L2LockRequest {
                                    auth: L2AuthPayload {
                                        ephemeral_pubkey: sender_pub,
                                        auth_signature: None,
                                    },
                                    layer2_voucher_id: voucher.voucher_id.clone(),
                                    ds_tag: Some(output.ds_tag.clone()),
                                    transaction_hash: tx_hash,
                                    is_genesis: false,
                                    sender_ephemeral_pub: sender_pub,
                                    receiver_ephemeral_pub_hash,
                                    change_ephemeral_pub_hash,
                                    layer2_signature: [0u8; 64],
                                    trap_r: Some("none".into()),
                                    trap_s: Some("none".into()),
                                    encrypted_timestamp: timestamp,
                                    deletable_at: None,
                                    privacy_guard: None,
                                };
                                let payload_hash = calculate_l2_payload_hash(&spend);
                                spend.layer2_signature = output.owner_key.sign(&payload_hash).to_bytes();

                                let mut updated_chain = output.chain_history.clone();
                                updated_chain.push(spend);

                                let chain_req = L2ChainLockRequest {
                                    auth: L2AuthPayload {
                                        ephemeral_pubkey: sender_pub,
                                        auth_signature: None,
                                    },
                                    layer2_voucher_id: voucher.voucher_id.clone(),
                                    chain: updated_chain.clone(),
                                };

                                let receiver_tag = bs58::encode(&tx_hash).into_string();
                                voucher.unspent_outputs.push(UnspentOutput {
                                    ds_tag: receiver_tag,
                                    owner_key: receiver_key,
                                    chain_history: updated_chain.clone(),
                                    last_timestamp: timestamp,
                                });

                                if let (Some(change_key), Some(change_hash)) = (change_key_opt, change_ephemeral_pub_hash) {
                                    let change_tag = bs58::encode(&change_hash).into_string();
                                    voucher.unspent_outputs.push(UnspentOutput {
                                        ds_tag: change_tag,
                                        owner_key: change_key,
                                        chain_history: updated_chain,
                                        last_timestamp: timestamp,
                                    });
                                }

                                let tag_display = if is_split {
                                    format!("Parent: {}... (Split 2x)", &output.ds_tag[..8.min(output.ds_tag.len())])
                                } else {
                                    format!("Parent: {}...", &output.ds_tag[..8.min(output.ds_tag.len())])
                                };

                                (IngressRequest::Chain(chain_req), tag_display, by)
                            }
                        };

                        let r_tier: f64 = rng.gen_range(0.0..1.0);
                        let sim_tier = if r_tier < 0.50 {
                            SimTier::F2F
                        } else if r_tier < 0.80 {
                            let vip_token = if rng.gen_bool(0.5) {
                                "pos_terminal_vip_1"
                            } else {
                                "merchant_checkout_vip_2"
                            };
                            SimTier::Vip(vip_token)
                        } else {
                            SimTier::Free
                        };

                        match post_lock_http(gateway.rpc_addr, &req, &sim_tier).await {
                            Ok((_status, duration, resp)) => {
                                match &resp.verdict {
                                    L2Verdict::Conflict { .. } => {
                                        println!(
                                            "  \x1b[1;31m💥 [COLLISION 409]\x1b[0m Gateway \x1b[1;34mKnoten {} (: {})\x1b[0m | {} | \x1b[1;31mDouble-Spend erfolgreich abgewiesen!\x1b[0m | Latenz: \x1b[1;32m{:.2}ms\x1b[0m",
                                            gateway.id + 1,
                                            gateway.rpc_addr.port(),
                                            tag_display,
                                            duration.as_secs_f64() * 1000.0,
                                        );
                                    }
                                    L2Verdict::Verified { .. } | L2Verdict::Ok { .. } => {
                                        batch_writes_count += 1;
                                        batch_writes_byte_years += byte_years_est;
                                        total_byte_years_consumed += byte_years_est;
                                        batch_writes_latency_sum += duration;
                                        match &sim_tier {
                                            SimTier::F2F => batch_writes_f2f += 1,
                                            SimTier::Vip(_) => batch_writes_vip += 1,
                                            SimTier::Free => batch_writes_free += 1,
                                        }
                                    }
                                    L2Verdict::Rejected { reason } => {
                                        eprintln!("\x1b[1;33m[TX #{:04}] Rejected: {}\x1b[0m", write_counter, reason);
                                    }
                                    _ => {}
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "\x1b[1;31m[TX #{:04}] Fehler beim Senden an Knoten {}: {}\x1b[0m",
                                    write_counter,
                                    gateway.id + 1,
                                    e
                                );
                            }
                        }
                    } else {
                        // Reads: 75% POST /v1/status, 25% GET /v1/node-status
                        total_reads_count += 1;
                        let should_post_status = !active_vouchers.is_empty() && rng.gen_bool(0.75);

                        if should_post_status {
                            let v_idx = rng.gen_range(0..active_vouchers.len());
                            let voucher = &active_vouchers[v_idx];
                            if let Some(output) = voucher.unspent_outputs.first() {
                                let status_req = L2StatusQuery {
                                    auth: L2AuthPayload {
                                        ephemeral_pubkey: [0u8; 32],
                                        auth_signature: None,
                                    },
                                    layer2_voucher_id: voucher.voucher_id.clone(),
                                    challenge_ds_tag: output.ds_tag.clone(),
                                    locator_prefixes: vec![],
                                    read_quorum: 1,
                                };
                                if let Ok((_status, duration, _envelope)) = post_status_http(gateway.rpc_addr, &status_req).await {
                                    batch_reads_count += 1;
                                    batch_reads_latency_sum += duration;
                                }
                            } else if let Ok((_status, duration, _node_status)) = get_status_http(gateway.rpc_addr).await {
                                batch_reads_count += 1;
                                batch_reads_latency_sum += duration;
                            }
                        } else if let Ok((_status, duration, _node_status)) = get_status_http(gateway.rpc_addr).await {
                            batch_reads_count += 1;
                            batch_reads_latency_sum += duration;
                        }
                    }
                }
            }
        }
    }

    println!("\x1b[1;32m✨ Simulation erfolgreich beendet.\x1b[0m");
    Ok(())
}
