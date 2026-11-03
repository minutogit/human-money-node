//! Real multi-process OS daemon cluster test (Milestone M5.1 / NODE-002).
//!
//! Spawns three independent `humoco` daemon processes communicating over real
//! loopback QUIC and HTTP sockets, asserting:
//! 1. Autonomous F2F cluster peering and heartbeat connectivity (`connected_peers >= 2`).
//! 2. Multi-node quorum signature collection and durable persistence on `POST /v1/lock`.
//! 3. Idempotent replay handling on secondary nodes.
//! 4. 409 Conflict rejection for double-spend attempts on the same parent.
//! 5. Graceful shutdown via `humoco stop`, process exit verification, and offline `humoco db compact`.

use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use humoco_node::{
    api::hmc::{calculate_l2_payload_hash, L2AuthPayload, L2LockRequest},
    config::NodeConfig,
    identity::NodeIdentity,
};
use tempfile::tempdir;

const SHARED_F2F_TOKEN: &str = "f2f_0123456789abcdef0123456789abcdef";

/// Drop-safe child process guard that guarantees termination on drop.
/// Prevents orphan `humoco` processes from leaking even if an assertion panics.
struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.wait()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Allocates distinct free TCP and UDP port pairs outside the OS ephemeral port range
/// (`19000..29999`, avoiding `32768..60999` where outgoing client sockets could steal a port).
/// Avoids `TcpListener::bind` + `listen()` pre-binding so user-space/sandbox TCP stacks do not
/// linger on closed listening sockets before child daemons bind.
fn allocate_distinct_ports(count: usize) -> Vec<(u16, u16)> {
    let seed = (std::process::id() as u64)
        .wrapping_mul(131)
        .wrapping_add(test_now_ms() % 9_973);
    let mut candidate = 19_000u16 + ((seed % 9_000) as u16);

    let mut udp_sockets = Vec::with_capacity(count);
    let mut pairs = Vec::with_capacity(count);

    while pairs.len() < count {
        let rpc_port = candidate;
        let p2p_port = candidate.saturating_add(1);
        candidate = if candidate >= 29_900 {
            19_000
        } else {
            candidate + 10
        };

        let rpc_addr = SocketAddr::from(([127, 0, 0, 1], rpc_port));
        let tcp_free = TcpStream::connect_timeout(&rpc_addr, Duration::from_millis(10)).is_err();
        if tcp_free {
            if let Ok(udp) = UdpSocket::bind(("127.0.0.1", p2p_port)) {
                udp_sockets.push(udp);
                pairs.push((rpc_port, p2p_port));
            }
        }
    }

    drop(udp_sockets);
    pairs
}

fn test_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn authenticate_root_fixture(req: &mut L2LockRequest, key: &SigningKey) {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(req.transaction_hash);
    hash.update(req.sender_ephemeral_pub);
    hash.update(req.deletable_at.as_deref().unwrap().as_bytes());
    req.layer2_voucher_id = hex::encode(hash.finalize());
    let mut proof = humoco_proto::causal::CausalOutputProof {
        version: 1,
        voucher_id: req.layer2_voucher_id.clone(),
        transaction_id: req.transaction_hash,
        state_hash: req.transaction_hash,
        sender_pubkey: req.sender_ephemeral_pub,
        receiver_pubkey_hash: None,
        change_pubkey_hash: None,
        root_valid_until_ms: req.deletable_at.as_ref().unwrap().parse().unwrap(),
        is_root: true,
        signature: [0; 64],
    };
    proof.signature = key.sign(&proof.digest().unwrap()).to_bytes();
    req.causal_output = Some(proof);
    req.layer2_signature = key.sign(&calculate_l2_payload_hash(req)).to_bytes();
}

fn make_test_hmc_genesis(
    parent_hex: &str,
    valid_until_ms: u64,
    sender_key: &SigningKey,
) -> L2LockRequest {
    let sender_pub = sender_key.verifying_key().to_bytes();
    let tx_hash = *blake3::hash(parent_hex.as_bytes()).as_bytes();
    let del_str = valid_until_ms.to_string();

    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: format!("voucher_{}", parent_hex),
        ds_tag: None,
        transaction_hash: tx_hash,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: test_now_ms(),
        deletable_at: Some(del_str),
        privacy_guard: None,
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    authenticate_root_fixture(&mut req, sender_key);
    req
}

fn make_test_hmc_spend(
    voucher_id: &str,
    ds_tag: &str,
    tx_hash: [u8; 32],
    sender_key: &SigningKey,
) -> L2LockRequest {
    let sender_pub = sender_key.verifying_key().to_bytes();

    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: Some(ds_tag.to_string()),
        transaction_hash: tx_hash,
        is_genesis: false,
        sender_ephemeral_pub: sender_pub,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: test_now_ms(),
        deletable_at: None,
        privacy_guard: None,
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

async fn post_lock_with_retry(
    client: &reqwest::Client,
    port: u16,
    req: &L2LockRequest,
) -> (u16, serde_json::Value) {
    let url = format!("http://127.0.0.1:{}/v1/lock", port);
    let mut last_status = 0u16;
    let mut last_val = serde_json::Value::Null;
    for _ in 0..60 {
        if let Ok(res) = client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Peer-Token", SHARED_F2F_TOKEN)
            .json(req)
            .send()
            .await
        {
            let status = res.status().as_u16();
            let body_bytes = res.bytes().await.unwrap_or_default();
            let val = serde_json::from_slice::<serde_json::Value>(&body_bytes)
                .unwrap_or(serde_json::Value::Null);
            last_status = status;
            last_val = val.clone();
            if status == 503 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            return (status, val);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "post_lock_with_retry timed out on port {} (last status={}, body={})",
        port, last_status, last_val
    );
}

#[tokio::test]
async fn test_m5_three_independent_daemon_processes_quorum_persistence_and_compaction() {
    // 1. Prepare 3 isolated temporary environments and Argon2d identities first
    let mut temp_dirs = Vec::with_capacity(3);
    let mut identities = Vec::with_capacity(3);
    let mut key_paths = Vec::with_capacity(3);
    for _ in 0..3 {
        let dir = tempdir().expect("tempdir");
        let key_path = dir.path().join("node_key.bin");
        let identity = NodeIdentity::generate();
        identity.save_to_file(&key_path).expect("save identity");
        key_paths.push(key_path);
        identities.push(identity);
        temp_dirs.push(dir);
    }

    // 2. Allocate distinct non-ephemeral port pairs (HTTP RPC, QUIC P2P) right before config/spawn
    let ports = allocate_distinct_ports(3);

    // Configure all 3 nodes in a full F2F clique
    let mut config_paths = Vec::with_capacity(3);
    for i in 0..3 {
        let mut config = NodeConfig::default();
        config.network.p2p_listen_addr = format!("127.0.0.1:{}", ports[i].1).parse().unwrap();
        config.network.rpc_listen_addr = format!("127.0.0.1:{}", ports[i].0).parse().unwrap();
        config.network.simulation_mode = true;
        config.network.fast_ticker_interval_secs = Some(1);
        config.storage.data_dir = temp_dirs[i].path().join("data");
        config.identity.key_path = key_paths[i].clone();
        config.network.control_socket = Some(temp_dirs[i].path().join("humoco.sock"));
        config.f2f.tokens.push(SHARED_F2F_TOKEN.to_string());

        // Peer with the other two nodes in the clique
        for j in 0..3 {
            if i != j {
                let peer_conn_str = format!(
                    "{}@127.0.0.1:{}",
                    identities[j].public_key_hex(),
                    ports[j].1
                );
                config.f2f.peers.push(peer_conn_str);
                config
                    .f2f
                    .trusted_pubkeys
                    .push(identities[j].public_key_hex());
            }
        }

        let cfg_path = temp_dirs[i].path().join("humoco.toml");
        config.save_to_file(&cfg_path).expect("save humoco.toml");
        config_paths.push(cfg_path);
    }

    // 3. Spawn all 3 independent humoco OS processes wrapped in ChildGuard
    let mut guards = Vec::with_capacity(3);
    for cfg_path in &config_paths {
        let child = Command::new(env!("CARGO_BIN_EXE_humoco"))
            .arg("run")
            .arg("--config")
            .arg(cfg_path)
            .arg("--bootstrap-new-region")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn humoco daemon");
        guards.push(ChildGuard { child });
    }

    // 4. Poll GET /healthz and humoco status --config <path> --json until all 3 processes report connected_peers >= 2
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(1500))
        .build()
        .expect("build reqwest client");

    let poll_start = Instant::now();
    let max_poll = Duration::from_secs(30);
    let mut cluster_ready = false;

    while poll_start.elapsed() < max_poll {
        // Fast-fail check: verify no child process has crashed prematurely
        for (idx, guard) in guards.iter_mut().enumerate() {
            if let Some(status) = guard.child.try_wait().expect("try_wait") {
                let mut err_buf = String::new();
                if let Some(mut stderr) = guard.child.stderr.take() {
                    use std::io::Read;
                    let _ = stderr.read_to_string(&mut err_buf);
                }
                let mut out_buf = String::new();
                if let Some(mut stdout) = guard.child.stdout.take() {
                    use std::io::Read;
                    let _ = stdout.read_to_string(&mut out_buf);
                }
                panic!(
                    "Daemon process {} exited prematurely with status: {}\nSTDOUT:\n{}\nSTDERR:\n{}",
                    idx + 1,
                    status,
                    out_buf,
                    err_buf
                );
            }
        }

        // Check HTTP /healthz on all 3 nodes
        let mut healthy_http = 0;
        for (rpc_port, _) in &ports {
            let healthz_url = format!("http://127.0.0.1:{}/healthz", rpc_port);
            if let Ok(resp) = http_client.get(&healthz_url).send().await {
                if resp.status().is_success() {
                    healthy_http += 1;
                }
            }
        }

        if healthy_http == 3 {
            // Check connected_peers >= 2 via humoco status --config <path> --json
            let mut connected_nodes = 0;
            for cfg_path in &config_paths {
                let status_output = Command::new(env!("CARGO_BIN_EXE_humoco"))
                    .arg("status")
                    .arg("--config")
                    .arg(cfg_path)
                    .arg("--json")
                    .output();
                if let Ok(output) = status_output {
                    if output.status.success() {
                        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&output.stdout)
                        {
                            let peers = val
                                .get("peers_connected")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            if peers >= 2 {
                                connected_nodes += 1;
                            }
                        }
                    }
                }
            }

            if connected_nodes == 3 {
                cluster_ready = true;
                break;
            }
        }

        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    assert!(
        cluster_ready,
        "Cluster failed to form 3-node connected clique within timeout"
    );

    // Allow initial boot heartbeat jitter (300..600ms) + 2s simulation HRW ticket incubation
    // (`SIM_HRW_INCUBATION_DURATION`) to complete so all 3 nodes are HRW-eligible (`Q(3) = 3/3`).
    tokio::time::sleep(Duration::from_millis(3200)).await;

    // 5. Submit valid genesis root lock and spend lock to Process 1
    let sender_key = SigningKey::from_bytes(&[0x42u8; 32]);
    let parent_hex = "aa".repeat(32);
    let now = test_now_ms();
    let root = make_test_hmc_genesis(&parent_hex, now + 600_000, &sender_key);

    // Register root anchor across all 3 nodes
    for (i, (rpc_port, _)) in ports.iter().enumerate() {
        let (status, _) = post_lock_with_retry(&http_client, *rpc_port, &root).await;
        assert!(
            status == 200 || status == 201,
            "Root anchor registration must return 200 or 201 on node {}, got {}",
            i + 1,
            status
        );
    }

    // Submit spend lock to Process 1 (collects provisional quorum across all 3 nodes over real QUIC)
    let spend_req = make_test_hmc_spend(
        &root.layer2_voucher_id,
        "m5-spend-slot-01",
        [0x11u8; 32],
        &sender_key,
    );
    let (status1, val1) = post_lock_with_retry(&http_client, ports[0].0, &spend_req).await;
    assert!(
        status1 == 200 || status1 == 201,
        "Expected HTTP 200 or 201 on Process 1 with provisional quorum, got {} ({})",
        status1,
        val1
    );
    let sig_count = val1["quorum_certificate"]["signatures"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    assert_eq!(
        sig_count, 3,
        "Expected 3/3 provisional quorum signatures across all 3 OS processes, got {}: {}",
        sig_count, val1
    );

    // 6. Replay exact same spend lock to Process 2 -> idempotent success (200 / 201)
    let (status2, _) = post_lock_with_retry(&http_client, ports[1].0, &spend_req).await;
    assert!(
        status2 == 200 || status2 == 201,
        "Expected idempotent HTTP 200 or 201 on Process 2 replay, got {}",
        status2
    );

    // 7. Submit conflicting double-spend on the same parent to Process 3 -> 409 Conflict
    let conflict_key = SigningKey::from_bytes(&[0x99u8; 32]);
    let conflict_req = make_test_hmc_spend(
        &root.layer2_voucher_id,
        "m5-spend-slot-01", // identical ds_tag = identical parent_lock
        [0xEEu8; 32],       // diverging transaction hash
        &conflict_key,
    );
    let (status3, _) = post_lock_with_retry(&http_client, ports[2].0, &conflict_req).await;
    assert_eq!(
        status3, 409,
        "Expected HTTP 409 Conflict on Process 3 for double-spend, got {}",
        status3
    );

    // 8. Gracefully stop Process 1 via humoco stop --config <path1>
    let stop_status1 = Command::new(env!("CARGO_BIN_EXE_humoco"))
        .arg("stop")
        .arg("--config")
        .arg(&config_paths[0])
        .status()
        .expect("humoco stop node 1");
    assert!(
        stop_status1.success(),
        "humoco stop node 1 must exit with 0"
    );

    // Verify Process 1 OS process has exited cleanly
    let exit1 = guards[0].wait().expect("wait for child 1");
    assert!(
        exit1.success(),
        "Process 1 child must exit cleanly with code 0"
    );

    // Run humoco db compact on Process 1 database and assert exit code 0
    let compact_status = Command::new(env!("CARGO_BIN_EXE_humoco"))
        .arg("db")
        .arg("compact")
        .arg("--config")
        .arg(&config_paths[0])
        .arg("--json")
        .status()
        .expect("humoco db compact node 1");
    assert!(
        compact_status.success(),
        "humoco db compact node 1 must exit with 0"
    );

    // 9. Cleanly stop Processes 2 and 3 via humoco stop
    for i in 1..3 {
        let stop_status = Command::new(env!("CARGO_BIN_EXE_humoco"))
            .arg("stop")
            .arg("--config")
            .arg(&config_paths[i])
            .status()
            .expect("humoco stop node");
        assert!(
            stop_status.success(),
            "humoco stop node {} must exit with 0",
            i + 1
        );
        let exit = guards[i].wait().expect("wait for child exit");
        assert!(
            exit.success(),
            "Process {} child must exit cleanly with code 0",
            i + 1
        );
    }
}
