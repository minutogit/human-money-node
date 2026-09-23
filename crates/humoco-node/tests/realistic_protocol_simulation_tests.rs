use std::net::SocketAddr;
use std::time::Duration;
use axum::http::StatusCode;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use humoco_node::{
    api::{
        hmc::{
            calculate_l2_payload_hash_raw, L2AuthPayload, L2ChainLockRequest, L2LockRequest,
            L2ResponseEnvelope, L2StatusQuery, L2Verdict, TRAP_NONE_PLACEHOLDER,
        },
        NodeStatusResponse,
    },
    config::NodeConfig,
    daemon::{BoundAddrs, NodeDaemon},
    error::NodeError,
    identity::NodeIdentity,
    storage::compute_hmc_canonical_hash,
};

fn test_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// HmcTestWallet
// ---------------------------------------------------------------------------

/// Realistic HMC V3 client wallet helper with Ed25519 signing capabilities.
pub struct HmcTestWallet {
    pub signing_key: SigningKey,
}

impl Default for HmcTestWallet {
    fn default() -> Self {
        Self::new()
    }
}

impl HmcTestWallet {
    /// Creates a fresh Ed25519 keypair for test transactions.
    pub fn new() -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        Self { signing_key }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Constructs a signed HMC V3 Genesis Lock request.
    pub fn make_genesis(
        &self,
        voucher_id: &str,
        valid_until_ms: u64,
        timestamp: u128,
    ) -> L2LockRequest {
        let sender_pub = self.pubkey_bytes();
        let mut h = blake3::Hasher::new();
        h.update(voucher_id.as_bytes());
        h.update(&timestamp.to_le_bytes());
        h.update(&sender_pub);
        let tx_hash = *h.finalize().as_bytes();

        let lookup_tag = bs58::encode(&tx_hash).into_string();
        let del_str = valid_until_ms.to_string();
        let payload_hash = calculate_l2_payload_hash_raw(
            TRAP_NONE_PLACEHOLDER,
            &lookup_tag,
            &tx_hash,
            &sender_pub,
            "none",
            "none",
            timestamp,
            Some(&del_str),
            "",
        );
        let sig = self.signing_key.sign(&payload_hash);
        L2LockRequest {
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
            layer2_signature: sig.to_bytes(),
            trap_r: Some("none".into()),
            trap_s: Some("none".into()),
            encrypted_timestamp: timestamp,
            deletable_at: Some(del_str),
            privacy_guard: None,
        }
    }

    /// Constructs a signed HMC V3 successor spend / split request.
    pub fn make_successor(
        &self,
        voucher_id: &str,
        ds_tag: &str,
        timestamp: u128,
        change_hash: Option<[u8; 32]>,
        receiver_hash: Option<[u8; 32]>,
    ) -> L2LockRequest {
        let sender_pub = self.pubkey_bytes();
        let mut h = blake3::Hasher::new();
        h.update(ds_tag.as_bytes());
        h.update(&timestamp.to_le_bytes());
        h.update(&sender_pub);
        let tx_hash = *h.finalize().as_bytes();

        let payload_hash = calculate_l2_payload_hash_raw(
            voucher_id,
            ds_tag,
            &tx_hash,
            &sender_pub,
            "none",
            "none",
            timestamp,
            None,
            "",
        );
        let sig = self.signing_key.sign(&payload_hash);
        L2LockRequest {
            auth: L2AuthPayload {
                ephemeral_pubkey: sender_pub,
                auth_signature: None,
            },
            layer2_voucher_id: voucher_id.to_string(),
            ds_tag: Some(ds_tag.to_string()),
            transaction_hash: tx_hash,
            is_genesis: false,
            sender_ephemeral_pub: sender_pub,
            receiver_ephemeral_pub_hash: receiver_hash,
            change_ephemeral_pub_hash: change_hash,
            layer2_signature: sig.to_bytes(),
            trap_r: Some("none".into()),
            trap_s: Some("none".into()),
            encrypted_timestamp: timestamp,
            deletable_at: None,
            privacy_guard: None,
        }
    }

    /// Constructs a signed successor lock with a specific transaction hash (e.g. for canonical resolver tests).
    pub fn make_successor_with_custom_tx(
        &self,
        voucher_id: &str,
        ds_tag: &str,
        tx_hash: [u8; 32],
        timestamp: u128,
        change_hash: Option<[u8; 32]>,
        receiver_hash: Option<[u8; 32]>,
    ) -> L2LockRequest {
        let sender_pub = self.pubkey_bytes();
        let payload_hash = calculate_l2_payload_hash_raw(
            voucher_id,
            ds_tag,
            &tx_hash,
            &sender_pub,
            "none",
            "none",
            timestamp,
            None,
            "",
        );
        let sig = self.signing_key.sign(&payload_hash);
        L2LockRequest {
            auth: L2AuthPayload {
                ephemeral_pubkey: sender_pub,
                auth_signature: None,
            },
            layer2_voucher_id: voucher_id.to_string(),
            ds_tag: Some(ds_tag.to_string()),
            transaction_hash: tx_hash,
            is_genesis: false,
            sender_ephemeral_pub: sender_pub,
            receiver_ephemeral_pub_hash: receiver_hash,
            change_ephemeral_pub_hash: change_hash,
            layer2_signature: sig.to_bytes(),
            trap_r: Some("none".into()),
            trap_s: Some("none".into()),
            encrypted_timestamp: timestamp,
            deletable_at: None,
            privacy_guard: None,
        }
    }

    /// Constructs an atomic chain lock request.
    pub fn make_chain(
        &self,
        voucher_id: &str,
        chain: Vec<L2LockRequest>,
    ) -> L2ChainLockRequest {
        L2ChainLockRequest {
            auth: L2AuthPayload {
                ephemeral_pubkey: self.pubkey_bytes(),
                auth_signature: None,
            },
            layer2_voucher_id: voucher_id.to_string(),
            chain,
        }
    }
}

// ---------------------------------------------------------------------------
// TestNode
// ---------------------------------------------------------------------------

/// Encapsulates a running node daemon in simulation tests.
pub struct TestNode {
    pub identity: NodeIdentity,
    pub config: NodeConfig,
    pub temp_dir: Option<TempDir>,
    pub cancel_token: CancellationToken,
    pub rpc_addr: SocketAddr,
    pub p2p_addr: SocketAddr,
    pub task_handle: Option<tokio::task::JoinHandle<Result<(), NodeError>>>,
}

impl TestNode {
    /// Creates a base config and identity in a given temporary directory.
    pub fn create_setup(temp: TempDir, _node_idx: usize) -> (NodeConfig, NodeIdentity, TempDir) {
        let identity = NodeIdentity::generate();
        let key_path = temp.path().join("node_key.bin");
        identity.save_to_file(&key_path).expect("save node identity key");

        let mut config = NodeConfig::default();
        config.network.p2p_listen_addr = "127.0.0.1:0".parse().unwrap();
        config.network.rpc_listen_addr = "127.0.0.1:0".parse().unwrap();
        config.storage.data_dir = temp.path().join("data");
        config.identity.key_path = key_path;
        config.network.control_socket = None;
        config.f2f.tokens.push("cluster_f2f_token".into());

        (config, identity, temp)
    }

    /// Spawns a new node daemon bound to dynamic ports.
    pub async fn spawn(
        mut config: NodeConfig,
        identity: NodeIdentity,
        temp_dir: TempDir,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let cancel_token = CancellationToken::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<BoundAddrs>();

        let daemon = NodeDaemon::with_bound_sender(
            config.clone(),
            identity.clone(),
            cancel_token.clone(),
            tx,
        );

        let task_handle = tokio::spawn(async move {
            daemon.run().await
        });

        let bound_addrs = tokio::time::timeout(Duration::from_secs(5), rx).await??;
        config.network.rpc_listen_addr = bound_addrs.rpc_addr;
        config.network.p2p_listen_addr = bound_addrs.p2p_addr;

        let node = Self {
            identity,
            config,
            temp_dir: Some(temp_dir),
            cancel_token,
            rpc_addr: bound_addrs.rpc_addr,
            p2p_addr: bound_addrs.p2p_addr,
            task_handle: Some(task_handle),
        };

        node.wait_until_ready().await?;
        Ok(node)
    }

    /// Polls the health endpoint until the daemon is ready to handle requests.
    pub async fn wait_until_ready(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for _ in 0..100 {
            if let Ok((status, status_dto)) = self.get_status().await {
                if status == StatusCode::OK && status_dto.status == "ok" {
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Err(format!(
            "Node {} failed to become ready on {}",
            self.identity.node_id_hex(),
            self.rpc_addr
        )
        .into())
    }

    /// Sends a raw HTTP JSON request to the node's REST API.
    pub async fn http_request(
        &self,
        method: &str,
        path: &str,
        body_json: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Result<(StatusCode, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        let mut stream = tokio::net::TcpStream::connect(self.rpc_addr).await?;
        let body_bytes = body_json.map(|s| s.as_bytes()).unwrap_or(&[]);

        let mut req_str = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            method, path, self.rpc_addr, body_bytes.len()
        );
        for (k, v) in headers {
            req_str.push_str(&format!("{}: {}\r\n", k, v));
        }
        req_str.push_str("\r\n");

        stream.write_all(req_str.as_bytes()).await?;
        if !body_bytes.is_empty() {
            stream.write_all(body_bytes).await?;
        }
        stream.flush().await?;

        let mut response_buf = Vec::new();
        stream.read_to_end(&mut response_buf).await?;

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
        Ok((status, body_part.to_vec()))
    }

    /// Queries the `/health` endpoint.
    pub async fn get_status(
        &self,
    ) -> Result<(StatusCode, NodeStatusResponse), Box<dyn std::error::Error + Send + Sync>> {
        let (status, body) = self.http_request("GET", "/health", None, &[]).await?;
        let resp: NodeStatusResponse = serde_json::from_slice(&body)?;
        Ok((status, resp))
    }

    /// Submits a single HMC lock request to `POST /v1/lock`.
    pub async fn post_hmc_lock(
        &self,
        req: &L2LockRequest,
    ) -> Result<(StatusCode, L2ResponseEnvelope), Box<dyn std::error::Error + Send + Sync>> {
        let json_body = serde_json::to_string(req)?;
        let (status, body) = self
            .http_request(
                "POST",
                "/v1/lock",
                Some(&json_body),
                &[
                    ("Content-Type", "application/json"),
                    ("X-Peer-Token", "cluster_f2f_token"),
                ],
            )
            .await?;
        let resp: L2ResponseEnvelope = serde_json::from_slice(&body)?;
        Ok((status, resp))
    }

    /// Submits an atomic chain lock request to `POST /v1/lock/chain`.
    pub async fn post_hmc_chain(
        &self,
        req: &L2ChainLockRequest,
    ) -> Result<(StatusCode, L2ResponseEnvelope), Box<dyn std::error::Error + Send + Sync>> {
        let json_body = serde_json::to_string(req)?;
        let (status, body) = self
            .http_request(
                "POST",
                "/v1/lock/chain",
                Some(&json_body),
                &[
                    ("Content-Type", "application/json"),
                    ("X-Peer-Token", "cluster_f2f_token"),
                ],
            )
            .await?;
        let resp: L2ResponseEnvelope = serde_json::from_slice(&body)?;
        Ok((status, resp))
    }

    /// Queries status of a voucher and challenge_ds_tag on `POST /v1/status`.
    pub async fn query_hmc_status(
        &self,
        voucher_id: &str,
        challenge_ds_tag: &str,
        sender_pub: [u8; 32],
    ) -> Result<(StatusCode, L2ResponseEnvelope), Box<dyn std::error::Error + Send + Sync>> {
        let query = L2StatusQuery {
            auth: L2AuthPayload {
                ephemeral_pubkey: sender_pub,
                auth_signature: None,
            },
            layer2_voucher_id: voucher_id.to_string(),
            challenge_ds_tag: challenge_ds_tag.to_string(),
            locator_prefixes: vec![],
            read_quorum: 1,
        };
        let json_body = serde_json::to_string(&query)?;
        let (status, body) = self
            .http_request(
                "POST",
                "/v1/status",
                Some(&json_body),
                &[
                    ("Content-Type", "application/json"),
                    ("X-Peer-Token", "cluster_f2f_token"),
                ],
            )
            .await?;
        let resp: L2ResponseEnvelope = serde_json::from_slice(&body)?;
        Ok((status, resp))
    }

    /// Gracefully stops the node daemon and waits for background tasks to terminate.
    pub async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.cancel_token.cancel();
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }
        Ok(())
    }

    /// Restarts the daemon using the same data directory, identity, and configuration.
    pub async fn restart(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.stop().await?;
        tokio::time::sleep(Duration::from_millis(50)).await;

        self.config.network.rpc_listen_addr = "127.0.0.1:0".parse().unwrap();
        self.config.network.p2p_listen_addr = "127.0.0.1:0".parse().unwrap();

        let cancel_token = CancellationToken::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<BoundAddrs>();

        let daemon = NodeDaemon::with_bound_sender(
            self.config.clone(),
            self.identity.clone(),
            cancel_token.clone(),
            tx,
        );

        let task_handle = tokio::spawn(async move {
            daemon.run().await
        });

        let bound_addrs = tokio::time::timeout(Duration::from_secs(5), rx).await??;

        self.cancel_token = cancel_token;
        self.rpc_addr = bound_addrs.rpc_addr;
        self.p2p_addr = bound_addrs.p2p_addr;
        self.task_handle = Some(task_handle);

        self.wait_until_ready().await?;
        Ok(())
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        self.cancel_token.cancel();
        if let Some(handle) = self.task_handle.take() {
            handle.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Scenario 1: Isolated Village Start (N=1+1=2) & Symmetric Mesh-Merge Sync
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "long-running simulation"]
async fn test_scenario_1_isolated_village_start_and_mesh_merge() {
    let temp1 = tempdir().expect("tempdir 1");
    let (mut cfg1, id1, temp1) = TestNode::create_setup(temp1, 0);

    let temp2 = tempdir().expect("tempdir 2");
    let (mut cfg2, id2, temp2) = TestNode::create_setup(temp2, 1);

    // Mutual F2F trusted pubkeys
    cfg1.f2f.trusted_pubkeys.push(id2.public_key_hex());
    cfg2.f2f.trusted_pubkeys.push(id1.public_key_hex());

    // 1. Spawn Node 1
    let mut node1 = TestNode::spawn(cfg1, id1, temp1).await.expect("spawn node 1");

    // 2. Configure Node 2 with Node 1's bound P2P address and spawn Node 2
    cfg2.f2f.peers.push(node1.p2p_addr.to_string());
    let mut node2 = TestNode::spawn(cfg2, id2, temp2).await.expect("spawn node 2");

    // 3. Interconnect peers before transactions
    node1.config.f2f.peers.push(node2.p2p_addr.to_string());
    node1.restart().await.expect("restart node 1");
    node2.config.f2f.peers = vec![node1.p2p_addr.to_string()];
    node2.restart().await.expect("restart node 2");

    // Wallets generate independent vouchers
    let wallet1 = HmcTestWallet::new();
    let wallet2 = HmcTestWallet::new();
    let now = test_now_ms();
    let valid_until = now + 600_000;

    let voucher_1 = "village_voucher_alpha_01";
    let voucher_2 = "village_voucher_beta_02";

    let genesis1 = wallet1.make_genesis(voucher_1, valid_until, 100);
    let genesis1_tag = bs58::encode(&genesis1.transaction_hash).into_string();

    let genesis2 = wallet2.make_genesis(voucher_2, valid_until, 100);
    let genesis2_tag = bs58::encode(&genesis2.transaction_hash).into_string();

    // 4. Lock voucher 1 on Node 1
    let (status1, resp1) = node1.post_hmc_lock(&genesis1).await.expect("lock genesis 1");
    assert_eq!(status1, StatusCode::CREATED);
    assert!(matches!(resp1.verdict, L2Verdict::Verified { .. }));

    // 5. Lock voucher 2 on Node 2
    let (status2, resp2) = node2.post_hmc_lock(&genesis2).await.expect("lock genesis 2");
    assert_eq!(status2, StatusCode::CREATED);
    assert!(matches!(resp2.verdict, L2Verdict::Verified { .. }));

    // 6. Mesh Merge: Node 1 pulls from running Node 2
    node1.config.f2f.peers = vec![node2.p2p_addr.to_string()];
    node1.restart().await.expect("restart node 1 to pull v2");
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Node 2 pulls from running Node 1
    node2.config.f2f.peers = vec![node1.p2p_addr.to_string()];
    node2.restart().await.expect("restart node 2 to pull v1");
    tokio::time::sleep(Duration::from_millis(600)).await;

    // 7. Await symmetric mesh merge sync between Node 1 and Node 2
    let mut synced = false;
    for _ in 0..70 {
        let n2_has_v1 = node2
            .query_hmc_status(voucher_1, &genesis1_tag, wallet1.pubkey_bytes())
            .await
            .map(|(s, r)| s == StatusCode::OK && matches!(r.verdict, L2Verdict::Verified { .. }))
            .unwrap_or(false);

        let n1_has_v2 = node1
            .query_hmc_status(voucher_2, &genesis2_tag, wallet2.pubkey_bytes())
            .await
            .map(|(s, r)| s == StatusCode::OK && matches!(r.verdict, L2Verdict::Verified { .. }))
            .unwrap_or(false);

        if n2_has_v1 && n1_has_v2 {
            synced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(synced, "Nodes 1 and 2 must symmetrically mesh-merge state");

    // 8. Follow-up payment for Voucher 1 submitted to Node 2 (which originally didn't hold it)
    let succ1 = wallet1.make_successor(voucher_1, "village_succ_tag_01", 200, None, None);
    let (succ1_status, succ1_resp) = node2.post_hmc_lock(&succ1).await.expect("post succ 1 to node 2");
    assert!(
        succ1_status == StatusCode::CREATED || succ1_status == StatusCode::OK,
        "Successor 1 on Node 2 should succeed, got {}",
        succ1_status
    );
    assert!(matches!(succ1_resp.verdict, L2Verdict::Verified { .. }));

    // 9. Follow-up payment for Voucher 2 submitted to Node 1
    let succ2 = wallet2.make_successor(voucher_2, "village_succ_tag_02", 200, None, None);
    let (succ2_status, succ2_resp) = node1.post_hmc_lock(&succ2).await.expect("post succ 2 to node 1");
    assert!(
        succ2_status == StatusCode::CREATED || succ2_status == StatusCode::OK,
        "Successor 2 on Node 1 should succeed, got {}",
        succ2_status
    );
    assert!(matches!(succ2_resp.verdict, L2Verdict::Verified { .. }));
}

// ---------------------------------------------------------------------------
// Scenario 2: Multi-Hop Causality Chain Ingress on Newcomer Node (N=3)
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "long-running simulation"]
async fn test_scenario_2_multi_hop_causality_chain_ingress_newcomer() {
    let temp1 = tempdir().expect("tempdir 1");
    let (mut cfg1, id1, temp1) = TestNode::create_setup(temp1, 0);

    let temp2 = tempdir().expect("tempdir 2");
    let (mut cfg2, id2, temp2) = TestNode::create_setup(temp2, 1);

    let temp3 = tempdir().expect("tempdir 3");
    let (mut cfg3, id3, temp3) = TestNode::create_setup(temp3, 2);

    // Mutual trust
    cfg1.f2f.trusted_pubkeys.extend([id2.public_key_hex(), id3.public_key_hex()]);
    cfg2.f2f.trusted_pubkeys.extend([id1.public_key_hex(), id3.public_key_hex()]);
    cfg3.f2f.trusted_pubkeys.extend([id1.public_key_hex(), id2.public_key_hex()]);

    let node1 = TestNode::spawn(cfg1, id1, temp1).await.expect("spawn node 1");
    cfg2.f2f.peers.push(node1.p2p_addr.to_string());
    let _node2 = TestNode::spawn(cfg2, id2, temp2).await.expect("spawn node 2");

    let wallet = HmcTestWallet::new();
    let now = test_now_ms();
    let valid_until = now + 600_000;
    let voucher_id = "chain_causality_voucher_01";

    // Build multi-hop chain: Genesis (0) -> Hop 1 -> Hop 2 -> Hop 3
    let genesis = wallet.make_genesis(voucher_id, valid_until, 100);
    let hop1 = wallet.make_successor(voucher_id, "causality_hop_tag_01", 200, None, None);
    let hop2 = wallet.make_successor(voucher_id, "causality_hop_tag_02", 300, None, None);
    let hop3 = wallet.make_successor(voucher_id, "causality_hop_tag_03", 400, None, None);

    // Submit Genesis, Hop 1, Hop 2 sequentially to Node 1
    let (s0, _) = node1.post_hmc_lock(&genesis).await.expect("genesis lock");
    assert_eq!(s0, StatusCode::CREATED);
    let (s1, _) = node1.post_hmc_lock(&hop1).await.expect("hop 1 lock");
    assert_eq!(s1, StatusCode::CREATED);
    let (s2, _) = node1.post_hmc_lock(&hop2).await.expect("hop 2 lock");
    assert_eq!(s2, StatusCode::CREATED);

    // Node 3 is a newcomer that has not participated yet
    cfg3.f2f.peers.push(node1.p2p_addr.to_string());
    let node3 = TestNode::spawn(cfg3, id3, temp3).await.expect("spawn node 3");

    // Wallet submits full causality chain [Genesis, Hop 1, Hop 2, Hop 3] atomically to Node 3
    let chain_req = wallet.make_chain(
        voucher_id,
        vec![genesis.clone(), hop1.clone(), hop2.clone(), hop3.clone()],
    );

    let (chain_status, chain_resp) = node3.post_hmc_chain(&chain_req).await.expect("post chain lock");
    assert!(
        chain_status == StatusCode::CREATED || chain_status == StatusCode::OK,
        "Atomic chain ingress on newcomer node must succeed with 201/200, got {}",
        chain_status
    );
    assert!(
        matches!(chain_resp.verdict, L2Verdict::Verified { .. }),
        "Chain verdict must be Verified"
    );

    // Verify terminal lock and root presence on Node 3
    let (query_s, query_resp) = node3
        .query_hmc_status(voucher_id, "causality_hop_tag_03", wallet.pubkey_bytes())
        .await
        .expect("query hop 3 on node 3");
    assert_eq!(query_s, StatusCode::OK);
    match query_resp.verdict {
        L2Verdict::Verified { lock_entry } => {
            assert_eq!(lock_entry.t_id, hop3.transaction_hash);
        }
        _ => panic!("Expected terminal Hop 3 to be Verified on newcomer Node 3"),
    }
}

// ---------------------------------------------------------------------------
// Scenario 3: Double-Spend During Partition & min(H_canon) Resolution
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "long-running simulation"]
async fn test_scenario_3_double_spend_partition_and_canonical_resolution() {
    let temp1 = tempdir().expect("tempdir 1");
    let (mut cfg1, id1, temp1) = TestNode::create_setup(temp1, 0);

    let temp2 = tempdir().expect("tempdir 2");
    let (mut cfg2, id2, temp2) = TestNode::create_setup(temp2, 1);

    // Mutual trust configured, but peer lists empty initially (Isolated Partition)
    cfg1.f2f.trusted_pubkeys.push(id2.public_key_hex());
    cfg2.f2f.trusted_pubkeys.push(id1.public_key_hex());

    let mut node1 = TestNode::spawn(cfg1, id1, temp1).await.expect("spawn node 1");
    let mut node2 = TestNode::spawn(cfg2, id2, temp2).await.expect("spawn node 2");

    let wallet_a = HmcTestWallet::new();
    let wallet_b = HmcTestWallet::new();
    let now = test_now_ms();
    let valid_until = now + 600_000;
    let voucher_id = "double_spend_split_voucher_01";

    // 1. Both nodes anchor the identical Genesis lock before / during partition
    let genesis = wallet_a.make_genesis(voucher_id, valid_until, 100);

    let (s1, _) = node1.post_hmc_lock(&genesis).await.expect("genesis node 1");
    assert_eq!(s1, StatusCode::CREATED);
    let (s2, _) = node2.post_hmc_lock(&genesis).await.expect("genesis node 2");
    assert_eq!(s2, StatusCode::CREATED);

    // 2. Prepare two conflicting spends on a shared ds_tag: Branch A vs Branch B
    let ds_shared_tag = "ds_shared_tag_branch_01";
    let parent_bytes = *blake3::hash(ds_shared_tag.as_bytes()).as_bytes();
    let mut rng = rand::thread_rng();
    let mut tx_hash_winner = [0u8; 32];
    let mut tx_hash_loser = [0u8; 32];

    // Find candidate hashes such that H_winner < H_loser (Branch A wins deterministically)
    loop {
        rng.fill_bytes(&mut tx_hash_winner);
        rng.fill_bytes(&mut tx_hash_loser);
        let h_winner = compute_hmc_canonical_hash(&parent_bytes, &wallet_a.pubkey_bytes(), &tx_hash_winner);
        let h_loser = compute_hmc_canonical_hash(&parent_bytes, &wallet_b.pubkey_bytes(), &tx_hash_loser);
        if h_winner < h_loser {
            break;
        }
    }

    let req_winner = wallet_a.make_successor_with_custom_tx(
        voucher_id,
        ds_shared_tag,
        tx_hash_winner,
        200,
        None,
        None,
    );
    let req_loser = wallet_b.make_successor_with_custom_tx(
        voucher_id,
        ds_shared_tag,
        tx_hash_loser,
        200,
        None,
        None,
    );

    // 3. Ingress during partition: Winner to Node 1, Loser to Node 2
    let (w_status, _) = node1.post_hmc_lock(&req_winner).await.expect("winner lock to node 1");
    assert_eq!(w_status, StatusCode::CREATED);

    let (l_status, _) = node2.post_hmc_lock(&req_loser).await.expect("loser lock to node 2");
    assert_eq!(l_status, StatusCode::CREATED);

    // Verify isolated states
    let (_, resp1) = node1.query_hmc_status(voucher_id, ds_shared_tag, wallet_a.pubkey_bytes()).await.unwrap();
    let (_, resp2) = node2.query_hmc_status(voucher_id, ds_shared_tag, wallet_b.pubkey_bytes()).await.unwrap();
    match resp1.verdict {
        L2Verdict::Verified { lock_entry } => assert_eq!(lock_entry.t_id, tx_hash_winner),
        _ => panic!("Node 1 must hold winner lock"),
    }
    match resp2.verdict {
        L2Verdict::Verified { lock_entry } => assert_eq!(lock_entry.t_id, tx_hash_loser),
        _ => panic!("Node 2 must hold loser lock"),
    }

    // 4. Partition heals: connect both nodes via P2P and trigger sync
    node1.config.f2f.peers.push(node2.p2p_addr.to_string());
    node1.restart().await.expect("restart node 1");

    node2.config.f2f.peers = vec![node1.p2p_addr.to_string()];
    node2.restart().await.expect("restart node 2");

    // 5. Poll both nodes until min(H_canon) canonical winner is adopted by both
    let mut resolved = false;
    for _ in 0..70 {
        let n1_winner = node1
            .query_hmc_status(voucher_id, ds_shared_tag, wallet_a.pubkey_bytes())
            .await
            .map(|(s, r)| match r.verdict {
                L2Verdict::Verified { lock_entry } => s == StatusCode::OK && lock_entry.t_id == tx_hash_winner,
                _ => false,
            })
            .unwrap_or(false);

        let n2_winner = node2
            .query_hmc_status(voucher_id, ds_shared_tag, wallet_a.pubkey_bytes())
            .await
            .map(|(s, r)| match r.verdict {
                L2Verdict::Verified { lock_entry } => s == StatusCode::OK && lock_entry.t_id == tx_hash_winner,
                _ => false,
            })
            .unwrap_or(false);

        if n1_winner && n2_winner {
            resolved = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        resolved,
        "Partition healing must deterministically converge on min(H_canon) winner across both nodes"
    );
}

// ---------------------------------------------------------------------------
// Scenario 4: Reconnect & Catch-Up Sync After Offline Maintenance (N=3)
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "long-running simulation"]
async fn test_scenario_4_offline_maintenance_catchup_sync() {
    let temp1 = tempdir().expect("tempdir 1");
    let (mut cfg1, id1, temp1) = TestNode::create_setup(temp1, 0);

    let temp2 = tempdir().expect("tempdir 2");
    let (mut cfg2, id2, temp2) = TestNode::create_setup(temp2, 1);

    let temp3 = tempdir().expect("tempdir 3");
    let (mut cfg3, id3, temp3) = TestNode::create_setup(temp3, 2);

    cfg1.f2f.trusted_pubkeys.extend([id2.public_key_hex(), id3.public_key_hex()]);
    cfg2.f2f.trusted_pubkeys.extend([id1.public_key_hex(), id3.public_key_hex()]);
    cfg3.f2f.trusted_pubkeys.extend([id1.public_key_hex(), id2.public_key_hex()]);

    let mut node1 = TestNode::spawn(cfg1, id1, temp1).await.expect("spawn node 1");
    cfg2.f2f.peers.push(node1.p2p_addr.to_string());
    let mut node2 = TestNode::spawn(cfg2, id2, temp2).await.expect("spawn node 2");
    cfg3.f2f.peers.extend([node1.p2p_addr.to_string(), node2.p2p_addr.to_string()]);
    let node3 = TestNode::spawn(cfg3, id3, temp3).await.expect("spawn node 3");

    // Interconnect peers
    node1.config.f2f.peers.extend([node2.p2p_addr.to_string(), node3.p2p_addr.to_string()]);
    node2.config.f2f.peers.push(node3.p2p_addr.to_string());
    node1.restart().await.expect("restart node 1");
    node2.config.f2f.peers = vec![node1.p2p_addr.to_string(), node3.p2p_addr.to_string()];
    node2.restart().await.expect("restart node 2");

    // 1. Node 2 goes down for maintenance
    node2.stop().await.expect("clean shutdown of node 2");

    // 2. Transactions occur while Node 2 is offline
    let wallet1 = HmcTestWallet::new();
    let wallet2 = HmcTestWallet::new();
    let now = test_now_ms();
    let valid_until = now + 600_000;

    let v1 = "maintenance_voucher_01";
    let v2 = "maintenance_voucher_02";

    let genesis1 = wallet1.make_genesis(v1, valid_until, 100);
    let genesis1_tag = bs58::encode(&genesis1.transaction_hash).into_string();

    let genesis2 = wallet2.make_genesis(v2, valid_until, 100);
    let genesis2_tag = bs58::encode(&genesis2.transaction_hash).into_string();

    let (s1, _) = node1.post_hmc_lock(&genesis1).await.expect("lock v1 on node 1");
    assert_eq!(s1, StatusCode::CREATED);
    let (s2, _) = node3.post_hmc_lock(&genesis2).await.expect("lock v2 on node 3");
    assert_eq!(s2, StatusCode::CREATED);

    // 3. Node 2 restarts after maintenance with the same database
    node2.restart().await.expect("restart node 2");

    // 4. Poll Node 2 until catch-up sync has recovered both vouchers
    let mut caught_up = false;
    for _ in 0..70 {
        let has_v1 = node2
            .query_hmc_status(v1, &genesis1_tag, wallet1.pubkey_bytes())
            .await
            .map(|(s, r)| s == StatusCode::OK && matches!(r.verdict, L2Verdict::Verified { .. }))
            .unwrap_or(false);

        let has_v2 = node2
            .query_hmc_status(v2, &genesis2_tag, wallet2.pubkey_bytes())
            .await
            .map(|(s, r)| s == StatusCode::OK && matches!(r.verdict, L2Verdict::Verified { .. }))
            .unwrap_or(false);

        if has_v1 && has_v2 {
            caught_up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        caught_up,
        "Node 2 must catch up with all missed locks from Node 1 and Node 3 after maintenance"
    );
}

// ---------------------------------------------------------------------------
// Scenario 5: Spam Rejection of Fantasy Locks Without Known Genesis Root
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "long-running simulation"]
async fn test_scenario_5_spam_rejection_fantasy_locks() {
    let temp = tempdir().expect("tempdir");
    let (cfg, id, temp) = TestNode::create_setup(temp, 0);
    let node = TestNode::spawn(cfg, id, temp).await.expect("spawn node");

    let wallet = HmcTestWallet::new();
    let fantasy_voucher_id = "unanchored_fantasy_voucher_999";
    let fantasy_ds_tag = "fantasy_parent_tag_abcdef123456";

    // Attempt to submit an unanchored successor lock without prior genesis anchor
    let fantasy_lock = wallet.make_successor(
        fantasy_voucher_id,
        fantasy_ds_tag,
        100,
        None,
        None,
    );

    let (status, resp) = node.post_hmc_lock(&fantasy_lock).await.expect("post fantasy lock");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Fantasy lock without known genesis must be rejected with 400 Bad Request"
    );

    match resp.verdict {
        L2Verdict::Rejected { reason } => {
            assert!(
                reason.contains("Unknown voucher root"),
                "Rejection reason must indicate unknown voucher root, got: {}",
                reason
            );
        }
        _ => panic!("Expected Rejected verdict for fantasy lock, got {:?}", resp.verdict),
    }

    // Verify RAM index and storage have zero bloat (query status returns MissingLocks / NotFound)
    let (_, query_resp) = node
        .query_hmc_status(fantasy_voucher_id, fantasy_ds_tag, wallet.pubkey_bytes())
        .await
        .expect("query fantasy tag");

    assert!(
        !matches!(query_resp.verdict, L2Verdict::Verified { .. }),
        "Fantasy lock must not exist in RAM or disk index"
    );
}
