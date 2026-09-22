//! MeshSimulator – central orchestrator for the modular mesh test framework.
//!
//! Manages a set of `SimNodeHandle` production daemons, virtual time,
//! diagnostics and topology wiring. Used by `sim_01_evolutionary_growth`.

use std::time::Duration;

use humoco_node::api::hmc::{L2LockRequest, L2ResponseEnvelope, L2StatusQuery};

use crate::simulation::diagnostic::DiagnosticReporter;
use crate::simulation::node_handle::SimNodeHandle;
use crate::simulation::reporter::Reporter;
use crate::simulation::time::SimTimeController;

/// Central mesh orchestrator.
pub struct MeshSimulator {
    pub nodes: Vec<SimNodeHandle>,
    pub time: SimTimeController,
    pub reporter: Reporter,
}

impl MeshSimulator {
    /// Creates an empty simulator.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            time: SimTimeController::new(),
            reporter: Reporter::new(),
        }
    }

    /// Returns mutable access to the diagnostic reporter.
    pub fn diagnostic_mut(&mut self) -> &mut DiagnosticReporter {
        self.reporter.diagnostic_mut()
    }

    /// Returns the number of live nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns true if no nodes exist.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Spawns a single isolated node (N=1 genesis scenario).
    pub async fn spawn_node(
        &mut self,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let id = self.nodes.len();
        let node = SimNodeHandle::spawn(id).await?;
        self.nodes.push(node);
        Ok(id)
    }

    /// Spawns a node that is F2F-paired with the nodes at `peer_indices`.
    /// Wires mutual trust: new node trusts peers, and peers' pubkeys are
    /// added to new node's trusted list. For full bidirectional peering
    /// the caller should restart or the mesh will converge via gossip from
    /// the new node's outbound connections.
    pub async fn spawn_node_with_f2f(
        &mut self,
        peer_indices: &[usize],
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let id = self.nodes.len();
        let mut peers = Vec::new();
        let mut trusted = Vec::new();
        for &pi in peer_indices {
            let peer = &self.nodes[pi];
            peers.push(peer.f2f_peer_string());
            trusted.push(peer.pubkey_hex());
        }
        let node = SimNodeHandle::spawn_with_peers(id, peers, trusted).await?;
        self.nodes.push(node);
        Ok(id)
    }

    /// Spawns `count` isolated nodes sequentially.
    pub async fn spawn_nodes(
        &mut self,
        count: usize,
    ) -> Result<Vec<usize>, Box<dyn std::error::Error + Send + Sync>> {
        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            ids.push(self.spawn_node().await?);
        }
        Ok(ids)
    }

    /// Returns a reference to a node.
    pub fn node(&self, idx: usize) -> &SimNodeHandle {
        &self.nodes[idx]
    }

    /// Returns a mutable reference to a node.
    pub fn node_mut(&mut self, idx: usize) -> &mut SimNodeHandle {
        &mut self.nodes[idx]
    }

    /// Stops a node (crash simulation) without removing it from the vector.
    pub async fn stop_node(&mut self, idx: usize) {
        self.nodes[idx].stop().await;
    }

    /// Restarts a previously stopped node, reusing its identity and storage.
    pub async fn restart_node(
        &mut self,
        idx: usize,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.nodes[idx].restart().await
    }

    /// Advances virtual time and yields to the scheduler.
    pub async fn advance_and_yield(&self, dur: Duration) {
        self.time.advance_and_yield(dur).await;
    }

    /// Convenience: advance by milliseconds.
    pub async fn advance_ms(&self, ms: u64) {
        self.advance_and_yield(Duration::from_millis(ms)).await;
    }

    /// Polls a node's L2 status query until it returns `Verified` or timeout.
    pub async fn poll_status_verified(
        &self,
        node_idx: usize,
        query: &L2StatusQuery,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Option<L2ResponseEnvelope> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Ok((status, envelope)) = self.nodes[node_idx].query_status(query).await {
                if status.is_success() {
                    if let humoco_node::api::hmc::L2Verdict::Verified { .. } = &envelope.verdict {
                        return Some(envelope);
                    }
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Polls `POST /v1/sync` style via `L2StatusQuery` or raw sync.
    /// Helper that waits until a specific `t_id` tag is present via status query.
    pub async fn wait_for_lock_on_node(
        &self,
        node_idx: usize,
        voucher_id: &str,
        challenge_ds_tag: &str,
        timeout: Duration,
    ) -> bool {
        let query = L2StatusQuery {
            auth: humoco_node::api::hmc::L2AuthPayload {
                ephemeral_pubkey: [0u8; 32],
                auth_signature: None,
            },
            layer2_voucher_id: voucher_id.to_string(),
            challenge_ds_tag: challenge_ds_tag.to_string(),
            locator_prefixes: vec![],
            read_quorum: 1,
        };
        self.poll_status_verified(node_idx, &query, timeout, Duration::from_millis(200))
            .await
            .is_some()
    }

    /// Posts a genesis lock on the given node.
    pub async fn post_genesis(
        &self,
        node_idx: usize,
        req: &L2LockRequest,
    ) -> Result<(axum::http::StatusCode, L2ResponseEnvelope), Box<dyn std::error::Error + Send + Sync>>
    {
        self.nodes[node_idx].post_lock(req).await
    }

    /// Helper to get F2F peer string of a node.
    pub fn peer_string(&self, idx: usize) -> String {
        self.nodes[idx].f2f_peer_string()
    }

    /// Returns the current time controller's now_ms.
    pub fn now_ms(&self) -> u64 {
        self.time.now_ms()
    }
}

impl Default for MeshSimulator {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MeshSimulator {
    fn drop(&mut self) {
        for node in &mut self.nodes {
            node.cancel_token.cancel();
        }
    }
}
