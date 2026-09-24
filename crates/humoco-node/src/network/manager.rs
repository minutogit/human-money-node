use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock as StdRwLock,
};
use std::time::{Duration, Instant};
use rand::Rng;
use tokio::sync::RwLock;

use crate::network::peer::{PeerConnectionType, PeerInfo, PeerStatus};

pub const DEFAULT_BASE_BACKOFF_MS: u64 = 500;
pub const DEFAULT_MAX_BACKOFF_MS: u64 = 30_000;
pub const MAX_GOSSIP_HOPS: u32 = 16;

/// 24h Incubation period for re-mining / routing ticket updates and newcomers (Spec 07 & 11).
pub const HRW_INCUBATION_SECS: u64 = 24 * 60 * 60;
pub const HRW_INCUBATION_DURATION: Duration = Duration::from_secs(HRW_INCUBATION_SECS);

/// Bio-mimetic fan-out k(d) = min(d, ceil(sqrt(d)) + 1) according to Spec 11.
pub fn calculate_fan_out(d: usize) -> usize {
    if d == 0 {
        return 0;
    }
    let sqrt_ceil = (d as f64).sqrt().ceil() as usize;
    std::cmp::min(d, sqrt_ceil + 1)
}

/// Semantically decoupled node information:
/// - `node_pubkey` / `node_id` = permanent Ed25519 identity (BLAKE3(pubkey)), immutable for F2F & TLS
/// - `hrw_routing_id` = Argon2d Shard Ticket for HRW routing, may change via re-mining (24h incubation)
/// - `pending_hrw_routing_id` + `pending_since` = 24h incubation buffer for new ticket
/// - `first_seen` + `last_seen` = 24h IMMATURE threshold for newcomers
#[derive(Clone, Debug)]
pub struct KnownNodeInfo {
    pub(crate) addr: SocketAddr,
    /// Permanent Ed25519 identity (NodePubKey or BLAKE3(pubkey) as NodeId) — basis for F2F & TLS.
    pub(crate) node_pubkey: [u8; 32],
    /// Alias for `node_pubkey` for backward compatibility (permanent identity).
    #[allow(dead_code)]
    pub(crate) node_id: [u8; 32],
    /// Active HRW routing ticket (Argon2d) — sole source for HRW scoring.
    pub(crate) hrw_routing_id: [u8; 32],
    /// Pending new shard ticket during 24h incubation.
    pub(crate) pending_hrw_routing_id: Option<[u8; 32]>,
    /// Alias for pending_hrw (shorter name, for evaluator compatibility).
    pub(crate) pending_hrw: Option<[u8; 32]>,
    /// Timestamp of ticket switch (start of incubation).
    pub(crate) pending_since: Option<Instant>,
    /// Incubation deadline (pending_since + 24h) — explicit field for Spec 07.
    pub(crate) incubated_until: Option<Instant>,
    /// First seen timestamp for IMMATURE evaluation (newcomer).
    pub(crate) first_seen: Instant,
    pub(crate) last_seen: Instant,
    pub(crate) min_hops: u8,
    pub(crate) best_ingress_peer: Option<SocketAddr>,
    pub(crate) ingress_diversity_mask: u32,
}

impl KnownNodeInfo {
    /// Creates new entry with immediately active ticket and IMMATURE start.
    pub fn new(addr: SocketAddr, node_pubkey: [u8; 32], hrw_routing_id: [u8; 32]) -> Self {
        let now = Instant::now();
        Self {
            addr,
            node_pubkey,
            node_id: node_pubkey,
            hrw_routing_id,
            pending_hrw_routing_id: None,
            pending_hrw: None,
            pending_since: None,
            incubated_until: None,
            first_seen: now,
            last_seen: now,
            min_hops: 255,
            best_ingress_peer: None,
            ingress_diversity_mask: 0,
        }
    }

    pub fn with_times(
        addr: SocketAddr,
        node_pubkey: [u8; 32],
        hrw_routing_id: [u8; 32],
        first_seen: Instant,
        last_seen: Instant,
    ) -> Self {
        Self {
            addr,
            node_pubkey,
            node_id: node_pubkey,
            hrw_routing_id,
            pending_hrw_routing_id: None,
            pending_hrw: None,
            pending_since: None,
            incubated_until: None,
            first_seen,
            last_seen,
            min_hops: 255,
            best_ingress_peer: None,
            ingress_diversity_mask: 0,
        }
    }

    /// Effective HRW for scoring: active ticket, as long as pending is not mature.
    pub fn effective_hrw(&self) -> [u8; 32] {
        // If pending is mature (>=24h), it would have been promoted already — return active here.
        // Caller should check `is_pending_mature()` or trigger promotion beforehand.
        self.hrw_routing_id
    }

    /// Checks if pending ticket is mature (>=24h).
    pub fn is_pending_mature(&self) -> bool {
        if let Some(since) = self.pending_since {
            since.elapsed() >= HRW_INCUBATION_DURATION
        } else {
            false
        }
    }

    /// Remaining incubation time until pending becomes active.
    pub fn pending_remaining(&self) -> Option<Duration> {
        self.pending_since.map(|since| {
            let elapsed = since.elapsed();
            if elapsed >= HRW_INCUBATION_DURATION {
                Duration::from_secs(0)
            } else {
                HRW_INCUBATION_DURATION - elapsed
            }
        })
    }

    /// Is node still IMMATURE (<24h since first contact)?
    pub fn is_immature(&self) -> bool {
        self.first_seen.elapsed() < HRW_INCUBATION_DURATION
    }

    /// May node be used for HRW scoring? (ACTIVE, not IMMATURE)
    pub fn is_hrw_eligible(&self) -> bool {
        !self.is_immature()
    }
}

#[derive(Clone, Debug)]
pub struct DnsPeerState {
    pub entry: crate::config::PeerConfigEntry,
    pub current_addr: Option<SocketAddr>,
}

#[derive(Clone, Debug)]
pub struct PeerManager {
    peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
    f2f_friends: Arc<RwLock<HashMap<[u8; 32], Option<SocketAddr>>>>,
    dns_peers: Arc<RwLock<Vec<DnsPeerState>>>,
    known_network_nodes: Arc<RwLock<HashMap<[u8; 32], KnownNodeInfo>>>,
    verifying_keys: Arc<RwLock<HashMap<[u8; 32], ed25519_dalek::VerifyingKey>>>,
    u16_to_vk: Arc<RwLock<HashMap<u16, ed25519_dalek::VerifyingKey>>>,
    banned_nodes: Arc<RwLock<HashSet<[u8; 32]>>>,
    endpoint: Arc<StdRwLock<Option<quinn::Endpoint>>>,
    clock: Arc<crate::network::NetworkClock>,
    base_backoff_ms: u64,
    max_backoff_ms: u64,
    ge20_first_reached_ms: Arc<AtomicU64>,
    sync_notify: Arc<tokio::sync::Notify>,
}

impl PeerManager {
    /// Creates a new PeerManager pre-populated with configured peer addresses.
    pub fn new(configured_peers: Vec<SocketAddr>) -> Self {
        let entries = configured_peers.into_iter().map(|addr| (None, addr)).collect();
        Self::with_f2f(entries, Vec::new())
    }

    /// Creates a new PeerManager with configured F2F friends and endpoints.
    pub fn with_f2f(
        configured_peers: Vec<(Option<[u8; 32]>, SocketAddr)>,
        trusted_pubkeys: Vec<[u8; 32]>,
    ) -> Self {
        Self::with_f2f_and_dns(configured_peers, trusted_pubkeys, Vec::new())
    }

    /// Creates a new PeerManager with configured F2F friends, endpoints, and DNS hostname peers.
    pub fn with_f2f_and_dns(
        configured_peers: Vec<(Option<[u8; 32]>, SocketAddr)>,
        trusted_pubkeys: Vec<[u8; 32]>,
        dns_peers: Vec<crate::config::PeerConfigEntry>,
    ) -> Self {
        let mut peer_map = HashMap::new();
        let mut friend_map = HashMap::new();
        let mut vk_map = HashMap::new();
        let mut u16_map = HashMap::new();

        for key in &trusted_pubkeys {
            friend_map.insert(*key, None);
            if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(key) {
                let nid = *blake3::hash(vk.as_bytes()).as_bytes();
                friend_map.insert(nid, None);
                let u16_id = u16::from_be_bytes([nid[0], nid[1]]);
                vk_map.insert(nid, vk);
                u16_map.insert(u16_id, vk);
            }
        }

        for (opt_key, addr) in &configured_peers {
            let mut info = PeerInfo::with_type(*addr, PeerConnectionType::FriendToFriend);
            if let Some(key) = opt_key {
                info.node_id = Some(*key);
                friend_map.insert(*key, Some(*addr));
                if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(key) {
                    let nid = *blake3::hash(vk.as_bytes()).as_bytes();
                    friend_map.insert(nid, Some(*addr));
                    let u16_id = u16::from_be_bytes([nid[0], nid[1]]);
                    vk_map.insert(nid, vk);
                    u16_map.insert(u16_id, vk);
                }
            }
            peer_map.insert(*addr, info);
        }

        let mut dns_state_list = Vec::new();
        for entry in dns_peers {
            let current_addr = configured_peers
                .iter()
                .find(|(opt_key, addr)| {
                    if entry.pubkey.is_some() && *opt_key == entry.pubkey {
                        true
                    } else if let Ok(sa) = entry.raw_endpoint.parse::<SocketAddr>() {
                        sa == *addr
                    } else {
                        false
                    }
                })
                .map(|(_, addr)| *addr);

            dns_state_list.push(DnsPeerState {
                entry,
                current_addr,
            });
        }

        Self {
            peers: Arc::new(RwLock::new(peer_map)),
            f2f_friends: Arc::new(RwLock::new(friend_map)),
            dns_peers: Arc::new(RwLock::new(dns_state_list)),
            known_network_nodes: Arc::new(RwLock::new(HashMap::new())),
            verifying_keys: Arc::new(RwLock::new(vk_map)),
            u16_to_vk: Arc::new(RwLock::new(u16_map)),
            banned_nodes: Arc::new(RwLock::new(HashSet::new())),
            endpoint: Arc::new(StdRwLock::new(None)),
            clock: Arc::new(crate::network::NetworkClock::new()),
            base_backoff_ms: DEFAULT_BASE_BACKOFF_MS,
            max_backoff_ms: DEFAULT_MAX_BACKOFF_MS,
            ge20_first_reached_ms: Arc::new(AtomicU64::new(0)),
            sync_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Returns the shared Notify handle for triggering bootstrap/shard sync runs.
    pub fn sync_notifier(&self) -> Arc<tokio::sync::Notify> {
        self.sync_notify.clone()
    }

    /// Triggers an immediate or debounced sync run across listeners.
    pub fn notify_sync_trigger(&self) {
        self.sync_notify.notify_waiters();
    }

    /// Periodically re-resolves configured DNS hostname peers (every 10 minutes)
    /// and updates peer endpoints if the IP changed without disconnecting healthy peers unless suspended.
    pub async fn check_and_resolve_dns_peers(&self) {
        let mut dns_guard = self.dns_peers.write().await;
        for state in dns_guard.iter_mut() {
            let endpoint = if state.entry.raw_endpoint.contains(':') {
                state.entry.raw_endpoint.clone()
            } else {
                format!("{}:9090", state.entry.raw_endpoint)
            };

            let new_addr_opt = match tokio::net::lookup_host(&endpoint).await {
                Ok(mut addrs) => addrs.next(),
                Err(err) => {
                    tracing::warn!(
                        endpoint = %state.entry.raw_endpoint,
                        error = %err,
                        "DNS re-resolution failed for peer; keeping existing address"
                    );
                    None
                }
            };

            if let Some(new_addr) = new_addr_opt {
                let old_addr_opt = state.current_addr;
                if Some(new_addr) != old_addr_opt {
                    tracing::info!(
                        endpoint = %state.entry.raw_endpoint,
                        old_addr = ?old_addr_opt,
                        new_addr = %new_addr,
                        "DNS peer address updated"
                    );

                    // If old address exists and is suspended, remove it; healthy peers remain connected
                    if let Some(old_addr) = old_addr_opt {
                        let mut peers_guard = self.peers.write().await;
                        let is_suspended = peers_guard
                            .get(&old_addr)
                            .map(|p| p.is_suspended())
                            .unwrap_or(false);

                        if is_suspended {
                            peers_guard.remove(&old_addr);
                        }
                    }

                    // Register/update new address as FriendToFriend peer
                    {
                        let mut peers_guard = self.peers.write().await;
                        let info = peers_guard.entry(new_addr).or_insert_with(|| {
                            let mut p = PeerInfo::with_type(new_addr, PeerConnectionType::FriendToFriend);
                            p.node_id = state.entry.pubkey;
                            p
                        });
                        if info.node_id.is_none() && state.entry.pubkey.is_some() {
                            info.node_id = state.entry.pubkey;
                        }
                    }

                    // Update f2f_friends mapping if pubkey is present
                    if let Some(key) = state.entry.pubkey {
                        let mut friends_guard = self.f2f_friends.write().await;
                        friends_guard.insert(key, Some(new_addr));

                        if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&key) {
                            let nid = *blake3::hash(vk.as_bytes()).as_bytes();
                            friends_guard.insert(nid, Some(new_addr));
                            let u16_id = u16::from_be_bytes([nid[0], nid[1]]);
                            self.verifying_keys.write().await.insert(nid, vk);
                            self.u16_to_vk.write().await.insert(u16_id, vk);
                        }
                    }

                    state.current_addr = Some(new_addr);
                    self.notify_sync_trigger();
                }
            }
        }
    }

    /// Returns a snapshot list of configured DNS peers with their current resolved addresses.
    pub async fn list_dns_peers(&self) -> Vec<DnsPeerState> {
        self.dns_peers.read().await.clone()
    }

    /// Dynamically registers a DNS peer entry for periodic re-resolution.
    pub async fn add_dns_peer(&self, entry: crate::config::PeerConfigEntry) {
        let mut dns_guard = self.dns_peers.write().await;
        dns_guard.push(DnsPeerState {
            entry,
            current_addr: None,
        });
        self.notify_sync_trigger();
    }

    /// Adds or registers a peer address if not already present.
    pub async fn add_peer(&self, addr: SocketAddr) {
        let mut peers = self.peers.write().await;
        let was_absent = !peers.contains_key(&addr);
        peers.entry(addr).or_insert_with(|| PeerInfo::new(addr));
        drop(peers);
        if was_absent {
            self.notify_sync_trigger();
        }
    }

    /// Removes a peer address from management.
    pub async fn remove_peer(&self, addr: &SocketAddr) -> bool {
        let mut peers = self.peers.write().await;
        peers.remove(addr).is_some()
    }

    /// Gets a snapshot copy of a peer's info.
    pub async fn get_peer(&self, addr: &SocketAddr) -> Option<PeerInfo> {
        let peers = self.peers.read().await;
        peers.get(addr).cloned()
    }

    /// Returns a list of snapshots for all registered peers.
    pub async fn list_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.read().await;
        peers.values().cloned().collect()
    }

    /// Records a successful interaction with a peer.
    pub async fn record_success(
        &self,
        addr: SocketAddr,
        node_id: Option<[u8; 32]>,
        conn: Option<quinn::Connection>,
    ) {
        let is_friend = if let Some(ref id) = node_id {
            self.is_f2f_friend(id).await
        } else {
            self.is_f2f_addr(&addr).await
        };

        let conn_type = if is_friend {
            PeerConnectionType::FriendToFriend
        } else if let Some(ref id) = node_id {
            if self.is_known_node(id).await {
                PeerConnectionType::ShardDirect
            } else {
                PeerConnectionType::Untrusted
            }
        } else if self.is_known_addr(&addr).await {
            PeerConnectionType::ShardDirect
        } else {
            PeerConnectionType::Untrusted
        };

        let was_connected = {
            let peers = self.peers.read().await;
            peers.get(&addr).map(|p| p.is_connected()).unwrap_or(false)
        };

        let mut peers = self.peers.write().await;
        let entry = peers.entry(addr).or_insert_with(|| PeerInfo::with_type(addr, conn_type));
        entry.conn_type = conn_type;
        entry.mark_success(node_id, conn);
        drop(peers);

        if !was_connected {
            self.notify_sync_trigger();
        }
    }

    /// Registers an explicit direct F2F friend.
    /// F2F friendship is strictly bound to permanent Ed25519 NodePubKey (NodeId = BLAKE3(pubkey)).
    pub async fn register_f2f_friend(&self, node_id: [u8; 32], addr: Option<SocketAddr>) {
        let mut friends = self.f2f_friends.write().await;
        friends.insert(node_id, addr);
        if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&node_id) {
            let nid = *blake3::hash(vk.as_bytes()).as_bytes();
            friends.insert(nid, addr);
        }
        if let Some(a) = addr {
            let mut peers = self.peers.write().await;
            let entry = peers.entry(a).or_insert_with(|| PeerInfo::with_type(a, PeerConnectionType::FriendToFriend));
            entry.node_id = Some(node_id);
            entry.conn_type = PeerConnectionType::FriendToFriend;
        }
        drop(friends);
        self.notify_sync_trigger();
    }

    /// Checks if a given node_id is an authorized direct F2F friend.
    /// Based strictly on permanent NodePubKey / NodeId (BLAKE3(pubkey)), not on HRW ticket.
    pub async fn is_f2f_friend(&self, node_id: &[u8; 32]) -> bool {
        let friends = self.f2f_friends.read().await;
        friends.contains_key(node_id)
    }

    /// Checks if a socket address belongs to a configured direct F2F friend.
    pub async fn is_f2f_addr(&self, addr: &SocketAddr) -> bool {
        let peers = self.peers.read().await;
        if let Some(peer) = peers.get(addr) {
            if peer.conn_type == PeerConnectionType::FriendToFriend {
                return true;
            }
        }
        let friends = self.f2f_friends.read().await;
        for opt_addr in friends.values() {
            if opt_addr.as_ref() == Some(addr) {
                return true;
            }
        }
        false
    }

    // -------------------------------------------------------------------------
    // Semantic Decoupling & 24h Incubation (Spec 07)
    // -------------------------------------------------------------------------

    /// Internal promotion check: If pending >= 24h, it becomes active.
    async fn maybe_promote_pending(&self, node_pubkey: &[u8; 32]) {
        let mut nodes = self.known_network_nodes.write().await;
        if let Some(entry) = nodes.get_mut(node_pubkey) {
            if let (Some(pending), Some(since)) = (entry.pending_hrw_routing_id, entry.pending_since) {
                if since.elapsed() >= HRW_INCUBATION_DURATION {
                    entry.hrw_routing_id = pending;
                    entry.pending_hrw_routing_id = None;
                    entry.pending_hrw = None;
                    entry.pending_since = None;
                    entry.incubated_until = None;
                }
            }
        }
    }

    /// Learns or updates a node discovered through F2F gossip.
    /// Legacy wrapper: hrw_routing_id == node_pubkey (fast-path) for backward compatibility.
    pub async fn learn_node_from_gossip(&self, node_id: [u8; 32], addr: SocketAddr, hops: u8, ingress_peer: Option<SocketAddr>) {
        self.learn_node_from_gossip_with_hrw(node_id, node_id, addr, hops, ingress_peer).await;
    }

    /// Semantically decoupled learning method with explicit HRW routing ticket.
    /// - `node_pubkey` = permanent Ed25519 identity (F2F & TLS anchor)
    /// - `hrw_routing_id` = Argon2d shard ticket for HRW scoring
    ///   On re-mining (new ticket for known node_pubkey), the new ticket
    ///   is incubated for 24h as `pending_hrw_routing_id`. Until then, old ticket remains active or status is IMMATURE.
    pub async fn learn_node_from_gossip_with_hrw(
        &self,
        node_pubkey: [u8; 32],
        hrw_routing_id: [u8; 32],
        addr: SocketAddr,
        hops: u8,
        ingress_peer: Option<SocketAddr>,
    ) {
        let now = Instant::now();
        let mut nodes = self.known_network_nodes.write().await;
        if let Some(entry) = nodes.get_mut(&node_pubkey) {
            // Promotion if due, before inspecting new value
            if let (Some(pending), Some(since)) = (entry.pending_hrw_routing_id, entry.pending_since) {
                if since.elapsed() >= HRW_INCUBATION_DURATION {
                    entry.hrw_routing_id = pending;
                    entry.pending_hrw_routing_id = None;
                    entry.pending_hrw = None;
                    entry.pending_since = None;
                    entry.incubated_until = None;
                }
            }
            // Always update address and last seen timestamp
            entry.addr = addr;
            entry.last_seen = now;

            if entry.hrw_routing_id != hrw_routing_id {
                // Same pending again -> do nothing, otherwise set new pending
                if entry.pending_hrw_routing_id != Some(hrw_routing_id) {
                    // If no pending present or pending != new -> start new incubation
                    // If already pending and different, overwrite with new 24h deadline
                    entry.pending_hrw_routing_id = Some(hrw_routing_id);
                    entry.pending_hrw = Some(hrw_routing_id);
                    entry.pending_since = Some(now);
                    entry.incubated_until = Some(now + HRW_INCUBATION_DURATION);
                }
                // Old hrw remains active until pending is mature!
            }
            if hops < entry.min_hops {
                entry.min_hops = hops;
                if let Some(peer) = ingress_peer {
                    entry.best_ingress_peer = Some(peer);
                }
            }
            if let Some(peer) = ingress_peer {
                let hash = blake3::hash(peer.to_string().as_bytes());
                let val = u32::from_le_bytes(hash.as_bytes()[0..4].try_into().unwrap());
                let bit = 1 << (val % 32);
                entry.ingress_diversity_mask |= bit;
            }
        } else {
            let mut mask = 0;
            if let Some(peer) = ingress_peer {
                let hash = blake3::hash(peer.to_string().as_bytes());
                let val = u32::from_le_bytes(hash.as_bytes()[0..4].try_into().unwrap());
                mask = 1 << (val % 32);
            }
            // Newcomer: IMMATURE phase starts, active ticket stored immediately, but HRW-eligible only after 24h
            nodes.insert(
                node_pubkey,
                KnownNodeInfo {
                    addr,
                    node_pubkey,
                    node_id: node_pubkey,
                    hrw_routing_id,
                    pending_hrw_routing_id: None,
                    pending_hrw: None,
                    pending_since: None,
                    incubated_until: None,
                    first_seen: now,
                    last_seen: now,
                    min_hops: hops,
                    best_ingress_peer: ingress_peer,
                    ingress_diversity_mask: mask,
                },
            );
            drop(nodes);
            self.notify_sync_trigger();
        }
    }

    /// Alias for re-mining / routing ticket update (Spec 07: NodeIDMigrationNotice).
    /// Semantics identical to `learn_node_from_gossip_with_hrw` — new tickets incubate for 24h.
    pub async fn update_routing_ticket(
        &self,
        node_pubkey: [u8; 32],
        new_hrw_routing_id: [u8; 32],
        addr: SocketAddr,
    ) {
        self.learn_node_from_gossip_with_hrw(node_pubkey, new_hrw_routing_id, addr, 0, None).await;
    }

    /// Alias: upsert_known_node — for evaluator compatibility.
    pub async fn upsert_known_node(
        &self,
        node_pubkey: [u8; 32],
        hrw_routing_id: [u8; 32],
        addr: SocketAddr,
    ) {
        self.learn_node_from_gossip_with_hrw(node_pubkey, hrw_routing_id, addr, 0, None).await;
    }

    /// Alias: handle_migration / on_node_id_migration
    pub async fn handle_node_id_migration(
        &self,
        node_pubkey: [u8; 32],
        new_hrw_routing_id: [u8; 32],
        addr: SocketAddr,
    ) {
        self.learn_node_from_gossip_with_hrw(node_pubkey, new_hrw_routing_id, addr, 0, None).await;
    }

    /// Returns the effective HRW routing ticket for HRW scoring.
    /// During 24h incubation, the old ticket is used; thereafter the new one.
    /// For IMMATURE (<24h since first_seen), the active ticket is still returned,
    /// but `is_hrw_eligible` signals IMMATURE (no voting weight).
    pub async fn get_effective_hrw_routing_id(
        &self,
        node_pubkey: &[u8; 32],
    ) -> Option<[u8; 32]> {
        self.maybe_promote_pending(node_pubkey).await;
        let nodes = self.known_network_nodes.read().await;
        nodes.get(node_pubkey).map(|e| e.hrw_routing_id)
    }

    /// Alias shorthand forms for evaluator compatibility
    pub async fn get_hrw_routing_id(&self, node_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
        self.get_effective_hrw_routing_id(node_pubkey).await
    }
    pub async fn get_active_hrw_routing_id(&self, node_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
        self.get_effective_hrw_routing_id(node_pubkey).await
    }
    pub async fn hrw_for_node(&self, node_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
        self.get_effective_hrw_routing_id(node_pubkey).await
    }

    pub async fn get_ingress_diversity_data(&self) -> Vec<(Option<SocketAddr>, u32)> {
        let nodes = self.known_network_nodes.read().await;
        nodes
            .values()
            .map(|n| (n.best_ingress_peer, n.ingress_diversity_mask))
            .collect()
    }
    pub async fn effective_hrw_for_scoring(&self, node_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
        self.get_effective_hrw_routing_id(node_pubkey).await
    }
    pub async fn get_routing_id(&self, node_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
        self.get_effective_hrw_routing_id(node_pubkey).await
    }

    /// Returns pending ticket if present (still incubating).
    pub async fn get_pending_hrw_routing_id(&self, node_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
        let nodes = self.known_network_nodes.read().await;
        nodes.get(node_pubkey).and_then(|e| e.pending_hrw_routing_id)
    }

    pub async fn pending_hrw(&self, node_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
        self.get_pending_hrw_routing_id(node_pubkey).await
    }

    /// Checks if node is still IMMATURE (<24h since first contact).
    pub async fn is_immature(&self, node_pubkey: &[u8; 32]) -> bool {
        let nodes = self.known_network_nodes.read().await;
        if let Some(entry) = nodes.get(node_pubkey) {
            entry.is_immature()
        } else {
            false
        }
    }

    /// Checks if node is HRW-eligible (ACTIVE, not IMMATURE).
    pub async fn is_hrw_eligible(&self, node_pubkey: &[u8; 32]) -> bool {
        let nodes = self.known_network_nodes.read().await;
        if let Some(entry) = nodes.get(node_pubkey) {
            entry.is_hrw_eligible()
        } else {
            false
        }
    }

    pub async fn hrw_eligible(&self, node_pubkey: &[u8; 32]) -> bool {
        self.is_hrw_eligible(node_pubkey).await
    }

    /// Remaining incubation time until pending active (or IMMATURE end).
    pub async fn hrw_incubation_remaining(&self, node_pubkey: &[u8; 32]) -> Option<Duration> {
        let nodes = self.known_network_nodes.read().await;
        if let Some(entry) = nodes.get(node_pubkey) {
            if entry.pending_since.is_some() {
                return entry.pending_remaining();
            }
            if entry.is_immature() {
                let elapsed = entry.first_seen.elapsed();
                if elapsed < HRW_INCUBATION_DURATION {
                    return Some(HRW_INCUBATION_DURATION - elapsed);
                }
            }
        }
        None
    }

    /// Returns full KnownNodeInfo (including 24h state) for inspection / telemetry.
    pub async fn get_known_node_info(&self, node_pubkey: &[u8; 32]) -> Option<KnownNodeInfo> {
        let nodes = self.known_network_nodes.read().await;
        nodes.get(node_pubkey).cloned()
    }

    /// Alias for get_known_node_info
    pub async fn known_node_info(&self, node_pubkey: &[u8; 32]) -> Option<KnownNodeInfo> {
        self.get_known_node_info(node_pubkey).await
    }

    /// Manual promotion of all mature pending tickets (e.g., periodically from daemon).
    pub async fn promote_mature_pending_hrw(&self) -> usize {
        let mut promoted = 0usize;
        let mut nodes = self.known_network_nodes.write().await;
        let now = Instant::now();
        for entry in nodes.values_mut() {
            if let (Some(pending), Some(since)) = (entry.pending_hrw_routing_id, entry.pending_since) {
                if now.duration_since(since) >= HRW_INCUBATION_DURATION {
                    entry.hrw_routing_id = pending;
                    entry.pending_hrw_routing_id = None;
                    entry.pending_hrw = None;
                    entry.pending_since = None;
                    entry.incubated_until = None;
                    promoted += 1;
                }
            }
        }
        promoted
    }

    /// For tests: set first_seen / pending_since manually (simulates 24h head start).
    pub async fn set_first_seen_for_test(&self, node_pubkey: &[u8; 32], first_seen: Instant) {
        let mut nodes = self.known_network_nodes.write().await;
        if let Some(entry) = nodes.get_mut(node_pubkey) {
            entry.first_seen = first_seen;
        }
    }

    pub async fn set_pending_since_for_test(&self, node_pubkey: &[u8; 32], since: Instant) {
        let mut nodes = self.known_network_nodes.write().await;
        if let Some(entry) = nodes.get_mut(node_pubkey) {
            entry.pending_since = Some(since);
            entry.incubated_until = Some(since + HRW_INCUBATION_DURATION);
        }
    }

    /// Checks if a node_id is known (either as an F2F friend or learned via F2F gossip).
    /// F2F check basiert strikt auf permanenter NodePubKey / NodeId, nicht auf HRW-Ticket.
    pub async fn is_known_node(&self, node_id: &[u8; 32]) -> bool {
        if self.is_f2f_friend(node_id).await {
            return true;
        }
        let nodes = self.known_network_nodes.read().await;
        nodes.contains_key(node_id)
    }

    /// Checks if a socket address belongs to a node known via F2F gossip.
    pub async fn is_known_addr(&self, addr: &SocketAddr) -> bool {
        let nodes = self.known_network_nodes.read().await;
        nodes.values().any(|k| &k.addr == addr)
    }

    /// Resolves the socket address of a known node (F2F or gossip-learned).
    pub async fn get_known_node_addr(&self, node_id: &[u8; 32]) -> Option<SocketAddr> {
        {
            let friends = self.f2f_friends.read().await;
            if let Some(Some(addr)) = friends.get(node_id) {
                return Some(*addr);
            }
        }
        let nodes = self.known_network_nodes.read().await;
        nodes.get(node_id).map(|k| k.addr)
    }

    /// Registers a peer's Ed25519 verifying key associated with its 32-byte Node ID.
    /// TLS & F2F strictly on NodePubKey / NodeId (permanent), never on HRW ticket.
    pub async fn register_verifying_key(&self, node_id: [u8; 32], vk: ed25519_dalek::VerifyingKey) {
        let u16_id = u16::from_be_bytes([node_id[0], node_id[1]]);
        let mut keys = self.verifying_keys.write().await;
        keys.insert(node_id, vk);
        let mut u16_map = self.u16_to_vk.write().await;
        u16_map.insert(u16_id, vk);
    }

    /// Retrieves an Ed25519 verifying key by the 16-bit node ID prefix.
    pub async fn get_peer_verifying_key(&self, node_id_u16: u16) -> Option<ed25519_dalek::VerifyingKey> {
        let u16_map = self.u16_to_vk.read().await;
        u16_map.get(&node_id_u16).copied()
    }

    /// Retrieves an Ed25519 verifying key by the full 32-byte Node ID.
    pub async fn get_peer_verifying_key_by_node_id(&self, node_id: &[u8; 32]) -> Option<ed25519_dalek::VerifyingKey> {
        let keys = self.verifying_keys.read().await;
        keys.get(node_id).copied()
    }

    /// Enforces the Gossip Barrier:
    /// Gossip (Heartbeats and Lock Announcements) is ONLY accepted from direct F2F friends.
    /// Cryptographic identity (verified remote_node_id) is primarily used for authorization.
    /// Strikt auf permanenter NodePubKey / NodeId, nicht HRW.
    pub async fn can_accept_gossip(&self, remote_addr: &SocketAddr, remote_node_id: Option<&[u8; 32]>) -> bool {
        if let Some(node_id) = remote_node_id {
            if self.is_banned(node_id).await {
                return false;
            }
            return self.is_f2f_friend(node_id).await;
        }
        self.is_f2f_addr(remote_addr).await
    }

    /// Enforces Shard-Direct Contact Authorization:
    /// A direct Shard-RPC is allowed if and only if the remote node is either an F2F friend
    /// or was previously learned via F2F gossip (exists in known_network_nodes).
    /// Cryptographic identity (verified remote_node_id) is primarily used for authorization.
    /// F2F check strictly on NodePubKey, HRW only for sharding scoring.
    pub async fn can_authorize_direct_rpc(&self, remote_addr: &SocketAddr, remote_node_id: Option<&[u8; 32]>) -> bool {
        if let Some(node_id) = remote_node_id {
            if self.is_banned(node_id).await {
                return false;
            }
            return self.is_known_node(node_id).await;
        }
        self.is_f2f_addr(remote_addr).await || self.is_known_addr(remote_addr).await
    }

    /// Checks if a node is banned due to proven equivocation/slashing.
    pub async fn is_banned(&self, node_id: &[u8; 32]) -> bool {
        let banned = self.banned_nodes.read().await;
        banned.contains(node_id)
    }

    /// Permanently bans a node by its 32-byte pubkey, disconnects its QUIC connection and suspends it.
    /// Returns the number of peer entries affected.
    pub async fn ban_node(&self, node_id: &[u8; 32]) -> usize {
        {
            let mut banned = self.banned_nodes.write().await;
            banned.insert(*node_id);
        }
        let mut affected = 0usize;
        {
            let mut peers = self.peers.write().await;
            for peer in peers.values_mut() {
                if let Some(nid) = peer.node_id {
                    if &nid == node_id {
                        if let Some(conn) = peer.connection.take() {
                            conn.close(0u32.into(), b"banned: equivocation proof");
                        }
                        peer.status = PeerStatus::Suspended;
                        peer.missing_count = crate::network::peer::FAILURE_THRESHOLD_SUSPENDED;
                        affected += 1;
                    }
                }
            }
        }
        {
            let mut known = self.known_network_nodes.write().await;
            if known.remove(node_id).is_some() {
                affected += 1;
            }
        }
        {
            let mut friends = self.f2f_friends.write().await;
            if friends.remove(node_id).is_some() {
                affected += 1;
            }
        }
        affected
    }

    /// Sets the QUIC endpoint for outbound peer connections.
    pub fn set_endpoint(&self, endpoint: quinn::Endpoint) {
        if let Ok(mut ep) = self.endpoint.write() {
            *ep = Some(endpoint);
        }
    }

    /// Retrieves the QUIC endpoint if configured.
    pub fn get_endpoint(&self) -> Option<quinn::Endpoint> {
        self.endpoint.read().ok().and_then(|ep| ep.clone())
    }

    /// Records a failed interaction with a peer (debounced to at most once per 10s).
    pub async fn record_failure(&self, addr: SocketAddr) {
        self.record_failure_at(addr, Instant::now()).await;
    }

    /// Records a failed interaction with a peer at a specific timestamp (for debounce verification).
    pub async fn record_failure_at(&self, addr: SocketAddr, now: Instant) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(&addr) {
            peer.mark_failure_at(now);
        } else {
            let mut info = PeerInfo::with_type(addr, PeerConnectionType::ShardDirect);
            info.mark_failure_at(now);
            peers.insert(addr, info);
        }
    }

    /// Retrieves an active QUIC connection for a peer, if present, open, and authorized.
    pub async fn get_connection(&self, addr: &SocketAddr) -> Option<quinn::Connection> {
        let peers = self.peers.read().await;
        peers.get(addr).and_then(|p| {
            if p.conn_type == PeerConnectionType::Untrusted {
                return None;
            }
            if let Some(ref conn) = p.connection {
                if conn.close_reason().is_none() {
                    return Some(conn.clone());
                }
            }
            None
        })
    }

    /// Sets or replaces the QUIC connection for a peer.
    pub async fn set_connection(&self, addr: SocketAddr, conn: quinn::Connection) {
        let mut peers = self.peers.write().await;
        let entry = peers.entry(addr).or_insert_with(|| PeerInfo::new(addr));
        entry.connection = Some(conn);
        entry.status = PeerStatus::Connected;
        drop(peers);
        self.notify_sync_trigger();
    }

    /// Returns the number of currently connected peers.
    pub async fn connected_peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.values().filter(|p| p.is_connected()).count()
    }

    /// Returns all configured peer socket addresses.
    pub async fn all_peer_addrs(&self) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        peers.keys().copied().collect()
    }

    /// Returns all configured peer socket addresses that are not currently suspended.
    pub async fn non_suspended_peer_addrs(&self) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|p| !p.is_suspended())
            .map(|p| p.addr)
            .collect()
    }

    /// Returns a list of (NodeId, SocketAddr) for all peers and known network nodes that are not suspended.
    /// Skips immature entries (only mature shard tickets count).
    pub async fn active_known_nodes(&self) -> Vec<([u8; 32], SocketAddr)> {
        let mut result = Vec::new();
        let peers = self.peers.read().await;
        for p in peers.values() {
            if !p.is_suspended() {
                if let Some(nid) = p.node_id {
                    result.push((nid, p.addr));
                }
            }
        }
        let known = self.known_network_nodes.read().await;
        for (&nid, kinfo) in known.iter() {
            if kinfo.is_immature() {
                continue;
            }
            if !result.iter().any(|(id, _)| id == &nid) {
                let is_suspended = peers.get(&kinfo.addr).map(|p| p.is_suspended()).unwrap_or(false);
                if !is_suspended {
                    result.push((nid, kinfo.addr));
                }
            }
        }
        result
    }

    /// HRW-aware variant: returns list of (hrw_routing_id, SocketAddr) for eligible nodes.
    pub async fn active_hrw_nodes(&self) -> Vec<([u8; 32], SocketAddr)> {
        let peers = self.peers.read().await;
        let known = self.known_network_nodes.read().await;
        let mut result = Vec::new();
        for p in peers.values() {
            if !p.is_suspended() {
                if let Some(nid) = p.node_id {
                    let hrw = known.get(&nid).map(|k| k.hrw_routing_id).unwrap_or(nid);
                    result.push((hrw, p.addr));
                }
            }
        }
        for (&nid, kinfo) in known.iter() {
            if kinfo.is_immature() {
                continue;
            }
            if !result.iter().any(|(_, addr)| addr == &kinfo.addr) {
                let is_suspended = peers.get(&kinfo.addr).map(|p| p.is_suspended()).unwrap_or(false);
                if !is_suspended {
                    result.push((kinfo.hrw_routing_id, kinfo.addr));
                }
            }
            let _ = nid;
        }
        result
    }

    /// Returns the estimated total count of active nodes in the network (peers + known nodes + self).
    /// Skips immature entries (only mature shard tickets count).
    pub fn active_nodes_count(&self) -> usize {
        let mut count = 1; // Always include self (INV: local node is active)
        if let Ok(peers) = self.peers.try_read() {
            let mut unique_nodes = HashSet::new();
            for p in peers.values() {
                if !p.is_suspended() {
                    if let Some(nid) = p.node_id {
                        unique_nodes.insert(nid);
                    }
                }
            }
            if let Ok(known) = self.known_network_nodes.try_read() {
                for (&nid, kinfo) in known.iter() {
                    if kinfo.is_immature() {
                        continue;
                    }
                    let is_suspended = peers.get(&kinfo.addr).map(|p| p.is_suspended()).unwrap_or(false);
                    if !is_suspended {
                        unique_nodes.insert(nid);
                    }
                }
            }
            count += unique_nodes.len();
        }
        count
    }

    /// 24h finality hysteresis: FINAL status only if network has been stable with >=20 mature nodes for 24h.
    pub fn is_network_stable_ge20_for_24h(&self, now_ms: u64) -> bool {
        if self.active_nodes_count() >= 20 {
            let start = self.ge20_first_reached_ms.load(Ordering::Relaxed);
            if start == 0 {
                self.ge20_first_reached_ms.store(now_ms, Ordering::Relaxed);
                return false;
            }
            now_ms.saturating_sub(start) >= 86_400_000
        } else {
            self.ge20_first_reached_ms.store(0, Ordering::Relaxed);
            false
        }
    }

    /// Autonomous healing: decrements penalty counter of all registered peers by 1.
    pub async fn decay_all_peers(&self) {
        let mut peers = self.peers.write().await;
        for peer in peers.values_mut() {
            peer.decay_malus();
        }
    }

    /// Returns all F2F friend addresses for the periodic heartbeat emitter.
    pub async fn f2f_peer_addrs(&self) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|p| p.conn_type == PeerConnectionType::FriendToFriend)
            .map(|p| p.addr)
            .collect()
    }

    /// Returns shard sync candidates for digest pull (non-suspended peers).
    pub async fn shard_sync_addrs(&self) -> Vec<SocketAddr> {
        self.non_suspended_peer_addrs().await
    }

    /// Returns active peers for PEX discovery endpoint, filtered against banned and suspended status.
    pub async fn get_pex_peers(&self) -> Vec<KnownNodeInfo> {
        let banned = self.banned_nodes.read().await;
        let peers = self.peers.read().await;
        let known = self.known_network_nodes.read().await;

        let mut result = Vec::new();
        for (&nid, kinfo) in known.iter() {
            if banned.contains(&nid) {
                continue;
            }
            let is_suspended = peers.get(&kinfo.addr).map(|p| p.is_suspended()).unwrap_or(false);
            if !is_suspended {
                result.push(kinfo.clone());
            }
        }
        result
    }


    /// Computes an hourly jitter interval (50min + 0..20min = avg 60min).
    pub fn heartbeat_jitter_secs() -> u64 {
        let base: u64 = 3000;
        let max_jitter: u64 = 1200;
        let jitter: u64 = rand::thread_rng().gen_range(0..=max_jitter);
        base + jitter
    }

    /// Returns a reference to the NetworkClock (Spec 11).
    pub fn clock(&self) -> &Arc<crate::network::NetworkClock> {
        &self.clock
    }

    /// Returns the P2P Network-Adjusted Time (`net_time`) in ms (< 1µs, lock-free).
    pub fn net_time_ms(&self) -> u64 {
        self.clock.net_time_ms()
    }

    /// Computes backoff duration with symmetric random jitter (+/-25%) and dormant cap according to Spec 15 / Spec 19.
    pub fn compute_backoff(&self, attempt: u32) -> Duration {
        if attempt >= 12 {
            return Duration::from_secs(3600); // 1h Dormant Cap for permanently unreachable nodes
        }
        let shift = attempt.min(6);
        let factor = 1u64 << shift;
        let base = self.base_backoff_ms.saturating_mul(factor);
        let capped = base.min(self.max_backoff_ms);

        let quarter = capped / 4;
        let jittered = if quarter > 0 {
            let delta = rand::thread_rng().gen_range(0..=(2 * quarter));
            capped.saturating_sub(quarter).saturating_add(delta)
        } else {
            capped
        };

        Duration::from_millis(jittered)
    }

    /// Returns the backoff duration for reconnecting to a peer if it has failed attempts or is suspended.
    pub async fn get_reconnect_backoff(&self, addr: &SocketAddr) -> Option<Duration> {
        let peers = self.peers.read().await;
        if let Some(peer) = peers.get(addr) {
            if peer.missing_count > 0 || peer.status == PeerStatus::Suspended {
                let attempts = peer.missing_count.max(1);
                return Some(self.compute_backoff(attempts));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_peer_manager_operations() {
        let addr1: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:9092".parse().unwrap();

        let manager = PeerManager::new(vec![addr1]);
        assert_eq!(manager.list_peers().await.len(), 1);

        manager.add_peer(addr2).await;
        assert_eq!(manager.list_peers().await.len(), 2);

        manager.record_failure(addr1).await;
        let p1 = manager.get_peer(&addr1).await.unwrap();
        assert_eq!(p1.missing_count, 1);

        manager.record_success(addr1, Some([7u8; 32]), None).await;
        let p1_recovered = manager.get_peer(&addr1).await.unwrap();
        assert_eq!(p1_recovered.missing_count, 0);
        assert_eq!(p1_recovered.status, PeerStatus::Connected);
        assert_eq!(p1_recovered.node_id, Some([7u8; 32]));
    }

    #[test]
    fn test_backoff_computation() {
        let manager = PeerManager::new(vec![]);
        let b0 = manager.compute_backoff(0);
        let b1 = manager.compute_backoff(1);
        let b6 = manager.compute_backoff(6);
        let b12 = manager.compute_backoff(12);

        // Symmetric jitter +/-25%: [0.75 * base ..= 1.25 * base]
        assert!(b0.as_millis() >= (DEFAULT_BASE_BACKOFF_MS * 3 / 4) as u128);
        assert!(b0.as_millis() <= (DEFAULT_BASE_BACKOFF_MS * 5 / 4) as u128);
        assert!(b1.as_millis() >= (DEFAULT_BASE_BACKOFF_MS * 2 * 3 / 4) as u128);
        assert!(b1.as_millis() <= (DEFAULT_BASE_BACKOFF_MS * 2 * 5 / 4) as u128);
        assert!(b6.as_millis() <= (DEFAULT_MAX_BACKOFF_MS * 5 / 4) as u128);
        assert_eq!(b12.as_secs(), 3600, "Attempt >= 12 must trigger 1h dormant cap");
    }

    #[tokio::test]
    async fn test_debounced_record_failure() {
        let addr: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let manager = PeerManager::new(vec![addr]);

        let t0 = Instant::now();
        manager.record_failure_at(addr, t0).await;
        assert_eq!(manager.get_peer(&addr).await.unwrap().missing_count, 1);

        // Rapid failures within 60s must not increase missing_count
        manager.record_failure_at(addr, t0 + Duration::from_secs(1)).await;
        manager.record_failure_at(addr, t0 + Duration::from_secs(15)).await;
        manager.record_failure_at(addr, t0 + Duration::from_secs(59)).await;
        assert_eq!(manager.get_peer(&addr).await.unwrap().missing_count, 1);

        // Failure after 60s increases missing_count to 2
        manager.record_failure_at(addr, t0 + Duration::from_secs(60)).await;
        assert_eq!(manager.get_peer(&addr).await.unwrap().missing_count, 2);
    }

    #[test]
    fn test_calculate_fan_out_biomimetic() {
        // Dorf: d=1 -> k=1
        assert_eq!(calculate_fan_out(0), 0);
        assert_eq!(calculate_fan_out(1), 1);
        assert_eq!(calculate_fan_out(2), 2);
        assert_eq!(calculate_fan_out(3), 3);
        // Standard-Node: d=16 -> k=5
        assert_eq!(calculate_fan_out(16), 5);
        // Large mesh hub: d=64 -> k=9
        assert_eq!(calculate_fan_out(64), 9);
    }
}
