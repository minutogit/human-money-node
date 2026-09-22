//! Topology helpers for mesh wiring.
//!
//! Provides deterministic F2F wiring for isolated, paired and chain topologies
//! used in the evolutionary growth scenario.

use std::net::SocketAddr;

use humoco_node::identity::NodeIdentity;

/// Topology pattern for a mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Topology {
    /// Single isolated node (N=1)
    Single,
    /// Pair with mutual F2F peering (N=2)
    Pair,
    /// Linear chain where each node peers with its predecessor/successor (N>=2)
    Chain,
    /// Fully meshed where every node peers with every other
    FullMesh,
}

/// Formats a F2F peer string `<pubkey_hex>@<addr>` for configuration.
pub fn f2f_peer_string(identity: &NodeIdentity, addr: SocketAddr) -> String {
    format!("{}@{}", identity.public_key_hex(), addr)
}

/// Formats a plain address peer string (no pubkey).
pub fn addr_peer_string(addr: SocketAddr) -> String {
    addr.to_string()
}

/// Generates F2F peer lists for a chain topology.
///
/// Given nodes with their identities and addresses, returns a vector
/// `peers_per_node` where `peers_per_node[i]` is the list of peer strings
/// that node `i` should be configured with (its immediate predecessor and
/// successor in the chain).
pub fn chain_peer_lists(
    identities: &[NodeIdentity],
    addrs: &[SocketAddr],
) -> Vec<Vec<String>> {
    assert_eq!(identities.len(), addrs.len());
    let n = identities.len();
    let mut result: Vec<Vec<String>> = vec![Vec::new(); n];
    for i in 0..n {
        if i > 0 {
            result[i].push(f2f_peer_string(&identities[i - 1], addrs[i - 1]));
        }
        if i + 1 < n {
            result[i].push(f2f_peer_string(&identities[i + 1], addrs[i + 1]));
        }
    }
    result
}

/// Generates peer lists for a full-mesh topology.
pub fn full_mesh_peer_lists(
    identities: &[NodeIdentity],
    addrs: &[SocketAddr],
) -> Vec<Vec<String>> {
    assert_eq!(identities.len(), addrs.len());
    let n = identities.len();
    let mut result: Vec<Vec<String>> = vec![Vec::new(); n];
    for (i, slot) in result.iter_mut().enumerate().take(n) {
        for j in 0..n {
            if i != j {
                slot.push(f2f_peer_string(&identities[j], addrs[j]));
            }
        }
    }
    result
}

/// Generates peer lists for a pair topology (mutual peering).
pub fn pair_peer_lists(
    id_a: &NodeIdentity,
    addr_a: SocketAddr,
    id_b: &NodeIdentity,
    addr_b: SocketAddr,
) -> (Vec<String>, Vec<String>) {
    (
        vec![f2f_peer_string(id_b, addr_b)],
        vec![f2f_peer_string(id_a, addr_a)],
    )
}

/// Human-readable description of a topology.
pub fn describe_topology(topology: Topology, n: usize) -> String {
    match topology {
        Topology::Single => format!("Single (N={n})"),
        Topology::Pair => format!("Pair (N={n}) mutual F2F"),
        Topology::Chain => format!("Chain (N={n}) linear"),
        Topology::FullMesh => format!("FullMesh (N={n}) all-to-all"),
    }
}
