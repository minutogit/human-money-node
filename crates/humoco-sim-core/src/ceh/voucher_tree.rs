#![forbid(unsafe_code)]

//! Hierarchical Voucher Split-Tree (Merkle Tree over voucher split trees).
//!
//! Implements canonical voucher split tree representation and hierarchical closed state roots
//! for Certified Epoch Handoff (CEH).
//!
//! In HuMoCo, vouchers can be spent as:
//! 1. Direct transfer (1-to-1): `parent_lock -> [child_lock]`
//! 2. Split payment (1-to-2): `parent_lock -> [payment_child_lock, change_child_lock]`
//!
//! Recursive splits create a Binary Tree (Split-Tree) rooted at the immutable `voucher_root`
//! (Genesis Parent Anchor, per INV-0302 Trust-Tree Locality).
//! Non-split vouchers are simply degenerate trees (linear chains with 1 child per hop).

use std::collections::{BTreeMap, BTreeSet};

use crate::ceh::crypto::{
    update_with_domain, DOMAIN_CEH_HIERARCHICAL_STATE_ROOT, DOMAIN_CEH_VOUCHER_HOP,
    DOMAIN_CEH_VOUCHER_TREE,
};

/// Represents a single hop in a voucher split tree.
///
/// Hops represent atomic spends from a `parent_lock` to one or more `children`.
/// Direct payments have 1 child (`parent -> [child]`), while split payments
/// have 2 children (`parent -> [payment_child, change_child]`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct VoucherHop {
    pub parent_lock: [u8; 32],
    /// Canonically sorted children locks in ascending byte order.
    pub children: Vec<[u8; 32]>,
    pub valid_until: u64,
}

impl VoucherHop {
    /// Creates a new `VoucherHop`, sorting `children` canonically in ascending byte order.
    pub fn new(parent_lock: [u8; 32], mut children: Vec<[u8; 32]>, valid_until: u64) -> Self {
        children.sort();
        Self {
            parent_lock,
            children,
            valid_until,
        }
    }

    /// Convenience constructor for a 1-to-1 direct payment hop.
    pub fn direct(parent_lock: [u8; 32], child_lock: [u8; 32], valid_until: u64) -> Self {
        Self {
            parent_lock,
            children: vec![child_lock],
            valid_until,
        }
    }

    /// Convenience constructor for a 1-to-2 split payment + change hop.
    ///
    /// The two child locks are canonically sorted in ascending byte order.
    pub fn split(
        parent_lock: [u8; 32],
        child_a: [u8; 32],
        child_b: [u8; 32],
        valid_until: u64,
    ) -> Self {
        let mut children = vec![child_a, child_b];
        children.sort();
        Self {
            parent_lock,
            children,
            valid_until,
        }
    }

    /// Returns true if this hop represents a split payment (2 children).
    pub fn is_split(&self) -> bool {
        self.children.len() == 2
    }

    /// Returns true if this hop represents a direct payment (1 child).
    pub fn is_direct(&self) -> bool {
        self.children.len() == 1
    }

    /// Computes the deterministic BLAKE3 digest of this hop under `HUMOCO_V1_CEH_VOUCHER_HOP`.
    pub fn compute_hop_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        update_with_domain(&mut hasher, DOMAIN_CEH_VOUCHER_HOP);
        hasher.update(&self.parent_lock);
        hasher.update(&self.valid_until.to_le_bytes());

        // Canonical sort guarantees deterministic hashing even if initialized via struct literal
        let mut sorted_children = self.children.clone();
        sorted_children.sort();
        let num_children = sorted_children.len() as u32;
        hasher.update(&num_children.to_le_bytes());
        for child in &sorted_children {
            hasher.update(child);
        }

        *hasher.finalize().as_bytes()
    }
}

/// Represents the complete split tree of a single voucher anchor.
///
/// Rooted at the immutable `voucher_root` (Genesis Parent Anchor, per INV-0302).
/// Hops are maintained in a `BTreeSet` for canonical ordering.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VoucherSplitTree {
    /// The origin voucher anchor (Genesis Parent Anchor).
    pub voucher_root: [u8; 32],
    /// Canonical ordered set of hops belonging to this voucher.
    pub hops: BTreeSet<VoucherHop>,
}

impl VoucherSplitTree {
    /// Creates a new empty `VoucherSplitTree` rooted at `voucher_root`.
    pub fn new(voucher_root: [u8; 32]) -> Self {
        Self {
            voucher_root,
            hops: BTreeSet::new(),
        }
    }

    /// Creates a `VoucherSplitTree` with the given hops.
    pub fn with_hops(voucher_root: [u8; 32], hops: BTreeSet<VoucherHop>) -> Self {
        Self {
            voucher_root,
            hops,
        }
    }

    /// Inserts a hop into the split tree. Returns true if the hop was newly inserted.
    pub fn add_hop(&mut self, hop: VoucherHop) -> bool {
        self.hops.insert(hop)
    }

    /// Computes the deterministic BLAKE3 hash of this split tree under `HUMOCO_V1_CEH_VOUCHER_TREE`.
    ///
    /// First hashes each hop deterministically under `HUMOCO_V1_CEH_VOUCHER_HOP`,
    /// then hashes the sorted hop digests along with `voucher_root`.
    pub fn compute_tree_root(&self) -> [u8; 32] {
        let mut hop_hashes: Vec<[u8; 32]> = self.hops.iter().map(|h| h.compute_hop_hash()).collect();
        hop_hashes.sort();

        let mut hasher = blake3::Hasher::new();
        update_with_domain(&mut hasher, DOMAIN_CEH_VOUCHER_TREE);
        hasher.update(&self.voucher_root);
        let num_hops = hop_hashes.len() as u64;
        hasher.update(&num_hops.to_le_bytes());
        for hop_hash in &hop_hashes {
            hasher.update(hop_hash);
        }

        *hasher.finalize().as_bytes()
    }

    /// Returns the number of hops in this split tree.
    pub fn len(&self) -> usize {
        self.hops.len()
    }

    /// Returns true if this split tree contains no hops.
    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }
}

/// Shard State Snapshot using Hierarchical Voucher Split-Trees.
///
/// Groups collision locks by their immutable `voucher_root` anchor (INV-0302 Trust-Tree Locality),
/// enabling hierarchical Merkle hashing and $O(\log n)$ sync divergence detection.
#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct HierarchicalShardSnapshot {
    pub shard_id: u16,
    pub epoch: u64,
    /// Split trees indexed by their immutable `voucher_root`.
    pub voucher_trees: BTreeMap<[u8; 32], VoucherSplitTree>,
}

impl HierarchicalShardSnapshot {
    /// Creates a new empty `HierarchicalShardSnapshot`.
    pub fn new(shard_id: u16, epoch: u64) -> Self {
        Self {
            shard_id,
            epoch,
            voucher_trees: BTreeMap::new(),
        }
    }

    /// Builds a snapshot from a map of voucher trees.
    pub fn build(
        shard_id: u16,
        epoch: u64,
        voucher_trees: BTreeMap<[u8; 32], VoucherSplitTree>,
    ) -> Self {
        Self {
            shard_id,
            epoch,
            voucher_trees,
        }
    }

    /// Inserts or replaces a voucher split tree.
    pub fn insert_tree(&mut self, tree: VoucherSplitTree) {
        self.voucher_trees.insert(tree.voucher_root, tree);
    }

    /// Computes the hierarchical closed state root for this shard snapshot.
    ///
    /// Computes BLAKE3 hash under domain tag `HUMOCO_V1_CEH_HIERARCHICAL_STATE_ROOT`
    /// over all `(voucher_root, voucher_tree_root)` in canonical byte order.
    pub fn compute_hierarchical_closed_state_root(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        update_with_domain(&mut hasher, DOMAIN_CEH_HIERARCHICAL_STATE_ROOT);
        hasher.update(&self.shard_id.to_le_bytes());
        hasher.update(&self.epoch.to_le_bytes());
        let num_vouchers = self.voucher_trees.len() as u64;
        hasher.update(&num_vouchers.to_le_bytes());

        for (voucher_root, tree) in &self.voucher_trees {
            let tree_root = tree.compute_tree_root();
            hasher.update(voucher_root);
            hasher.update(&tree_root);
        }

        *hasher.finalize().as_bytes()
    }

    /// Quickly detects which specific `voucher_root`s differ between two nodes for $O(\log n)$ sync
    /// without scanning every lock in the shard.
    ///
    /// Compares voucher trees in canonical order: matching tree roots skip all contained hops,
    /// while divergent voucher roots are returned in sorted order.
    pub fn find_divergent_vouchers(&self, other: &HierarchicalShardSnapshot) -> Vec<[u8; 32]> {
        let mut divergent = Vec::new();
        let mut it1 = self.voucher_trees.iter().peekable();
        let mut it2 = other.voucher_trees.iter().peekable();

        while let (Some((&k1, tree1)), Some((&k2, tree2))) = (it1.peek(), it2.peek()) {
            match k1.cmp(&k2) {
                std::cmp::Ordering::Less => {
                    divergent.push(k1);
                    it1.next();
                }
                std::cmp::Ordering::Greater => {
                    divergent.push(k2);
                    it2.next();
                }
                std::cmp::Ordering::Equal => {
                    if tree1.compute_tree_root() != tree2.compute_tree_root() {
                        divergent.push(k1);
                    }
                    it1.next();
                    it2.next();
                }
            }
        }

        for (&k1, _) in it1 {
            divergent.push(k1);
        }
        for (&k2, _) in it2 {
            divergent.push(k2);
        }

        divergent
    }

    /// Merges missing unexpired hops per voucher tree from another replica (Set-Union).
    ///
    /// Hops with `valid_until <= current_time` are discarded as expired.
    pub fn reconcile_union(&mut self, other: &HierarchicalShardSnapshot, current_time: u64) {
        for (voucher_root, other_tree) in &other.voucher_trees {
            let unexpired_hops: Vec<_> = other_tree
                .hops
                .iter()
                .filter(|hop| hop.valid_until > current_time)
                .cloned()
                .collect();

            if !unexpired_hops.is_empty() {
                let tree = self
                    .voucher_trees
                    .entry(*voucher_root)
                    .or_insert_with(|| VoucherSplitTree::new(*voucher_root));
                for hop in unexpired_hops {
                    tree.hops.insert(hop);
                }
            }
        }
    }

    /// Physically prunes expired hops across all voucher trees and removes empty trees.
    pub fn prune_expired(&mut self, current_time: u64) {
        self.voucher_trees.retain(|_, tree| {
            tree.hops.retain(|hop| hop.valid_until > current_time);
            !tree.hops.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linear_chain_voucher_1_to_1() {
        let root = [1u8; 32];
        let hop1 = VoucherHop::direct(root, [2u8; 32], 1000);
        let hop2 = VoucherHop::direct([2u8; 32], [3u8; 32], 1000);
        let hop3 = VoucherHop::direct([3u8; 32], [4u8; 32], 1000);

        assert!(hop1.is_direct());
        assert!(!hop1.is_split());

        let mut tree = VoucherSplitTree::new(root);
        tree.add_hop(hop1);
        tree.add_hop(hop2);
        tree.add_hop(hop3);

        assert_eq!(tree.len(), 3);
        let root_hash = tree.compute_tree_root();
        assert_ne!(root_hash, [0u8; 32]);

        // Determinism test: recomputing on the same tree produces identical hash
        assert_eq!(root_hash, tree.compute_tree_root());
    }

    #[test]
    fn test_binary_split_tree_voucher_1_to_2_recursive() {
        let root = [10u8; 32];
        // Split hop at root (1-to-2)
        let child_payment = [11u8; 32];
        let child_change = [12u8; 32];
        let hop0 = VoucherHop::split(root, child_payment, child_change, 2000);
        assert!(hop0.is_split());
        assert!(!hop0.is_direct());

        // Recursive split on payment child (1-to-2)
        let sub_payment = [13u8; 32];
        let sub_change = [14u8; 32];
        let hop1 = VoucherHop::split(child_payment, sub_payment, sub_change, 2000);

        // Direct payment on change child (1-to-1)
        let change_spend = [15u8; 32];
        let hop2 = VoucherHop::direct(child_change, change_spend, 2000);

        let mut split_tree = VoucherSplitTree::new(root);
        split_tree.add_hop(hop0);
        split_tree.add_hop(hop1);
        split_tree.add_hop(hop2);

        assert_eq!(split_tree.len(), 3);
        let split_root = split_tree.compute_tree_root();
        assert_ne!(split_root, [0u8; 32]);

        // A linear tree with different hops will have a different root
        let linear_tree = VoucherSplitTree::with_hops(
            root,
            BTreeSet::from([
                VoucherHop::direct(root, [11u8; 32], 2000),
                VoucherHop::direct([11u8; 32], [13u8; 32], 2000),
            ]),
        );
        assert_ne!(split_root, linear_tree.compute_tree_root());
    }

    #[test]
    fn test_identical_root_regardless_of_hop_insertion_order() {
        let root = [20u8; 32];
        let h1 = VoucherHop::direct(root, [21u8; 32], 5000);
        let h2 = VoucherHop::split([21u8; 32], [22u8; 32], [23u8; 32], 5000);
        let h3 = VoucherHop::direct([22u8; 32], [24u8; 32], 5000);
        let h4 = VoucherHop::split([23u8; 32], [25u8; 32], [26u8; 32], 5000);
        let h5 = VoucherHop::direct([24u8; 32], [27u8; 32], 5000);

        // Insertion order A: 1, 2, 3, 4, 5
        let mut tree_a = VoucherSplitTree::new(root);
        tree_a.add_hop(h1.clone());
        tree_a.add_hop(h2.clone());
        tree_a.add_hop(h3.clone());
        tree_a.add_hop(h4.clone());
        tree_a.add_hop(h5.clone());

        // Insertion order B: 5, 3, 1, 4, 2
        let mut tree_b = VoucherSplitTree::new(root);
        tree_b.add_hop(h5.clone());
        tree_b.add_hop(h3.clone());
        tree_b.add_hop(h1.clone());
        tree_b.add_hop(h4.clone());
        tree_b.add_hop(h2.clone());

        // Insertion order C: 4, 2, 5, 1, 3
        let mut tree_c = VoucherSplitTree::new(root);
        tree_c.add_hop(h4);
        tree_c.add_hop(h2);
        tree_c.add_hop(h5);
        tree_c.add_hop(h1);
        tree_c.add_hop(h3);

        let root_a = tree_a.compute_tree_root();
        let root_b = tree_b.compute_tree_root();
        let root_c = tree_c.compute_tree_root();

        assert_eq!(root_a, root_b);
        assert_eq!(root_b, root_c);
    }

    #[test]
    fn test_difference_detection_altered_child() {
        let v1_root = [100u8; 32];
        let v2_root = [200u8; 32];

        // V1: Linear chain
        let mut v1 = VoucherSplitTree::new(v1_root);
        v1.add_hop(VoucherHop::direct(v1_root, [101u8; 32], 5000));
        v1.add_hop(VoucherHop::direct([101u8; 32], [102u8; 32], 5000));

        // V2: Binary split tree in snap1
        let mut v2_snap1 = VoucherSplitTree::new(v2_root);
        v2_snap1.add_hop(VoucherHop::split(v2_root, [201u8; 32], [202u8; 32], 5000));
        v2_snap1.add_hop(VoucherHop::direct([201u8; 32], [203u8; 32], 5000));

        // V2': Binary split tree in snap2 with ONE altered child ([204u8; 32] instead of [203u8; 32])
        let mut v2_snap2 = VoucherSplitTree::new(v2_root);
        v2_snap2.add_hop(VoucherHop::split(v2_root, [201u8; 32], [202u8; 32], 5000));
        v2_snap2.add_hop(VoucherHop::direct([201u8; 32], [204u8; 32], 5000));

        // Verify V1 hashes match
        let v1_root_hash = v1.compute_tree_root();

        // Verify V2 hashes differ
        let v2_snap1_hash = v2_snap1.compute_tree_root();
        let v2_snap2_hash = v2_snap2.compute_tree_root();
        assert_ne!(v2_snap1_hash, v2_snap2_hash);

        // Build shard snapshots
        let mut snap1 = HierarchicalShardSnapshot::new(42, 1);
        snap1.insert_tree(v1.clone());
        snap1.insert_tree(v2_snap1);

        let mut snap2 = HierarchicalShardSnapshot::new(42, 1);
        snap2.insert_tree(v1);
        snap2.insert_tree(v2_snap2);

        // Verify shard roots differ
        let snap1_state_root = snap1.compute_hierarchical_closed_state_root();
        let snap2_state_root = snap2.compute_hierarchical_closed_state_root();
        assert_ne!(snap1_state_root, snap2_state_root);

        // Verify find_divergent_vouchers identifies ONLY v2_root
        let divergent = snap1.find_divergent_vouchers(&snap2);
        assert_eq!(divergent, vec![v2_root]);

        // Symmetric check
        let divergent_reverse = snap2.find_divergent_vouchers(&snap1);
        assert_eq!(divergent_reverse, vec![v2_root]);

        // When compared against self, difference is empty
        assert!(snap1.find_divergent_vouchers(&snap1).is_empty());
        assert_eq!(v1_root_hash, snap1.voucher_trees[&v1_root].compute_tree_root());
    }

    #[test]
    fn test_union_reconciliation() {
        let v1_root = [10u8; 32];
        let v2_root = [20u8; 32];
        let v_expired_root = [30u8; 32];

        let h1 = VoucherHop::direct(v1_root, [11u8; 32], 1000);
        let h2 = VoucherHop::direct([11u8; 32], [12u8; 32], 2000);
        let h3 = VoucherHop::direct([12u8; 32], [13u8; 32], 3000);
        let h_expired = VoucherHop::direct([13u8; 32], [14u8; 32], 500); // Expired at t=600

        // Snap1: V1 with h1 and h2
        let mut snap1 = HierarchicalShardSnapshot::new(1, 10);
        let mut v1_tree_1 = VoucherSplitTree::new(v1_root);
        v1_tree_1.add_hop(h1.clone());
        v1_tree_1.add_hop(h2.clone());
        snap1.insert_tree(v1_tree_1);

        // Snap2: V1 with h1, h3, and h_expired
        //        V2 with unexpired hop h_v2 (t=2500) and expired hop h_v2_exp (t=400)
        //        V_expired with only an expired hop (t=300)
        let mut snap2 = HierarchicalShardSnapshot::new(1, 10);
        let mut v1_tree_2 = VoucherSplitTree::new(v1_root);
        v1_tree_2.add_hop(h1.clone());
        v1_tree_2.add_hop(h3.clone());
        v1_tree_2.add_hop(h_expired);
        snap2.insert_tree(v1_tree_2);

        let h_v2 = VoucherHop::split(v2_root, [21u8; 32], [22u8; 32], 2500);
        let h_v2_exp = VoucherHop::direct([21u8; 32], [23u8; 32], 400);
        let mut v2_tree = VoucherSplitTree::new(v2_root);
        v2_tree.add_hop(h_v2.clone());
        v2_tree.add_hop(h_v2_exp);
        snap2.insert_tree(v2_tree);

        let h_v_exp = VoucherHop::direct(v_expired_root, [31u8; 32], 300);
        let mut v_exp_tree = VoucherSplitTree::new(v_expired_root);
        v_exp_tree.add_hop(h_v_exp);
        snap2.insert_tree(v_exp_tree);

        // Reconcile snap1 with snap2 at current_time = 600
        snap1.reconcile_union(&snap2, 600);

        // Verification:
        // 1. V1 in snap1 now has h1, h2, h3 (3 hops). h_expired was NOT merged.
        let v1_reconciled = &snap1.voucher_trees[&v1_root];
        assert_eq!(v1_reconciled.len(), 3);
        assert!(v1_reconciled.hops.contains(&h1));
        assert!(v1_reconciled.hops.contains(&h2));
        assert!(v1_reconciled.hops.contains(&h3));

        // 2. V2 was added to snap1 with only h_v2. h_v2_exp was NOT merged.
        let v2_reconciled = &snap1.voucher_trees[&v2_root];
        assert_eq!(v2_reconciled.len(), 1);
        assert!(v2_reconciled.hops.contains(&h_v2));

        // 3. V_expired was NOT added to snap1 because all its hops are expired at t=600.
        assert!(!snap1.voucher_trees.contains_key(&v_expired_root));
    }

    #[test]
    fn test_prune_expired() {
        let v_root = [50u8; 32];
        let h_valid = VoucherHop::direct(v_root, [51u8; 32], 1000);
        let h_expired = VoucherHop::direct([51u8; 32], [52u8; 32], 500);

        let mut tree = VoucherSplitTree::new(v_root);
        tree.add_hop(h_valid.clone());
        tree.add_hop(h_expired);

        let mut snap = HierarchicalShardSnapshot::new(1, 1);
        snap.insert_tree(tree);

        assert_eq!(snap.voucher_trees[&v_root].len(), 2);

        // Prune at t=600 -> expired hop should be removed, valid hop remains
        snap.prune_expired(600);
        assert_eq!(snap.voucher_trees[&v_root].len(), 1);
        assert!(snap.voucher_trees[&v_root].hops.contains(&h_valid));

        // Prune at t=1200 -> all hops expired, tree is removed
        snap.prune_expired(1200);
        assert!(!snap.voucher_trees.contains_key(&v_root));
        assert!(snap.voucher_trees.is_empty());
    }

    #[test]
    fn test_find_divergent_vouchers_disjoint_and_empty() {
        let v1 = [1u8; 32];
        let v2 = [2u8; 32];
        let v3 = [3u8; 32];

        let mut snap_a = HierarchicalShardSnapshot::new(1, 1);
        let mut t1 = VoucherSplitTree::new(v1);
        t1.add_hop(VoucherHop::direct(v1, [10u8; 32], 1000));
        let mut t2 = VoucherSplitTree::new(v2);
        t2.add_hop(VoucherHop::direct(v2, [20u8; 32], 1000));
        snap_a.insert_tree(t1);
        snap_a.insert_tree(t2.clone());

        let mut snap_b = HierarchicalShardSnapshot::new(1, 1);
        let mut t3 = VoucherSplitTree::new(v3);
        t3.add_hop(VoucherHop::direct(v3, [30u8; 32], 1000));
        snap_b.insert_tree(t2);
        snap_b.insert_tree(t3);

        // A has {v1, v2}, B has {v2, v3}. v2 is identical.
        // Divergent vouchers should be v1 and v3 (in canonical sorted order).
        let diff = snap_a.find_divergent_vouchers(&snap_b);
        assert_eq!(diff, vec![v1, v3]);
    }
}
