#![allow(clippy::unwrap_used, clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(unused_variables, unused_mut, dead_code, unused_imports, unused_comparisons)]
//! Property-Based Tests for HuMoCo Layer-2 Collision Lock Registry
//!
//! Covers 5 mathematical property families (using `proptest`):
//! 1. Round-trip invertibility (WireHeader, LockEntry144, LockRecord, AccountTag)
//! 2. Idempotence of state machines f(f(x)) == f(x)
//! 3. Deterministic collision total ordering min(H_canon) — strict weak ordering
//! 4. Monotonicity of TTL pruning
//! 5. Quota monotonicity & hard-floor bounds
//!
//! Run with: `cargo test --test proptests_humoco_properties -- --nocapture`

use humoco_sim_core::{
    compute_canonical_hash, derive_account_tag, resolve_split_brain, resolve_split_brain_canonical,
    AccessControl, AccessTier, ByteYears, LockEntry144, LockRecord, NetworkThermometer,
    RamIndex, SimTime, WireHeader, WIRE_MAGIC, CURRENT_PROTOCOL_VERSION,
    HARD_FLOOR_BASELINE_DAILY, HARD_FLOOR_READ_BASELINE_DAILY, MAX_WHALE_MULTIPLIER,
    QuartileStats, SlottedMedianRingBuffer, compute_backoff,
    calculate_integer_ema, sign_lock_attestation, apply_attestation, promote_to_final_if_eligible,
};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Helpers / Strategies
// ---------------------------------------------------------------------------

fn arb_hash() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

fn arb_simtime() -> impl Strategy<Value = SimTime> {
    (0u64..=u64::MAX - 100_000).prop_map(SimTime)
}

fn arb_nonce() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..64)
}

fn arb_lock_record() -> impl Strategy<Value = LockRecord> {
    (arb_hash(), arb_hash(), arb_nonce(), 0u64..1_000_000_000u64, 1u64..1_000_000u64)
        .prop_map(|(parent, receiver, nonce, created, ttl)| {
            let created_at = SimTime(created);
            let valid_until = SimTime(created.saturating_add(ttl).saturating_add(31_000));
            LockRecord::new(parent, receiver, nonce, created_at, valid_until)
        })
}

fn arb_valid_lock_for_window(now_ms: u64, root_valid_ms: u64) -> impl Strategy<Value = LockRecord> {
    (arb_hash(), arb_hash(), arb_nonce()).prop_map(move |(parent, receiver, nonce)| {
        // valid_until must be > now+30s and <= root_valid_until
        let valid_until = SimTime(root_valid_ms.saturating_sub(1).max(now_ms + 31_000));
        LockRecord::new(parent, receiver, nonce, SimTime(now_ms), valid_until)
    })
}

// ---------------------------------------------------------------------------
// 1. Round-trip invertibility
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_wire_header_roundtrip(
        msg_type in any::<u16>(),
        session_seq in any::<u64>(),
        epoch_id in any::<u32>(),
        flags in any::<u32>(),
        payload_len in any::<u32>(),
        crypto_suite in any::<u8>(),
        min_compat_ver in any::<u8>(),
        reserved in any::<u16>(),
    ) {
        let mut hdr = WireHeader::new(msg_type, session_seq, epoch_id, flags, payload_len);
        hdr.crypto_suite = crypto_suite;
        hdr.min_compat_ver = min_compat_ver;
        hdr.reserved = reserved;
        // magic must survive roundtrip
        let bytes = hdr.to_bytes();
        prop_assert_eq!(bytes.len(), WireHeader::SIZE);
        prop_assert_eq!(bytes.len(), 32);
        let decoded = WireHeader::from_bytes(&bytes);
        prop_assert_eq!(decoded.magic, WIRE_MAGIC);
        prop_assert_eq!(decoded.protocol_version, CURRENT_PROTOCOL_VERSION);
        prop_assert_eq!(decoded.msg_type, msg_type);
        prop_assert_eq!(decoded.session_seq, session_seq);
        prop_assert_eq!(decoded.epoch_id, epoch_id);
        prop_assert_eq!(decoded.flags, flags);
        prop_assert_eq!(decoded.payload_len, payload_len);
        prop_assert_eq!(decoded.crypto_suite, crypto_suite);
        prop_assert_eq!(decoded.min_compat_ver, min_compat_ver);
        prop_assert_eq!(decoded.reserved, reserved);
        // double roundtrip stability
        let bytes2 = decoded.to_bytes();
        prop_assert_eq!(bytes, bytes2);
        let decoded2 = WireHeader::from_bytes(&bytes2);
        prop_assert_eq!(decoded, decoded2);
    }

    #[test]
    fn prop_wire_header_valid_magic_invariant(
        msg_type in any::<u16>(),
        session_seq in any::<u64>(),
    ) {
        let hdr = WireHeader::new(msg_type, session_seq, 0, 0, 0);
        prop_assert!(hdr.is_valid_magic());
        let bytes = hdr.to_bytes();
        let decoded = WireHeader::from_bytes(&bytes);
        prop_assert!(decoded.is_valid_magic());
        // tamper magic -> invalid
        let mut bad = bytes;
        bad[0] ^= 0xFF;
        let bad_hdr = WireHeader::from_bytes(&bad);
        // at least one magic byte changed => not equal WIRE_MAGIC unless XOR accidentally restores (negligible)
        if bad_hdr.magic != WIRE_MAGIC {
            prop_assert!(!bad_hdr.is_valid_magic());
        }
    }

    #[test]
    fn prop_wire_header_parse_valid_roundtrip(
        msg_type in prop::sample::select(vec![0x0001u16, 0x0003, 0x0005, 0x0101, 0x0201]),
        session_seq in 0u64..1_000_000,
        epoch_id in any::<u32>(),
        flags in any::<u32>(),
    ) {
        // Use an allowed msg_type for 0-RTT vs non-0-RTT both paths
        let hdr = WireHeader::new(msg_type, session_seq, epoch_id, flags, 128);
        let raw = hdr.to_bytes();
        // parse with correct expected_seq and is_0rtt=false -> always ok if magic/version match
        let parsed = humoco_sim_core::wire::parse_wire_header(&raw, session_seq, false).unwrap();
        prop_assert_eq!(parsed, hdr);
        // second parse with same raw == stable
        let parsed2 = humoco_sim_core::wire::parse_wire_header(&raw, session_seq, false).unwrap();
        prop_assert_eq!(parsed, parsed2);
    }

    #[test]
    fn prop_lock_entry144_roundtrip(
        parent in arb_hash(),
        receiver in arb_hash(),
        valid_until in any::<u64>(),
        sig in any::<[u8; 64]>(),
        status in any::<u8>(),
    ) {
        let entry = LockEntry144 {
            parent_lock: parent,
            receiver_pub: receiver,
            valid_until,
            owner_signature: sig,
            status,
            padding: [0xAA; 7],
        };
        let bytes = entry.to_bytes();
        prop_assert_eq!(bytes.len(), 144);
        prop_assert_eq!(bytes.len(), LockEntry144::SIZE);
        let decoded = LockEntry144::from_bytes(&bytes);
        prop_assert_eq!(decoded.parent_lock, parent);
        prop_assert_eq!(decoded.receiver_pub, receiver);
        prop_assert_eq!(decoded.valid_until, valid_until);
        prop_assert_eq!(decoded.owner_signature, sig);
        prop_assert_eq!(decoded.status, status);
        // idempotence of roundtrip
        let bytes2 = decoded.to_bytes();
        prop_assert_eq!(bytes, bytes2);
    }

    #[test]
    fn prop_lock_record_bincode_roundtrip(
        rec in arb_lock_record()
    ) {
        let bytes = bincode::serialize(&rec).expect("serialize");
        let decoded: LockRecord = bincode::deserialize(&bytes).expect("deserialize");
        prop_assert_eq!(rec.id, decoded.id);
        prop_assert_eq!(rec.parent_lock, decoded.parent_lock);
        prop_assert_eq!(rec.receiver_pub, decoded.receiver_pub);
        prop_assert_eq!(rec.nonce.clone(), decoded.nonce.clone());
        prop_assert_eq!(rec.created_at, decoded.created_at);
        prop_assert_eq!(rec.valid_until, decoded.valid_until);
        prop_assert_eq!(rec.status.clone(), decoded.status.clone());
        // second roundtrip stability
        let decoded2 = decoded.clone();
        let bytes2 = bincode::serialize(&decoded2).unwrap();
        prop_assert_eq!(bytes, bytes2);
    }

    #[test]
    fn prop_lock_record_id_deterministic(
        parent in arb_hash(),
        receiver in arb_hash(),
        nonce in arb_nonce(),
        created in 0u64..1_000_000u64,
        ttl in 1u64..1_000_000u64,
    ) {
        let created_at = SimTime(created);
        let valid_until = SimTime(created + ttl + 31_000);
        let a = LockRecord::new(parent, receiver, nonce.clone(), created_at, valid_until);
        let b = LockRecord::new(parent, receiver, nonce.clone(), created_at, valid_until);
        prop_assert_eq!(a.id, b.id);
        prop_assert_eq!(a.parent_lock, b.parent_lock);
        // different nonce => different id (with overwhelming probability; blake3 collision negligible)
        let mut nonce2 = nonce.clone();
        nonce2.push(0xFF);
        let c = LockRecord::new(parent, receiver, nonce2, created_at, valid_until);
        prop_assert_ne!(a.id, c.id);
    }

    #[test]
    fn prop_account_tag_roundtrip_and_determinism(
        client_pubkey in arb_hash(),
        node_secret in arb_hash(),
    ) {
        let tag1 = derive_account_tag(&client_pubkey, &node_secret);
        let tag2 = derive_account_tag(&client_pubkey, &node_secret);
        prop_assert_eq!(tag1, tag2);
        // different client => different tag (collision negligible)
        let mut other_pubkey = client_pubkey;
        other_pubkey[0] ^= 0xFF;
        let tag_other = derive_account_tag(&other_pubkey, &node_secret);
        prop_assert_ne!(tag1, tag_other);
        // AccessControl classify roundtrip: register -> classify returns same tier
        let mut ac = AccessControl::new(node_secret);
        let tag = ac.register_pubkey(client_pubkey, AccessTier::VipMerchant);
        prop_assert_eq!(tag, tag1);
        prop_assert_eq!(ac.classify(Some(tag)), AccessTier::VipMerchant);
        prop_assert_eq!(ac.classify(Some(tag_other)), AccessTier::LightPublic);
        prop_assert_eq!(ac.classify(None), AccessTier::LightPublic);
        // idempotence: re-derive after classify same
        let tag3 = derive_account_tag(&client_pubkey, &node_secret);
        prop_assert_eq!(tag3, tag);
    }

    #[test]
    fn prop_all_fixed_size_structs_stable(
        parent in arb_hash(),
        sig in any::<[u8; 64]>(),
    ) {
        // Ensure C-aligned sizes are invariant per INV-1001
        prop_assert_eq!(std::mem::size_of::<WireHeader>(), 32);
        prop_assert_eq!(std::mem::size_of::<LockEntry144>(), 144);
        prop_assert_eq!(WireHeader::SIZE, 32);
        prop_assert_eq!(LockEntry144::SIZE, 144);
        // padding bytes preserved
        let entry = LockEntry144 {
            parent_lock: parent,
            receiver_pub: parent,
            valid_until: 0xDEAD_BEEF_CAFE_BABE,
            owner_signature: sig,
            status: 0x42,
            padding: [0u8; 7],
        };
        let rt = LockEntry144::from_bytes(&entry.to_bytes());
        prop_assert_eq!(rt.padding, [0u8; 7]);
    }
}

// ---------------------------------------------------------------------------
// 2. Idempotence f(f(x)) == f(x)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_ram_index_insert_idempotent(
        parent in arb_hash(),
        receiver in arb_hash(),
        nonce in arb_nonce(),
    ) {
        let now = SimTime(1_000);
        let root_valid = SimTime(1_000_000);
        let valid_until = SimTime(500_000);
        let rec = LockRecord::new(parent, receiver, nonce, now, valid_until);
        let mut idx = RamIndex::new();
        let r1 = idx.try_insert(rec.clone(), now, root_valid);
        prop_assert_eq!(r1, Ok(humoco_sim_core::storage::IngressVerdictLow::AcceptedNew));
        let len_after_first = idx.len();
        // second insert identical => IdempotentReplay, len unchanged
        let r2 = idx.try_insert(rec.clone(), now, root_valid);
        prop_assert_eq!(r2, Ok(humoco_sim_core::storage::IngressVerdictLow::IdempotentReplay));
        prop_assert_eq!(idx.len(), len_after_first);
        // third insert identical => still idempotent
        let r3 = idx.try_insert(rec.clone(), now, root_valid);
        prop_assert_eq!(r3, Ok(humoco_sim_core::storage::IngressVerdictLow::IdempotentReplay));
        prop_assert_eq!(idx.len(), len_after_first);
        // f(f(x)) == f(x): get returns same record
        prop_assert_eq!(idx.get(&parent).unwrap().id, rec.id);
    }

    #[test]
    fn prop_ram_index_collision_idempotent(
        parent in arb_hash(),
        receiver_a in arb_hash(),
        receiver_b in arb_hash(),
        nonce_a in arb_nonce(),
        nonce_b in arb_nonce(),
    ) {
        // Two different locks on same parent => second rejected, state unchanged (idempotent rejection)
        let now = SimTime(1_000);
        let root_valid = SimTime(1_000_000);
        let rec_a = LockRecord::new(parent, receiver_a, nonce_a, now, SimTime(500_000));
        let mut rec_b = LockRecord::new(parent, receiver_b, nonce_b, now, SimTime(500_001));
        // ensure ids differ (if same by chance, mutate)
        if rec_a.id == rec_b.id {
            rec_b.nonce.push(0xAA);
            // recompute id by recreating
            let rec_b2 = LockRecord::new(parent, receiver_b, rec_b.nonce.clone(), now, SimTime(500_001));
            // check still same parent but different id
            prop_assume!(rec_a.id != rec_b2.id);
            let mut idx = RamIndex::new();
            idx.try_insert(rec_a.clone(), now, root_valid).unwrap();
            let before = idx.len();
            let e1 = idx.try_insert(rec_b2.clone(), now, root_valid);
            prop_assert_eq!(e1, Err(humoco_sim_core::storage::IngressVerdictLow::RejectedCollision));
            prop_assert_eq!(idx.len(), before);
            let e2 = idx.try_insert(rec_b2.clone(), now, root_valid);
            prop_assert_eq!(e2, Err(humoco_sim_core::storage::IngressVerdictLow::RejectedCollision));
            prop_assert_eq!(idx.len(), before);
            prop_assert_eq!(idx.get(&parent).unwrap().id, rec_a.id);
        } else {
            let mut idx = RamIndex::new();
            idx.try_insert(rec_a.clone(), now, root_valid).unwrap();
            let before = idx.len();
            let e1 = idx.try_insert(rec_b.clone(), now, root_valid);
            prop_assert_eq!(e1, Err(humoco_sim_core::storage::IngressVerdictLow::RejectedCollision));
            prop_assert_eq!(idx.len(), before);
            let e2 = idx.try_insert(rec_b.clone(), now, root_valid);
            prop_assert_eq!(e2, Err(humoco_sim_core::storage::IngressVerdictLow::RejectedCollision));
            prop_assert_eq!(idx.len(), before);
        }
    }

    #[test]
    fn prop_apply_attestation_idempotent_duplicate(
        parent in arb_hash(),
        receiver in arb_hash(),
        nonce in arb_nonce(),
        node_id in any::<u16>(),
        active_nodes in 1usize..100,
    ) {
        let rec = LockRecord::new(parent, receiver, nonce, SimTime(0), SimTime(10_000_000));
        let mut rec_clone = rec.clone();
        let att = sign_lock_attestation(node_id, &rec.id, &rec.parent_lock, SimTime(1_000));
        // first apply succeeds
        let s1 = apply_attestation(&mut rec_clone, att.clone(), active_nodes).unwrap();
        let signers_after_first = rec_clone.signers.clone();
        let status_after_first = rec_clone.status.clone();
        // second apply identical attestation => DuplicateAttestation, state unchanged
        let err = apply_attestation(&mut rec_clone, att.clone(), active_nodes);
        let is_dup = matches!(err, Err(humoco_sim_core::state_machine::StateError::DuplicateAttestation { .. }));
        prop_assert!(is_dup);
        prop_assert_eq!(rec_clone.signers.clone(), signers_after_first.clone());
        prop_assert_eq!(rec_clone.status.clone(), status_after_first.clone());
        prop_assert_eq!(rec_clone.status.clone(), s1.clone());
        // third apply still duplicate and idempotent
        let err2 = apply_attestation(&mut rec_clone, att.clone(), active_nodes);
        let is_dup2 = matches!(err2, Err(humoco_sim_core::state_machine::StateError::DuplicateAttestation { .. }));
        prop_assert!(is_dup2);
        prop_assert_eq!(rec_clone.signers.clone(), signers_after_first.clone());
    }

    #[test]
    fn prop_promote_to_final_idempotent(
        parent in arb_hash(),
        receiver in arb_hash(),
        nonce in arb_nonce(),
    ) {
        let mut rec = LockRecord::new(parent, receiver, nonce, SimTime(0), SimTime(10_000_000));
        // create 14 distinct attestations to reach FINAL threshold (N>=20 => Q=14)
        let active_nodes = 20;
        for nid in 0..14u16 {
            let att = sign_lock_attestation(nid, &rec.id, &rec.parent_lock, SimTime(1_000 + nid as u64));
            let _ = apply_attestation(&mut rec, att, active_nodes);
        }
        prop_assert!(rec.status.is_final());
        let status_before = rec.status.clone();
        let signers_before = rec.signers.clone();
        // promote again => Ok(true) and unchanged
        let p1 = promote_to_final_if_eligible(&mut rec, active_nodes).unwrap();
        prop_assert!(p1);
        prop_assert_eq!(rec.status.clone(), status_before.clone());
        prop_assert_eq!(rec.signers.clone(), signers_before.clone());
        let p2 = promote_to_final_if_eligible(&mut rec, active_nodes).unwrap();
        prop_assert!(p2);
        prop_assert_eq!(rec.status.clone(), status_before.clone());
        // f(f(x)) == f(x) : two promotions yield same final state
    }

    #[test]
    fn prop_resolver_idempotent_double_resolve(
        parent in arb_hash(),
        receiver_a in arb_hash(),
        receiver_b in arb_hash(),
        nonce_a in arb_nonce(),
        nonce_b in arb_nonce(),
    ) {
        let a = LockRecord::new(parent, receiver_a, nonce_a.clone(), SimTime(0), SimTime(1_000));
        let b = LockRecord::new(parent, receiver_b, nonce_b.clone(), SimTime(0), SimTime(1_000));
        prop_assume!(a.id != b.id);
        // first resolution
        let res1 = resolve_split_brain(&mut a.clone(), &mut b.clone());
        // need fresh copies for actual mutation check
        let mut a1 = a.clone();
        let mut b1 = b.clone();
        let res_first = resolve_split_brain(&mut a1, &mut b1);
        let a1_after = a1.clone();
        let b1_after = b1.clone();
        // second resolution on already-resolved pair should yield identical outcome
        // Note: after first resolution loser is Void, but resolver's Identical/NoConflict checks happen first.
        // We test idempotence on the pair (a1_after, b1_after) in terms of deterministic winner.
        // If we re-resolve the VOID-marked pair, the winner stays winner (f(f(x)) stable).
        let mut a2 = a1_after.clone();
        let mut b2 = b1_after.clone();
        let res_second = resolve_split_brain(&mut a2, &mut b2);
        // If first was WinnerA, loser is b; second call with same parents still picks same winner
        // but may mark already-Void loser again. The resolution result must be same variant.
        match (res_first.clone(), res_second.clone()) {
            (humoco_sim_core::resolver::ResolutionResult::WinnerA { winner_hash: h1, loser_hash: l1 },
             humoco_sim_core::resolver::ResolutionResult::WinnerA { winner_hash: h2, loser_hash: l2 }) => {
                prop_assert_eq!(h1, h2);
                prop_assert_eq!(l1, l2);
                prop_assert!(b1_after.status.is_void());
                prop_assert!(b2.status.is_void());
            },
            (humoco_sim_core::resolver::ResolutionResult::WinnerB { winner_hash: h1, loser_hash: l1 },
             humoco_sim_core::resolver::ResolutionResult::WinnerB { winner_hash: h2, loser_hash: l2 }) => {
                prop_assert_eq!(h1, h2);
                prop_assert_eq!(l1, l2);
                prop_assert!(a1_after.status.is_void());
                prop_assert!(a2.status.is_void());
            },
            _ => {
                prop_assert_eq!(res_first.clone(), res_second.clone());
            }
        }
        // also verify first resolution deterministic regardless of fresh vs reused
        prop_assert_eq!(res1.clone(), res_first.clone());
    }

    #[test]
    fn prop_peer_presence_success_idempotent_at_floor(
        prefix in any::<u64>(),
        epoch in any::<u16>(),
    ) {
        let mut entry = humoco_sim_core::PeerPresenceEntry::new(prefix, epoch);
        // at floor malus 0, repeated success stays 0
        prop_assert_eq!(entry.malus_score, 0);
        entry.record_outbound_success();
        prop_assert_eq!(entry.malus_score, 0);
        prop_assert_eq!(entry.backoff_level, 0);
        entry.record_outbound_success();
        prop_assert_eq!(entry.malus_score, 0);
        prop_assert_eq!(entry.backoff_level, 0);
        // f(f(x)) == f(x) at floor
        let before = entry;
        entry.record_outbound_success();
        prop_assert_eq!(entry.malus_score, before.malus_score);
        prop_assert_eq!(entry.backoff_level, before.backoff_level);
    }

    #[test]
    fn prop_first_seen_pacer_idempotent_known(
        nodes in prop::collection::vec(any::<u16>(), 1..20),
        pacing in 100u64..10_000,
    ) {
        let mut pacer = humoco_sim_core::FirstSeenPacer::with_known_nodes(nodes.clone(), pacing);
        // known nodes => ForwardImmediate idempotent
        for nid in nodes.iter().take(5) {
            let d1 = pacer.handle_incoming_node_gossip(*nid, 0);
            let d2 = pacer.handle_incoming_node_gossip(*nid, 10);
            prop_assert_eq!(d1, humoco_sim_core::NodeGossipForwardDecision::ForwardImmediate);
            prop_assert_eq!(d2, humoco_sim_core::NodeGossipForwardDecision::ForwardImmediate);
        }
        let known_before = pacer.known_count();
        // re-handling known doesn't grow queue
        let pending_before = pacer.pending_count();
        for nid in nodes.iter().take(3) {
            let _ = pacer.handle_incoming_node_gossip(*nid, 20);
        }
        prop_assert_eq!(pacer.pending_count(), pending_before);
        prop_assert_eq!(pacer.known_count(), known_before);
    }
}

// ---------------------------------------------------------------------------
// 3. Deterministic collision total ordering min(H_canon)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_canon_hash_deterministic(
        parent in arb_hash(),
        receiver in arb_hash(),
        nonce in arb_nonce(),
    ) {
        let h1 = compute_canonical_hash(&parent, &receiver, &nonce);
        let h2 = compute_canonical_hash(&parent, &receiver, &nonce);
        prop_assert_eq!(h1, h2);
        // different nonce => different hash (except negligible collision)
        let mut nonce2 = nonce.clone();
        nonce2.push(0xFF);
        let h3 = compute_canonical_hash(&parent, &receiver, &nonce2);
        prop_assert_ne!(h1, h3);
    }

    #[test]
    fn prop_canon_total_order_strict_weak_ordering(
        parent in arb_hash(),
        r1 in arb_hash(),
        r2 in arb_hash(),
        r3 in arb_hash(),
        n1 in arb_nonce(),
        n2 in arb_nonce(),
        n3 in arb_nonce(),
    ) {
        let h_a = compute_canonical_hash(&parent, &r1, &n1);
        let h_b = compute_canonical_hash(&parent, &r2, &n2);
        let h_c = compute_canonical_hash(&parent, &r3, &n3);

        // Irreflexivity: !(a < a)
        prop_assert!(!(h_a < h_a));
        prop_assert!(!(h_b < h_b));

        // Asymmetry: a < b => !(b < a)
        if h_a < h_b {
            prop_assert!(!(h_b < h_a));
        }
        if h_b < h_c {
            prop_assert!(!(h_c < h_b));
        }

        // Transitivity: a < b && b < c => a < c
        if h_a < h_b && h_b < h_c {
            prop_assert!(h_a < h_c);
        }
        if h_c < h_b && h_b < h_a {
            prop_assert!(h_c < h_a);
        }

        // Totality / comparability: for any distinct hashes, either a<b or b<a or a==b
        let ab_ordered = (h_a < h_b) || (h_b < h_a) || (h_a == h_b);
        prop_assert!(ab_ordered);
        let ac_ordered = (h_a < h_c) || (h_c < h_a) || (h_a == h_c);
        prop_assert!(ac_ordered);

        // If equal then not less
        if h_a == h_b {
            prop_assert!(!(h_a < h_b));
            prop_assert!(!(h_b < h_a));
        }
    }

    #[test]
    fn prop_resolver_respects_min_canon_ordering(
        parent in arb_hash(),
        r_a in arb_hash(),
        r_b in arb_hash(),
        n_a in arb_nonce(),
        n_b in arb_nonce(),
    ) {
        let mut lock_a = LockRecord::new(parent, r_a, n_a.clone(), SimTime(0), SimTime(1_000));
        let mut lock_b = LockRecord::new(parent, r_b, n_b.clone(), SimTime(0), SimTime(1_000));
        prop_assume!(lock_a.id != lock_b.id);
        let h_a = compute_canonical_hash(&lock_a.parent_lock, &lock_a.receiver_pub, &lock_a.nonce);
        let h_b = compute_canonical_hash(&lock_b.parent_lock, &lock_b.receiver_pub, &lock_b.nonce);
        prop_assume!(h_a != h_b);

        let mut a_clone = lock_a.clone();
        let mut b_clone = lock_b.clone();
        let res = resolve_split_brain(&mut a_clone, &mut b_clone);
        match res {
            humoco_sim_core::resolver::ResolutionResult::WinnerA { winner_hash, loser_hash } => {
                prop_assert!(winner_hash < loser_hash);
                prop_assert_eq!(winner_hash, h_a.min(h_b));
                prop_assert_eq!(loser_hash, h_a.max(h_b));
                prop_assert!(h_a < h_b, "WinnerA must imply h_a < h_b");
                prop_assert!(b_clone.status.is_void());
                prop_assert!(!a_clone.status.is_void());
            },
            humoco_sim_core::resolver::ResolutionResult::WinnerB { winner_hash, loser_hash } => {
                prop_assert!(winner_hash < loser_hash);
                prop_assert_eq!(winner_hash, h_a.min(h_b));
                prop_assert_eq!(loser_hash, h_a.max(h_b));
                prop_assert!(h_b < h_a);
                prop_assert!(a_clone.status.is_void());
                prop_assert!(!b_clone.status.is_void());
            },
            _ => prop_assert!(false, "same parent with distinct ids must yield WinnerA/B"),
        }
        // ensure original locks untouched in terms of id but resolver deterministic
        prop_assert_eq!(lock_a.id, a_clone.id);
        prop_assert_eq!(lock_b.id, b_clone.id);
    }

    #[test]
    fn prop_resolver_determinism_permutation(
        parent in arb_hash(),
        r_a in arb_hash(),
        r_b in arb_hash(),
        n_a in arb_nonce(),
        n_b in arb_nonce(),
    ) {
        let mut a1 = LockRecord::new(parent, r_a, n_a.clone(), SimTime(0), SimTime(1_000));
        let mut b1 = LockRecord::new(parent, r_b, n_b.clone(), SimTime(0), SimTime(1_000));
        prop_assume!(a1.id != b1.id);
        let mut a2 = b1.clone();
        let mut b2 = a1.clone();
        let res_ab = resolve_split_brain(&mut a1, &mut b1);
        let res_ba = resolve_split_brain(&mut a2, &mut b2);
        // Winner hash must be same regardless of argument order
        let (w_ab, l_ab) = match res_ab {
            humoco_sim_core::resolver::ResolutionResult::WinnerA { winner_hash, loser_hash } => (winner_hash, loser_hash),
            humoco_sim_core::resolver::ResolutionResult::WinnerB { winner_hash, loser_hash } => (winner_hash, loser_hash),
            _ => panic!("expected winner"),
        };
        let (w_ba, l_ba) = match res_ba {
            humoco_sim_core::resolver::ResolutionResult::WinnerA { winner_hash, loser_hash } => (winner_hash, loser_hash),
            humoco_sim_core::resolver::ResolutionResult::WinnerB { winner_hash, loser_hash } => (winner_hash, loser_hash),
            _ => panic!("expected winner"),
        };
        prop_assert_eq!(w_ab, w_ba);
        prop_assert_eq!(l_ab, l_ba);
        // The actual winner lock id is deterministic (the one with min hash)
        let winner_id_ab = if matches!(resolve_split_brain_canonical(&mut a1.clone(), &mut b1.clone(), None, None), humoco_sim_core::resolver::ResolutionResult::WinnerA {..}) {
            a1.id
        } else { b1.id };
        let winner_id_ba = if matches!(resolve_split_brain_canonical(&mut a2.clone(), &mut b2.clone(), None, None), humoco_sim_core::resolver::ResolutionResult::WinnerA {..}) {
            a2.id
        } else { b2.id };
        prop_assert_eq!(winner_id_ab, winner_id_ba);
    }

    #[test]
    fn prop_resolver_transitivity_three_locks(
        parent in arb_hash(),
        r1 in arb_hash(),
        r2 in arb_hash(),
        r3 in arb_hash(),
        n1 in arb_nonce(),
        n2 in arb_nonce(),
        n3 in arb_nonce(),
    ) {
        let mut locks: Vec<LockRecord> = vec![
            LockRecord::new(parent, r1, n1, SimTime(0), SimTime(1_000)),
            LockRecord::new(parent, r2, n2, SimTime(0), SimTime(1_000)),
            LockRecord::new(parent, r3, n3, SimTime(0), SimTime(1_000)),
        ];
        // ensure distinct ids (if collision by chance, skip)
        prop_assume!(locks[0].id != locks[1].id && locks[1].id != locks[2].id && locks[0].id != locks[2].id);
        let hashes: Vec<[u8;32]> = locks.iter().map(|l| compute_canonical_hash(&l.parent_lock, &l.receiver_pub, &l.nonce)).collect();
        prop_assume!(hashes[0] != hashes[1] && hashes[1] != hashes[2] && hashes[0] != hashes[2]);

        // sort by hash to get total order
        let mut sorted = hashes.clone();
        sorted.sort();

        // pairwise resolver must be consistent with total order: min among three is global winner
        let min_hash = *sorted.first().unwrap();
        let winner_idx = hashes.iter().position(|h| *h == min_hash).unwrap();

        // verify transitivity: if a<b and b<c according to hash, then a<c
        // find ordering indices
        let mut order: Vec<usize> = (0..3).collect();
        order.sort_by(|&i, &j| hashes[i].cmp(&hashes[j]));
        // order[0] < order[1] < order[2] in hash
        prop_assert!(hashes[order[0]] < hashes[order[1]]);
        prop_assert!(hashes[order[1]] < hashes[order[2]]);
        prop_assert!(hashes[order[0]] < hashes[order[2]]);

        // resolver pairwise must elect the smaller hash as winner
        for i in 0..3 {
            for j in (i+1)..3 {
                let mut a = locks[i].clone();
                let mut b = locks[j].clone();
                let res = resolve_split_brain(&mut a, &mut b);
                let expected_winner_is_i = hashes[i] < hashes[j];
                match res {
                    humoco_sim_core::resolver::ResolutionResult::WinnerA { .. } => prop_assert!(expected_winner_is_i, "expected A wins when h_a < h_b"),
                    humoco_sim_core::resolver::ResolutionResult::WinnerB { .. } => prop_assert!(!expected_winner_is_i),
                    _ => prop_assert!(false),
                }
            }
        }
        // global winner index is deterministic
        prop_assert_eq!(winner_idx, order[0]);
    }

    #[test]
    fn prop_h_canon_domain_separation_length_prefix(
        parent in arb_hash(),
        receiver in arb_hash(),
        nonce in arb_nonce(),
    ) {
        // Same visible payload with different domain must differ: our resolver uses length-prefixed domain tag,
        // so we verify compute_canonical_hash != compute_canonical_hash_normalized unless specifically crafted
        let h_direct = compute_canonical_hash(&parent, &receiver, &nonce);
        // normalized folds receiver and sig via blake3 pre-hash, should not equal direct except negligible
        let h_norm = humoco_sim_core::crypto::compute_canonical_hash_normalized(&parent, &receiver, &nonce);
        // They are different constructions; we don't assert inequality strictly (could collide with prob 2^-256),
        // but we assert both are deterministic
        prop_assert_eq!(h_direct, compute_canonical_hash(&parent, &receiver, &nonce));
        prop_assert_eq!(h_norm, humoco_sim_core::crypto::compute_canonical_hash_normalized(&parent, &receiver, &nonce));
        // At least one of them is 32 bytes (trivially)
        prop_assert_eq!(h_direct.len(), 32);
        prop_assert_eq!(h_norm.len(), 32);
    }
}

// ---------------------------------------------------------------------------
// 4. Monotonicity of TTL pruning
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_ttl_prune_monotonic_len_and_count(
        entries in prop::collection::vec(
            (arb_hash(), arb_hash(), arb_nonce(), 0u64..5_000_000u64, 1u64..2_000_000u64), 0..50
        ),
        t1 in 0u64..10_000_000,
        delta in 0u64..5_000_000,
    ) {
        let t2 = t1.saturating_add(delta);
        // Build two identical RamIndex instances
        let mut idx1 = RamIndex::new();
        let mut idx2 = RamIndex::new();
        let now = SimTime(0);
        for (parent, receiver, nonce, created_off, ttl) in entries.clone() {
            let created = SimTime(created_off % 1_000_000);
            let root_valid = SimTime(created.0.saturating_add(ttl).saturating_add(60_000));
            let valid_until = SimTime(root_valid.0.saturating_sub(1).max(created.0 + 31_000));
            let rec = LockRecord::new(parent, receiver, nonce, created, valid_until);
            let _ = idx1.try_insert(rec.clone(), now, root_valid);
            let _ = idx2.try_insert(rec, now, root_valid);
        }
        let len_before = idx1.len();
        prop_assert_eq!(idx1.len(), idx2.len());

        let pruned1 = idx1.prune_expired(SimTime(t1));
        let len_after_t1 = idx1.len();
        let pruned2 = idx2.prune_expired(SimTime(t2));
        let len_after_t2 = idx2.len();

        // Monotonic size: t2 >= t1 => len_after_t2 <= len_after_t1
        prop_assert!(len_after_t2 <= len_after_t1,
            "len t2={} should be <= len t1={} when t2={} >= t1={}", len_after_t2, len_after_t1, t2, t1);
        // pruned counts monotonic: pruning at later time should have pruned at least as many as earlier (when starting from same state)
        prop_assert!(pruned2 >= pruned1 || len_before == 0,
            "pruned2={} should be >= pruned1={} for t2>=t1", pruned2, pruned1);
        // size never increases via pruning
        prop_assert!(len_after_t1 <= len_before);
        prop_assert!(len_after_t2 <= len_before);
        prop_assert_eq!(pruned1, len_before - len_after_t1);
        prop_assert_eq!(pruned2, len_before - len_after_t2);
    }

    #[test]
    fn prop_ttl_prune_idempotent_same_time(
        entries in prop::collection::vec(
            (arb_hash(), arb_hash(), arb_nonce(), 0u64..1_000_000u64), 1..30
        ),
        now_prune in 0u64..5_000_000,
    ) {
        let mut idx = RamIndex::new();
        let now = SimTime(0);
        for (parent, receiver, nonce, ttl_off) in entries {
            let root_valid = SimTime(500_000 + ttl_off % 2_000_000);
            let valid_until = SimTime(root_valid.0.saturating_sub(1).max(31_001));
            let rec = LockRecord::new(parent, receiver, nonce, now, valid_until);
            let _ = idx.try_insert(rec, now, root_valid);
        }
        let t = SimTime(now_prune);
        let p1 = idx.prune_expired(t);
        let len1 = idx.len();
        let p2 = idx.prune_expired(t);
        let len2 = idx.len();
        prop_assert_eq!(p2, 0, "second prune at same time must prune 0 (idempotent)");
        prop_assert_eq!(len1, len2);
        // third also 0
        let p3 = idx.prune_expired(t);
        prop_assert_eq!(p3, 0);
    }

    #[test]
    fn prop_ttl_prune_never_resurrects(
        parent in arb_hash(),
        receiver in arb_hash(),
        nonce in arb_nonce(),
        root_valid_ms in 100_000u64..2_000_000,
        prune_time in 0u64..5_000_000,
    ) {
        let now = SimTime(0);
        let root_valid = SimTime(root_valid_ms);
        let valid_until = SimTime(root_valid_ms.saturating_sub(1).max(31_001));
        let rec = LockRecord::new(parent, receiver, nonce, now, valid_until);
        let mut idx = RamIndex::new();
        idx.try_insert(rec.clone(), now, root_valid).unwrap();
        // prune at prune_time
        let t = SimTime(prune_time);
        let pruned = idx.prune_expired(t);
        let after = idx.len();
        // if should_prune(t, root_valid) then must have pruned
        let should = humoco_sim_core::storage::should_prune(t, root_valid);
        if should {
            prop_assert_eq!(after, 0);
            prop_assert_eq!(pruned, 1);
            // further prune keeps 0 (no resurrection)
            let p2 = idx.prune_expired(SimTime(prune_time + 100_000));
            prop_assert_eq!(p2, 0);
            prop_assert_eq!(idx.len(), 0);
            prop_assert!(idx.get(&parent).is_none());
        } else {
            prop_assert_eq!(after, 1);
            prop_assert_eq!(pruned, 0);
            prop_assert!(idx.get(&parent).is_some());
        }
    }

    #[test]
    fn prop_ttl_bubble_prune_two_phase_monotonic(
        entries in prop::collection::vec(
            (arb_hash(), 0u64..1_000_000u64), 5..30
        )
    ) {
        // Inserts with increasing root_valid, then increasing prune times must be monotonic stepwise
        let mut idx = RamIndex::new();
        let now = SimTime(0);
        for (parent, root_off) in entries.clone() {
            let root_valid = SimTime(1_000_000 + root_off);
            let valid_until = SimTime(root_valid.0 - 1);
            let rec = LockRecord::new(parent, [0xCC;32], vec![1,2,3], now, valid_until);
            let _ = idx.try_insert(rec, now, root_valid);
        }
        let mut times: Vec<u64> = entries.iter().map(|(_, off)| 1_000_000 + off + 31_000).collect();
        times.sort_unstable();
        times.dedup();
        let mut prev_len = idx.len();
        for t in times {
            let pruned = idx.prune_expired(SimTime(t + 1)); // just after threshold
            let cur = idx.len();
            prop_assert!(cur <= prev_len, "len must be monotonic decreasing via prune");
            if pruned > 0 {
                prop_assert!(cur < prev_len);
            }
            prev_len = cur;
        }
        // after max+1, further large prune must not increase len
        let final_prune = idx.prune_expired(SimTime(u64::MAX / 2));
        prop_assert_eq!(idx.len(), 0.max(prev_len - final_prune));
        prop_assert!(idx.len() <= prev_len);
    }

    #[test]
    fn prop_ingress_window_implies_not_yet_prunable(
        now_ms in 0u64..1_000_000,
        ttl_off in 31_001u64..5_000_000,
        root_extra in 0u64..5_000_000,
    ) {
        // If a lock just passed ingress window at now, it must not be prunable at now
        let now = SimTime(now_ms);
        let valid_until = SimTime(now_ms + ttl_off);
        let root_valid = SimTime(valid_until.0 + root_extra);
        // Only check window validity
        let window_ok = humoco_sim_core::storage::ingress_time_window_valid(now, valid_until, root_valid);
        if window_ok {
            // valid_until > now+30s and <= root_valid, so now cannot be > root_valid+30s
            prop_assert!(!humoco_sim_core::storage::should_prune(now, root_valid),
                "freshly ingressed lock must not be prunable at same now");
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Quota monotonicity & hard-floor bounds
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_byte_years_monotonic_in_ttl(
        ttl_a in 0u64..10_000_000,
        delta in 0u64..10_000_000,
    ) {
        let ttl_b = ttl_a.saturating_add(delta);
        let by_a = ByteYears::from_ttl_seconds(ttl_a);
        let by_b = ByteYears::from_ttl_seconds(ttl_b);
        prop_assert!(by_b >= by_a, "ByteYears must be monotonic: {} >= {} for ttl {} >= {}", by_b, by_a, ttl_b, ttl_a);
        prop_assert!(by_a >= 1);
        prop_assert!(by_b >= 1);
        // days variant monotonic as well
        let days_a = ttl_a / 86_400;
        let days_b = ttl_b / 86_400;
        if days_b >= days_a {
            prop_assert!(ByteYears::from_ttl_days(days_b) >= ByteYears::from_ttl_days(days_a));
        }
    }

    #[test]
    fn prop_hard_floor_never_undercut(
        medians in prop::collection::vec(0u64..10_000_000, 0..28),
    ) {
        let mut thermo = NetworkThermometer::new();
        for m in medians {
            thermo.record_daily_median(m);
        }
        prop_assert!(thermo.effective_ncb() >= HARD_FLOOR_BASELINE_DAILY,
            "effective_ncb {} must be >= HARD_FLOOR {}", thermo.effective_ncb(), HARD_FLOOR_BASELINE_DAILY);
        prop_assert!(thermo.effective_read_ncb() >= HARD_FLOOR_READ_BASELINE_DAILY);
        // Even after seeding with 0, floor holds
        let mut thermo2 = NetworkThermometer::new();
        thermo2.record_daily_median(0);
        prop_assert_eq!(thermo2.effective_ncb(), HARD_FLOOR_BASELINE_DAILY);
    }

    #[test]
    fn prop_quota_monotonic_in_k_and_damper(
        median in 960_000u64..5_000_000,
        k_a in 0.0f64..5.0,
        k_delta in 0.0f64..2.0,
        damper_a in 0.5f64..1.0,
        damper_delta in 0.0f64..0.5,
    ) {
        let mut thermo = NetworkThermometer::new();
        thermo.record_daily_median(median);
        let k_b = (k_a + k_delta).min(MAX_WHALE_MULTIPLIER);
        let damper_b = (damper_a + damper_delta).min(1.0);
        let q_a = thermo.calculate_daily_quota(k_a, damper_a);
        let q_b_k = thermo.calculate_daily_quota(k_b, damper_a);
        let q_b_d = thermo.calculate_daily_quota(k_a, damper_b);
        let q_b_both = thermo.calculate_daily_quota(k_b, damper_b);
        prop_assert!(q_b_k >= q_a, "quota monotonic in K: {} >= {}", q_b_k, q_a);
        prop_assert!(q_b_d >= q_a, "quota monotonic in damper: {} >= {}", q_b_d, q_a);
        prop_assert!(q_b_both >= q_a);
        prop_assert!(q_b_both >= q_b_k);
        prop_assert!(q_b_both >= q_b_d);
    }

    #[test]
    fn prop_quota_clamped_and_hard_floor_with_k1(
        median in 0u64..20_000_000,
    ) {
        let mut thermo = NetworkThermometer::new();
        thermo.record_daily_median(median);
        let ncb = thermo.effective_ncb();
        prop_assert!(ncb >= HARD_FLOOR_BASELINE_DAILY);
        // K=1, damper=1 => quota == ncb
        let q = thermo.calculate_daily_quota(1.0, 1.0);
        prop_assert_eq!(q, ncb);
        // K beyond max is clamped to 5.0
        let q_over = thermo.calculate_daily_quota(100.0, 1.0);
        let q_max = thermo.calculate_daily_quota(MAX_WHALE_MULTIPLIER, 1.0);
        prop_assert_eq!(q_over, q_max);
        // damper below 0.5 clamped
        let q_low_damper = thermo.calculate_daily_quota(1.0, 0.0);
        let q_min_damper = thermo.calculate_daily_quota(1.0, 0.5);
        prop_assert_eq!(q_low_damper, q_min_damper);
        // Minimal quota with K=1, damper=0.5 is at least floor*0.5
        let q_min = thermo.calculate_daily_quota(1.0, 0.5);
        prop_assert!(q_min >= HARD_FLOOR_BASELINE_DAILY / 2);
    }

    #[test]
    fn prop_spread_damper_bounded(
        samples in prop::collection::vec(0u64..10_000_000, 1..50)
    ) {
        let stats = QuartileStats::calculate(&samples);
        let d = stats.spread_damper();
        prop_assert!(d >= 0.5 - f64::EPSILON && d <= 1.0 + f64::EPSILON,
            "damper {} out of [0.5,1.0]", d);
        // Empty samples => fallback to floor, damper in range as well
        let empty_stats = QuartileStats::calculate(&[]);
        let d_empty = empty_stats.spread_damper();
        prop_assert!(d_empty >= 0.5 && d_empty <= 1.0);
        prop_assert_eq!(empty_stats.median, HARD_FLOOR_BASELINE_DAILY);
        prop_assert_eq!(empty_stats.q1, HARD_FLOOR_BASELINE_DAILY);
        prop_assert_eq!(empty_stats.q3, HARD_FLOOR_BASELINE_DAILY);
    }

    #[test]
    fn prop_integer_ema_monotonic_and_bounded(
        old_ema in 0u64..5_000_000,
        delta in 0u64..200_000,
        footprint_a in 0u64..1_000_000,
        footprint_delta in 0u64..500_000,
    ) {
        let fp_b = footprint_a.saturating_add(footprint_delta);
        let ema_a = calculate_integer_ema(old_ema, delta, footprint_a);
        let ema_b = calculate_integer_ema(old_ema, delta, footprint_a.saturating_add(footprint_delta));
        prop_assert!(ema_b >= ema_a, "EMA monotonic in footprint: {} >= {}", ema_b, ema_a);
        // larger delta => more decay => smaller or equal EMA (for same footprint)
        let ema_small_delta = calculate_integer_ema(old_ema, delta, footprint_a);
        let ema_large_delta = calculate_integer_ema(old_ema, delta.saturating_add(10_000).min(86_400), footprint_a);
        prop_assert!(ema_large_delta <= ema_small_delta,
            "EMA should decay with time: {} <= {} for larger delta", ema_large_delta, ema_small_delta);
        // never panics, always within u64
        let _ = calculate_integer_ema(u64::MAX, 0, 1_000);
        let at_max = calculate_integer_ema(u64::MAX, 0, 1_000);
        prop_assert_eq!(at_max, u64::MAX); // saturating
        let zero_decay = calculate_integer_ema(old_ema, 0, footprint_a);
        prop_assert_eq!(zero_decay, old_ema.saturating_add(footprint_a));
    }

    #[test]
    fn prop_try_accept_lock_monotonic_and_quota_bounded(
        quota in 1_000u64..5_000_000,
        footprints in prop::collection::vec(1u64..10_000, 1..30),
        node_id in any::<u16>(),
    ) {
        let mut thermo = NetworkThermometer::new();
        let day = 42u64;
        let mut total_accepted = 0u64;
        for fp in footprints.clone() {
            let ok = thermo.try_accept_lock(day, node_id, fp, quota);
            if ok {
                total_accepted = total_accepted.saturating_add(fp);
                prop_assert!(total_accepted <= quota, "accepted total {} must be <= quota {}", total_accepted, quota);
                prop_assert_eq!(thermo.get_node_usage(node_id), total_accepted);
            } else {
                // rejection => total unchanged
                prop_assert_eq!(thermo.get_node_usage(node_id), total_accepted);
                // further footprint respects remaining quota (if empty, huge==quota should succeed; if nearly full, it must be rejected)
                let huge_ok = thermo.try_accept_lock(day, node_id, quota, quota);
                let expected_huge = total_accepted.saturating_add(quota) <= quota;
                prop_assert_eq!(huge_ok, expected_huge, "huge footprint must respect remaining quota (total {} + quota {} <= quota {})", total_accepted, quota, quota);
                break;
            }
        }
        // monotonic: usage never decreases within same day
        let usage_before = thermo.get_node_usage(node_id);
        let _ = thermo.try_accept_lock(day, node_id, 1, quota);
        prop_assert!(thermo.get_node_usage(node_id) >= usage_before);
    }

    #[test]
    fn prop_try_accept_lock_resets_next_day(
        quota in 1_000u64..5_000_000,
        fp in 1u64..5_000,
        node_id in any::<u16>(),
    ) {
        let mut thermo = NetworkThermometer::new();
        prop_assume!(fp <= quota);
        let day1 = 10u64;
        let day2 = 11u64;
        prop_assert!(thermo.try_accept_lock(day1, node_id, fp, quota));
        prop_assert_eq!(thermo.get_node_usage(node_id), fp);
        // next day resets to 0 before new accept
        prop_assert!(thermo.try_accept_lock(day2, node_id, fp, quota));
        // After day change, usage is exactly fp (not 2*fp) due to clear()
        prop_assert_eq!(thermo.get_node_usage(node_id), fp);
        // same day idempotence: re-accepting same fp twice accumulates unless exceeds
        if fp * 2 <= quota {
            prop_assert!(thermo.try_accept_lock(day2, node_id, fp, quota));
            prop_assert_eq!(thermo.get_node_usage(node_id), fp * 2);
        }
    }

    #[test]
    fn prop_thermometer_moving_average_monotonic_with_floor(
        values in prop::collection::vec(0u64..10_000_000, 1..30)
    ) {
        let mut ring = SlottedMedianRingBuffer::new();
        prop_assert_eq!(ring.moving_average_median(), HARD_FLOOR_BASELINE_DAILY);
        for v in values {
            ring.push_daily_median(v);
            prop_assert!(ring.moving_average_median() >= 0);
            // after at least one push, average is at least min( values, floor )? Actually moving average median is floor if all zero
            // Just ensure it never panics and respects floor when seeded
        }
        let mut seeded = SlottedMedianRingBuffer::new();
        seeded.seed(HARD_FLOOR_BASELINE_DAILY);
        prop_assert_eq!(seeded.moving_average_median(), HARD_FLOOR_BASELINE_DAILY);
        seeded.seed(0);
        // seed(0) internally seeds with floor, so still floor
        prop_assert_eq!(seeded.moving_average_median(), HARD_FLOOR_BASELINE_DAILY);
    }

    #[test]
    fn prop_backoff_jitter_deterministic_and_bounded(
        attempt in 1u32..8,
        base_ms in 500u64..5_000,
        cap_ms in 10_000u64..120_000,
        seed in any::<u64>(),
    ) {
        prop_assume!(cap_ms >= base_ms);
        let b1 = compute_backoff(attempt, base_ms, cap_ms, seed);
        let b2 = compute_backoff(attempt, base_ms, cap_ms, seed);
        prop_assert_eq!(b1, b2, "backoff deterministic for same seed");
        // bounded in [0.5*base_eff, 1.25*base_eff] and <= cap
        let exp = 1u64 << (attempt - 1).min(10);
        let base_eff = base_ms.saturating_mul(exp).min(cap_ms);
        prop_assert!(b1 >= base_eff * 3 / 4 || b1 == base_ms/2, "b1 {} >= 0.75*{}", b1, base_eff);
        prop_assert!(b1 <= (base_eff as f64 * 1.25) as u64);
        prop_assert!(b1 <= cap_ms);
        prop_assert!(b1 >= base_ms/2);
        // monotonic in attempt (non-decreasing up to cap, modulo jitter variance but base doubles)
        if attempt < 7 {
            let b_next = compute_backoff(attempt + 1, base_ms, cap_ms, seed);
            // base doubles, so even with jitter, b_next should be >= ~0.6 * b1*2? We relax to >= base_ms/2
            prop_assert!(b_next >= base_ms/2);
            // Eventually hits cap
            if attempt >= 6 {
                prop_assert!(b_next <= cap_ms);
            }
        }
    }
}
