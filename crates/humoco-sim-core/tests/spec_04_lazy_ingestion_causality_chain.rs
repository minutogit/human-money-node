use humoco_sim_core::crypto::sign_lock_attestation;
use humoco_sim_core::types::{
    sign_causality_client_signature, verify_causality_proof_chain,
    verify_causality_proof_chain_stateless, CausalityError, CausalityProofChain, LockRecord,
    ProofChainHop, SimTime,
};
use std::collections::HashSet;
use std::time::Instant;

fn make_hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn make_attestation_for_hash(hash: [u8; 32], parent_lock: [u8; 32], node_id: u16) -> humoco_sim_core::types::Attestation {
    sign_lock_attestation(node_id, &hash, &parent_lock, SimTime(100))
}

fn build_valid_3_hop_chain() -> (CausalityProofChain, HashSet<[u8; 32]>) {
    let genesis_root = make_hash(0xAA);
    let h1 = make_hash(0x11);
    let h2 = make_hash(0x22);
    let h3 = make_hash(0x33);

    // Each hop has a quorum attestation over next_hash
    let hop0 = ProofChainHop {
        prev_hash: genesis_root,
        next_hash: h1,
        owner_pub: make_hash(0x01),
        quorum_signatures: vec![make_attestation_for_hash(h1, genesis_root, 1), make_attestation_for_hash(h1, genesis_root, 2)],
    };
    let hop1 = ProofChainHop {
        prev_hash: h1,
        next_hash: h2,
        owner_pub: make_hash(0x02),
        quorum_signatures: vec![make_attestation_for_hash(h2, h1, 3)],
    };
    let hop2 = ProofChainHop {
        prev_hash: h2,
        next_hash: h3,
        owner_pub: make_hash(0x03),
        quorum_signatures: vec![make_attestation_for_hash(h3, h2, 4)],
    };

    let target_lock = LockRecord::new(
        h3,
        make_hash(0xBB),
        b"final_lock_nonce".to_vec(),
        SimTime(500),
        SimTime(50_000),
    );
    let client_sig = sign_causality_client_signature(&target_lock, &genesis_root);
    let chain = CausalityProofChain {
        genesis_root,
        hops: vec![hop0, hop1, hop2],
        target_lock,
        client_signature: client_sig,
    };
    let mut allowed = HashSet::new();
    allowed.insert(genesis_root);
    (chain, allowed)
}

#[test]
fn test_lazy_ingestion_valid_3_hop_chain_accepted_in_ram() {
    let (chain, allowed) = build_valid_3_hop_chain();
    let start = Instant::now();
    // Use stateless for performance <2ms without side effect first
    let res = verify_causality_proof_chain_stateless(&chain, &allowed);
    let elapsed = start.elapsed();
    assert_eq!(res, Ok(()), "Valid 3-hop chain must be accepted, got {:?}", res);
    assert!(
        elapsed.as_millis() < 2 || elapsed.as_micros() < 5000,
        "Validation must be <2ms (or at least <5ms), took {:?}",
        elapsed
    );
    // Now stateful verification also succeeds and would commit to RAM (local seen set)
    let mut seen = HashSet::new();
    let res2 = verify_causality_proof_chain(&chain, &allowed, &mut seen);
    assert_eq!(res2, Ok(()), "Stateful verification must also accept");
    assert!(seen.contains(&chain.target_lock.parent_lock));
    // Simulate RAM commit: insertion into map
    let mut ram: std::collections::BTreeMap<[u8; 32], LockRecord> = std::collections::BTreeMap::new();
    ram.insert(chain.target_lock.id, chain.target_lock.clone());
    assert_eq!(ram.len(), 1);
}

#[test]
fn test_lazy_ingestion_rejects_tampered_hash_link() {
    let (mut chain, allowed) = build_valid_3_hop_chain();
    // Manipulate intermediate hash: hop 1 prev_hash no longer matches hop0 next_hash
    chain.hops[1].prev_hash = make_hash(0xFF);
    let res = verify_causality_proof_chain_stateless(&chain, &allowed);
    match res {
        Err(CausalityError::BrokenChainLink { hop_index }) => {
            assert_eq!(hop_index, 1);
        }
        _ => panic!("Expected BrokenChainLink at hop 1, got {:?}", res),
    }
}

#[test]
fn test_lazy_ingestion_rejects_fake_genesis_root() {
    let (mut chain, mut allowed) = build_valid_3_hop_chain();
    let fake_genesis = make_hash(0x99);
    chain.genesis_root = fake_genesis;
    // Re-sign client to not trigger InvalidClientSignature first - genesis check is first
    chain.client_signature = sign_causality_client_signature(&chain.target_lock, &fake_genesis);
    // But allowed set still contains old genesis, not fake -> InvalidGenesisRoot
    let res = verify_causality_proof_chain_stateless(&chain, &allowed);
    assert_eq!(res.unwrap_err(), CausalityError::InvalidGenesisRoot);

    // Also ensure stateful variant same
    let mut seen = HashSet::new();
    let res2 = verify_causality_proof_chain(&chain, &allowed, &mut seen);
    assert_eq!(res2.unwrap_err(), CausalityError::InvalidGenesisRoot);

    // Keep allowed empty also fails
    allowed.clear();
    let res3 = verify_causality_proof_chain_stateless(&chain, &allowed);
    assert_eq!(res3.unwrap_err(), CausalityError::InvalidGenesisRoot);
}

#[test]
fn test_lazy_ingestion_first_seen_collision_detection() {
    let (chain, allowed) = build_valid_3_hop_chain();
    let mut seen = HashSet::new();
    // First insertion should succeed
    let res1 = verify_causality_proof_chain(&chain, &allowed, &mut seen);
    assert_eq!(res1, Ok(()), "First chain insertion must succeed: {:?}", res1);

    // Build second chain with same parent_lock (same genesis chain) -> collision
    let h3 = make_hash(0x33);
    let target_lock2 = LockRecord::new(
        h3,
        make_hash(0xCC),
        b"collision_nonce".to_vec(),
        SimTime(600),
        SimTime(50_000),
    );
    let chain2 = CausalityProofChain {
        genesis_root: chain.genesis_root,
        hops: chain.hops.clone(),
        target_lock: target_lock2.clone(),
        client_signature: sign_causality_client_signature(&target_lock2, &chain.genesis_root),
    };
    let res2 = verify_causality_proof_chain(&chain2, &allowed, &mut seen);
    match res2 {
        Err(CausalityError::ParentAlreadyLocked { parent_lock }) => {
            assert_eq!(parent_lock, h3);
        }
        _ => panic!("Expected ParentAlreadyLocked, got {:?}", res2),
    }
}

#[test]
fn test_causality_proofchain_hop_limit_boundary() {
    fn hash_from_index(idx: usize) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0..8].copy_from_slice(&(idx as u64).to_le_bytes());
        h[8..16].copy_from_slice(&((idx as u64).wrapping_mul(0x9E3779B97F4A7C15)).to_le_bytes());
        // Fill rest with deterministic pattern to avoid collision with genesis_root [0xAA;32]
        for (i, b) in h[16..].iter_mut().enumerate() {
            *b = (idx.wrapping_add(i).wrapping_mul(31) % 251) as u8;
        }
        // Ensure not accidentally equal to genesis_root
        if h == [0xAA; 32] {
            h[0] ^= 0x01;
        }
        h
    }

    fn build_chain_with_n_hops(n: usize) -> (CausalityProofChain, HashSet<[u8; 32]>) {
        let genesis_root = make_hash(0xAA);
        let mut hops = Vec::with_capacity(n);
        let mut prev = genesis_root;
        for i in 0..n {
            let next = hash_from_index(i);
            let hop = ProofChainHop {
                prev_hash: prev,
                next_hash: next,
                owner_pub: make_hash(0x01),
                quorum_signatures: vec![make_attestation_for_hash(next, prev, ((i % 65535) + 1) as u16)],
            };
            hops.push(hop);
            prev = next;
        }
        let parent_for_target = if n == 0 { genesis_root } else { prev };
        let target_lock = LockRecord::new(
            parent_for_target,
            make_hash(0xBB),
            b"boundary_test_nonce".to_vec(),
            SimTime(500),
            SimTime(50_000),
        );
        let client_sig = sign_causality_client_signature(&target_lock, &genesis_root);
        let chain = CausalityProofChain {
            genesis_root,
            hops,
            target_lock,
            client_signature: client_sig,
        };
        let mut allowed = HashSet::new();
        allowed.insert(genesis_root);
        (chain, allowed)
    }

    // 1024 hops must be accepted (Ok)
    let (chain_1024, allowed_1024) = build_chain_with_n_hops(1024);
    assert_eq!(chain_1024.hops.len(), 1024);
    let res_1024 = verify_causality_proof_chain_stateless(&chain_1024, &allowed_1024);
    assert_eq!(
        res_1024,
        Ok(()),
        "CausalityProofChain with 1024 hops must be accepted, got {:?}",
        res_1024
    );
    // Also stateful variant
    let mut seen = HashSet::new();
    let res_1024_stateful = verify_causality_proof_chain(&chain_1024, &allowed_1024, &mut seen);
    assert_eq!(res_1024_stateful, Ok(()), "Stateful verification with 1024 hops must be Ok, got {:?}", res_1024_stateful);

    // 1025 hops must be rejected with BrokenChainLink { hop_index: 1025 }
    let (chain_1025, allowed_1025) = build_chain_with_n_hops(1025);
    assert_eq!(chain_1025.hops.len(), 1025);
    let res_1025 = verify_causality_proof_chain_stateless(&chain_1025, &allowed_1025);
    assert_eq!(
        res_1025.unwrap_err(),
        CausalityError::BrokenChainLink { hop_index: 1025 },
        "1025 hops must be rejected with BrokenChainLink {{ hop_index: 1025 }}"
    );
    let mut seen2 = HashSet::new();
    let res_1025_stateful = verify_causality_proof_chain(&chain_1025, &allowed_1025, &mut seen2);
    assert_eq!(
        res_1025_stateful.unwrap_err(),
        CausalityError::BrokenChainLink { hop_index: 1025 }
    );
}
