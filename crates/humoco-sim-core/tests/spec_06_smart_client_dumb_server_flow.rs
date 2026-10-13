//! Spec 06: Smart Client / Dumb Server Flow (INV-0601..0605)

use humoco_sim_core::client_flow::{verify_quorum_certificate, DumbServer, SmartClient, IngressVerdict};
use humoco_sim_core::crypto::sign_lock_attestation;
use humoco_sim_core::types::{LockRecord, SimTime};

fn make_parent(b: u8) -> [u8;32] { [b;32] }
fn make_receiver(b: u8) -> [u8;32] { [b;32] }

// INV-0601: Client-Side Custody (ProofChain)
#[test]
fn test_inv0601_client_side_custody_proof_chain_discarded_by_server() {
    let top20: Vec<u16> = (0..20).collect();
    let mut server = DumbServer::new(top20.clone(), SimTime(1_000_000));
    let mut client = SmartClient::new(99);

    // Client builds 3-hop chain in custody
    let genesis = make_parent(0xAA);
    let h1 = make_parent(0x11);
    let h2 = make_parent(0x22);
    // Create locks forming chain
    let lock1 = LockRecord::new(genesis, make_receiver(0x01), b"hop1".to_vec(), SimTime(10), SimTime(500_000));
    let lock2 = LockRecord::new(h1, make_receiver(0x02), b"hop2".to_vec(), SimTime(20), SimTime(500_000));
    let lock3 = LockRecord::new(h2, make_receiver(0x03), b"final".to_vec(), SimTime(30), SimTime(500_000));

    // Client custody stores hops (simulating ProofChain)
    client.add_to_chain(lock1.clone());
    client.add_to_chain(lock2.clone());
    client.add_to_chain(lock3.clone());
    assert_eq!(client.custody_len(), 3, "Client must store own chain (INV-0601)");

    // Server only stores active lock, not chain history
    // Submit final lock with proof chain (server validates)
    let now = SimTime(100);
    let verdict = server.ingress(lock3.clone(), now).expect("ingress ok");
    match verdict {
        IngressVerdict::NewLock { cert, .. } => {
            assert!(server.verify_quorum_certificate(&cert), "quorum must verify");
        },
        _ => panic!("expected NewLock"),
    }
    // Server RAM only contains the one final parent, not whole chain
    assert_eq!(server.ram.len(), 1);
    assert!(server.ram.get(&h2).is_some());
    // Server does NOT retain hops
    assert!(server.ram.get(&genesis).is_none(), "dumb server discards history");

    // Client still retains full chain
    assert_eq!(client.custody_len(), 3);
}

// INV-0602: Idempotentes Concurrent Ingress (200 OK für beide bei identischem Lock)
#[test]
fn test_inv0602_idempotent_concurrent_ingress_both_200_ok() {
    let top20: Vec<u16> = (0..20).collect();
    let mut server = DumbServer::new(top20, SimTime(1_000_000));
    let parent = make_parent(0x55);
    let lock = LockRecord::new(parent, make_receiver(0xBB), b"identical_nonce".to_vec(), SimTime(0), SimTime(500_000));
    let now = SimTime(1000);
    // Concurrent ingress: two identical submissions
    let v1 = server.ingress(lock.clone(), now).expect("first ingress");
    let v2 = server.ingress(lock.clone(), now).expect("second ingress idempotent");

    // Both must be 200 OK: first is NewLock, second is Verified idempotent
    assert!(matches!(v1, IngressVerdict::NewLock { .. }), "first should be NewLock");
    assert!(matches!(v2, IngressVerdict::Verified { .. }), "second identical must be Verified (200 OK idempotent)");

    // No duplicate entry, ram size stays 1
    assert_eq!(server.ram.len(), 1);
}

// INV-0603: 3-Wege Ingress Verdict
#[test]
fn test_inv0603_three_way_ingress_verdict() {
    let top20: Vec<u16> = (0..20).collect();
    let mut server = DumbServer::new(top20, SimTime(1_000_000));
    let parent = make_parent(0x60);
    let receiver_a = make_receiver(0xAA);
    let receiver_b = make_receiver(0xBB);
    let now = SimTime(100);

    // Case 3: New Lock -> QuorumCertificate
    let lock_a = LockRecord::new(parent, receiver_a, b"lock_a".to_vec(), SimTime(10), SimTime(500_000));
    let v3 = server.ingress(lock_a.clone(), now).expect("case3");
    let (cert, is_final) = match v3 {
        IngressVerdict::NewLock { cert, status_is_final } => (cert, status_is_final),
        _ => panic!("expected NewLock for case 3"),
    };
    assert_eq!(cert.lock_id, lock_a.id);
    assert!(cert.signatures.len() >= 14);
    assert!(is_final, "with N=20 and 20 sigs, status must be FINAL");
    assert!(verify_quorum_certificate(&cert, &(0..20).collect::<Vec<_>>(), 14));

    // Case 1: Verified - same t_id re-query matches
    let v1 = server.ingress(lock_a.clone(), now).expect("case1");
    match v1 {
        IngressVerdict::Verified { lock } => {
            assert_eq!(lock.id, lock_a.id, "Case1 Verified must return identical lock");
        },
        _ => panic!("expected Verified for duplicate identical"),
    }

    // Case 2: 409 Conflict / Double-Spend (different receiver/nonce same parent)
    let lock_b = LockRecord::new(parent, receiver_b, b"lock_b".to_vec(), SimTime(10), SimTime(500_000));
    assert_ne!(lock_a.id, lock_b.id);
    let v2 = server.ingress(lock_b.clone(), now).expect("case2 conflict");
    match v2 {
        IngressVerdict::Conflict { existing, reason } => {
            assert_eq!(existing.id, lock_a.id);
            assert!(reason.contains("409"), "must contain 409 Conflict");
        },
        _ => panic!("expected Conflict for double-spend"),
    }
}

// INV-0604: Client-Side Verification (>=14 Ed25519-Signaturen der Top-20 Shards)
#[test]
fn test_inv0604_client_side_verification_14_of_20() {
    let top20: Vec<u16> = (0..20).collect();
    let lock_id = [0xCC; 32];
    let parent_lock = [0xDD; 32];
    // Honest quorum: 14 sigs
    let mut sigs = Vec::new();
    for i in 0..14 {
        sigs.push(sign_lock_attestation(i, &lock_id, &parent_lock, SimTime(100)));
    }
    let cert = humoco_sim_core::client_flow::QuorumCertificate {
        lock_id,
        shard_id: 42,
        signatures: sigs.clone(),
        signer_bitmap: (1u32<<14)-1,
    };
    assert!(verify_quorum_certificate(&cert, &top20, 14), "14 valid sigs must verify");

    // 13 sigs must fail
    let cert13 = humoco_sim_core::client_flow::QuorumCertificate {
        lock_id,
        shard_id: 42,
        signatures: sigs[..13].to_vec(),
        signer_bitmap: (1u32<<13)-1,
    };
    assert!(!verify_quorum_certificate(&cert13, &top20, 14), "13 sigs must NOT verify");

    // Tampered signature must fail
    let mut bad = sigs.clone();
    bad[0].signature[0] ^= 0xFF;
    let cert_bad = humoco_sim_core::client_flow::QuorumCertificate {
        lock_id,
        shard_id: 42,
        signatures: bad,
        signer_bitmap: (1u32<<14)-1,
    };
    assert!(!verify_quorum_certificate(&cert_bad, &top20, 14), "tampered sig must fail");

    // Non-top20 signer must fail
    let mut sigs_outside = sigs.clone();
    sigs_outside[0] = sign_lock_attestation(99, &lock_id, &parent_lock, SimTime(100)); // 99 not in top20
    let cert_out = humoco_sim_core::client_flow::QuorumCertificate {
        lock_id,
        shard_id: 42,
        signatures: sigs_outside,
        signer_bitmap: (1u32<<14)-1,
    };
    assert!(!verify_quorum_certificate(&cert_out, &top20, 14), "non-top20 signer must fail");

    // DumbServer helper also verifies
    let server = DumbServer::new(top20.clone(), SimTime(1_000_000));
    assert!(server.verify_quorum_certificate(&cert));
    assert!(!server.verify_quorum_certificate(&cert13));
}

// INV-0605: Independently authenticated snapshots and cryptographic context binding.
#[test]
fn zero_trust_exact_membership_and_context() {
    use ed25519_dalek::{Signer, SigningKey};
    use humoco_sim_core::client_flow::{verify_zero_trust_quorum, SignerEntry, ZeroTrustVerifyError};
    use humoco_sim_core::types::{CommitteeMember, NetworkId, select_shard_committee};
    use humoco_sim_core::crypto::{compute_sig_digest, compute_attestation_payload_digest, domain_approve_final};
    let keys: Vec<_> = (0..120u8).map(|i| SigningKey::from_bytes(&[i;32])).collect();
    let members: Vec<_> = keys.iter().enumerate().map(|(i,k)| CommitteeMember {
        node_pubkey: k.verifying_key().to_bytes(), hrw_routing_id: [i as u8;32]
    }).collect();
    let committee = select_shard_committee(42, &members);
    let parent = [0xAB;32]; let lock = [0xEE;32];
    let digest = compute_sig_digest(domain_approve_final(NetworkId::Mainnet),0,0,0,42,1,
        &compute_attestation_payload_digest(&parent,&lock));
    let signers: Vec<_> = committee[..14].iter().map(|m| {
        let key = keys.iter().find(|k| k.verifying_key().to_bytes() == m.node_pubkey).unwrap();
        SignerEntry { hrw_id: m.hrw_routing_id, pub_key: m.node_pubkey, signature: key.sign(&digest).to_bytes() }
    }).collect();
    let verify = |network, shard, p: &[u8;32], l: &[u8;32], s: &[SignerEntry]| {
        verify_zero_trust_quorum(network,1,shard,p,l,s,&committee)
    };
    assert_eq!(verify(NetworkId::Mainnet,42,&parent,&lock,&signers),Ok(()));
    for (network, shard, p, l) in [
        (NetworkId::Testnet,42,parent,lock),(NetworkId::Mainnet,43,parent,lock),
        (NetworkId::Mainnet,42,[0;32],lock),(NetworkId::Mainnet,42,parent,[0;32])
    ] { assert!(matches!(verify(network,shard,&p,&l,&signers),Err(ZeroTrustVerifyError::InvalidSignature {..}))); }
    let mut invalid = signers.clone(); invalid[13] = invalid[0].clone();
    assert!(matches!(verify(NetworkId::Mainnet,42,&parent,&lock,&invalid),Err(ZeroTrustVerifyError::DuplicateSigner {..})));
    let outsider = members.iter().find(|m| !committee.contains(m)).unwrap();
    invalid[13].pub_key = outsider.node_pubkey; invalid[13].hrw_id = outsider.hrw_routing_id;
    assert!(matches!(verify(NetworkId::Mainnet,42,&parent,&lock,&invalid),Err(ZeroTrustVerifyError::UnknownNodeIdentity {..})));
    invalid = signers.clone(); invalid[0].hrw_id[0] ^= 1;
    assert!(matches!(verify(NetworkId::Mainnet,42,&parent,&lock,&invalid),Err(ZeroTrustVerifyError::UnknownNodeIdentity {..})));
    invalid = signers.clone(); invalid[0].signature[0] ^= 1;
    assert!(matches!(verify(NetworkId::Mainnet,42,&parent,&lock,&invalid),Err(ZeroTrustVerifyError::InvalidSignature {..})));
    assert!(matches!(verify(NetworkId::Mainnet,42,&parent,&lock,&signers[..13]),Err(ZeroTrustVerifyError::InsufficientSignatures)));
    let mut duplicate_committee = committee.clone(); duplicate_committee[19] = duplicate_committee[0];
    assert_eq!(verify_zero_trust_quorum(NetworkId::Mainnet,1,42,&parent,&lock,&signers,&duplicate_committee),Err(ZeroTrustVerifyError::InvalidCommittee));
}

#[test]
fn zero_trust_twenty_member_provisional_hysteresis() {
    use ed25519_dalek::{Signer, SigningKey};
    use humoco_sim_core::client_flow::{verify_zero_trust_quorum, SignerEntry, ZeroTrustVerifyError};
    use humoco_sim_core::types::{CommitteeMember, NetworkId};
    use humoco_sim_core::crypto::{compute_sig_digest, compute_attestation_payload_digest, domain_approve_prov};
    let keys: Vec<_> = (0..20u8).map(|i| SigningKey::from_bytes(&[i;32])).collect();
    let committee: Vec<_> = keys.iter().enumerate().map(|(i,k)| CommitteeMember {
        node_pubkey:k.verifying_key().to_bytes(),hrw_routing_id:[i as u8;32]
    }).collect();
    let parent = [1;32]; let lock = [2;32];
    let digest = compute_sig_digest(domain_approve_prov(NetworkId::Mainnet),0,0,0,42,0,
        &compute_attestation_payload_digest(&parent,&lock));
    let signers: Vec<_> = keys[..14].iter().zip(&committee).map(|(key,m)| SignerEntry {
        hrw_id:m.hrw_routing_id,pub_key:m.node_pubkey,signature:key.sign(&digest).to_bytes()
    }).collect();
    assert_eq!(verify_zero_trust_quorum(NetworkId::Mainnet,0,42,&parent,&lock,&signers,&committee),Ok(()));
    assert!(matches!(verify_zero_trust_quorum(NetworkId::Mainnet,1,42,&parent,&lock,&signers,&committee),Err(ZeroTrustVerifyError::InvalidSignature{..})));
    assert_eq!(verify_zero_trust_quorum(NetworkId::Mainnet,1,42,&parent,&lock,&signers,&committee[..19]),Err(ZeroTrustVerifyError::InvalidCommittee));
    assert_eq!(verify_zero_trust_quorum(NetworkId::Mainnet,2,42,&parent,&lock,&signers,&committee),Err(ZeroTrustVerifyError::InvalidCommittee));
}
