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

// INV-0605: Offline-Pending Grace (Offline gesammelt, bei Reconnect idempotent verriegelt)
#[test]
fn test_inv0605_offline_pending_grace_reconnect_idempotent() {
    let top20: Vec<u16> = (0..20).collect();
    let mut server = DumbServer::new(top20, SimTime(1_000_000));
    let mut client = SmartClient::new(7);

    // Client offline collects 3 locks (e.g., flohmarkt)
    let p1 = make_parent(0x10);
    let p2 = make_parent(0x11);
    let p3 = make_parent(0x12);
    let l1 = LockRecord::new(p1, make_receiver(0x21), b"offline1".to_vec(), SimTime(10), SimTime(800_000));
    let l2 = LockRecord::new(p2, make_receiver(0x22), b"offline2".to_vec(), SimTime(20), SimTime(800_000));
    let l3 = LockRecord::new(p3, make_receiver(0x23), b"offline3".to_vec(), SimTime(30), SimTime(800_000));

    client.collect_offline(l1.clone());
    client.collect_offline(l2.clone());
    client.collect_offline(l3.clone());
    assert_eq!(client.pending_offline.len(), 3);
    assert_eq!(server.ram.len(), 0, "server knows nothing while offline");

    // Reconnect: grace submit
    let results = client.reconnect_and_submit(&mut server, SimTime(500));
    assert_eq!(results.len(), 3);
    for r in &results {
        assert!(matches!(r.as_ref().unwrap(), IngressVerdict::NewLock { .. }), "offline grace submit must be NewLock, got {:?}", r);
    }
    assert_eq!(server.ram.len(), 3, "all 3 offline locks now on server");
    assert_eq!(client.pending_offline.len(), 0, "pending cleared after reconnect");
    assert_eq!(client.custody_len(), 3);

    // Reconnect again with same locks (idempotent retry, e.g., network retry)
    client.collect_offline(l1.clone());
    client.collect_offline(l2.clone());
    let results2 = client.reconnect_and_submit(&mut server, SimTime(600));
    for r in results2 {
        assert!(matches!(r.unwrap(), IngressVerdict::Verified { .. }), "duplicate offline retry must be Verified idempotent");
    }
    assert_eq!(server.ram.len(), 3, "idempotent reconnect must not duplicate");
}

// INV-0605: Zero-Trust Quorum-Verifikation für Smart Clients (Fake-Server & Statistische Rang-Abweisung)
#[test]
fn test_inv0605_zero_trust_fake_server_identity_and_statistical_rank_rejection() {
    use humoco_sim_core::client_flow::{
        compute_hrw_score_f64, ConsensusBloomFilter, SignerEntry, ZeroTrustVerifyError,
        verify_zero_trust_quorum,
    };
    use humoco_sim_core::crypto::sign_deterministic_sig;

    const NUM_NODES: usize = 120;
    const SHARD_ID: u16 = 42;
    let lock_id = [0xEE; 32];

    // 1. Erzeuge 120 legitime Knoten im Netzwerk
    let mut network_nodes: Vec<([u8; 32], [u8; 32])> = Vec::new();
    for i in 0..NUM_NODES {
        let mut node_id = [0u8; 32];
        let mut pub_key = [0u8; 32];
        node_id[0..4].copy_from_slice(&(i as u32).to_le_bytes());
        pub_key[0..4].copy_from_slice(&((i + 1000) as u32).to_le_bytes());
        network_nodes.push((node_id, pub_key));
    }

    // 2. Erzeuge Bloom-Filter für 3 Seed-Knoten (A, B ehrlich, C böswillig vergiftet)
    let mut filter_a = ConsensusBloomFilter::new();
    let mut filter_b = ConsensusBloomFilter::new();
    let mut filter_c = ConsensusBloomFilter::new();

    for (nid, pkey) in &network_nodes {
        filter_a.insert_identity(nid, pkey);
        filter_b.insert_identity(nid, pkey);
        filter_c.insert_identity(nid, pkey);
    }

    // Böswilliger Seed C fügt 10 Fake-Knoten ein (Poisoning-Versuch)
    for f in 9000..9010 {
        let mut fake_id = [0xFF; 32];
        let mut fake_pk = [0xFE; 32];
        fake_id[0..4].copy_from_slice(&(f as u32).to_le_bytes());
        fake_pk[0..4].copy_from_slice(&(f as u32).to_le_bytes());
        filter_c.insert_identity(&fake_id, &fake_pk);
    }

    // Client holt A, B, C und bildet 2-aus-3 Konsens-Filter
    let consensus_filter = ConsensusBloomFilter::bitwise_majority(&filter_a, &filter_b, &filter_c);
    let est_n = consensus_filter.estimate_network_size();
    assert!((100..=140).contains(&est_n), "N-Schätzung muss nahe 120 liegen, ist: {}", est_n);

    // Vergiftete Fake-Identitäten von Seed C wurden sauber herausgefiltert!
    let mut fake_c_id = [0xFF; 32];
    let mut fake_c_pk = [0xFE; 32];
    fake_c_id[0..4].copy_from_slice(&(9005u32).to_le_bytes());
    fake_c_pk[0..4].copy_from_slice(&(9005u32).to_le_bytes());
    assert!(
        !consensus_filter.contains_identity(&fake_c_id, &fake_c_pk),
        "Konsens-Voting muss vergiftete Keys von Seed C restlos eliminieren!"
    );

    // 3. Finde die echten Top-20 Knoten für Shard 42 (geordnet nach HRW-Score)
    let mut ranked_nodes = network_nodes.clone();
    ranked_nodes.sort_by(|a, b| {
        let score_a = compute_hrw_score_f64(&a.0, SHARD_ID);
        let score_b = compute_hrw_score_f64(&b.0, SHARD_ID);
        score_b.partial_cmp(&score_a).unwrap()
    });

    // 4. Testfall A: Fake-Identitäten (Potemkin-Dorf) -> MUSS ABGELEHNT WERDEN
    let mut fake_signers = Vec::new();
    for i in 0..14 {
        let mut fake_id = [0xAA; 32];
        let mut fake_pk = [0xBB; 32];
        fake_id[0] = i as u8;
        fake_pk[0] = i as u8;
        let sig = sign_deterministic_sig(&fake_pk, &lock_id);
        fake_signers.push(SignerEntry {
            hrw_id: fake_id,
            pub_key: fake_pk,
            signature: sig,
        });
    }
    let res_fake = verify_zero_trust_quorum(&lock_id, SHARD_ID, &fake_signers, &consensus_filter, 1.5);
    assert!(
        matches!(res_fake, Err(ZeroTrustVerifyError::UnknownNodeIdentity { .. })),
        "Fake-Identitäten müssen am Konsens-Filter scheitern!"
    );

    // 5. Testfall B: Echte Knoten, aber mit falschem / niedrigem Shard-Rang -> MUSS ABGELEHNT WERDEN
    // Nimm die 14 SCHLECHTESTEN Knoten (Ränge 106..120)
    let mut wrong_rank_signers = Vec::new();
    for (nid, pkey) in ranked_nodes.iter().rev().take(14) {
        let sig = sign_deterministic_sig(pkey, &lock_id);
        wrong_rank_signers.push(SignerEntry {
            hrw_id: *nid,
            pub_key: *pkey,
            signature: sig,
        });
    }
    let res_wrong_rank = verify_zero_trust_quorum(&lock_id, SHARD_ID, &wrong_rank_signers, &consensus_filter, 1.5);
    assert!(
        matches!(res_wrong_rank, Err(ZeroTrustVerifyError::StatisticalRankTooLow { .. })),
        "Echte Knoten mit zu niedrigem Rang müssen statistisch abgewiesen werden!"
    );

    // 6. Testfall C: Echte Top-Knoten, aber gefälschte Signatur -> MUSS ABGELEHNT WERDEN
    let mut bad_sig_signers = Vec::new();
    for (nid, pkey) in ranked_nodes.iter().take(14) {
        let mut sig = sign_deterministic_sig(pkey, &lock_id);
        sig[0] ^= 0xFF; // Bit-Flip in Signatur
        bad_sig_signers.push(SignerEntry {
            hrw_id: *nid,
            pub_key: *pkey,
            signature: sig,
        });
    }
    let res_bad_sig = verify_zero_trust_quorum(&lock_id, SHARD_ID, &bad_sig_signers, &consensus_filter, 1.5);
    assert!(
        matches!(res_bad_sig, Err(ZeroTrustVerifyError::InvalidSignature { .. })),
        "Gefälschte Signatur muss scheitern!"
    );

    // 7. Testfall D (Happy Path): Echte Top-14 Knoten mit gültigen Signaturen -> MUSS ERFOLGREICH SEIN!
    let mut honest_signers = Vec::new();
    for (nid, pkey) in ranked_nodes.iter().take(14) {
        let sig = sign_deterministic_sig(pkey, &lock_id);
        honest_signers.push(SignerEntry {
            hrw_id: *nid,
            pub_key: *pkey,
            signature: sig,
        });
    }
    let res_ok = verify_zero_trust_quorum(&lock_id, SHARD_ID, &honest_signers, &consensus_filter, 1.5);
    assert_eq!(
        res_ok, Ok(()),
        "Echtes Quorum der Top-Knoten muss in < 1 ms verifiziert werden: {:?}",
        res_ok
    );

    // 8. Testfall E (Chaos / Störung): 10 Top-Knoten + 4 Notfall-Nachrücker bis Rang 35 -> MUSS TOLERIERT WERDEN!
    let mut emergency_signers = Vec::new();
    // 10 Knoten aus den Rängen 1..10
    for (nid, pkey) in ranked_nodes.iter().take(10) {
        let sig = sign_deterministic_sig(pkey, &lock_id);
        emergency_signers.push(SignerEntry {
            hrw_id: *nid,
            pub_key: *pkey,
            signature: sig,
        });
    }
    // 4 Notfall-Knoten aus den Rängen 30..34
    for (nid, pkey) in ranked_nodes.iter().skip(29).take(4) {
        let sig = sign_deterministic_sig(pkey, &lock_id);
        emergency_signers.push(SignerEntry {
            hrw_id: *nid,
            pub_key: *pkey,
            signature: sig,
        });
    }
    assert_eq!(emergency_signers.len(), 14);
    let res_emergency = verify_zero_trust_quorum(&lock_id, SHARD_ID, &emergency_signers, &consensus_filter, 1.5);
    assert_eq!(
        res_emergency, Ok(()),
        "Notfall-Quorum mit Nachrückern bis Rang 35 muss dank Top-5-Anker & Median toleriert werden: {:?}",
        res_emergency
    );
}
