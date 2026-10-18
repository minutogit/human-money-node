#![forbid(unsafe_code)]

//! Certified Epoch Handoff (CEH) architecture module.
//!
//! Provides deterministic epoch transition, BFT round progression,
//! shard handoff certificates, and pioneer mode unified manifests.
//!
//! ⚠️ ARCHITECTURAL BOUNDARY & EVALUATED DEAD-END (DEC-053 / DEC-055):
//! Mandatory predecessor epoch chaining (where epoch E+1 strictly requires 14 signatures
//! from the epoch E committee) has been evaluated and rejected as an architectural dead end.
//! If > f nodes disappear or an internet partition occurs, mandatory predecessor
//! baton passing produces a fatal, unrecoverable liveness deadlock (halting ~88.5% of shards).
//! The canonical HuMoCo design derives shard membership autonomously from the living active
//! mesh via HRW (`select_shard_committee`), using deterministic `min(H_canon)` convergence upon network merge.
//!
//! ⚠️ THE 4-FOLD EPOCH & LIVENESS DISAMBIGUATION:
//! 1. Argon2d Incubation Wall (24h): Cryptographic maturation for newly mined shard tickets (`HrwRoutingId`)
//!    to prevent opportunistic grinding / shard-hopping. Unchanged.
//! 2. Calendar `epoch_day`: Purely calendar integer slot `(unix_sec - T0) / 86400` in wire envelopes for
//!    rate-limiting, ingress quotas, and network thermometer EMA decay. Zero connection to committee elections.
//! 3. Dynamic Presence (Passive Dunbar Liveness): Peer liveness is tracked via hourly Dunbar heartbeats;
//!    peers missing consecutive heartbeats (e.g. 3 missed hours -> `missing_count >= 3`) become suspended/dormant
//!    and are excluded from upcoming HRW snapshots. There is NO 24h committee tenure and NO 24h wait for offline detection.
//! 4. Autonomous HRW Computation: Shard committees are computed per request/snapshot via Rendezvous Hashing
//!    from the local active mesh view, NOT via predecessor epoch certificates ("Staffelstab").

pub mod barrier;
pub mod consensus;
pub mod crypto;
pub mod snapshot;
pub mod types;
pub mod verifier;
pub mod voucher_tree;

pub use barrier::*;
pub use consensus::*;
pub use crypto::*;
pub use snapshot::*;
pub use types::*;
pub use verifier::*;
pub use voucher_tree::*;

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn generate_keypair(seed: u8) -> (SigningKey, NodePubKey) {
        let mut seed_bytes = [0u8; 32];
        seed_bytes[0] = seed;
        let signing_key = SigningKey::from_bytes(&seed_bytes);
        let pubkey = signing_key.verifying_key().to_bytes();
        (signing_key, pubkey)
    }

    fn generate_committee(start_seed: u8) -> ([SigningKey; CEH_COMMITTEE_SIZE], [NodePubKey; CEH_COMMITTEE_SIZE]) {
        // We use dummy uninitialized arrays and fill them safely
        let mut signers: Vec<SigningKey> = Vec::with_capacity(CEH_COMMITTEE_SIZE);
        let mut pubkeys: Vec<NodePubKey> = Vec::with_capacity(CEH_COMMITTEE_SIZE);
        for i in 0..CEH_COMMITTEE_SIZE {
            let (sk, pk) = generate_keypair(start_seed + i as u8);
            signers.push(sk);
            pubkeys.push(pk);
        }
        let signers_arr: [SigningKey; CEH_COMMITTEE_SIZE] = signers.try_into().map_err(|_| ()).unwrap();
        let pubkeys_arr: [NodePubKey; CEH_COMMITTEE_SIZE] = pubkeys.try_into().map_err(|_| ()).unwrap();
        (signers_arr, pubkeys_arr)
    }

    #[test]
    fn test_domain_tags_length_prefixed() {
        assert_eq!(DOMAIN_CEH_GENESIS, b"HUMOCO_V1_CEH_GENESIS");
        assert_eq!(DOMAIN_CEH_CERT, b"HUMOCO_V1_CEH_CERT");
        assert_eq!(DOMAIN_CEH_UNIFIED_MANIFEST, b"HUMOCO_V1_CEH_UNIFIED_MANIFEST");
        assert_eq!(DOMAIN_CEH_LOCK_RECEIPT, b"HUMOCO_V1_CEH_LOCK_RECEIPT");
        assert_eq!(DOMAIN_CEH_PROPOSAL, b"HUMOCO_V1_CEH_PROPOSAL");
        assert_eq!(DOMAIN_CEH_PREPARE, b"HUMOCO_V1_CEH_PREPARE");
        assert_eq!(DOMAIN_CEH_COMMIT, b"HUMOCO_V1_CEH_COMMIT");
        assert_eq!(DOMAIN_CEH_ROUND_CHANGE, b"HUMOCO_V1_CEH_ROUND_CHANGE");
        assert_eq!(DOMAIN_CEH_VOUCHER_HOP, b"HUMOCO_V1_CEH_VOUCHER_HOP");
        assert_eq!(DOMAIN_CEH_VOUCHER_TREE, b"HUMOCO_V1_CEH_VOUCHER_TREE");
        assert_eq!(DOMAIN_CEH_HIERARCHICAL_STATE_ROOT, b"HUMOCO_V1_CEH_HIERARCHICAL_STATE_ROOT");
    }

    #[test]
    fn test_genesis_manifest_hashing_and_signing() {
        let (signers, committee) = generate_committee(1);
        let mut manifest = GenesisManifest::new(
            1,
            [0xaa; 32],
            1_700_000_000,
            committee,
        );

        let hash1 = manifest.canonical_hash();
        let hash2 = manifest.canonical_hash();
        assert_eq!(hash1, hash2);

        // Sign with 14 committee members (quorum)
        for sk in signers.iter().take(CEH_BFT_QUORUM) {
            let (pk, sig) = sign_genesis_manifest(sk, &manifest);
            assert!(verify_genesis_signature(&manifest, &pk, &sig));
            manifest.add_signature(pk, sig);
        }

        assert!(verify_genesis_manifest_signatures(&manifest, CEH_BFT_QUORUM).is_ok());

        // Insufficient signatures
        let mut partial_manifest = manifest.clone();
        partial_manifest.genesis_signatures.truncate(CEH_BFT_QUORUM - 1);
        assert!(matches!(
            verify_genesis_manifest_signatures(&partial_manifest, CEH_BFT_QUORUM),
            Err(CehError::QuorumNotReached { have: 13, required: 14 })
        ));

        // Non-committee signer
        let (outsider_sk, outsider_pk) = generate_keypair(99);
        let (_, outsider_sig) = sign_genesis_manifest(&outsider_sk, &manifest);
        let mut rogue_manifest = manifest.clone();
        rogue_manifest.genesis_signatures[0] = (outsider_pk, outsider_sig);
        assert!(matches!(
            verify_genesis_manifest_signatures(&rogue_manifest, CEH_BFT_QUORUM),
            Err(CehError::SignerNotInCommittee(_))
        ));

        // Duplicate signer
        let mut dup_manifest = manifest.clone();
        dup_manifest.genesis_signatures[1] = dup_manifest.genesis_signatures[0];
        assert!(matches!(
            verify_genesis_manifest_signatures(&dup_manifest, CEH_BFT_QUORUM),
            Err(CehError::DuplicateSigner(_))
        ));
    }

    #[test]
    fn test_epoch_certificate_hashing_and_signing() {
        let (signers, committee) = generate_committee(10);
        let (_, successor_comm) = generate_committee(30);

        let mut cert = EpochCertificate::new(
            42,
            5,
            0,
            [0x11; 32],
            [0x22; 32],
            successor_comm,
        );

        let h1 = cert.canonical_hash();
        let h2 = cert.canonical_hash();
        assert_eq!(h1, h2);

        for sk in signers.iter().take(14) {
            let (pk, sig) = sign_epoch_certificate(sk, &cert);
            assert!(verify_epoch_certificate_signature(&cert, &pk, &sig));
            cert.add_signature(pk, sig);
        }

        assert!(verify_epoch_certificate_signatures(&cert, &committee, 14).is_ok());

        // Wrong committee check
        assert!(matches!(
            verify_epoch_certificate_signatures(&cert, &successor_comm, 14),
            Err(CehError::SignerNotInCommittee(_))
        ));
    }

    #[test]
    fn test_lock_receipt_attestation() {
        let (signers, committee) = generate_committee(50);
        let mut receipt = LockReceipt::new(
            7,
            12,
            [0x01; 32],
            [0x02; 32],
            1_800_000_000,
        );

        for sk in signers.iter().take(14) {
            let (pk, sig) = sign_lock_receipt(sk, &receipt);
            assert!(verify_lock_receipt_signature(&receipt, &pk, &sig));
            receipt.add_attestation(pk, sig);
        }

        assert!(verify_lock_receipt_signatures(&receipt, Some(&committee), 14).is_ok());
    }

    #[test]
    fn test_candidate_proof_and_proposal() {
        let (sk, pk) = generate_keypair(77);
        let ticket = [0x55; 32];
        let timestamp = 1_700_000_123;
        let candidate = sign_candidate_proof(&sk, ticket, timestamp);
        assert_eq!(candidate.pubkey, pk);
        assert!(verify_candidate_proof(&candidate));

        let (_, successor) = generate_committee(100);
        let proposal = EpochProposal::new(
            1,
            10,
            0,
            [0x88; 32],
            successor,
            vec![candidate],
            None,
        );

        let h1 = proposal.canonical_hash();
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn test_prepare_and_commit_votes() {
        let (signers, committee) = generate_committee(120);
        let shard_id = 99;
        let epoch = 3;
        let round = 1;
        let proposal_hash = [0x77; 32];

        // Prepare vote
        let vote = sign_prepare_vote(&signers[0], shard_id, epoch, round, proposal_hash);
        assert_eq!(vote.voter, committee[0]);
        assert!(verify_prepare_vote(&vote));

        // Commit vote
        let commit = sign_commit_vote(&signers[1], shard_id, epoch, round, proposal_hash);
        assert_eq!(commit.voter, committee[1]);
        assert!(verify_commit_vote(&commit));

        // PreparedProof aggregation
        let mut prepared = PreparedProof::new(shard_id, epoch, round, proposal_hash);
        for sk in signers.iter().take(14) {
            let v = sign_prepare_vote(sk, shard_id, epoch, round, proposal_hash);
            prepared.add_signature(v.voter, v.signature);
        }
        assert!(verify_prepared_proof(&prepared, &committee, 14).is_ok());
    }

    #[test]
    fn test_round_change_and_new_view() {
        let (signers, committee) = generate_committee(150);
        let shard_id = 15;
        let epoch = 2;
        let failed_round = 0;
        let next_round = 1;

        let rc = sign_round_change(&signers[0], shard_id, epoch, failed_round, next_round, None);
        assert!(verify_round_change(&rc));

        let mut nvc = NewViewCertificate::new(shard_id, epoch, next_round);
        for sk in signers.iter().take(14) {
            let msg = sign_round_change(sk, shard_id, epoch, failed_round, next_round, None);
            nvc.add_message(msg);
        }

        assert!(verify_new_view_certificate(&nvc, &committee, 14).is_ok());
    }

    #[test]
    fn test_merkle_tree_65536_leaves_root_and_proofs() {
        // Allocate 65536 dummy closed state roots deterministically on heap
        let mut shard_roots = alloc_shards_closed_state_roots();
        for (i, root) in shard_roots.iter_mut().enumerate() {
            let mut h = blake3::Hasher::new();
            h.update(b"TEST_SHARD_STATE");
            h.update(&(i as u32).to_le_bytes());
            *root = *h.finalize().as_bytes();
        }

        let root = compute_unified_shards_merkle_root(&shard_roots);
        assert_ne!(root, [0u8; 32]);

        // Test boundary and random shard IDs
        let test_shards = [0u16, 1u16, 2u16, 15u16, 255u16, 1024u16, 32767u16, 65534u16, 65535u16];
        for &shard_id in &test_shards {
            let proof = generate_shard_merkle_proof(&shard_roots, shard_id);
            assert_eq!(proof.shard_id, shard_id);
            assert_eq!(proof.closed_state_root, shard_roots[shard_id as usize]);
            assert_eq!(proof.audit_path.len(), CEH_MERKLE_TREE_DEPTH);

            // Valid verification
            assert!(proof.verify(&root), "Merkle proof failed for shard {shard_id}");
            assert!(verify_shard_merkle_leaf(&root, shard_id, &proof.closed_state_root, &proof.audit_path));

            // Tamper state root -> fails
            let mut tampered_proof = proof.clone();
            tampered_proof.closed_state_root[0] ^= 0xff;
            assert!(!tampered_proof.verify(&root));

            // Tamper shard id -> fails
            let mut tampered_shard = proof.clone();
            tampered_shard.shard_id ^= 0x01;
            assert!(!tampered_shard.verify(&root));

            // Tamper audit path -> fails
            let mut tampered_path = proof.clone();
            tampered_path.audit_path[0][0] ^= 0xff;
            assert!(!tampered_path.verify(&root));
        }
    }

    #[test]
    fn test_unified_network_epoch_manifest() {
        let (signers, committee) = generate_committee(200);
        let mut shard_roots = alloc_shards_closed_state_roots();
        for (i, root) in shard_roots.iter_mut().enumerate() {
            root[0] = (i % 256) as u8;
        }
        let shards_merkle_root = compute_unified_shards_merkle_root(&shard_roots);

        let mut manifest = UnifiedNetworkEpochManifest::new(
            1,
            0,
            [0x99; 32],
            shards_merkle_root,
            committee,
        );

        for sk in signers.iter().take(14) {
            let (pk, sig) = sign_unified_manifest(sk, &manifest);
            assert!(verify_unified_manifest_signature(&manifest, &pk, &sig));
            manifest.add_signature(pk, sig);
        }

        assert!(verify_unified_manifest_signatures(&manifest, 14).is_ok());
    }

    #[test]
    fn test_serde_roundtrips() {
        let (_, committee) = generate_committee(1);
        let manifest = GenesisManifest::new(1, [2u8; 32], 1000, committee);
        let bytes = bincode::serialize(&manifest).expect("bincode serialize failed");
        let decoded: GenesisManifest = bincode::deserialize(&bytes).expect("bincode deserialize failed");
        assert_eq!(manifest, decoded);

        let cert = EpochCertificate::new(1, 2, 3, [4u8; 32], [5u8; 32], committee);
        let cert_bytes = bincode::serialize(&cert).expect("bincode serialize failed");
        let decoded_cert: EpochCertificate = bincode::deserialize(&cert_bytes).expect("bincode deserialize failed");
        assert_eq!(cert, decoded_cert);
    }
}
