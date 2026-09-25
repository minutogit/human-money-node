use std::path::Path;
use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::Sha512;

use crate::error::NodeError;

/// Constants for Argon2d HrwRoutingId (Spec 07: NodeID = Argon2d(PubKey || Nonce || T0))
pub const HUMOCO_ARGON2D_SALT: &[u8] = b"HUMOCO_ARGON2D_ROUTING_SALT_V1";
pub const ARGON2D_M_COST: u32 = 64 * 1024; // 64 MiB
pub const ARGON2D_T_COST: u32 = 3;
pub const ARGON2D_P_COST: u32 = 1;

/// Calculates the hybrid node ID as BLAKE3 domain separation hash over Ed25519 and PQC public keys.
///
/// HybridNodeId = BLAKE3(len(DOMAIN_HYBRID_NODE_ID) || DOMAIN_HYBRID_NODE_ID || ed25519_pub || pqc_pub)
pub fn compute_hybrid_node_id(ed25519_pub: &[u8; 32], pqc_pub: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let domain = humoco_sim_core::crypto::DOMAIN_HYBRID_NODE_ID;
    let tag_len = domain.len() as u8;
    hasher.update(&[tag_len]);
    hasher.update(domain);
    hasher.update(ed25519_pub);
    hasher.update(pqc_pub);
    *hasher.finalize().as_bytes()
}

/// Computes the raw Argon2d PoW proof hash over NodePubKey || Nonce || T0.
pub fn compute_pow_proof(node_pubkey: &[u8; 32], nonce: u64, t0: u64) -> [u8; 32] {
    if nonce == 0 && t0 == 0 {
        return *blake3::hash(node_pubkey).as_bytes();
    }
    // Input: pubkey || nonce_le || t0_le
    let mut input = Vec::with_capacity(48);
    input.extend_from_slice(node_pubkey);
    input.extend_from_slice(&nonce.to_le_bytes());
    input.extend_from_slice(&t0.to_le_bytes());

    // Argon2d with 64MiB, 3 iterations, 1 lane
    let params = Params::new(ARGON2D_M_COST, ARGON2D_T_COST, ARGON2D_P_COST, Some(32))
        .expect("valid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2d, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(&input, HUMOCO_ARGON2D_SALT, &mut out)
        .expect("argon2 hashing must succeed");
    out
}

/// Computes the HRW routing ID via 2-stage PoW proof + BLAKE3 whitening (or BLAKE3 fast-path).
///
/// - If `nonce == 0 && t0 == 0` (fast tests / legacy): `BLAKE3(pubkey)`
/// - Otherwise: `compute_whitened_hrw_id(pubkey, nonce, t0, &compute_pow_proof(pubkey, nonce, t0))`
pub fn compute_hrw_routing_id(node_pubkey: &[u8; 32], nonce: u64, t0: u64) -> [u8; 32] {
    if nonce == 0 && t0 == 0 {
        return *blake3::hash(node_pubkey).as_bytes();
    }
    let pow_proof = compute_pow_proof(node_pubkey, nonce, t0);
    humoco_sim_core::crypto::compute_whitened_hrw_id(node_pubkey, nonce, t0, &pow_proof)
}

/// Computes the work score for given identity parameters.
pub fn compute_work_score(node_pubkey: &[u8; 32], nonce: u64, t0: u64) -> u64 {
    if nonce == 0 && t0 == 0 {
        return 1;
    }
    let pow_proof = compute_pow_proof(node_pubkey, nonce, t0);
    humoco_sim_core::crypto::compute_work_from_hash(&pow_proof)
}

#[derive(Clone)]
pub struct NodeIdentity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    node_id: [u8; 32],
    hrw_routing_id: [u8; 32],
    nonce: u64,
    t0: u64,
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("node_id", &self.node_id_hex())
            .field("public_key", &self.public_key_hex())
            .field("hrw_routing_id", &self.hrw_routing_id_hex())
            .field("nonce", &self.nonce)
            .field("t0", &self.t0)
            .finish()
    }
}

impl NodeIdentity {
    /// Constructs a NodeIdentity from an existing SigningKey (nonce=0, t0=0, fast BLAKE3 path).
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        Self::from_signing_key_with_pow(signing_key, 0, 0)
    }

    /// Constructs a NodeIdentity from SigningKey with explicit PoW parameters.
    pub fn from_signing_key_with_pow(signing_key: SigningKey, nonce: u64, t0: u64) -> Self {
        let verifying_key = signing_key.verifying_key();
        let node_id = *blake3::hash(verifying_key.as_bytes()).as_bytes();
        let hrw_routing_id = compute_hrw_routing_id(verifying_key.as_bytes(), nonce, t0);
        Self {
            signing_key,
            verifying_key,
            node_id,
            hrw_routing_id,
            nonce,
            t0,
        }
    }

    /// Internal constructor from raw parts when hrw_routing_id already known (e.g. file load).
    fn from_parts(
        signing_key: SigningKey,
        verifying_key: VerifyingKey,
        node_id: [u8; 32],
        hrw_routing_id: [u8; 32],
        nonce: u64,
        t0: u64,
    ) -> Self {
        Self {
            signing_key,
            verifying_key,
            node_id,
            hrw_routing_id,
            nonce,
            t0,
        }
    }

    /// Generates a new random Ed25519 node identity using a cryptographically secure RNG.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self::from_signing_key(signing_key)
    }

    /// Generates with explicit PoW parameters (for production mining).
    pub fn generate_with_pow(nonce: u64, t0: u64) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self::from_signing_key_with_pow(signing_key, nonce, t0)
    }

/// Constructs an Ed25519 node identity from a BIP-39 mnemonic phrase and optional passphrase
/// using SLIP-0010 Ed25519 master key derivation (matching the human-money-core standard).
///
/// The derivation steps are:
/// 1. BIP-39 mnemonic to seed via PBKDF2-HMAC-SHA512 (2048 iterations) with salt "mnemonic" + passphrase.
/// 2. SLIP-0010 master key derivation: HMAC-SHA512(key = b"ed25519 seed", data = bip39_seed).
/// 3. The first 32 bytes (I_L) form the Ed25519 seed for SigningKey::from_bytes(&seed).
    pub fn from_mnemonic(phrase: &str, passphrase: Option<&str>) -> Result<Self, NodeError> {
        let mnemonic = bip39::Mnemonic::parse_normalized(phrase)
            .map_err(|err| NodeError::Identity(format!("Invalid mnemonic phrase: {err}")))?;
        let bip39_seed = mnemonic.to_seed_normalized(passphrase.unwrap_or(""));

        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(b"ed25519 seed")
            .map_err(|err| NodeError::Identity(format!("HMAC initialization failed: {err}")))?;
        mac.update(&bip39_seed);
        let result = mac.finalize().into_bytes();

        let mut ed25519_seed = [0u8; 32];
        ed25519_seed.copy_from_slice(&result[..32]);

        let signing_key = SigningKey::from_bytes(&ed25519_seed);
        Ok(Self::from_signing_key(signing_key))
    }

    /// Derives an Ed25519 node identity from a BIP-39 mnemonic phrase and optional passphrase
    /// using SLIP-0010 Ed25519 master key derivation (matching the human-money-core standard).
    ///
    /// The derivation steps are:
    /// 1. BIP-39 mnemonic to seed via PBKDF2-HMAC-SHA512 (2048 iterations) with salt "mnemonic" + passphrase.
    /// 2. SLIP-0010 master key derivation: HMAC-SHA512(key = b"ed25519 seed", data = bip39_seed).
    /// 3. The first 32 bytes (I_L) form the Ed25519 seed for SigningKey::from_bytes(&seed).
    pub fn generate_with_mnemonic(word_count: usize) -> Result<(Self, String), NodeError> {
        if word_count != 12 && word_count != 24 {
            return Err(NodeError::Identity(format!(
                "Failed to generate mnemonic: invalid word count {}, expected 12 or 24",
                word_count
            )));
        }
        let mnemonic = bip39::Mnemonic::generate(word_count)
            .map_err(|err| NodeError::Identity(format!("Failed to generate mnemonic: {err}")))?;
        let phrase = mnemonic.to_string();
        let identity = Self::from_mnemonic(&phrase, None)?;
        Ok((identity, phrase))
    }

    // -------------------------------------------------------------------------
    // Getter
    // -------------------------------------------------------------------------

    /// Returns a reference to the Ed25519 SigningKey (private key).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Returns a reference to the Ed25519 VerifyingKey (public key).
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Alias / Übergangs-Getter für public_key (verifying_key).
    pub fn public_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Returns the 32-byte Ed25519 public key bytes (NodePubKey).
    pub fn node_pubkey(&self) -> &[u8; 32] {
        self.verifying_key.as_bytes()
    }

    /// Returns the 32-byte BLAKE3 fingerprint Node ID (permanent identity).
    pub fn node_id(&self) -> &[u8; 32] {
        &self.node_id
    }

    /// Returns the 16-bit numeric node ID prefix.
    pub fn node_id_u16(&self) -> u16 {
        u16::from_be_bytes([self.node_id[0], self.node_id[1]])
    }

    /// Returns the hex-encoded representation of the Node ID.
    pub fn node_id_hex(&self) -> String {
        blake3::Hash::from(self.node_id).to_hex().to_string()
    }

    /// Returns the 32-byte HRW Routing ID (Argon2d ticket, semantisch entflochten von NodePubKey).
    pub fn hrw_routing_id(&self) -> &[u8; 32] {
        &self.hrw_routing_id
    }

    /// Alias for hrw_routing_id.
    pub fn hrw_id(&self) -> &[u8; 32] {
        &self.hrw_routing_id
    }

    /// Alias for hrw_routing_id (RoutingId getter).
    pub fn routing_id(&self) -> &[u8; 32] {
        &self.hrw_routing_id
    }

    /// Returns hex-encoded HRW routing id.
    pub fn hrw_routing_id_hex(&self) -> String {
        hex::encode(self.hrw_routing_id)
    }

    /// Returns the PoW nonce used for HRW derivation.
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Returns the T0 genesis timestamp used for HRW derivation.
    pub fn t0(&self) -> u64 {
        self.t0
    }

    /// Returns the work score achieved by this node identity.
    pub fn work_score(&self) -> u64 {
        compute_work_score(self.node_pubkey(), self.nonce, self.t0)
    }

    /// Returns the hex-encoded representation of the public key.
    pub fn public_key_hex(&self) -> String {
        let hex_chars: Vec<String> = self
            .verifying_key
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        hex_chars.join("")
    }

    /// Returns the W3C `did:key` representation of the Ed25519 public key.
    /// Format: `did:key:z` + Base58BTC(0xed, 0x01, <32-byte pubkey>)
    pub fn did_key(&self) -> String {
        let mut bytes = Vec::with_capacity(34);
        bytes.extend_from_slice(&[0xed, 0x01]);
        bytes.extend_from_slice(self.verifying_key.as_bytes());
        format!("did:key:z{}", bs58::encode(bytes).into_string())
    }

    /// Saves the private key to a file with restricted POSIX permissions (0600 on Unix).
    /// Format: 32B SigningKey + 8B nonce_le + 8B t0_le + 32B HrwRoutingId = 80 Bytes.
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), NodeError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|err| NodeError::IoWithPath {
                    path: parent.to_path_buf(),
                    source: err,
                })?;
            }
        }

        let key_bytes = self.signing_key.to_bytes();
        let mut out = Vec::with_capacity(80);
        out.extend_from_slice(&key_bytes);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.t0.to_le_bytes());
        out.extend_from_slice(&self.hrw_routing_id);

        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .map_err(|err| NodeError::IoWithPath {
                    path: path.to_path_buf(),
                    source: err,
                })?;

            file.write_all(&out)
                .map_err(|err| NodeError::IoWithPath {
                    path: path.to_path_buf(),
                    source: err,
                })?;
            file.flush().map_err(|err| NodeError::IoWithPath {
                path: path.to_path_buf(),
                source: err,
            })?;

            // Ensure permissions are 0600 even if file already existed with different permissions
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }

        #[cfg(not(unix))]
        {
            std::fs::write(path, out).map_err(|err| NodeError::IoWithPath {
                path: path.to_path_buf(),
                source: err,
            })?;
        }

        Ok(())
    }

    /// Loads the private key from a binary file and derives the identity.
    /// Supports both legacy 32-byte files and new 80-byte format.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, NodeError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|err| NodeError::IoWithPath {
            path: path.to_path_buf(),
            source: err,
        })?;

        match bytes.len() {
            32 => {
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(&bytes);
                let signing_key = SigningKey::from_bytes(&key_array);
                Ok(Self::from_signing_key(signing_key))
            }
            80 => {
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(&bytes[0..32]);
                let signing_key = SigningKey::from_bytes(&key_array);
                let verifying_key = signing_key.verifying_key();
                let node_id = *blake3::hash(verifying_key.as_bytes()).as_bytes();

                let mut nonce_bytes = [0u8; 8];
                nonce_bytes.copy_from_slice(&bytes[32..40]);
                let nonce = u64::from_le_bytes(nonce_bytes);

                let mut t0_bytes = [0u8; 8];
                t0_bytes.copy_from_slice(&bytes[40..48]);
                let t0 = u64::from_le_bytes(t0_bytes);

                let mut hrw = [0u8; 32];
                hrw.copy_from_slice(&bytes[48..80]);

                // If file contains hrw that doesn't match recomputed value we still trust file
                // but we keep it as stored to preserve roundtrip determinism.
                Ok(Self::from_parts(
                    signing_key,
                    verifying_key,
                    node_id,
                    hrw,
                    nonce,
                    t0,
                ))
            }
            other => Err(NodeError::Identity(format!(
                "Invalid private key file size at {}: expected 32 or 80 bytes, got {}",
                path.display(),
                other
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_and_node_id_derivation() {
        let identity = NodeIdentity::generate();
        let expected_node_id = *blake3::hash(identity.verifying_key().as_bytes()).as_bytes();
        assert_eq!(*identity.node_id(), expected_node_id);
        assert_eq!(identity.node_id_hex().len(), 64);
        assert_eq!(identity.public_key_hex().len(), 64);
        // HrwRoutingId fast path (nonce 0, t0 0) equals BLAKE3(pubkey) == node_id
        assert_eq!(*identity.hrw_routing_id(), expected_node_id);
        assert_eq!(identity.nonce(), 0);
        assert_eq!(identity.t0(), 0);
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let temp = tempdir().expect("tempdir");
        let key_path = temp.path().join("keys/node_key.bin");

        let identity = NodeIdentity::generate();
        identity.save_to_file(&key_path).expect("Save identity");
        assert!(key_path.exists());
        // new format is 80 bytes
        assert_eq!(std::fs::metadata(&key_path).unwrap().len(), 80);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&key_path).expect("Metadata");
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }

        let loaded = NodeIdentity::load_from_file(&key_path).expect("Load identity");
        assert_eq!(identity.node_id(), loaded.node_id());
        assert_eq!(
            identity.verifying_key().as_bytes(),
            loaded.verifying_key().as_bytes()
        );
        assert_eq!(
            identity.signing_key().to_bytes(),
            loaded.signing_key().to_bytes()
        );
        assert_eq!(identity.hrw_routing_id(), loaded.hrw_routing_id());
        assert_eq!(identity.nonce(), loaded.nonce());
        assert_eq!(identity.t0(), loaded.t0());
    }

    #[test]
    fn test_load_invalid_key_length() {
        let temp = tempdir().expect("tempdir");
        let invalid_key_path = temp.path().join("invalid_key.bin");
        std::fs::write(&invalid_key_path, b"short").expect("write short key");

        let result = NodeIdentity::load_from_file(&invalid_key_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_mnemonic_deterministic_and_slip10_vector() {
        // Standard BIP-39 vector (12 words, all zeros entropy)
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let id1 = NodeIdentity::from_mnemonic(phrase, None).expect("Derive identity 1");
        let id2 = NodeIdentity::from_mnemonic(phrase, None).expect("Derive identity 2");

        // Determinism: same mnemonic phrase always produces the same public key and node_id
        assert_eq!(id1.public_key_hex(), id2.public_key_hex());
        assert_eq!(id1.node_id(), id2.node_id());
        assert_eq!(id1.node_id_hex(), id2.node_id_hex());
        assert_eq!(id1.signing_key().to_bytes(), id2.signing_key().to_bytes());

        // Verify SLIP-0010 Ed25519 test vector matching human-money-core
        assert_eq!(
            id1.public_key_hex(),
            "e96b1c6b8769fdb0b34fbecfdf85c33b053cecad9517e1ab88cba614335775c1"
        );

        // Derivation with passphrase matching human-money-core vector
        let id_pass = NodeIdentity::from_mnemonic(phrase, Some("TREZOR")).expect("Derive with passphrase");
        assert_eq!(
            id_pass.public_key_hex(),
            "8e07aa919abc1427adf010d10467dfba6f1f354b6707916dc9c059771ec13ecd"
        );
        assert_ne!(id1.public_key_hex(), id_pass.public_key_hex());
    }

    #[test]
    fn test_generate_with_mnemonic_and_rederivation() {
        let (id, phrase) = NodeIdentity::generate_with_mnemonic(12).expect("Generate 12-word mnemonic");
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 12);

        // Rederiving from the phrase produces identical keys and node_id
        let rederived = NodeIdentity::from_mnemonic(&phrase, None).expect("Rederive from phrase");
        assert_eq!(id.public_key_hex(), rederived.public_key_hex());
        assert_eq!(id.node_id(), rederived.node_id());
        assert_eq!(id.signing_key().to_bytes(), rederived.signing_key().to_bytes());

        // Invalid word count returns descriptive error
        let bad_count_res = NodeIdentity::generate_with_mnemonic(13);
        assert!(bad_count_res.is_err());
        if let Err(NodeError::Identity(msg)) = bad_count_res {
            assert!(msg.contains("Failed to generate mnemonic"));
        } else {
            panic!("Expected NodeError::Identity");
        }

        // 24-word mnemonic also supported
        let (id24, phrase24) = NodeIdentity::generate_with_mnemonic(24).expect("Generate 24-word mnemonic");
        let words24: Vec<&str> = phrase24.split_whitespace().collect();
        assert_eq!(words24.len(), 24);
        let rederived24 = NodeIdentity::from_mnemonic(&phrase24, None).expect("Rederive 24");
        assert_eq!(id24.public_key_hex(), rederived24.public_key_hex());
    }

    #[test]
    fn test_invalid_mnemonic_phrases_return_descriptive_error() {
        // Unknown words
        let bad_words = "notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let res1 = NodeIdentity::from_mnemonic(bad_words, None);
        assert!(res1.is_err());
        if let Err(NodeError::Identity(msg)) = res1 {
            assert!(msg.contains("Invalid mnemonic phrase"));
        } else {
            panic!("Expected NodeError::Identity");
        }

        // Invalid checksum (last word altered)
        let bad_checksum = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let res2 = NodeIdentity::from_mnemonic(bad_checksum, None);
        assert!(res2.is_err());
        if let Err(NodeError::Identity(msg)) = res2 {
            assert!(msg.contains("Invalid mnemonic phrase"));
        } else {
            panic!("Expected NodeError::Identity");
        }

        // Empty string
        let res3 = NodeIdentity::from_mnemonic("", None);
        assert!(res3.is_err());
    }

    #[test]
    fn test_mnemonic_identity_roundtrip_save_load() {
        let temp = tempdir().expect("tempdir");
        let key_path = temp.path().join("keys/mnemonic_key.bin");

        let (identity, _phrase) = NodeIdentity::generate_with_mnemonic(12).expect("Generate mnemonic");
        identity.save_to_file(&key_path).expect("Save identity");
        assert!(key_path.exists());

        let loaded = NodeIdentity::load_from_file(&key_path).expect("Load identity");
        assert_eq!(identity.node_id(), loaded.node_id());
        assert_eq!(
            identity.verifying_key().as_bytes(),
            loaded.verifying_key().as_bytes()
        );
        assert_eq!(
            identity.signing_key().to_bytes(),
            loaded.signing_key().to_bytes()
        );
        assert_eq!(identity.hrw_routing_id(), loaded.hrw_routing_id());
    }

    #[test]
    fn test_did_key_format() {
        let identity = NodeIdentity::generate();
        let did = identity.did_key();
        assert!(did.starts_with("did:key:z6Mk"), "Ed25519 multicodec did:key should start with did:key:z6Mk, got: {}", did);
    }

    #[test]
    fn test_fast_path_and_work_score() {
        let identity = NodeIdentity::generate();
        assert_eq!(identity.nonce(), 0);
        assert_eq!(identity.t0(), 0);
        assert_eq!(identity.work_score(), 1);
        let expected_blake = *blake3::hash(identity.verifying_key().as_bytes()).as_bytes();
        assert_eq!(*identity.hrw_routing_id(), expected_blake);
    }
}
