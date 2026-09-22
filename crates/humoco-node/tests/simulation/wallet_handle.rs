//! SimWallet – Ed25519 wallet handle for HMC V3 Wire-DTOs.
//!
//! Provides helpers to generate Genesis / Successor / Chain locks with
//! correct `HMC_TX_AUTH_V3` domain separation and Ed25519 signatures.
//! Uses 100% real production crypto: `ed25519-dalek`, `sha3::Sha3_256`,
//! `bs58`, `blake3`.

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;

use humoco_node::api::hmc::{
    calculate_l2_payload_hash_raw, L2AuthPayload, L2ChainLockRequest, L2LockRequest,
    TRAP_NONE_PLACEHOLDER,
};

/// Lightweight wallet that owns an Ed25519 keypair and can produce
/// HMC V3 lock requests.
#[derive(Debug)]
pub struct SimWallet {
    signing_key: SigningKey,
    /// Hex voucher id used for chain tests; generated lazily.
    default_voucher_id: String,
}

impl SimWallet {
    /// Generates a new random wallet with a fresh Ed25519 keypair.
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut vid_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut vid_bytes);
        let default_voucher_id = hex::encode(vid_bytes);
        Self {
            signing_key,
            default_voucher_id,
        }
    }

    /// Creates a wallet from a given signing key.
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let mut vid_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut vid_bytes);
        let default_voucher_id = hex::encode(vid_bytes);
        Self {
            signing_key,
            default_voucher_id,
        }
    }

    /// Returns the 32-byte Ed25519 public key.
    pub fn pubkey(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Returns the signing key reference.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Returns the default voucher id.
    pub fn voucher_id(&self) -> &str {
        &self.default_voucher_id
    }

    /// Generates a fresh random voucher id (32 hex chars).
    pub fn fresh_voucher_id(&self) -> String {
        let mut b = [0u8; 16];
        OsRng.fill_bytes(&mut b);
        hex::encode(b)
    }

    /// Current wall-clock in ms.
    pub fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Creates a Genesis lock (is_genesis = true) with a fresh t_id.
    /// `voucher_id` may be `None` to use the wallet's default.
    /// `ttl_ms` defaults to 600_000 ms (10 minutes).
    pub fn create_genesis_lock(
        &self,
        voucher_id: Option<&str>,
        ttl_ms: Option<u64>,
    ) -> L2LockRequest {
        let mut rng = OsRng;
        let mut t_id = [0u8; 32];
        rng.fill_bytes(&mut t_id);
        let voucher = voucher_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.default_voucher_id.clone());
        let valid_until_ms = Self::now_ms() + ttl_ms.unwrap_or(600_000);
        let deletable_at = valid_until_ms.to_string();
        let challenge_ds_tag = bs58::encode(&t_id).into_string();
        let sender_pub = self.pubkey();
        let payload_hash = calculate_l2_payload_hash_raw(
            TRAP_NONE_PLACEHOLDER,
            &challenge_ds_tag,
            &t_id,
            &sender_pub,
            TRAP_NONE_PLACEHOLDER,
            TRAP_NONE_PLACEHOLDER,
            0,
            Some(&deletable_at),
            "",
        );
        let sig = self.signing_key.sign(&payload_hash);
        L2LockRequest {
            auth: L2AuthPayload {
                ephemeral_pubkey: sender_pub,
                auth_signature: None,
            },
            layer2_voucher_id: voucher,
            ds_tag: None,
            transaction_hash: t_id,
            is_genesis: true,
            sender_ephemeral_pub: sender_pub,
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: sig.to_bytes(),
            trap_r: Some(TRAP_NONE_PLACEHOLDER.to_string()),
            trap_s: Some(TRAP_NONE_PLACEHOLDER.to_string()),
            encrypted_timestamp: 0,
            deletable_at: Some(deletable_at),
            privacy_guard: None,
        }
    }

    /// Creates a successor (is_genesis = false) that spends `parent_ds_tag`.
    /// Uses a fresh random t_id.
    pub fn create_successor_lock(
        &self,
        voucher_id: &str,
        parent_ds_tag: &str,
    ) -> L2LockRequest {
        let mut rng = OsRng;
        let mut t_id = [0u8; 32];
        rng.fill_bytes(&mut t_id);
        let sender_pub = self.pubkey();
        let payload_hash = calculate_l2_payload_hash_raw(
            voucher_id,
            parent_ds_tag,
            &t_id,
            &sender_pub,
            TRAP_NONE_PLACEHOLDER,
            TRAP_NONE_PLACEHOLDER,
            0,
            None,
            "",
        );
        let sig = self.signing_key.sign(&payload_hash);
        L2LockRequest {
            auth: L2AuthPayload {
                ephemeral_pubkey: sender_pub,
                auth_signature: None,
            },
            layer2_voucher_id: voucher_id.to_string(),
            ds_tag: Some(parent_ds_tag.to_string()),
            transaction_hash: t_id,
            is_genesis: false,
            sender_ephemeral_pub: sender_pub,
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: sig.to_bytes(),
            trap_r: Some(TRAP_NONE_PLACEHOLDER.to_string()),
            trap_s: Some(TRAP_NONE_PLACEHOLDER.to_string()),
            encrypted_timestamp: 0,
            deletable_at: None,
            privacy_guard: None,
        }
    }

    /// Creates a chain lock request that contains `count` sequential successor hops
    /// starting from `parent_ds_tag`. Each hop gets a strictly increasing
    /// `encrypted_timestamp` (monotonicity requirement).
    pub fn create_chain_locks(
        &self,
        voucher_id: &str,
        parent_ds_tag: &str,
        count: usize,
    ) -> L2ChainLockRequest {
        assert!(count > 0, "chain must have at least one hop");
        let mut rng = OsRng;
        let sender_pub = self.pubkey();
        let mut chain = Vec::with_capacity(count);
        let mut current_parent = parent_ds_tag.to_string();
        for i in 0..count {
            let mut t_id = [0u8; 32];
            rng.fill_bytes(&mut t_id);
            let ts = (i as u128) + 1;
            let payload_hash = calculate_l2_payload_hash_raw(
                voucher_id,
                &current_parent,
                &t_id,
                &sender_pub,
                TRAP_NONE_PLACEHOLDER,
                TRAP_NONE_PLACEHOLDER,
                ts,
                None,
                "",
            );
            let sig = self.signing_key.sign(&payload_hash);
            let req = L2LockRequest {
                auth: L2AuthPayload {
                    ephemeral_pubkey: sender_pub,
                    auth_signature: None,
                },
                layer2_voucher_id: voucher_id.to_string(),
                ds_tag: Some(current_parent.clone()),
                transaction_hash: t_id,
                is_genesis: false,
                sender_ephemeral_pub: sender_pub,
                receiver_ephemeral_pub_hash: None,
                change_ephemeral_pub_hash: None,
                layer2_signature: sig.to_bytes(),
                trap_r: Some(TRAP_NONE_PLACEHOLDER.to_string()),
                trap_s: Some(TRAP_NONE_PLACEHOLDER.to_string()),
                encrypted_timestamp: ts,
                deletable_at: None,
                privacy_guard: None,
            };
            current_parent = bs58::encode(&t_id).into_string();
            chain.push(req);
        }
        L2ChainLockRequest {
            auth: L2AuthPayload {
                ephemeral_pubkey: sender_pub,
                auth_signature: None,
            },
            layer2_voucher_id: voucher_id.to_string(),
            chain,
        }
    }

    /// Creates a genesis lock and returns both the voucher id and the request.
    pub fn genesis_with_voucher(&self, ttl_ms: Option<u64>) -> (String, L2LockRequest) {
        let voucher = self.fresh_voucher_id();
        let req = self.create_genesis_lock(Some(&voucher), ttl_ms);
        (voucher, req)
    }

    /// Helper to compute the lookup tag (ds_tag / challenge) for a given t_id.
    pub fn t_id_to_tag(t_id: &[u8; 32]) -> String {
        bs58::encode(t_id).into_string()
    }
}

impl Default for SimWallet {
    fn default() -> Self {
        Self::new()
    }
}
