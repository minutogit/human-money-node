use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

use crate::identity::NodeIdentity;

macro_rules! impl_base58_array {
    ($mod_name:ident, $N:literal) => {
        pub mod $mod_name {
            use serde::{de, Deserialize, Deserializer, Serializer};
            use std::convert::TryInto;

            pub fn serialize<S>(data: &[u8; $N], serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&bs58::encode(data).into_string())
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; $N], D::Error>
            where
                D: Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                let vec = bs58::decode(s).into_vec().map_err(de::Error::custom)?;
                vec.try_into()
                    .map_err(|_| de::Error::custom(concat!("Length mismatch, expected ", stringify!($N), " bytes")))
            }
        }
    };
    ($mod_name:ident, $N:literal, opt) => {
        pub mod $mod_name {
            use serde::{de, Deserialize, Deserializer, Serializer};
            use std::convert::TryInto;

            pub fn serialize<S>(data: &Option<[u8; $N]>, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                match data {
                    Some(d) => serializer.serialize_str(&bs58::encode(d).into_string()),
                    None => serializer.serialize_none(),
                }
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; $N]>, D::Error>
            where
                D: Deserializer<'de>,
            {
                let s: Option<String> = Option::deserialize(deserializer)?;
                match s {
                    Some(s) => {
                        let vec = bs58::decode(s).into_vec().map_err(de::Error::custom)?;
                        let arr: [u8; $N] = vec
                            .try_into()
                            .map_err(|_| de::Error::custom(concat!("Length mismatch, expected ", stringify!($N), " bytes")))?;
                        Ok(Some(arr))
                    }
                    None => Ok(None),
                }
            }
        }
    };
}

impl_base58_array!(base58_32, 32);
impl_base58_array!(base58_32_opt, 32, opt);
impl_base58_array!(base58_64, 64);
impl_base58_array!(base58_64_opt, 64, opt);

pub mod base58_u128 {
    use serde::{de, Deserialize, Deserializer, Serializer};
    use std::convert::TryInto;

    pub fn serialize<S>(data: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&bs58::encode(data.to_le_bytes()).into_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = bs58::decode(s).into_vec().map_err(de::Error::custom)?;
        let arr: [u8; 16] = vec
            .try_into()
            .map_err(|_| de::Error::custom("Length mismatch, expected 16 bytes"))?;
        Ok(u128::from_le_bytes(arr))
    }
}

/// Preparation for future anti-spam / Sybil access control.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct L2AuthPayload {
    #[serde(with = "base58_32")]
    pub ephemeral_pubkey: [u8; 32],
    #[serde(with = "base58_64_opt", default)]
    pub auth_signature: Option<[u8; 64]>,
}

/// Request: Anchor a voucher (genesis) or a transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2LockRequest {
    pub auth: L2AuthPayload,
    pub layer2_voucher_id: String,
    pub ds_tag: Option<String>,

    #[serde(with = "base58_32")]
    pub transaction_hash: [u8; 32],
    pub is_genesis: bool,
    #[serde(with = "base58_32")]
    pub sender_ephemeral_pub: [u8; 32],

    #[serde(with = "base58_32_opt", default)]
    pub receiver_ephemeral_pub_hash: Option<[u8; 32]>,

    #[serde(with = "base58_32_opt", default)]
    pub change_ephemeral_pub_hash: Option<[u8; 32]>,

    #[serde(with = "base58_64")]
    pub layer2_signature: [u8; 64],

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap_r: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap_s: Option<String>,

    #[serde(with = "base58_u128", default)]
    pub encrypted_timestamp: u128,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletable_at: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_guard: Option<String>,
}

/// Data structure for a single lock entry on Layer 2.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct L2LockEntry {
    pub layer2_voucher_id: String,
    #[serde(with = "base58_32")]
    pub t_id: [u8; 32],
    #[serde(with = "base58_32")]
    pub sender_ephemeral_pub: [u8; 32],
    #[serde(with = "base58_32_opt", default)]
    pub receiver_ephemeral_pub_hash: Option<[u8; 32]>,
    #[serde(with = "base58_32_opt", default)]
    pub change_ephemeral_pub_hash: Option<[u8; 32]>,
    #[serde(with = "base58_64")]
    pub layer2_signature: [u8; 64],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap_r: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap_s: Option<String>,
    #[serde(with = "base58_u128", default)]
    pub encrypted_timestamp: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletable_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_guard: Option<String>,
}

impl From<&L2LockRequest> for L2LockEntry {
    fn from(req: &L2LockRequest) -> Self {
        Self {
            layer2_voucher_id: req.layer2_voucher_id.clone(),
            t_id: req.transaction_hash,
            sender_ephemeral_pub: req.sender_ephemeral_pub,
            receiver_ephemeral_pub_hash: req.receiver_ephemeral_pub_hash,
            change_ephemeral_pub_hash: req.change_ephemeral_pub_hash,
            layer2_signature: req.layer2_signature,
            trap_r: req.trap_r.clone(),
            trap_s: req.trap_s.clone(),
            encrypted_timestamp: req.encrypted_timestamp,
            deletable_at: req.deletable_at.clone(),
            privacy_guard: req.privacy_guard.clone(),
        }
    }
}

fn default_read_quorum() -> u8 {
    1
}

/// Request: Query the state of a voucher and reconcile transaction history.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2StatusQuery {
    pub auth: L2AuthPayload,
    pub layer2_voucher_id: String,
    pub challenge_ds_tag: String,
    pub locator_prefixes: Vec<String>,
    #[serde(default = "default_read_quorum")]
    pub read_quorum: u8,
}

/// Atomares Ketten-Locking: Batch of HMC locks that must be committed or rejected atomically.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2ChainLockRequest {
    pub auth: L2AuthPayload,
    pub layer2_voucher_id: String,
    pub chain: Vec<L2LockRequest>,
}

/// Response: The verdict of the L2 server regarding the state of a tag or the chain.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
#[serde(tag = "type")]
pub enum L2Verdict {
    Verified {
        lock_entry: L2LockEntry,
    },
    Conflict {
        existing_lock: L2LockEntry,
    },
    MissingLocks {
        sync_point: String,
    },
    UnknownVoucher,
    #[serde(rename = "Ok")]
    Ok {
        #[serde(with = "base58_64")]
        signature: [u8; 64],
    },
    Rejected {
        reason: String,
    },
}

/// Envelope for all L2 server responses.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2ResponseEnvelope {
    pub verdict: L2Verdict,
    #[serde(with = "base58_64")]
    pub server_signature: [u8; 64],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quorum_certificate: Option<crate::api::dto::QuorumCertificateDto>,
}

// =============================================================================
// V3 Cryptography & Hashing Helpers
// =============================================================================

pub const HMC_TX_AUTH_V3_DOMAIN: &[u8] = b"HMC_TX_AUTH_V3";
pub const TRAP_NONE_PLACEHOLDER: &str = "none";

/// Computes a SHA3-256 hash with 4-byte LE length prefix for each slice.
pub fn get_raw_hash_from_slices(inputs: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for input in inputs {
        hasher.update((input.len() as u32).to_le_bytes());
        hasher.update(input);
    }
    let hash_bytes = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash_bytes);
    out
}

/// Computes a SHA3-256 hash of input and returns it as a Base58 string.
pub fn get_hash(input: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(input.as_ref());
    let hash_bytes = hasher.finalize();
    bs58::encode(hash_bytes).into_string()
}

/// Canonical commitment of a transaction's privacy_guard.
pub fn privacy_guard_commitment(privacy_guard: Option<&str>) -> String {
    match privacy_guard {
        Some(guard) if !guard.is_empty() => get_hash(guard.as_bytes()),
        _ => String::new(),
    }
}

/// Inner logic for hashing the L2 payload (canonical V3 definition).
#[allow(clippy::too_many_arguments)]
pub fn calculate_l2_payload_hash_raw(
    layer2_voucher_id: &str,
    challenge_ds_tag: &str,
    t_id_bytes: &[u8; 32],
    sender_pub_bytes: &[u8; 32],
    trap_r_str: &str,
    trap_s_str: &str,
    encrypted_timestamp: u128,
    deletable_at: Option<&str>,
    privacy_guard_commitment: &str,
) -> [u8; 32] {
    get_raw_hash_from_slices(&[
        HMC_TX_AUTH_V3_DOMAIN,
        layer2_voucher_id.as_bytes(),
        challenge_ds_tag.as_bytes(),
        t_id_bytes,
        sender_pub_bytes,
        trap_r_str.as_bytes(),
        trap_s_str.as_bytes(),
        &encrypted_timestamp.to_le_bytes(),
        deletable_at.unwrap_or("").as_bytes(),
        privacy_guard_commitment.as_bytes(),
    ])
}

/// Computes the V3 payload hash for an L2LockRequest.
pub fn calculate_l2_payload_hash(req: &L2LockRequest) -> [u8; 32] {
    let challenge_ds_tag = if req.is_genesis {
        bs58::encode(req.transaction_hash).into_string()
    } else {
        req.ds_tag.clone().unwrap_or_default()
    };

    let effective_voucher_id = if req.is_genesis {
        TRAP_NONE_PLACEHOLDER
    } else {
        req.layer2_voucher_id.as_str()
    };

    calculate_l2_payload_hash_raw(
        effective_voucher_id,
        &challenge_ds_tag,
        &req.transaction_hash,
        &req.sender_ephemeral_pub,
        req.trap_r.as_deref().unwrap_or(TRAP_NONE_PLACEHOLDER),
        req.trap_s.as_deref().unwrap_or(TRAP_NONE_PLACEHOLDER),
        req.encrypted_timestamp,
        req.deletable_at.as_deref(),
        privacy_guard_commitment(req.privacy_guard.as_deref()).as_str(),
    )
}

/// Verifies the V3 Ed25519 signature of an L2LockRequest.
pub fn verify_l2_lock_signature(req: &L2LockRequest) -> bool {
    let verifying_key = match VerifyingKey::from_bytes(&req.sender_ephemeral_pub) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&req.layer2_signature);
    let payload_hash = calculate_l2_payload_hash(req);
    verifying_key.verify(&payload_hash, &sig).is_ok()
}

/// Verifies the V3 Ed25519 signature of an L2LockEntry against its lookup tag (challenge_ds_tag).
pub fn verify_l2_lock_entry_signature(entry: &L2LockEntry, lookup_tag: &str) -> bool {
    let verifying_key = match VerifyingKey::from_bytes(&entry.sender_ephemeral_pub) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&entry.layer2_signature);
    let payload_hash = calculate_l2_payload_hash_raw(
        &entry.layer2_voucher_id,
        lookup_tag,
        &entry.t_id,
        &entry.sender_ephemeral_pub,
        entry.trap_r.as_deref().unwrap_or(TRAP_NONE_PLACEHOLDER),
        entry.trap_s.as_deref().unwrap_or(TRAP_NONE_PLACEHOLDER),
        entry.encrypted_timestamp,
        entry.deletable_at.as_deref(),
        privacy_guard_commitment(entry.privacy_guard.as_deref()).as_str(),
    );
    verifying_key.verify(&payload_hash, &sig).is_ok()
}

/// Wraps a verdict into an L2ResponseEnvelope signed with the node identity.
pub fn wrap_and_sign_verdict(identity: &NodeIdentity, verdict: L2Verdict) -> L2ResponseEnvelope {
    wrap_and_sign_verdict_with_quorum(identity, verdict, None)
}

/// Wraps a verdict and an optional QuorumCertificate into an L2ResponseEnvelope signed with the node identity.
pub fn wrap_and_sign_verdict_with_quorum(
    identity: &NodeIdentity,
    verdict: L2Verdict,
    quorum_certificate: Option<crate::api::dto::QuorumCertificateDto>,
) -> L2ResponseEnvelope {
    let serialized = serde_json::to_vec(&verdict).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&serialized);
    let digest = hasher.finalize();

    let signature = identity.signing_key().sign(&digest);

    L2ResponseEnvelope {
        verdict,
        server_signature: signature.to_bytes(),
        quorum_certificate,
    }
}
