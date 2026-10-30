//! Separate, versioned L2 output commitment. L1 transaction/SST bytes are immutable.
use serde::{Deserialize, Serialize};
/// A transaction author authenticates blind output commitments for subsequent
/// causal admission. The recipient independently checks this sidecar against L1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalOutputProof {
    /// Encoding version, currently one.
    pub version: u8,
    /// Blind voucher domain identifier.
    pub voucher_id: String,
    /// The L1 transaction identifier authenticated by its author.
    pub transaction_id: [u8; 32],
    /// SHA3-256 of the complete canonical L1 transaction (the next prev_hash).
    pub state_hash: [u8; 32],
    /// Author of this output commitment, matching the L1 ephemeral sender.
    pub sender_pubkey: [u8; 32],
    /// SHA3-256 commitment to the receiver output owner.
    pub receiver_pubkey_hash: Option<[u8; 32]>,
    /// Independent SHA3-256 commitment to the change output owner.
    pub change_pubkey_hash: Option<[u8; 32]>,
    /// Immutable monetary validity of the voucher root.
    pub root_valid_until_ms: u64,
    /// True for a root anchor, which is never a spend.
    pub is_root: bool,
    #[serde(with = "crate::types::serde_bytes_64")]
    /// Author signature in the separate L2 output purpose.
    pub signature: [u8; 64],
}
impl CausalOutputProof {
    /// Canonical length-prefixed L2 signing digest; no L1/SST bytes change.
    pub fn digest(&self) -> Result<[u8; 32], &'static str> {
        if self.version != 1 || self.voucher_id.len() > 256 || self.root_valid_until_ms == 0 {
            return Err("invalid causal output context");
        }
        let mut h = blake3::Hasher::new();
        let tag = b"HUMOCO_V1_CAUSAL_OUTPUT";
        h.update(&[tag.len() as u8]);
        h.update(tag);
        h.update(&[self.version, u8::from(self.is_root)]);
        h.update(&(self.voucher_id.len() as u16).to_le_bytes());
        h.update(self.voucher_id.as_bytes());
        h.update(&self.transaction_id);
        h.update(&self.state_hash);
        h.update(&self.sender_pubkey);
        h.update(&self.root_valid_until_ms.to_le_bytes());
        for hash in [self.receiver_pubkey_hash, self.change_pubkey_hash] {
            match hash {
                Some(hash) => {
                    h.update(&[1]);
                    h.update(&hash);
                }
                None => {
                    h.update(&[0]);
                }
            }
        }
        Ok(*h.finalize().as_bytes())
    }
    /// Verify the output author signature, without treating it as a node vote.
    pub fn verify(&self) -> bool {
        let (Ok(digest), Ok(key)) = (
            self.digest(),
            ed25519_dalek::VerifyingKey::from_bytes(&self.sender_pubkey),
        ) else {
            return false;
        };
        key.verify_strict(
            &digest,
            &ed25519_dalek::Signature::from_bytes(&self.signature),
        )
        .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    #[test]
    fn versioned_output_commitment_binds_every_causal_field() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut proof = CausalOutputProof {
            version: 1,
            voucher_id: "voucher".into(),
            transaction_id: [1; 32],
            state_hash: [2; 32],
            sender_pubkey: key.verifying_key().to_bytes(),
            receiver_pubkey_hash: Some([3; 32]),
            change_pubkey_hash: Some([4; 32]),
            root_valid_until_ms: 50_000,
            is_root: true,
            signature: [0; 64],
        };
        proof.signature = key.sign(&proof.digest().unwrap()).to_bytes();
        assert!(proof.verify());
        for field in 0..8 {
            let mut changed = proof.clone();
            match field {
                0 => changed.version = 2,
                1 => changed.voucher_id.push('x'),
                2 => changed.transaction_id[0] ^= 1,
                3 => changed.state_hash[0] ^= 1,
                4 => changed.receiver_pubkey_hash = None,
                5 => changed.change_pubkey_hash = None,
                6 => changed.root_valid_until_ms += 1,
                _ => changed.is_root = false,
            }
            assert!(!changed.verify(), "field {field} must be authenticated");
        }
    }
}
