//! Wire protocol types and data transfer objects for HuMoCo Layer 2.

use serde::{Deserialize, Serialize};

/// Identifier for a network shard.
pub type ShardId = u16;

/// 32-byte Ed25519 public key identifying a validator/shard node.
pub type NodePubKey = [u8; 32];

/// 64-byte Ed25519 signature payload.
pub type SignatureBytes = [u8; 64];

/// Custom serializer and deserializer for 64-byte fixed-size arrays.
pub mod serde_bytes_64 {
    use serde::{de::Error, Deserializer, Serializer};

    /// Serializes a 64-byte array as raw bytes.
    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    /// Deserializes a 64-byte array from raw bytes or a sequence of bytes.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a byte array of length 64")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                if v.len() == 64 {
                    let mut arr = [0u8; 64];
                    arr.copy_from_slice(v);
                    Ok(arr)
                } else {
                    Err(E::custom(format!("expected 64 bytes, got {}", v.len())))
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut arr = [0u8; 64];
                for item in &mut arr {
                    *item = seq
                        .next_element()?
                        .ok_or_else(|| Error::custom("expected 64 elements"))?;
                }
                Ok(arr)
            }
        }

        deserializer.deserialize_bytes(Visitor)
    }
}

/// A single attestation vote signed by a shard committee member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationVote {
    /// Public key of the node that created this attestation.
    pub signer_pubkey: NodePubKey,
    /// Ed25519 signature bytes.
    #[serde(with = "serde_bytes_64")]
    pub signature: SignatureBytes,
}

/// A cryptographic quorum proof consisting of aggregated votes from shard committee members.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumProof {
    /// The shard identifier responsible for this quorum.
    pub shard_id: ShardId,
    /// List of attestation votes from committee nodes.
    pub votes: Vec<AttestationVote>,
}

/// Verdict returned by Layer 2 for a lock operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum L2Verdict {
    /// Lock was successfully registered with a valid quorum proof.
    Confirmed {
        /// Quorum proof validating the lock confirmation.
        proof: QuorumProof,
    },
    /// Lock was rejected due to a conflict with an existing tag.
    Conflict {
        /// Lookup tag of the conflicting existing lock.
        existing_tag: [u8; 32],
    },
    /// Request was rejected with a reason.
    Rejected {
        /// Human-readable or machine-parsable rejection reason.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_vote_bincode_roundtrip() {
        let vote = AttestationVote {
            signer_pubkey: [7u8; 32],
            signature: [42u8; 64],
        };

        let encoded = bincode::serialize(&vote).expect("serialization failed");
        let decoded: AttestationVote =
            bincode::deserialize(&encoded).expect("deserialization failed");
        assert_eq!(vote, decoded);
    }

    #[test]
    fn test_quorum_proof_bincode_roundtrip() {
        let proof = QuorumProof {
            shard_id: 3,
            votes: vec![
                AttestationVote {
                    signer_pubkey: [1u8; 32],
                    signature: [11u8; 64],
                },
                AttestationVote {
                    signer_pubkey: [2u8; 32],
                    signature: [22u8; 64],
                },
            ],
        };

        let encoded = bincode::serialize(&proof).expect("serialization failed");
        let decoded: QuorumProof = bincode::deserialize(&encoded).expect("deserialization failed");
        assert_eq!(proof, decoded);
    }

    #[test]
    fn test_l2_verdict_roundtrip() {
        let proof = QuorumProof {
            shard_id: 5,
            votes: vec![AttestationVote {
                signer_pubkey: [9u8; 32],
                signature: [8u8; 64],
            }],
        };

        let confirmed = L2Verdict::Confirmed { proof };
        let conflict = L2Verdict::Conflict {
            existing_tag: [0xaa; 32],
        };
        let rejected = L2Verdict::Rejected {
            reason: "rate limited".to_string(),
        };

        for verdict in [&confirmed, &conflict, &rejected] {
            let encoded = bincode::serialize(verdict).expect("serialization failed");
            let decoded: L2Verdict =
                bincode::deserialize(&encoded).expect("deserialization failed");
            assert_eq!(*verdict, decoded);
        }
    }
}
