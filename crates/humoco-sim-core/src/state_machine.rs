use crate::crypto::verify_attestation;
use crate::types::{
    required_quorum, Attestation, Hash256, LockRecord, LockStatus, NodeId, SimTime,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateError {
    InvalidSignature,
    LockExpired {
        current_time: SimTime,
        valid_until: SimTime,
    },
    LockAlreadyVoid {
        reason: String,
    },
    DuplicateAttestation {
        node_id: NodeId,
    },
    LockIdMismatch,
    ParentAlreadyLocked {
        parent_lock: Hash256,
        existing_lock_id: Hash256,
    },
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateError::InvalidSignature => write!(f, "Invalid attestation signature"),
            StateError::LockExpired {
                current_time,
                valid_until,
            } => {
                write!(
                    f,
                    "Lock expired (current: {}, valid_until: {})",
                    current_time, valid_until
                )
            }
            StateError::LockAlreadyVoid { reason } => write!(f, "Lock already void: {}", reason),
            StateError::DuplicateAttestation { node_id } => {
                write!(f, "Duplicate attestation from node {}", node_id)
            }
            StateError::LockIdMismatch => write!(f, "Attestation lock_id does not match record"),
            StateError::ParentAlreadyLocked {
                parent_lock,
                existing_lock_id,
            } => {
                write!(
                    f,
                    "409 Conflict: parent_lock {:?} already locked by {:?}",
                    parent_lock, existing_lock_id
                )
            }
        }
    }
}

impl std::error::Error for StateError {}

/// Applies an attestation to a LockRecord and updates the maturity traffic light (default: hysteresis satisfied)
pub fn apply_attestation(
    record: &mut LockRecord,
    attestation: Attestation,
    active_nodes: usize,
) -> Result<LockStatus, StateError> {
    apply_attestation_with_hysteresis(record, attestation, active_nodes, true)
}

/// Applies an attestation to a LockRecord respecting the 24h network-stability hysteresis (INV-0802)
pub fn apply_attestation_with_hysteresis(
    record: &mut LockRecord,
    attestation: Attestation,
    active_nodes: usize,
    hysteresis_stable: bool,
) -> Result<LockStatus, StateError> {
    if record.id != attestation.lock_id {
        return Err(StateError::LockIdMismatch);
    }

    if let LockStatus::Void { ref reason } = record.status {
        return Err(StateError::LockAlreadyVoid {
            reason: reason.clone(),
        });
    }

    if attestation.timestamp > record.valid_until {
        return Err(StateError::LockExpired {
            current_time: attestation.timestamp,
            valid_until: record.valid_until,
        });
    }

    if !verify_attestation(&attestation) {
        return Err(StateError::InvalidSignature);
    }

    if !record.signers.insert(attestation.node_id) {
        return Err(StateError::DuplicateAttestation {
            node_id: attestation.node_id,
        });
    }

    let sigs = record.signers.len();
    let (required, is_final_threshold) = required_quorum(active_nodes);

    if is_final_threshold {
        if sigs >= required {
            if hysteresis_stable {
                record.status = LockStatus::Final { sigs };
            } else {
                record.status = LockStatus::Provisional { sigs, required };
            }
        } else {
            record.status = LockStatus::Pending;
        }
    } else {
        if sigs >= required {
            record.status = LockStatus::Provisional { sigs, required };
        } else {
            record.status = LockStatus::Pending;
        }
    }

    Ok(record.status.clone())
}

/// Promotes a PROVISIONAL lock to FINAL once the global threshold (N >= 20, sigs >= 14) is met
pub fn promote_to_final_if_eligible(
    record: &mut LockRecord,
    active_nodes: usize,
) -> Result<bool, StateError> {
    promote_to_final_if_eligible_with_hysteresis(record, active_nodes, true)
}

/// Promotes a PROVISIONAL lock to FINAL once the global threshold (N >= 20, sigs >= 14) and 24h hysteresis are met (INV-0206)
pub fn promote_to_final_if_eligible_with_hysteresis(
    record: &mut LockRecord,
    active_nodes: usize,
    hysteresis_stable: bool,
) -> Result<bool, StateError> {
    if let LockStatus::Void { ref reason } = record.status {
        return Err(StateError::LockAlreadyVoid {
            reason: reason.clone(),
        });
    }

    if let LockStatus::Final { .. } = record.status {
        return Ok(true); // Already FINAL (idempotent)
    }

    let (required, is_final_threshold) = required_quorum(active_nodes);
    let sigs = record.signers.len();

    if is_final_threshold && sigs >= required && hysteresis_stable {
        record.status = LockStatus::Final { sigs };
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Verifies a FraudProofPayload statelessly (<100µs)
pub fn verify_fraud_proof(proof: &crate::fraud::FraudProofPayload) -> bool {
    proof.verify()
}

/// Verifies and bans the perpetrator in O(1) via banned_nodes set
pub fn apply_fraud_proof(
    proof: &crate::fraud::FraudProofPayload,
    banned_nodes: &mut std::collections::HashSet<NodeId>,
) -> bool {
    if !proof.verify() {
        return false;
    }
    banned_nodes.insert(proof.perpetrator);
    let pk_nid = u16::from_le_bytes([proof.perpetrator_node_id[0], proof.perpetrator_node_id[1]]);
    if pk_nid != proof.perpetrator {
        banned_nodes.insert(pk_nid);
    }
    true
}
