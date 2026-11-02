#![forbid(unsafe_code)]

//! # Humoco Simulation Core (`humoco-sim-core`)
//!
//! Deterministic in-memory execution specification and discrete-event simulator
//! for the HuMoCo Layer-2 Collision Lock Registry.
//!
//! ## Invariants & Guarantees:
//! - Zero-I/O: No external system clock access or uncontrolled asynchrony.
//! - Deterministic resolver via `min(H_canon)` with BLAKE3 domain tags.
//! - Mathematical maturity traffic light: `PROVISIONAL` (< 20 nodes) and `FINAL` (>= 20 nodes, >= 14 signatures).
//! - Split-brain resilience and deterministic convergence on network merge.

pub mod client_flow;
pub mod crypto;
pub mod fraud;
pub mod quota;
pub mod resolver;
pub mod storage;
pub mod telemetry;
pub mod types;
pub mod wire;

pub use client_flow::*;
pub use crypto::*;
pub use fraud::{
    compute_heartbeat_digest, verify_heartbeat_signature, verify_heartbeat_signature_strict,
    FraudProofPayload, FraudProofPillar, Heartbeat, HeartbeatSlashingSlot, SlotDetector128,
};
pub use quota::*;
pub use resolver::*;
pub use storage::*;
pub use telemetry::{
    detect_gateway_concentration, detect_shard_operator_dominance,
    evaluate_gateway_concentration_ratio, evaluate_subnet_dominance_max, DiagnosticWarning,
    WarningLevel,
};
pub use types::*;
pub use wire::*;
