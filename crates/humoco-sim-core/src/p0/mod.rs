//! Executable P0 research model; not a production wire implementation.
//!
//! Ed25519 proofs are real. Argon work validation, authenticated heartbeat/probe
//! delivery, trusted clock and durable-commit acknowledgments are explicit injected
//! simulation boundaries. No network security or physical fsync is established here.

mod admission;
mod collection;
mod evidence;
mod state;

pub use admission::*;
pub use collection::*;
pub use evidence::*;
pub use state::*;

pub type Id = [u8; 32];
pub type Key = [u8; 32];
pub const HOUR_MS: u64 = 3_600_000;
pub const DAY_MS: u64 = 24 * HOUR_MS;
pub const LEASE_MS: u64 = 120_000;
pub const VIEW_MS: u64 = 30_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Signature,
    WrongNetwork,
    UnknownAdmission,
    ForeignFriend,
    InvalidWork,
    Immature,
    InvalidTicket,
    Stale,
    NotStable,
    UnknownView,
    WrongView,
    Duplicate,
    Quorum,
    UnknownRoot,
    UnknownAncestry,
    InvalidOwner,
    InvalidIntent,
    Expired,
    NotReady,
    Capacity,
    Conflict,
    NoWinner,
    InvalidEvidence,
    TimeRollback,
}

pub(crate) fn hash(domain: &[u8], bytes: &[u8]) -> Id {
    let mut h = blake3::Hasher::new();
    // All model domains below are fixed literals shorter than 256 bytes.
    h.update(&[domain.len() as u8]);
    h.update(domain);
    h.update(bytes);
    *h.finalize().as_bytes()
}

pub(crate) fn bytes(domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(domain.len() + payload.len() + 1);
    b.push(domain.len() as u8);
    b.extend_from_slice(domain);
    b.extend_from_slice(payload);
    b
}

/// There is deliberately no accepted global-proof scheme in baseline P0.
pub fn can_display_global() -> bool {
    false
}
