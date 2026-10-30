#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # humoco-proto
//! Canonical wire formats, domain separators, and zero-trust receipt verifiers
//! for the HuMoCo Layer 2 Collision Lock Registry.

pub mod crypto;
pub mod live;
pub mod types;
pub mod verify;

pub use crypto::*;
pub use types::*;
pub use verify::*;

/// Recipient-configured signed regional mesh views.
pub mod mesh;

pub mod causal;
