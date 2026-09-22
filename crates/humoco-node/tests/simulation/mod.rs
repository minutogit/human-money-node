//! Modular MeshSimulator Test-Framework
//!
//! Re-exports all simulation sub-modules for ergonomic `mod simulation;` usage
//! in integration tests. Uses 100% real production components.

#![allow(dead_code, unused_imports)]

pub mod diagnostic;
pub mod node_handle;
pub mod reporter;
pub mod simulator;
pub mod time;
pub mod topology;
pub mod wallet_handle;

pub use diagnostic::{DiagnosticEntry, DiagnosticLevel, DiagnosticReporter};
pub use node_handle::{SimNodeHandle, SIM_F2F_TOKEN};
pub use reporter::Reporter;
pub use simulator::MeshSimulator;
pub use time::SimTimeController;
pub use topology::{chain_peer_lists, f2f_peer_string, Topology};
pub use wallet_handle::SimWallet;
