# Executed commands (2026-10-25, Europe/Berlin)

Repository baseline reported by the parent: `a41459aa120d730f7f99ea38450780b7a5f2df9d`. Concurrent audit work exists; no clean-tree claim is made for test execution.

- Read `AGENTS.md`, the complete Audit 19 prompt, historical report, current Specs 09/10/13/14, and relevant invariant registry rows.
- Inspected `network/transport.rs`, `network/framing.rs`, `ingress/tier.rs`, `storage/engine.rs`, `humoco-sim-core/src/quota.rs` and `fraud.rs`.
- `rg -l 'QuicTransport|quinn::Endpoint' crates/humoco-node/tests/*.rs` -> quic_test_inventory.txt.
- `rg -n 'FLAG_QUOTA_EXCEEDED|FLAG_QUOTA_FRAUD|evaluate_node_(read|write)_quota' crates/humoco-node/tests/*.rs` -> quota_test_inventory.txt.
- `cargo test -p humoco-node --test phase4_net_time_and_quotas -- --nocapture` -> phase4.log, 8 passed.
- `cargo test -p humoco-node --test anti_self_slashing_wire_tests -- --nocapture` -> anti_self_slashing_wire.log; sandbox UDP bind EPERM, environmental failure, no security conclusion.
- Same command with authorized sandbox escalation for loopback UDP -> anti_self_slashing_wire_unrestricted.log.

No production edit, new probe, attack tool, load generator or temporary integration target was created by Audit 19. Full workspace tests and Clippy are delegated to the parent. Search inventories are discovery aids, not independent proofs of executed network coverage; relevant matches were inspected manually.
