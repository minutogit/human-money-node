# Audit 23 — Dual-tier concurrency and signing history

Date: 2026-10-25. Scope: engine.rs, db.rs, db/signing.rs, api/hmc.rs and original-approval release paths. Audit only; no fixes applied.

## Finding

**A23-R1 — P2: Runtime integrity checks miss structurally valid signing-history replacement.** `crates/humoco-node/src/storage/db.rs:327` checks row count, decoding, generation ceiling and TTL membership, but never compares the retained row with an independently stored integrity commitment. `db/signing.rs:133` XORs the already modified old row out of the fingerprint without verifying it. Startup verification detects the resulting mismatch only after restart.

Reproduction with a temporary external Rust probe: commit native choice A; replace its JSON row with child B and empty approvals, preserving generation, expiry and table cardinality; replace the collision state with B (representing subsequent canonical replacement); call `commit_original_record_approval` for B. Result: `Ok(approval-B)`, signing health remains true. This establishes a runtime integrity failure under logical storage corruption, not a remotely demonstrated double signature. The existing loss/malformed-row tests do not cover valid row substitution.

Verified safeguards: reservation precedes RAM mutation; original approvals await immediate durable transactions; worker commits run in `spawn_blocking`; pending acceptance remains non-authoritative after an unavailable acknowledgement. No additional confirmed defect in those paths. The sub-20 ms SLA was not benchmarked.

Validation: `cargo test -p humoco-node --test audit23_regressions --test storage_tests`: **13 passed** including real QUIC. Initial sandbox execution denied UDP binding; the unrestricted rerun passed. The external corruption probe reproduced the finding.

## Integrated fix plan

1. Add regressions for valid JSON replacement of child, approvals and generation while keeping cardinality and TTL unchanged. Require `SigningHistoryCorrupt`, a durable latch and no contradictory approval.
2. Maintain an independent per-slot commitment atomically with choices, TTL and aggregate state. Verify it before exact retries, replacement, pruning and release. Detect missing commitments as corruption; define safe legacy migration explicitly. A full-table fingerprint recomputation on every checkout would violate the intended latency profile.
3. Extend backup/startup/pruning handling for these commitments and keep the corruption latch permanent. Apply the same validation to HMC and native decisions.
4. Add a real QUIC fault-injection regression showing that a previously attested A cannot be followed by a valid B attestation after semantic row replacement. Verify healthy retries, expiry and restart, then run `cargo test-std` and Clippy. Benchmark durable latency separately.

Final shared validation: `cargo test-std` — **722 passed, 0 failed, 14 ignored**; `cargo clippy --workspace --all-targets -- -D warnings` passed. These green checks do not invalidate the separate defect probes above.
