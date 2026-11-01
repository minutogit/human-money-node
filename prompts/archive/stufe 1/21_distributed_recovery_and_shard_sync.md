# Audit 21 — Distributed recovery and shard sync

Date: 2026-10-25. Scope: daemon reconciliation/readiness, engine/recovery.rs, db/install.rs, db/snapshot.rs and framing. Audit only; no fixes applied.

## Findings

**A21-R1 — P2: A safely rejected installation permanently closes node-wide signing.** `crates/humoco-node/src/storage/engine/recovery.rs:163` creates an installation guard with `uncertain = true`, but clears it only on success (`:175`). Its destructor (`:20`) sets global `signing_failed` for every error, including validation failures with a completely rolled-back transaction. There is no normal retry reset.

A temporary external probe reused the real four-peer QUIC recovery fixture: three sources held A; the target retained a conflicting FINAL B. The island cut was correctly rejected as `quorum cut loses native class/hash ordering`; durable B remained intact, but `engine.is_signing_healthy()` became false. Thus an ordinary rejected merge disables unrelated shard signing until restart. Expiry before commit follows the same error path by inspection.

**A21-R2 — P2: Fragmented reconciliation bypasses the claimed memory budget.** `crates/humoco-node/src/daemon.rs:1780` loads complete root/native/HMC vectors, including all valid HMC rows before shard filtering. `:1901` retains full facts and witness sets in HashMaps across all downloaded cuts. Only 512 KiB is reserved at `:1394`; staging limits bound each downloaded database, not aggregate expanded heap allocations or the target's existing database. Up to 32 sync jobs can run. Large fragmented cuts can therefore consume substantially more heap than the shared 8 MiB admission budget. This is a source-confirmed accounting gap; peak RSS/OOM was not experimentally measured.

Verified safeguards: authenticated distinct source keys, per-fact quorum counting, monotonic owner-bound cursors, stage/page caps, atomic multi-table installation, checks before commit and activation, frozen committee revalidation and owned semaphore permits. No partial productive commit was observed on rejected cuts.

Validation: recovery regression suite **3 passed**; cluster sync **10 passed**; inherited support **6 passed**; pull sync/readiness **7 passed**. The additional QUIC probe reproduced A21-R1 with unchanged durable state. These existing tests do not assert node-wide signing health after an ordering rejection.

## Integrated fix plan

1. For R1, distinguish pre-commit rejection, committed-but-unpublished state and unknown worker outcome. Clear uncertainty after a known rolled-back failure; retain fail-closed behavior for cancellation during a running commit and post-commit publication failure. Add real QUIC regressions for ordering rejection and expired leases; assert intact state, healthy unrelated shard signing and successful retry.
2. For R2, replace full-table materialization with bounded paginated scans and disk-backed fact aggregation keyed by canonical identity plus witness bitset. Filter by shard during scanning; cap and reserve any remaining heap buffers before allocation across all simultaneous jobs.
3. Add fragmented QUIC recovery with large source cuts and many unrelated target-shard rows. Verify bounded memory/admission, permit release after cancellation and eventual retry, without weakening per-fact quorum or support qualification.
4. Re-run the four suites, `cargo test-std` and Clippy. Verify cancellation during commit still fails closed and ordinary validation failures do not.

Final shared validation: `cargo test-std` — **722 passed, 0 failed, 14 ignored**; `cargo clippy --workspace --all-targets -- -D warnings` passed. These green checks do not invalidate the separate defect probes above.
