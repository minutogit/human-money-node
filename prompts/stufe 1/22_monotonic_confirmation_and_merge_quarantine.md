# Audit 22 — Confirmation classes and merge quarantine

Date: 2026-10-25. Scope: resolver.rs, types.rs, db/support.rs, db/install.rs, database pruning and RAM support publication. Audit only; no fixes applied.

## Finding

**A22-R1 — P3: Lock pruning rounds the required grace horizon down.** `crates/humoco-node/src/storage/db.rs:434`, `:947`, `:999`, `:1028` and `storage/db/install.rs:533`/`:554` derive TTL buckets using `(root_valid_until + 30_000) / 1000`. Both pruning implementations (`db.rs:520`, `:1140`) delete active/provisional entries and support solely from that bucket, without checking the precise horizon. The new voucher-root pruner rounds up correctly, so roots and their lock rows can disagree.

A temporary external Rust probe stored a native lock with root expiry **50,001 ms** and called `prune_expired_buckets(80)`: the row was already absent at **80,000 ms**, although its 30-second grace ends at **80,001 ms**. Early deletion can reach 999 ms. This concerns retention after expiry; no acceptance of an expired spend or live double-spend is demonstrated. Installed/quarantined rows use the same rounded-down indexing scheme; that extension is established by source inspection, not a new wire reproduction.

Verified safeguards: class-first comparison and deterministic native ID tie-breaker; distinct authenticated support witnesses; quorum-qualified inherited support; atomic quarantine with installation; monotonic RAM publication for the same child. No further confirmed violation of these filters.

Validation: `cargo test -p humoco-node --test audit22_regressions`: **6 passed**, including real QUIC convergence and root metadata expiry boundaries. The external native-row probe reproduced A22-R1. Existing fractional-second tests cover root metadata, not collision-row retention.

## Integrated fix plan

1. Add boundary regressions for native/HMC active rows, quarantined copies and their support at `expiry + 30s - 1ms`, the precise horizon and the first representable pruning second. Exercise both public pruning and batch pruning, plus snapshot installation.
2. Centralize ceiling conversion, matching root/signing-choice indexing: `expiry.saturating_add(30_999) / 1000`. Replace every floor-based insertion path, including installation and batched persistence.
3. Protect existing databases with exact root-horizon checks before deleting rows indexed by legacy buckets; reindex premature buckets instead. Keep bounded pruning progress and transactional index cleanup.
4. Add a real QUIC merge/quarantine retention test with a non-integral-second root lifetime, verify eventual purge and no tombstones, then run `cargo test-std` and Clippy.

Final shared validation: `cargo test-std` — **722 passed, 0 failed, 14 ignored**; `cargo clippy --workspace --all-targets -- -D warnings` passed. These green checks do not invalidate the separate defect probes above.
