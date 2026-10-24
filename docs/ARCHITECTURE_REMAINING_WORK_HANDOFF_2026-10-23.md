# Architecture completion handoff — 2026-10-23

## Execution status

The maintainer explicitly stopped implementation and requested this handoff for another AI. Resume implementation only under a subsequent instruction. This document records unfinished work; it is not a completion certificate. The remaining items belong to the existing architecture completion plan, not a newly expanded scope.

Substantial work is present **uncommitted** in Node, Core, and App. Preserve it and inspect every diff before editing. No commit was created at this stop point. Do not reset repositories or rerun mutation scripts from `/tmp`.

Repositories are siblings under `/home/basti/Coding/humoco`:

| Repository | Last observed HEAD | Working state |
| --- | --- | --- |
| human-money-node | `1208eab` | Recovery, storage, transport, chain tests, E2E harness modified/new |
| human-money-core | `28b39bf` | Atomic transfer/send-intent integration and lint changes modified/new |
| human-money-app | `25164a5` | Transfer dispatch, recipient checkout backend, regional cache/config modified/new |
| humoco protocol repository | `3fc5dd8` | Previously clean; verify actual sibling path and HEAD |

Core HEAD changed externally during execution. These hashes are observations, not permission to reset. Inspect current status and instructions in every repository. Existing unrelated Core `fuzz/corpus/`, `fuzz/target/`, and offline-gossip `__pycache__` must not enter commits. The last Core `cargo clippy --fix` process has finished; inspect its changes, including `tests/coin_selection_test.rs`.

## Decisions already authorized — do not reopen

1. Preserve all L1 serialization, signatures, and SST mathematics. Canonical L1 `ds_tag` remains Base58 of SHA3-256 over `u32LE(32) || previous_transaction_hash || u32LE(32) || sender_ephemeral_pub`. The previous hash covers the canonical L1 transaction, not merely `t_id`. Owner hashes use SHA3. Receiver and change remain independent branches. Use the separate author-signed versioned L2 causal output proof.
2. Genesis registers the Voucher Root Anchor in `voucher_roots`; it must never become a spend in `locks` or receive an original spend vote. Locks begin with the first actual spend.
3. G5 fails closed on detectable corruption, truncation, and contradictory first-party self-signature evidence. A complete internally consistent offline directory rollback without external contradictory evidence is outside the local guarantee. No TPM, notary, or pre-signing network dependency.
4. G1 uses explicitly configured authenticated regional mesh sources, under the documented conditional Byzantine bound, rejecting unresolved disagreement. Cold authenticated roster plus local HRW and 14/20 verification; no multiple-gateway live cross-check on checkout.
5. G2 fresh-network creation requires explicit operator bootstrap. Normal joins/restarts stay unready until ready-source quorum evidence. No automatic empty-database fallback.

## Implemented in the current uncommitted increment

### Node

- Disk-backed bounded shard staging and streaming digest; a single immediate redb installation transaction handles roots, locks, quarantine, indices, and current support. New files: `storage/db/install.rs`, `storage/activity.rs`, `storage/engine/recovery.rs`.
- Per-shard admission leases and FIFO persistence fences. Authenticated current-committee sources can freeze a shard for an absolute 25-second lease; collection has an 8-second cold recovery budget. Source fences span target durable commit, RAM publication, and readiness. Other shards remain available.
- Global staging reservations account for cut cache, pages, entries, and installation; maximum 32 source leases. Current-cut support is persisted rather than importing historical signature bundles.
- Tracked blocking recovery work participates in shutdown. Uncertain installation cancellation latches local signing failure.
- Historical causal predecessors can be admitted only after whole-path author-proof validation with a fresh signed terminal wallet timestamp. Unknown roots no longer receive guessed validity; root TTL uses the signed root parser.
- Expanded real QUIC recovery tests and shared fixtures in `tests/common/recovery.rs`.
- Reproducible cross-repository acceptance harness: `scripts/run-architecture-e2e.sh` and `scripts/architecture-e2e/main.rs`.

### Core

- `create_transfer_bundle_with_l2_intents` persists L1 transfer changes and exact signed L2 send bytes in the same wallet transaction before HTTP dispatch.
- New model/wallet intent modules; optional exact chain-request bytes. Original timestamp and L1 bytes are preserved. Automatic intents key the spent input, keeping split change independent.
- Existing offline transfer API remains available. Missing legacy author proofs are not fabricated.
- Real two-wallet purchase test uses atomic send-intent creation and checks exact restart persistence.
- Lint cleanup is incomplete as acceptance evidence: the auto-fix process finished, but a fresh strict run is still needed.

### App backend

- Actual transfer command uses atomic Core intent creation, releases the service mutex, then dispatches saved bytes under one bounded budget.
- Origin-isolated tokens and redirect rejection; bounded free-tier PoW challenge and exact-byte retry.
- New `checkout.rs`: authenticated cold regional-view cache scoped to owner/policy; durable recipient challenge; one-gateway current proof; atomic Core purchase completion.
- Explicit regional-source settings, cache invalidation, registered `refresh_regional_mesh_views` and `checkout_received_bundle` Tauri commands.
- Frontend integration and automatic cold-refresh orchestration are not finished.

## Remaining execution plan, in order

### 1. Review and finalize recovery safety (Z07, Z03, G2/G3)

Review the new protocol before calling it closed:

- Prove no-gap source fencing through target commit/publication/readiness, including membership changes, lease expiry, disconnection, cancellation, restart, and delayed blocking completion.
- Review the justification of persisted class from a current authenticated quorum cut. Ensure omissions/replacements cannot downgrade confirmed choices; preserve local signing-journal invariants and immutable root TTL.
- Distinguish confirmed transaction rollback from uncertain commit where appropriate: current installation guard conservatively latches signing failure even on ordinary validation failure. Do not weaken failure behavior without proof.
- Address authenticated lease abuse and repeated freezes. Bounded 32 leases do not alone prove resistance to repeated shard unavailability; no cooldown is currently implemented.
- Analyze small-mesh growth: a new target cannot self-count unknown state, and N=2 may lack sufficient ready sources under Q(N). Preserve explicit bootstrap rules; do not invent an automatic fallback.
- Measure and test the 32-job / 8 MiB / 10,000-entry staging claims, including HMC rows and concurrent load. Reservation accounting is not yet a measured process-RSS guarantee.
- Add turnover and asymmetric partition scenarios, including 8+6+6 and crash/late-commit paths. Recovery fixtures establish source-readiness/mature-ticket premises; they do not prove automatic bootstrap or 24-hour observation.

### 2. Complete causal/freshness verification (Z09)

- Independently review whole-path prevalidation and the fresh signed terminal timestamp policy without altering L1.
- The new historical-clock test is still engine-level. Add actual HTTP and real QUIC coverage: stale/future/invalid terminal, historical predecessor, durable valid prefix, restart, RFC3339 root TTL, and independent receiver/change branches.
- Keep genesis out of `locks` and preserve exact error reporting for the failing suffix.

### 3. Finish productive App/PoS integration (Z08)

- Update frontend types and send UI for `l2_dispatch`; HTTP observations must not authorize goods release.
- Add explicit authenticated regional-source configuration UI and cold refresh on login/config/network lifecycle plus periodic renewal. Keep roster network I/O outside checkout.
- Wire the real receive/merchant UI to `checkout_received_bundle` using a stable purchase/cart ID. Backend command registration alone is not product integration.
- Preserve ordinary offline L1 transfer/receive and explain provisional/uncertain status correctly.
- Handle already-committed purchase replay when the network is unavailable. Current backend fetches a new proof before completion even for an already completed purchase.
- Physical release must be idempotent by purchase ID. `newly_committed=false` on replay must not trigger another actuation.
- Review unexpected missing intents after durable transfer: current collection uses `filter_map(...ok())`, which may hide diagnostics.

### 4. Implement terminal retained-choice reconciliation (Z10)

This remains incomplete. A single retained original is observation only and cannot safely clear an intent.

- After 30 seconds, query retained choice, then obtain independently authenticated current-state quorum resolution bound to the proper context and stored fresh challenge.
- Reject conflicting choices; never regenerate the original timestamp or signed bytes during retries.
- Add explicit terminal resolution/expiry lifecycle and bounded journal cleanup. Current model principally records `retained_original_observed`.
- Preserve spent-input intent identity and independent split change.

### 5. Complete adversarial acceptance (Z11–Z14, E01–E15)

- Extend the new acceptance harness to real Tauri IPC/frontend binding tests. Its current pass exercises production App Rust modules, not the graphical application.
- Add process/file crash cuts around the exact send-intent and purchase transactions, including rename/fsync uncertainty. Generic wallet journal tests do not alone establish these paths.
- Use child-process environment injection for crash tests; do not introduce unsafe environment mutation or a public production fault switch.
- Add positive/adversarial PoW exact-retry tests, token-origin isolation, redirect rejection, regional source wrong-key/replay/expiry/disagreement/missing-source tests, and owner/network-switch races.
- Verify mixed public ingress / high-priority shard RPC / low-priority sync load, pre-allocation rejection above 64 KiB, TTL cleanup of every new support/staging record, repeated shutdown signals, and actual redb lock release.
- Review new source-fence protocol documentation and operational availability tradeoff: a frozen quorum can temporarily prevent checkout for that shard, while promptly rejecting writes.

### 6. Validate the exact final multi-repository graph

Run after final edits, not merely against a prior intermediate tree:

1. Node mandatory `cargo test-std`, relevant deep scenarios, and `cargo clippy --workspace --all-targets -- -D warnings` with real sockets permitted.
2. Core full nextest suite and strict all-target Clippy; deliberately review remaining test lint changes.
3. App mandatory `./run-tests.sh --quiet` after frontend/backend integration, including TypeScript and frontend checks. Keep local dependency overrides in ignored `.cargo/config.toml`, never release-manifest `[patch]`.
4. Protocol tests if changed.
5. `scripts/run-architecture-e2e.sh` against the exact final sibling graph. Record prepared source/maturity premises honestly.

### 7. Evidence, documentation, and commits

- Update Core/App STATUS files and Node `ARCHITECTURE_COMPLETION_MANIFEST.md`, `ARCHITECTURE_IMPLEMENTATION_PROGRESS.md`, affected contracts, and E01–E15 matrix.
- Record exact source hashes and distinguish passed, conditional, open, and not run. Copy useful temporary logs to durable evidence before they disappear; `.log` files may be ignored and require intentional staging.
- Review all diffs, including auto-fixes and new `scripts/` content. Commit coherent changes in dependency order with English messages. Exclude unrelated fuzz/cache data. No push was requested.
- Do not declare completion from focused tests or a happy-path E2E pass while the above product, reconciliation, crash, and acceptance items remain open.

## Verification already observed — scope matters

| Evidence | Result | Limit |
| --- | --- | --- |
| `/tmp/humoco-atomic-wire-final.log` | 6 real QUIC cluster recovery tests passed | Prepared ready/mature source fixtures; not full bootstrap proof |
| `/tmp/humoco-atomic-unit.log` | 2 installation tests passed | Focused rollback/class preservation |
| `/tmp/humoco-history-clock.log` | 4 chain tests passed | New historical-clock case is engine-level |
| `/tmp/humoco-wallet-atomic-tests.log` | 2 focused Core nextest tests passed | Not full current Core suite |
| `/tmp/humoco-productive-e2e.log` | App transport → atomic Core intent → HTTP → real QUIC committee → recipient challenge → atomic purchase → idempotent restart passed | Production Rust modules, prepared regional authority/readiness/maturity; no frontend/Tauri IPC; harness emits unused-code warnings |
| `/tmp/humoco-atomic-full.log` | Intermediate Node full run passed | Predates latest edits; not final certification |
| `/tmp/humoco-atomic-clippy-final.log` | Intermediate strict Node Clippy passed | Predates latest edits |
| `/tmp/humoco-app-checkout-check.log` | App backend check passed | Before final visibility/registration fixes; E2E later compiled those modules |
| `/tmp/humoco-core-lint-fix.log` | Auto-fix process finished | Review changes and rerun strict Clippy; no final clean result recorded |

Earlier committed baseline had Node 643 passed / 14 ignored, Core 824 passed / 7 skipped, protocol 17 passed, and App backend/TypeScript checks. Those results do not certify the current uncommitted increment.

## Starting instruction for the implementing AI

Read the repository instructions and this document, inventory all four repositories, review the existing uncommitted implementation, then execute sections 1–7 without reopening authorized architecture decisions. Preserve L1, fail-closed boundaries, and existing unrelated work. Report completion only with final-source evidence and explicit limits. Communicate with the maintainer in German; write code, documentation, and commits in English.
