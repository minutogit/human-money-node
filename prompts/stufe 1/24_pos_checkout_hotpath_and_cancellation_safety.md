# Audit 24 — Checkout hot path and cancellation safety

Date: 2026-10-25. Scope: api/live.rs, api/routes.rs, api/hmc.rs, network transport/pool/peer and durable checkout calls. Audit only; no fixes applied.

## Finding

**A24-R1 — P2: Write collection has a fresh 800 ms timer rather than an end-to-end checkout deadline.** `crates/humoco-node/src/api/routes.rs:2405` waits for local durability, then `:2464` starts quorum assembly. Assembly itself can await a second durable original-approval commit (`:1420`), before `:1051` starts a new 800 ms collection timeout. Only `/v1/verify-current` has ingress deadline middleware (`:253`). `/v1/lock` has no equivalent enclosing deadline.

Trigger: local persistence/approval consumes part of the budget; enough remote members remain pending so collection continues until its own 800 ms timer. Total processing is the local preparation time plus 800 ms, potentially far longer under storage contention (each durable wait permits 750 ms). The handler can therefore continue processing after an 800 ms client timeout, losing the response for a potentially committed operation. The timer composition is confirmed by source inspection; no newly injected slow-disk wire reproduction or production latency measurement was performed. The shared 750 ms live-proof deadline fixes a different endpoint and does not close this write-path gap.

Verified safeguards: immutable top-20 collection, full identity/TLS checks, distinct votes, impossibility fast-exit, bounded retries, neutral aborted stragglers/NOT_READY, validated 409 conflicts, live-proof grouping by exact state, and leased 256-session pool with neutral resource turnover. Quinn streams and pool leases use owned drop paths; no additional confirmed cancellation leak.

Validation: `cargo test -p humoco-node --test status_reconciliation_tests --test phase11_wire_level_adversarial_tests --test quorum_assembly_tests --test shard_pool_lifecycle_tests`: **28 passed**, including real QUIC fast-exit, retry, conflict, deadline and 256-session lifecycle coverage. The audit prompt's historical multi-hop timeout formula is not treated as the single-lock SLA; chain recovery requires a separately defined total request budget.

## Integrated fix plan

1. Add an HTTP-plus-real-QUIC regression delaying local durable acknowledgement and remote responses. Measure from handler ingress; require a bounded error before the absolute server deadline, with pending commits retained safely and no penalty for cancellation.
2. Assign an absolute monotonic deadline before parsing/preparation for single-lock checkout, with response headroom below 800 ms. Pass it through local persistence, original-approval collection, connection establishment and remote collection; use `timeout_at` with remaining time rather than fresh durations.
3. Preserve durable-before-vote and exact retry semantics when the deadline expires: cancellation cannot undo an already running disk commit or release an uncommitted signature. Reconcile/retry pending exact operations safely.
4. Specify and apply one total chain budget separately; avoid resetting collection budgets across stages. Retain the existing independent live-proof deadline.
5. Re-run the above wire suites, `cargo test-std` and Clippy; measure end-to-end and local durable latency under normal load and controlled contention.

Final shared validation: `cargo test-std` — **722 passed, 0 failed, 14 ignored**; `cargo clippy --workspace --all-targets -- -D warnings` passed. These green checks do not invalidate the separate defect probes above.
