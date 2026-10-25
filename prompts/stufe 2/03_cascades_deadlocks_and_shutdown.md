# Audit 03 — Cascades, deadlocks and shutdown

Date: 2026-10-25. Scope: current working tree, including pre-existing uncommitted changes. Audit only; no fixes applied.

## Findings

**A03-01 · P2 · Pending QUIC handlers survive transport cancellation.** In `crates/humoco-node/src/network/transport.rs:3195`, the tracked bidirectional task awaits `handle_authenticated()` without cancellation or an overall handler deadline; the corresponding unidirectional task at line 3300 has the same lifetime boundary. `drain_tasks()` (line 2410) only closes the tracker and waits. Closing the endpoint cancels socket operations, but cannot cancel a handler waiting on an unrelated future. Trigger: admitted RPC → handler stalls → cancellation/endpoint close → tracked handler keeps its lease and permit → transport drain never completes. The daemon has an outer shutdown deadline (`daemon.rs:315` onward), so this is **not proof of an indefinitely blocked daemon API**; teardown can instead return incomplete while tracked work remains alive in the same runtime.

Evidence: an isolated integration probe used two real localhost QUIC endpoints, waited until a handler entered a pending future, then cancelled the token and closed the endpoint. A 250 ms `drain_tasks()` deadline expired. The safe-behavior assertion failed as expected; no socket permission error occurred in the unsandboxed run. The intentionally pending test handler proves the cancellation contract gap, not that ordinary production requests always hang.

Checked without additional confirmed findings: bounded persistence queue (10,000), reservation before lock mutation, awaited blocking persistence worker, RAM guard release before disk I/O, bounded recovery jobs (32), heartbeat/fraud deduplication and TTL, local failure feedback, and reconnect jitter before the dormant cap. The dormant 1h cap has no jitter; this is a secondary hardening opportunity, not demonstrated cascade evidence. The old prompt's rank-21 checkout replacement is excluded by the current fixed-committee invariant.

## Integrated fix plan

1. Add a real-QUIC regression with a handler blocked on a notification. Assert cancellation releases its task, stream permit and connection lease within a bounded time. Include both stream directions and distinguish ordinary cancellation from a peer failure.
2. Give handler tasks explicit cancellation ownership. Select the transport token against the complete request future; use a bounded graceful drain followed by cancellation for work that has not completed. Keep already dispatched blocking durable commits owned and awaited by the persistence/recovery workers; cancellation must never release a vote before commit or discard a committed write's publication.
3. Ensure `drain_tasks()` can finish after handler cancellation and verify database reopening in the same runtime. Preserve the daemon's truthful incomplete-shutdown result for genuinely uninterruptible disk work.
4. Run the targeted QUIC/daemon/shutdown tests and `cargo test-std`; check that quorum fast-exit and neutral cancellation feedback still hold.

Validation limits: the first standard run was blocked by sandbox socket permissions (150 passed, 3 failed in the node library). A permitted standard rerun reached `api_tests`, then stopped on `test_checkout_edge_case_split_dag_change_branch`; it does not establish a green workspace baseline. Temporary probes and logs live under `/tmp`, not as additional repository deliverables.

Final shared validation: the bounded workspace run (`timeout 240s cargo test-std --no-fail-fast -- --skip test_a23_01_runtime_malformed_state_and_row_integrity_latches`) ended with exit 124 while running `status_reconciliation_tests`. Completed targets reported 415 passed, 1 failed and 14 ignored; the unfinished target and the explicitly skipped signing-history test are not included in those totals. The failure was `test_chaos_ingress_quota_exhaustion_under_flood` (503 versus 429). This is an incomplete run, not a clean baseline. The live workspace changed concurrently; the isolated probes/mutations used the earlier copied snapshot.
