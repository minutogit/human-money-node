# Parallel follow-up audit: S02, S04 and S05

Date: 2026-11-09. Reviewed revision: `6322d7bdf1ec0d7fe6f7490ef0e84a331a0c6726`.
The working tree was clean before the review.

Exactly three agents each executed `prompts/AUDIT_LOOP.md` once, reviewing one
distinct slice. All slices had completed their initial baseline; S02, S04 and
S05 were selected from the pending ReChecks in slice order. Each agent changed
only its own ledger row. The coordinator checked all three source traces,
independently repeated every successful reproduction described below, and
created this report and the combined maintenance prompt. No production code or
repository tests under `crates/` were changed.

## Results

| Slice | New findings | Clean_Streak | Total_Finds | Last_Run | Status |
| --- | ---: | ---: | ---: | --- | --- |
| S02 | 1 Medium | 0 | 15 | 2026-11-09 | `Fix_Open` |
| S04 | 1 Medium | 0 | 19 | 2026-11-09 | `Fix_Open` |
| S05 | 1 High | 0 | 15 | 2026-11-09 | `Fix_Open` |

- **S02-15:** stale waiter/background completion cleanup removes a replacement
  pending approval with the same key, defeating exact-retry coalescing and
  undercounting pending work. Both independent cleanup schedules reproduced.
- **S04-19:** F2F operator messages are transmitted before their outbox/history
  entry exists. A genuine early ACK is discarded, leaving an acknowledged
  message pending. Component state transitions reproduced; the specific race
  was not executed end to end over QUIC.
- **S05-15:** an intact gateway controller restart resets declared write/read
  EMAs while continuing its durable sequence. Valid signed envelopes then
  establish a counter conflict and the receiving peer bans the honest gateway.
  Separate write/read cases reproduced over actual authenticated QUIC.

Earlier repaired findings were not recounted. Ineffective nonzero-EMA restart
coverage is included in S05-15, not counted separately. No extra cleanup defect
was asserted without a verified functional trace.

## Central verification

- `cargo clippy --workspace --all-targets -- -D warnings`: passed, exit 0.
  Log: `/tmp/humoco-audit-2026-11-09-clippy.log`.
- Initial sandboxed `cargo test-std`: stopped in the node library at three
  `Operation not permitted` local QUIC socket-bind errors. These were execution
  environment restrictions, not counted findings. Log:
  `/tmp/humoco-audit-2026-11-09-test-std.log`.
- Socket-enabled `cargo test-std`: **failed**, exit 101. The 57 completed result
  groups reported **653 passed, 2 failed, 5 ignored**. It stopped in
  `tests/s02_regressions.rs`: the controlled pending-isolation test reported
  `Commit acknowledgment timed out; operation remains pending` at line 2792
  for Public task 117; the real-QUIC pending-isolation test could not decode an
  attestation at line 3078. Later test binaries were not run by this command.
  Log: `/tmp/humoco-audit-2026-11-09-test-std-network.log`.
- Immediate socket-enabled isolated rerun,
  `cargo test -p humoco-node --test s02_regressions test_s02_14_`: passed,
  **2 passed, 0 failed, 21 filtered out**, exit 0. Log:
  `/tmp/humoco-audit-2026-11-09-s02-14-rerun.log`.
  This does not establish a green full suite or explain the earlier failures.
  No fourth defect was inferred solely from those non-reproduced failures.
- The coordinator inspected temporary probe sources before executing their
  compiled production-library binaries. Both S02 cleanup probes, the S04 store
  ordering probe, the S05 signed-proof probe and the real-QUIC S05 write/read
  probe all completed successfully with the reported outputs.
- The S05 QUIC probe recreates the gateway `TierController` against its intact
  database while retaining the gateway transport and receiving peer evidence.
  It isolates the startup accounting reset; it is not a whole-daemon crash or
  subprocess restart test. Accounting was explicitly drained before restart.
- No new permanent regression test was added during this read-only audit.
  Ignored deep simulations were not run. The following slice reports document
  coverage and reproduction limits; they do not constitute an exhaustive
  schedule search or proof of workspace-wide conformance.

## Handoff

Use [the combined maintenance prompt](2026-11-09_S02_S04_S05_REMEDIATION_PROMPT.md).
It requires test-first fixes for all three findings, real-QUIC regressions,
correction of ineffective restart fixtures, full validation and separate
`Fix_Open` to `ReCheck` transitions after successful repairs.

## Detailed slice reports

The following are the three agents' completed single-pass reports, retained
with their source references, coverage and evidence boundaries.


## Slice S02 follow-up audit, 2026-11-09

Exactly one AUDIT_LOOP review of S02, centrally selected as a ReCheck after all initial passes. Reviewed HEAD: 6322d7b. Production and repository tests remained read-only. Only S02's ledger row was updated: Clean_Streak=0, Total_Finds=15, Last_Run=2026-11-09, Fix_Open.

### Coverage

All five target files were read and reviewed: `crates/humoco-node/src/storage/engine.rs` (4,382 lines), `db.rs` (2,587), `db/signing.rs` (671), `activity.rs` (59), and `recent.rs` (214). Review included both production definitions and embedded regression tests, not only text-pattern searches.

Engine coverage: root anchoring, collision/idempotency and class precedence, exact durable markers and acknowledgments, pending-approval counters/coalescing/waiters, public/internal admission, original choice publication, confirmation-support deadline/background lifecycle, ingress shape/signature/time checks, chain prefix preservation, diagnostic readers, worker batching/FIFO/barriers/retries/shutdown, recovery and TTL pruning. DB coverage: schema initialization/rejection, original group transactions and retained choices, corruption/TTL cleanup, evidence/ban lifecycle, ticket persistence, quota/accounting/VIP persistence, quarantine, mixed flush transaction, sync serialization/snapshot bounds, backup, voucher indexes, events and compaction. Signing coverage: startup measurement, commitments, checked generation/count changes, checkpoint observation and durable corruption latch. Activity coverage: admission close/drain/cancellation release. Recent coverage: bounded buffer and DTO APIs.

Relevant direct boundaries inspected: `storage/engine/recovery.rs`, `storage/db/roots.rs`, `storage/db/support.rs`, `storage/db/projection.rs`, `storage/filter.rs`; recovery's install and committed-shard interfaces in `storage/db/install.rs`; HTTP original self-vote and QUIC original approval callers; core time/expiry predicates. Relevant Specs 12/14, invariant registry and G1-G5 contracts were consulted. Existing `tests/s02_regressions.rs` tests S02-05 through S02-14 and root/status/durability coverage were inspected. Previous reports/remediation prompts were checked: S02-13 service admission and S02-14 separate pending budgets are present and are not counted again.

### S02-15 — Medium — Stale completion removes a replacement pending approval

Primary references: `crates/humoco-node/src/storage/engine.rs:928` (ApprovalWaiterGuard drop), `:1301` (background completion cleanup), `:1248` (pruning before reuse), `:1284` (replacement insertion). Spec 14 section 4.1 (`docs/14_node_persistenz_und_redb_speicher.md:137`) requires identical in-flight operations to coalesce with bounded waiters/memory.

Expected: completion of pending operation A may remove only A's pending-map entry. When that key has already been reused for operation B, A's waiter destructor and A's background cleanup must leave B present, with its owning service counter and waiter semaphore intact. Subsequent exact retries join B.

Actual deterministic trace:

1. Poll original approval A until it enqueues. Use `DualTierEngine::flush_batch` on the extracted real operation to commit the exact lock and own choice to redb; keep A's future unpolled.
2. Poll exact retry B. Its ordinary `wait_original_approval` call prunes completed A and inserts a fresh pending entry B. B remains uncommitted in the controlled channel.
3. Resume A to completion. Its guard sees A's completed receiver and unconditionally removes the shared key, now belonging to B. Alternatively, leave A unpolled and yield to A's background cleanup: it removes the same replacement entry.
4. Poll exact retry C. B is absent from the map, so C enqueues a second persistence operation rather than joining B.

Executed probe output (guard variant):

```text
retry B queued: pending=1, queue=1
old A waiter exits: pending=0, queue=1
identical retry C: pending=1, queue=2
```

Executed background-cleanup variant:

```text
retry B queued: pending=1, queue=1
old A background cleanup runs: pending=0, queue=1
identical retry C: pending=1, queue=2
```

Impact: pending operation/accounting and coalescing diverge; outstanding B is undercounted and new exact retries obtain separate waiter semaphores and persistence work. This weakens the explicit pending/waiter bounds and increases queue/commit work. The independent persistence channel/service semaphores still bound work; no premature signature, conflicting own choice or unbounded-memory claim was demonstrated.

Standalone sources: `/tmp/s02_cleanup_probe.rs`, `/tmp/s02_cleanup_background_probe.rs`; binaries with the same names without `.rs`. They link the already built production library, operate only on test-owned temporary databases and require no network. No repository source/test edits were made. Both variants executed successfully. The coordinator independently repeated the guard binary and observed the same trace. Initially selecting mismatched cached Tokio rlibs caused compile-time type mismatch; final executions used the matching dependency below.

```bash
rustc --edition=2021 /tmp/s02_cleanup_probe.rs -L dependency=target/debug/deps --extern humoco_node=target/debug/deps/libhumoco_node-c288c34cd62417b2.rlib --extern tokio=target/debug/deps/libtokio-622acc3342248aac.rlib -o /tmp/s02_cleanup_probe
/tmp/s02_cleanup_probe
```

Regression: add deterministic controlled-completion tests for both guard and background cleanup actors. Complete A, reuse its key for B before A cleanup, and require B to remain counted; C must coalesce without an extra queued operation. Cover Public/Internal owners, cancellation and failed/closed completions, max-waiter refusal and complete reservation cleanup. Extend real-QUIC approval tests with coordinated retries/completions to verify no signature is released until the retained operation's exact commit and neutral backpressure under exhaustion.

Minimal fix: make both cleanup actors remove only if the currently stored receiver identifies the actor's watch channel (`Receiver::same_channel`, available in the current Tokio) or a simple operation generation. Perform comparison/removal under the same pending-map mutex and use existing `remove` to update owner counters. Add no compatibility path, retry queue or new archival state.

### Verification scope

Both standalone reproductions passed. Full standard suite and Clippy were centrally coordinated; this agent did not launch duplicate workspace test runs. No new QUIC regression was authored/executed during this read-only audit. Final combined report should use the coordinator's actual final check outcomes.

## S04 follow-up audit — 2026-11-09

Reviewed revision: 6322d7b. Exactly one S04 audit-loop execution. Initial ledger: ReCheck, Clean_Streak 0, Total_Finds 18. Production and repository test files unchanged. Only the S04 ledger row updated: Fix_Open, Clean_Streak 0, Total_Finds 19, Last_Run 2026-11-09.

### Verified finding: S04-19 — Medium — Outbound dialogue records are published after transmission

Primary: crates/humoco-node/src/network/transport.rs:3381–3391, `QuicTransport::send_f2f_operator_message`.
Independent authenticated ACK dispatch: transport.rs:4258–4267.
Direct callee: network/f2f_collab.rs:181–211 (`queue_outbound`) and :215–242 (`on_ack_received`).

Expected contract: send_f2f_operator_message is documented at transport.rs:3342 as queueing and sending a direct F2F message. F2fInboxStore::queue_outbound explicitly promises a one-slot reconnect outbox for undelivered messages (f2f_collab.rs:179–180); on_ack_received promises to clear the pending slot and mark the stored message delivered (:214). Thus a genuine authenticated ACK for a sent message must resolve its already recorded pending message, regardless of sender/ACK-task scheduling.

Actual trace: send_f2f_operator_message validates the payload, resolves a live connection, then exposes bytes through `.send_unidirectional(...).await` at transport.rs:3381–3383 before installing the message at :3391. The peer can receive and acknowledge it while this task has not yet acquired the collab mutex. The separate ACK task calls `on_ack_received(friend, id)` at :4267. With no matching record/outbox slot, that call returns false and remembers nothing. The sender then calls `queue_outbound(..., false)`, leaving the already acknowledged message pending and `delivered=false`. The later reconnect/session-sync resend (transport.rs:3322–3338) can clear it only with another ACK; it does not repair the original race. Cancellation/process termination after transmission but before queue publication can similarly leave a transmitted message without its local outbox/history record. This is a local diagnostic delivery-state defect, not a consensus/signature issue.

Executed component reproduction: /tmp/humoco-s04-ack-order-probe.rs, compiled directly against the workspace's current humoco_node rlib with rustc. It executes the exact permitted local interleaving `on_ack_received(friend, 42)` followed by `queue_outbound(friend, message42, false)`. Output: `early_ack_retained=false, pending_after_ack=true, delivered=false`. This proves the callee state transitions; no end-to-end QUIC reproduction of the racing schedule was claimed or added. Source tracing establishes that the production task ordering permits this interleaving.

Minimal implementation: after validation, publish the pending message before any connection lookup/await/transmission; keep that exact slot on send failure. Let the existing authenticated ACK handler mark the recorded message delivered and clear only its matching pending ID. Do not introduce an unbounded early-ACK cache or message-history shim. If return state must reflect an ACK that already arrived, reload the matching record rather than requeueing an old `delivered=false` clone.

Regression recommendation: tests/f2f_collab_tests.rs real authenticated direct-friend QUIC test using a deterministic sender/ACK scheduling barrier around transmission/return, rather than timing-only sleeps. Assert the ID is already in history and pending at first receiver visibility; after an ACK processed before the sender completes, pending is absent and the matching message delivered. Include stalled-send cancellation and failed-send/reconnect controls. Existing test at f2f_collab_tests.rs:164–187 polls the ordinary eventual-ACK path, but does not force early ACK before sender bookkeeping. Add a focused state-order regression too.

### Coverage

All S04 target files read in full:
- network/transport.rs (4592 lines): handlers, signed envelope gates, durable approval calls, status/discovery responses, frozen source leases and digests, bucket-range and snapshot serving, heartbeat/checkpoint/fraud handling, bounded worker helper, socket setup, dial/cache TLS checks, both stream directions, deadlines/cancellation, all forwarders, connection admission, tests.
- network/framing.rs (1706 lines): every payload/codec, signature helper, full header semantics, 64 KiB body cap, service admission, dedicated-stream EOF/trailing checks, bounded F2F payloads and roster formula, all tests.
- network/pool.rs (207 lines): reservation ownership, idle LRU eviction, stable connection identity, active leases, normal turnover errors, cancellation fixture.

Direct-callee review included relevant network/tls.rs configuration/extraction/handshake verification; manager.rs authorization, expected-key resolution, cached connection lifecycle, friend roster access, evidence storage, heartbeat dedup, friend/session helpers; f2f_collab.rs in full; sim-core wire.rs fixed headers/flags; db/snapshot.rs page admission/cursor/byte bounds. Storage-engine persistence/recovery and live-proof helpers were traced at their call boundaries; those broader modules belong to other slices.

Norms read: AGENTS.md, AUDIT_LOOP.md, AUDIT_STATE.md, Spec10 (wire semantics/bounds/identity/gossip), Spec15 (roles, bounded budgets, neutral teardown, deadline semantics), registry transport entries; reviewed the 2026-11-01 and 2026-11-08 S04 reports to avoid recounting repaired findings.

Existing regression coverage inspected: s04_regressions.rs stream-credit/blocked-drain/forwarder/cancellation/refusal tests, network_tests.rs framing boundaries, f2f_gossip_and_shard_rpc_tests.rs identity/gossip cases, shard_pool_lifecycle_tests.rs capacity/LRU/inbound protection, f2f_collab_tests.rs ordinary message/ACK and S04-18 roster-boundary delivery. S04-17 EOF checks and S04-18 62-neighbor budget are repaired in current code and not recounted.

Discarded candidates: bidirectional Heartbeat does not enter the NodeRequestHandler unidirectional mutation path; it only receives DefaultRequestHandler acknowledgement, so no claimed presence mutation bypass. Transport session_seq enforcement remains a specification/integration concern, but fixed sequence usages and insufficiently specified session semantics prevent a new concrete defect claim in this pass. No cosmetic compatibility-alias observation was counted.

Workspace test/clippy execution is centralized by the coordinator; refer to that run rather than duplicate it here.

## S05 single-pass audit — 2026-11-09

Reviewed HEAD `6322d7b`. Exactly one AUDIT_LOOP iteration for centrally assigned ReCheck slice S05. No files in `crates/` were edited. New verified findings: **1**, S05-15 (High). Prior S05-13 and S05-14 repairs were verified in source and were not counted again.

### Complete target coverage

- `crates/humoco-node/src/ingress/mod.rs`: entire module and exports.
- `crates/humoco-node/src/ingress/pow.rs`: entire production module and unit tests; parent/slot binding, shared crypto parity, stateless retry, accepted current/previous window, checked expiry arithmetic, load difficulty and clock wiring.
- `crates/humoco-node/src/ingress/tier.rs`: entire production module and unit tests; VIP/account secrets, F2F registry, shared O(1) public counter, read and full-key P2P counters, time-based quota charging, fractional candidate admission, persistence reservation, workers, initialization/restart, declared allocation and day rollover.
- `crates/humoco-node/src/api/auth.rs`: entire production module and unit tests; bearer parsing, nonempty secret, bounded failure tracking and overflow storage, expiry handling and POSIX token-file paths.

Direct dependencies/callers checked: `humoco-proto/src/crypto.rs` stateless challenge/work and difficulty; `humoco-sim-core/src/quota.rs` ByteYears, RollingQuotaCounter, NetworkThermometer and EMA operations; `humoco-sim-core/src/fraud.rs` genuine signature checks, sequence comparison and conservative decay; `humoco-node/src/storage/db.rs` ingress accounting schema/load/store, quota load/batch persistence, VIP credential store; relevant `api/routes.rs` write/read admission and signed-envelope construction, `api/dashboard.rs` guarded friend registration and operator authentication, `daemon.rs` validated configured client tokens and clock/lifecycle wiring, `network/transport.rs` envelope validation, evidence retention and fraud sanction.

Relevant requirements read: AGENTS.md; Specs 09/13; invariant registry INV-0901–0913, INV-1005, INV-1301–1307; existing `tests/ingress_accounting_regressions.rs` S05-01 through S05-14 cases and prior 2026-11-08 S05 report.

### S05-15 — High — Ordinary restart loses signed write/read EMA continuity

Primary source: `crates/humoco-node/src/ingress/tier.rs:370`.

Expected: After an ordinary same-day restart using intact committed storage, honest gateway accounting retains justified physical-time write/read EMA continuity. Higher sequence numbers must not accompany a physically impossible reduction of the exact counters signed in ingress envelopes.

Observed: `tier.rs:287–310` restores day, reserved sequence, timestamp and cumulative bytes, but line 370 replaces the thermometer with an empty `NetworkThermometer`. The durable schema `storage/db.rs:145` contains no write/read EMA state. `tier.rs:560–573` checkpoints the zeroed/new EMA only AFTER awaiting persistence of a state that does not contain those EMA fields. Allocation sequence therefore advances correctly (1 -> 1025) while signed write/read EMA starts over. This is distinct from S05-14's fixed uncommitted cumulative usage window: the reproduction explicitly drains accounting before restart and uses the intact DB.

Receiver consequence: `humoco-sim-core/src/fraud.rs:826–841` checks both signed EMAs against elapsed-time lower bounds for same-day increasing sequences; `humoco-node/src/network/transport.rs:1060–1092` persists the resulting proof, bans the identity in RAM/peer manager and broadcasts fraud evidence. An honest restarted gateway is permanently banned.

#### Executed production-library reproduction

Source `/tmp/humoco_s05_restart_probe.rs`, binary `/tmp/humoco_s05_restart_probe`, linked against the current production node/core rlibs. Signatures were generated using a real Ed25519 NodeIdentity and verified by `FraudProofPayload::verify_ingress_counter_conflict_network`:

```
before seq=1 write=1920000000 read=100; after seq=1025 write=192000000 read=0; honest_restart_flagged_fraud=true
```

#### Executed real-QUIC reproduction, write and read independently

Source `/tmp/humoco_s05_restart_quic_probe.rs`; binary `/tmp/humoco_s05_restart_quic_probe`; exact compile script `/tmp/humoco_s05_restart_quic_compile.sh`. Local QUIC execution received socket permission and exited 0. The request handler, identity authorization, root authentication, signed envelope checks, receiver evidence tracking and permanent ban are actual production paths. Wire footprints are root-derived, envelope signature rejection is asserted absent, and the pre-restart response must succeed and store evidence.

```
mode=write phase=0 seq=1 write=1920000000 read=0 flags=0 banned=false evidence_stored=true
mode=write phase=1 seq=1025 write=192000000 read=0 flags=832 banned=true evidence_stored=false
mode=read phase=0 seq=1 write=0 read=100 flags=0 banned=false evidence_stored=true
mode=read phase=1 seq=1025 write=0 read=0 flags=832 banned=true evidence_stored=false
```

In write mode ten actual anonymous admissions with annual TTL populate the first write EMA, and one annual admission follows controller restart one second later. In read mode 100 actual read credits populate the first read EMA, and the restarted controller has none. Each phase calls `record_declared_usage`, signs its returned exact EMA fields and sends a valid real `LockVerifyRequest`. The first controller is drained before being dropped. The QUIC transport itself remains alive while TierController is recreated, isolating the restart/reset defect. `flags=832` contains QUOTA_EXCEEDED | PEER_SUSPENDED | QUOTA_FRAUD, and `PeerManager::is_banned` is true in both modes.

#### Existing coverage gap (included in S05-15, not counted separately)

The existing restart QUIC tests sign hard-coded zero EMAs rather than actual nonzero controller allocations (`ingress_accounting_regressions.rs:3712–3713`, `3728–3730`), so cannot detect continuity loss. They also sign an arbitrary footprint 123 at line 3714 for a 100-second root lifetime, while the receiver recomputes `ByteYears::micro_from_ttl_seconds(100)` in `transport.rs:1007`. Assertions at test lines 3749–3751 check only response type, UNAUTHORIZED and QUOTA_FRAUD, and fail to check SIGNATURE_INVALID or actual retained evidence. Replace these with truthful root-derived footprints and successful receiver-state assertions so the test cannot pass before fraud tracking is reached.

### Regression-first repair boundary

1. Add permanent separate nonzero write/read same-day restart cases in `tests/ingress_accounting_regressions.rs`: no time advance, one-second advance, normal elapsed decay, restart with ordinary intact database, and abrupt interruption immediately after an acknowledged allocation. Require actual receiver success/evidence retention before restart and no fraud/suspension/ban after restart over real QUIC.
2. Persist and restore exact fixed-point write/read EMA state plus justified time anchors. Bind the snapshot covered by a returned allocation to the same durable acknowledgment before any signed envelope release. Preserve fractional precision and ordinary decay; daily cumulative bytes are not an EMA substitute. Coalesced snapshots and sequence/day high-water behavior must remain monotonic under concurrency.
3. Correct existing restart wire fixtures to derive footprint from the authenticated root and timestamp and use the returned EMA fields. Assert no SIGNATURE_INVALID or UNAUTHORIZED and prove the receiver reached evidence tracking.
4. Do not weaken first-party verification, zero the declarations or introduce a post-restart exemption. No legacy table/migration compatibility is required in pre-launch.
5. Run cargo test-std and clippy, then change only S05 to ReCheck with Clean_Streak 0 once repaired.

### Validation scope and limits

Audit reproduction changes live only under /tmp. Full suite and Clippy are coordinated by the parent agent. A first probe linked a different cached Tokio rlib and failed before execution with 'no reactor'; rebuilding against the precise Tokio dependency fingerprint of the production node rlib resolved the artifact mismatch. This environment error is not a repository finding. Two successful production/library and real-QUIC reproductions establish the finding; this is not a formal exhaustive schedule or workspace conformance proof.
