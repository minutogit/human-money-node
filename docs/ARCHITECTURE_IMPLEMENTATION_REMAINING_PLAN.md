# Remaining implementation and acceptance plan

Historical residual snapshot. The current
[implementation completion plan](ARCHITECTURE_IMPLEMENTATION_CLOSURE_PLAN.md)
dated 2026-10-23 reconciles newer commits and the full read-only audit. In
particular, the wallet transaction proposal has since been integrated, while
new release/readiness/quarantine regressions remain. Its six-assignment estimate
is provisional history, not authorization or a fixed current queue.

Date: 2026-10-20. Basis: CP-0095, current working trees and completed independent
wallet patch review. Status: **planning; implementation incomplete**.

## 1. Sources, scope and current evidence

The authoritative requirement source is
[ARCHITECTURE_INTERVIEW_NOTES.md, §2.1](ARCHITECTURE_INTERVIEW_NOTES.md#21-current-decision-register-and-provenance)
and its linked §7 rationale. There are still **89 decisions**. This document adds
no decision or consensus mechanism. It complements the stable A01–A15 packages
and G1–G5 prerequisites in the
[original implementation plan](ARCHITECTURE_IMPLEMENTATION_PLAN.md), using the
[execution record](ARCHITECTURE_IMPLEMENTATION_PROGRESS.md),
[consolidation](ARCHITECTURE_CONSOLIDATION.md) and
[invariant registry](INVARIANT_REGISTRY.md).

Code spans this repository, `../humoco-proto`, `../human-money-core` and the actual
host `../human-money-app`. The host is now located; earlier unknown-host statements
describe the audit baseline. Offline transfer and diagnostic status flows do not
constitute an integrated live checkout.

Already implemented portions must be reused: shared challenge-bound verification,
separate original/live purposes, atomic durable node lock/own-choice transactions,
bounded acknowledgments, per-shard fail-closed readiness, demand-repair scaffolding,
durable valid prefixes, bounded idle-LRU QUIC sessions, private operator routing,
explicit HTTP discovery, bounded expiry/history and instance-bound shutdown.
Their remaining composition and acceptance criteria still apply.

| Area | Latest observed evidence | Remaining limit |
| --- | --- | --- |
| Node writes | Corrected rejected single writes falling through to HTTP 200; 50 API and four time-bucket tests then passed; targeted strict Clippy passed. | Fresh full standard run after correction; the prior full run failed three targets, including a checkout latency case. |
| Transport/operator | Actual 258-server QUIC pool test and targeted private-browser/startup/stop tests passed. | Combined pressure, repeated signals, storage failure and final revision acceptance. |
| Core/proto | Core library/full bounded run passed before proposed wallet transaction changes; protocol tests passed. | Final combined revision and actual host checkout. |
| Wallet proposal | Six isolated tests, including 15 process-kill cuts, passed outside the productive Core tree. | Independent review found two P1 blockers and one P2 defect. Do not apply unchanged. |
| Host frontend | Fabricated FINAL 15/20 removed; browser-storage test setup corrected. | Required frontend script still fails for missing translation keys; actual payment dispatch/release remains absent. |

A prepared patch, selected requirement, implemented call path, passing scenario
and justified safety argument are separate states. The earlier 30–40% remaining
figure was qualitative, not an audited completion metric. Proof-gate difficulty
and new findings can change effort; code size/test counts do not measure delivery.

## 2. Work order and agent approval

No agent starts through this plan. The maintainer requires confirmation before
**every further agent activation**, including a new assignment to an existing
agent. The approved independent wallet review has finished.

Planning baseline: **six further agent assignments**, plus root-owned integration
and documentation. This is provisional, not a promise that unresolved design
gates close in six calls. Extra repair/review assignments require new approval.

| Assignment | Deliverable | Assignments planned after it |
| --- | --- | --- |
| E1 | Correct wallet transaction review findings and verify them (R1). | 5 |
| E2 | Explicit authority, time, support, transfer and actual-loss contracts (R3). | 4 |
| E3 | Justified shard installation/readiness activation after applicable E2 gates (R4). | 3 |
| E4 | Authenticated merge and bounded exceptional own-approval retrieval (R5). | 2 |
| E5 | Durable wallet dispatch, recipient proof verification and purchase release (R6). | 1 |
| E6 | Independent combined-code, real-interface and evidence review (R8). | 0 |

Root owns R2/R7 integration and final documentation/commits. E6 checks their result.
Before each start, ask in German: “Agent E1 soll starten. Danach sind noch fünf
Agenteneinsätze geplant. Start freigeben?” If a prerequisite fails, dependent
activation stays disabled; investigate and state the exact unresolved leaf.
Ask one A/B with a recommendation only for a genuine new maintainer tradeoff.
Do not repeat settled questions or silently expand the agent queue.

## R1 — Correct and integrate the wallet transaction proposal

**Priority:** P0, prerequisite of host payment work. **Source:** A09; DEC-071/072
in the decision register. The review defects are engineering findings, not new
architecture choices.

**Targets:** Core `src/storage/{file_storage,wallet_transaction,lock,event_store}.rs`,
`src/app_service/{orchestrator,lifecycle,storage_ops}.rs`,
`src/wallet/lifecycle.rs`; prepared package `/tmp/humoco-wallet-atomic-patch`.

1. Correct successful commit-marker rename followed by failed directory fsync.
   The caller must not receive an ordinary rollback-style error while the new
   transfer state remains installed and its bundle/result is discarded. Explicitly
   distinguish confirmed rollback, confirmed durable commit and uncertain outcome;
   retain the operation result/recovery identity as needed. Visible marker does
   not by itself prove durability. Update callers to prevent a new replacement
   spend after an uncertain result.
2. Prevent selective replay of an authentic stale undo journal over newer security
   metadata. All managed safety-relevant writers, including seal-only fork-lock
   writes, need a consistent freshness/ordering contract. Recovery cannot restore
   an old unlocked seal/integrity file. The observed case replays only a journal,
   not the whole wallet directory.
3. Clean exactly recognized journal/marker nonce temporary files under the wallet
   lock, even without a completed journal name. Repeated pre-rename crashes must
   not accumulate encrypted full snapshots outside bounds. Preserve unknown files.
4. Recheck AEAD-before-restore, recovery-before-login, OS-lock ownership, bounds and
   every managed writer. Resolve/document platform scope: the proposal is Unix
   only and excludes unconverted direct low-level writers. Do not imply Windows/
   WASM durability or ship unexplained supported-target failures.
5. Apply only reviewed manifest paths against matching baselines, preserving
   existing root and unrelated changes. Recheck actual final callers and status.

**Acceptance:** regression tests for post-rename directory-fsync error, stale
journal after abort plus newer fork lock, and both internal pre-rename crash cuts;
repeated recovery/cleanup, corrupt/wrong-key/foreign journal, process-kill cuts,
snapshot limits and no-mutation unsupported outcomes. Then run applicable complete
Core checks. Existing six green tests do not close the new review findings.

## R2 — Restore a reliable combined regression baseline

**Priority:** P0/P1; independent of unresolved consensus design.
**Source:** A03/A08/A14; DEC-087–089 and the affected package decisions.

1. Review node `src/api/routes.rs` rejection mapping: unavailable durability =>503,
   capacity =>429, invalid input =>400, never success. Restore private chain
   rejection counters lost during refactoring without changing response semantics.
2. Diagnose the remaining full-run latency failure in
   `tests/cluster_e2e_tests.rs` using actual body/timing data. Separate contention,
   legitimate timeout, fixture mismatch and production error. Do not blanket-accept
   503, loosen the 800ms policy or enable unsafe readiness to make it pass.
3. Fill missing host English/German translation keys with truthful diagnostic
   wording; rerun `./run-tests.sh --quiet --frontend-only`. Keep the translation
   checker and meaningful assertions enabled.
4. Rerun `cargo test-std` and strict workspace all-target Clippy after corrections.
   Record historical failures separately from new revision results. The 54 passing
   targeted tests are not a full workspace result.

**Acceptance:** intended regressions pass with real error bodies on failure.
Manual-ready application fixtures remain labelled fixtures, not recovery evidence.

## R3 — Establish explicit safety and progress prerequisites

**Priority:** P0. **Source:** original G1–G5/A01–A06; DEC-053–065, DEC-080–087.
Each contract must state assumptions, authenticated inputs, retained fields,
allowed transitions, counterexamples and enforceable verifier inputs.

1. **G1/current authority:** independent recipient justification of roster, network,
   domain and admission; disagreement between local mesh views; actual conditional
   Byzantine scope. Gateway roster, TLS connection and mature work ticket alone
   cannot establish all three.
2. **G2/state completeness:** source/omission coverage, stable snapshot cut, bounded
   delta cursor, no-gap install and progress conditions. Address concurrent old/new
   writes, repeated full turnover, all original signers gone, agreeing incomplete
   sources, and 8+6+6 support without fourteen identical whole-state digests.
3. **G3/support and merge:** evidence admitting class2/class1/class0, protected
   original-choice slot, legal promotion/live reporting and minimum descendant/
   VOID evidence. A claimed status byte does not establish confirmed support.
4. **G4/time and reentry:** signed wallet T0, entry-only freshness, fixed closed
   windows plus bounded open tail, root expiry, median-clock changes, ticket
   maturation and three missed hourly slots across restart/reentry. Do not add a
   second wallet freshness gate after waiting for storage.
5. **G5/actual own-history loss:** detectable stale restore/loss/key-copy cases,
   blocked scope, evidence needed for same-key resumption and unavailable outcomes.
   Intact durable process crash stays separate; canonical-state copying cannot
   reconstruct unknown past own approvals.

**Acceptance:** each counterexample is excluded by an explicit argument or retained
as an unresolved leaf. A helper or matching empty digest is not proof. No implicit
restart of broad trust research, old-committee permission, historical quorum
archives, added payment round or ordinary-crash quarantine is authorized.

## R4 — Complete safe on-demand shard installation and activation

**Priority/dependencies:** P0 after applicable G1/G2/G4 outputs and frozen G3 merge
contract; full R5 enforcement can follow the shared contract without circular
waiting. **Source:** A02/A04/A05/A07; DEC-057–062, DEC-083–086.
**Targets:** node `src/daemon.rs`, `src/network/{transport,manager,framing}.rs`,
`src/storage/{engine,db}.rs`, necessary shared transfer types.

1. Implement justified snapshot/cursor/delta transfer. Verify source identity,
   shard, root validity, page boundaries, all imports and byte/count/work bounds.
   Retain full active root lifetime instead of an arbitrary 24-hour lookback.
2. Close concurrent-write and assignment-change gaps. Failed/cancelled/partial
   transfers cannot activate or overwrite a known-safe state. Durable install and
   resumed delta handling must survive restart.
3. Activate only after verified complete install, current assignment and healthy
   storage. Recheck before every countable original/live signature. Keep network-
   size FINAL hysteresis separate from per-shard readiness, as approved.
4. Preserve one recovery per shard, bounded total jobs, demand-only triggering and
   client retry. Ready shards remain independent. No node payment queue or eager
   65,536-shard sweep; retired original signers are not an archive prerequisite.

**Acceptance:** actual QUIC/process tests for omitted/partial pages, concurrent
writes, restart/cancellation at install cuts, source/membership changes and full
turnover. Prove refusal when unjustified and eventual progress under stated
conditions. Permanent NOT_READY is an interim protection, not completed recovery.

## R5 — Finish supported merge, fraud boundaries and exceptional retrieval

**Priority:** P0 merge, P2 retrieval. **Source:** A06/A08/A15; DEC-064–070,
DEC-083/089. Requires applicable G1/G3 plus existing immutable own-choice storage.
**Targets:** node `src/storage/engine.rs`, `src/network/transport.rs`,
`src/api/routes.rs`, simulation `src/resolver.rs`, shared evidence/verifiers.

1. Enforce authenticated class2 > class1 > class0 in production replacement;
   min-hash applies within the highest admitted confirmed class. Unsupported low
   hashes do not displace confirmed state.
2. Preserve original choices across canonical changes; implement required losing-
   descendant invalidation/promotion and minimum exclusion evidence without full
   losing trees or inherited signature bundles.
3. Complete bounded authenticated inline 409 evidence and precise batch-prefix
   results. Verified matching 14/20 outranks unsupported minority collision;
   independently supported competing branches follow the merge contract.
4. Sanction only verified incompatible original signatures in the same protected
   context. Lawful A-original then purpose-separated B-live is not equivocation.
5. Add bounded read-only retrieval of exact retained own approvals for uncertain
   originals: fixed context, count/byte/deadline limits, rootTTL+30s and honest
   absence. No new original vote/state change. Valid current live clearance does
   not depend on old signers or this exceptional service.
6. Trace and migrate remaining unsafe legacy acceptance callers before removing
   obsolete productive paths; keep useful models/historical notes clearly scoped.

**Acceptance:** real-interface class/tie/late-support/descendant and anti-framing
tests, preserved original choices, valid quorum plus weak collision succeeds,
retrieval remains bounded/read-only and unnecessary after original-signer turnover.

## R6 — Integrate the actual wallet-to-checkout flow

**Priority/dependencies:** P0/P1 after R1 and relevant G1/G4/producer contracts.
**Source:** A01/A09/A12; DEC-060/068, DEC-071–073, DEC-078–084.
**Targets:** Core `src/app_service/{orchestrator,conflicts}.rs`,
`src/services/{l2_gateway,latency_router}.rs` and actual stores; host
`src-tauri/src/commands/transfers.rs`, models/callers and receive/success UI.
Core owns business rules; host stays thin.

1. Document actual preparation/storage/send/response/restart/release callers and
   ownership. Reuse wallet stores; do not move purchases or client caching to L2.
2. Atomically persist exact signed request bytes, wallet T0, operation identity and
   consumed-output pending state before first HTTP send. Retry/restart/gateway
   rotation reuse those bytes. Timeout cannot free the output for a new spend.
3. Implement finite conditional three-send and bounded read-only reconciliation/
   backoff. After freshness expires, do not rebuild the payment. Partial purchases
   retain completed and uncertain components; no automatic replacement/refund.
4. Bind one recipient challenge to its checkout and independently justified
   authority. Use the shared full verifier through the productive Core path:
   fourteen distinct authorized keys and every context field. Preserve Found,
   provisional, uncertain and verified-current outcomes.
5. Release only after acceptable current proof plus durable received L1 voucher
   and purchase binding. Recovery preserves the result without duplicate release.
   Completion creates no historical L2 certificate storage duty.
6. Integrate public HTTP discovery and client-only bounded last-known fallback,
   freshness/revocation and provider-scoped credentials. Never infer HTTPS from
   QUIC addresses or forward friend/VIP tokens to unrelated gateways.
7. Feed UI from the actual verified application result. DTO counts, flags and old
   receipts cannot restore the removed fabricated FINAL indication.

**Acceptance:** real host/Core HTTP/QUIC producer-to-consumer success at valid14;
reject13, forged/duplicate/rank21/wrong-purpose/context/replayed proofs. Kill around
intent/send/response/purchase/release and recover the exact operation honestly.
Cover partial payment, expired freshness, gateway outage, directory fallback and
credential isolation. No helper-only or boolean-only release evidence.

## R7 — Complete operational composition and remaining bounds

**Priority:** P1/P2, mainly extending existing code. **Source:** A07/A08/A10–A13;
DEC-035/036, DEC-074–079, DEC-086/088.

- **Load isolation:** demonstrate bounded public/internal/sync admission and actual
  protected progress under stated flood/slow-disk load. Verify coalesced waiter
  limits, byte/time batch seals, cancellation cleanup and pool pressure without
  active-RPC eviction or capacity-related peer malus.
- **Prefix batches:** test byte/count/work limits and mid-prefix failure over
  HTTP/QUIC. Preserve committed prefix versus uncertain suffix and honest counters.
- **Shutdown:** actual repeated signals retain the first deadline; stalled I/O,
  quota and flush errors cannot report clean. Verify process exit and external DB
  reopen, plus supervisor margin. Async cancellation cannot stop kernel fsync.
- **Private operator:** finish every route/alias/returned-field and proxy/deployment
  review. Keep opt-in loopback HTTP, Host/Origin protection and socket permissions;
  document protected access without leaking topology.
- **Discovery:** authenticated identity/network publication, bounded endpoint
  lengths/counts, freshness/revocation and no invented HTTP endpoint for P2P-only
  peers. Client fallback belongs to R6.
- **Expiry/history:** byte/count/time progress, immediate logical expiry versus
  physical grace, own-choice retention, persistent hourly reset/gap/replacement/
  crash recovery and retention bounds. All metrics remain private diagnostics.

**Acceptance:** declare bounds, workload and observed effects; measure latency
without claiming a physical guarantee. Direct-handler quota tests do not prove
receiving-shard QUIC protection.

## R8 — Final independent acceptance, documentation and Git delivery

**Source:** A14/DEC-089 and original per-package acceptance criteria. Targeted
checks accompany implementation; this is final combined acceptance.

1. Refresh the 89-decision crosswalk: selected requirement, justified design,
   production call path, actual evidence and explicit remaining exception. Retain
   A01–A15/G1–G5 IDs and links; no checkbox bypasses a proof prerequisite.
2. Independently review combined producer/consumer bytes, authority, install/
   readiness, original/live fraud distinction, commit disposition and release.
   Reproduce newly found regressions at the final revisions.
3. Run node standard workspace tests and strict all-target Clippy; proto tests;
   applicable complete Core and subprocess checks; required frontend script and
   relevant Tauri/backend tests. Deeper models run only for justified changed
   assumptions. Record preexisting lint failures and all unexecuted coverage.
4. Execute the real checkout/turnover/merge/crash/pressure acceptance scenarios.
   Distinguish process kill from power loss, manually prepared fixtures from
   actual daemon recovery, and conditional regional safety from global finality.
5. Reconcile English implementation/protocol docs and checkpoint/evidence links
   with approved decisions. Preserve historical withdrawn A/B provenance.
6. Commit reviewed task-owned files with English messages in each affected repo;
   record dependency revisions in the node delivery. Preserve unrelated AGENTS/
   .agents edits, Core fuzz/cache and the host's preexisting
   `src-tauri/Cargo.toml` changes. No push is requested.

**Definition of done:** selected package behavior and applicable gates are
accounted for at recorded matching revisions with required real-interface evidence.
If a gate remains unresolved, a commit can deliver a scoped increment, but cannot
claim the entire architecture implemented or release-ready.
