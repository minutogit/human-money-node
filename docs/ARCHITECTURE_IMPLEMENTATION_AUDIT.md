# Architecture Interview — Implementation Audit and Remaining Work

Date: 2026-10-20. Scope: all **89 interview decisions**, interpreted with current
supersessions and the CP-0092 consolidation. Performed by the main reviewer plus
three read-only subagents: checkout/consumer, recovery/membership, storage/operations.
This report records inspected code, not executed runtime verification.

> Detailed execution breakdown: [ARCHITECTURE_IMPLEMENTATION_PLAN.md](ARCHITECTURE_IMPLEMENTATION_PLAN.md). It retains A01–A15 and links each package directly to the source decisions in ARCHITECTURE_INTERVIEW_NOTES.md. This pointer does not update the audit findings into implemented/tested results.

> Historical baseline: implementation has since started. Current code, actual tests, host scope and remaining gates are tracked in [ARCHITECTURE_IMPLEMENTATION_PROGRESS.md](ARCHITECTURE_IMPLEMENTATION_PROGRESS.md). The matrix below records the inspected baseline and must not be mistaken for the current working tree.

## Executive result

Implementation is **partial**. Several important building blocks already exist,
but their actual productive call paths and failure behavior still contradict
selected requirements. New helpers, renamed methods and tests of those helpers
are not sufficient implementation of a payment/recovery contract.

Already present and worth retaining:

- A real shared `humoco-proto` crate used by node, simulation core and HMC, with
  full-key membership, duplicate and Ed25519 verification against a supplied roster.
  Its caller must establish the roster and required threshold; the actual HMC
  verdict path still uses the older statistical checker.
- One genesis/successor registry model, the frozen checkout collector with an 800 ms budget
  and quorum/impossibility exits, cheap default read1, and direct write submission.
- A durable acknowledgment path for **new** HMC locks, bounded persistence channel,
  initial per-shard readiness map/HTTP demand trigger, active digest pull and buckets.
  The missing paths below prevent treating them as complete safety barriers.
- Automatic root expiry+grace, useful dashboard/minute-history and systemd/Docker
  artifacts. Safe fixed-byte header parsing and `forbid(unsafe_code)` are already
  present; the obsolete unsafe document example did not mean production required
  an entirely new parser.

The highest-impact gaps are productive cryptographic acceptance, separated live
proof purposes/challenges, all-path readiness, immutable own-choice durability,
full-lifetime concurrent transfer, eligible membership and supported class-aware
merge/conflict precedence. Privacy and stop completion also have concrete code
violations. Unreviewed host-wallet/PoS behavior is explicitly separated from
proven absent node functionality.

## Inspected revisions and limits

- `human-money-node`: **51347f6e5ef0a4753ce7c86781c3dbb079b6be7c**; clean at audit start.
- `humoco-proto`: **7d3dea75bba2c6e54a2ceda46dbf5044c84fde8a**; clean when inspected.
- `human-money-core`: **b9bbdf795e9f0e282e70d94713fc9e0edd1a6259 plus existing working-tree changes**,
  including `src/services/l2_gateway.rs`, `src/models/layer2_api.rs`, manifests and
  simulator work. Findings refer to the observed working files, not just that HEAD.
- Host/Tauri applications and an actual merchant goods-release integration were
  not audited. HMC request/result helpers and a client simulator are not proof of
  the host's persistence, dispatch, credential/cache or physical-release behavior.
- No source changes, commits, builds, benchmarks or tests were performed. Test
  bodies and call sites were inspected; every execution status remains **not run**.
  All findings are static; potential concurrency deadlocks are not claimed observed.

Status labels below distinguish implemented-in-reviewed-scope, partial/divergent,
missing/contradicted, design-open, external-unverified and documentary/deferred.
None means universal safety or a newly passing test. The complete decision matrix
prevents an old superseded proposal becoming a new implementation ticket.

## Prioritized implementation work streams

P0 means required before claiming the selected checkout/recovery safety contract.
P1 completes selected operational/integration behavior. P2 covers later bounded
operations/exceptional support. These are **15 grouped work streams**, not 89 new
features or a task for every interview answer. Each includes its acceptance gate.
Implementation order depends on the proof gates below; privacy can proceed in
parallel and need not wait for a consensus design.

### A01 — Connect real live-proof verification to the productive consumer

**Priority:** P0. **Decisions:** DEC-006, DEC-015, DEC-017, DEC-020, DEC-021, DEC-038, DEC-080, DEC-081, DEC-082, DEC-083, DEC-084.

**Observed:** New shared full-key Ed25519 verification exists, but productive process_l2_verdict -> evaluate_quorum_certificate still calls statistical verify_quorum_plausibility. ConfirmLocal/Provisional/Final collapse to one Confirmed outcome. Status uses the original approval domains without a fresh recipient challenge; the declared payload digest binds only parent/lock rather than the full live context.

**Evidence:** [l2_gateway.rs:597](/home/basti/Coding/humoco/human-money-core/src/services/l2_gateway.rs:597), [conflicts.rs:295](/home/basti/Coding/humoco/human-money-core/src/app_service/conflicts.rs:295), [verify.rs:22](/home/basti/Coding/humoco/humoco-proto/src/verify.rs:22), [routes.rs:555](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:555), [hmc.rs:235](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/hmc.rs:235).

**Remaining work / acceptance:** Freeze one shared network/purpose/root/output/target/state/committee/request/challenge encoding. Call the genuine verifier from the actual application acceptance path using a justified recipient-selected roster and required threshold; keep cheap ordinary read1 distinct. Reject forged signatures, duplicate/unauthorized keys, wrong network/target/purpose/nonce and 13 votes in that actual path. Preserve local/provisional/final/uncertain outcomes. Do not merely add another unused helper.

**Dependencies and scope:** G1 authority and exact shared context are dependencies. Existing humoco-proto should be completed/reused, not extracted anew.

### A02 — One fail-closed per-shard gate at every signing and activation site

**Priority:** P0. **Decisions:** DEC-026, DEC-030, DEC-031, DEC-041, DEC-057, DEC-083, DEC-084, DEC-085, DEC-086.

**Observed:** HTTP has a per-shard manager; QUIC write checks a global bool, QUIC status does not apply the equivalent gate and status self-votes can be manufactured without checking local safe state. Recovery sets READY without peers and after skipped page/import failures.

**Evidence:** [routes.rs:1257](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:1257), [routes.rs:1311](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:1311), [transport.rs:358](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/transport.rs:358), [transport.rs:1046](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/transport.rs:1046), [daemon.rs:911](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:911), [daemon.rs:1377](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:1377).

**Remaining work / acceptance:** Centralize current assignment, per-shard safe installation and storage-health checks for original, idempotent, live-state and self votes. Failed/absent/unverified sources, failed imports/commits and stale task completion remain NOT_READY. Invalidate readiness on relevant assignment change. Test actual QUIC plus HTTP with global-ready/one-shard-unready and a separate ready shard. Distinguish explicit first network creation from loss of existing state.

**Dependencies and scope:** A03/A04/A05 supply the underlying safe state and identity premises; no historical-signature archive.

### A03 — Atomic own-choice durability and a shared exact commit acknowledgment

**Priority:** P0. **Decisions:** DEC-029, DEC-030, DEC-032, DEC-033, DEC-035, DEC-063, DEC-070, DEC-087, DEC-088.

**Observed:** New HMC writes can await a durable lock commit. However, a simultaneous identical retry sees the pending RAM record and skips if is_new, so it can proceed before acknowledgment. The atomic DB batch stores locks/evidence/quota/bans, not a separate immutable node-own signing choice.

**Evidence:** [engine.rs:880](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:880), [engine.rs:913](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:913), [db.rs:61](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/db.rs:61), [db.rs:472](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/db.rs:472), [transport.rs:736](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/transport.rs:736).

**Remaining work / acceptance:** Persist exact lock+immutable original own choice/signature context in one durable transaction. All matching pending requests share the same bounded operation/ack; no self/status/legacy/idempotent shortcut. Persistent shared-store failure gates all dependent signing while diagnostics remain available. Preserve successful late commits. Restore exact own choices after actual process kills and retain to authenticated rootTTL+30s; canonical sync never rewrites them.

**Dependencies and scope:** Durable-before-release is selected and implementable; actual lost/rolled-back/copied storage remains separate G5, not an invitation to add rejected ordinary-crash markers/quarantine.

### A04 — Complete authenticated active-state transfer and safe concurrent installation

**Priority:** P0. **Decisions:** DEC-031, DEC-045, DEC-046, DEC-057, DEC-058, DEC-059, DEC-061, DEC-083, DEC-085, DEC-086.

**Observed:** Pull and buckets exist, but source responses are counted using local u16 indices; search starts from local knowledge/24h and is truncated by365days/u16bucket count. Each offset page reads a new mutable state. Import failures can be ignored and there is no bound fixed snapshot+gap-free deltas followed by complete durable installation verification.

**Evidence:** [daemon.rs:1256](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:1256), [daemon.rs:1295](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:1295), [daemon.rs:1377](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:1377), [daemon.rs:1416](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:1416), [framing.rs:456](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/framing.rs:456), [transport.rs:1350](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/transport.rs:1350).

**Remaining work / acceptance:** Use distinct authenticated current full keys and snapshot/shard/network/request-bound evidence. Enumerate the entire relevant still-live root lifetime, including older-than24h/227d/365d records on an empty new node. Establish a stable cut, bounded no-gap deltas/cursors and atomic durable install; recheck digest, counts, entries and assignment before READY. Challenge concurrent inserts/pruning/merge, partial sources, restart and stale completions. Align live entry and bucket projection on the original wallet-signed created_at_ms across HTTP/QUIC; do not invent a missing timestamp at the gateway or substitute encrypted_timestamp. Keep the selected entry-only freshness and fixed nominal seal; durable waiting adds no renewed wallet-freshness test.

**Dependencies and scope:** G1/G2 must justify sources and omission coverage.14equal digests alone do not solve8+6+6 independent-lock support. No retired-original-signer archive or predecessor permission is proposed.

### A05 — Unify eligible HRW selection, ticket admission and passive presence

**Priority:** P0. **Decisions:** DEC-018, DEC-019, DEC-040, DEC-044, DEC-048, DEC-054, DEC-055, DEC-056.

**Observed:** Ticket ratchet/incubation exists in gossip paths, but shard_committee admits connected unknown peers with NodePubKey substituted as routing ticket, ignores presence and inserts self unconditionally. Other routing paths use2h freshness/RPC suspension rather than the selected three missed hourly heartbeats.

**Evidence:** [manager.rs:33](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/manager.rs:33), [manager.rs:1130](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/manager.rs:1130), [manager.rs:2000](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/manager.rs:2000), [manager.rs:2010](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/manager.rs:2010), [peer.rs:129](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/peer.rs:129).

**Remaining work / acceptance:** One validated candidate-selection predicate for identity-bound mature ticket, permitted admission, passive presence and verified revocation, including self. Three missed gossip slots change later eligibility; RPC misses/capacity/idle/cancellation do not. Persist/reconstruct observed maturation and specify safe restart/reentry boundaries. An in-flight frozen committee never borrows replacements.

**Dependencies and scope:** G1/G4 still define the fault/authority and clock/reentry assumptions. No daily term, mandatory hourly handoff or active presence ping campaign.

### A06 — Class-aware supported merge and correct conflict/quorum precedence

**Priority:** P0. **Decisions:** DEC-014, DEC-022, DEC-023, DEC-053, DEC-054, DEC-064, DEC-065, DEC-066, DEC-067.

**Observed:** Production HMC sync uses minhash without admitted confirmation classes; core resolver only distinguishes FINAL versus nonFINAL. Separately a single collected collision is returned409 before a collected14vote success is evaluated.

**Evidence:** [engine.rs:147](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:147), [resolver.rs:67](/home/basti/Coding/humoco/human-money-node/crates/humoco-sim-core/src/resolver.rs:67), [routes.rs:1030](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:1030), [routes.rs:1920](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:1920), [routes.rs:2144](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:2144), [routes.rs:2536](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:2536).

**Remaining work / acceptance:** Admit verified support then class2>class1>class0, minhash only within the highest admissible confirmed class. Unsupported low hashes cannot seize confirmed state. Keep own original choice separate from canonical winner/live report and define descendant/minimum-exclusion evidence.14valid matching votes plus one weak collision succeeds; justified competing evidence is handled under its own class rules.409 carries exact authenticated compact collision context.

**Dependencies and scope:** G1/G3 are proof dependencies. A valid recipient/roster check is required before treating14as valid. Review first-party proof context across network/purpose so lawful reports do not frame signers.

### A07 — Bound worker, recovery, retry and transport lifecycles

**Priority:** P1. **Decisions:** DEC-008, DEC-024, DEC-025, DEC-027, DEC-028, DEC-042, DEC-060, DEC-085, DEC-086, DEC-088.

**Observed:** Counts/intervals and inbound semaphores exist. Demand tasks can start before cheap admission, lack global active-shard bounds and use detached cancellation; readiness manager has opposite lock acquisition orders. Third checkout sends are detached. TLS enables5s keepalive even for shard-direct sessions; outgoing connects do not establish the selected bounded idle-first pool.

**Evidence:** [daemon.rs:46](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:46), [daemon.rs:57](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:57), [routes.rs:1754](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:1754), [routes.rs:891](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:891), [transport.rs:1768](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/transport.rs:1768), [tls.rs:305](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/tls.rs:305).

**Remaining work / acceptance:** One bounded recovery scheduler with consistent lock order, guaranteed failure cleanup, daemon cancellation and per-shard dedup across periodic/demand triggers. Run cheap admission before work. Bound batch age/count/bytes, coalesced waiters, outgoing retries and acknowledgment waits; reserve separate inbound shard/sync budgets. Implement role-specific persistent F2F versus bounded idle-first shard sessions without aborting active RPCs; neutral overload/idle/cancel. Test concurrent trigger/finish/stop and flood many distinct shards.

**Dependencies and scope:** The lock inversion is a static deadlock risk, not an observed hang. Preserve conditional exact-payload three-send and800ms; do not implement unselected DEC028 suppression.

### A08 — Valid-prefix ancestry batches with explicit work/byte limits

**Priority:** P1. **Decisions:** DEC-005, DEC-010, DEC-011, DEC-012, DEC-013, DEC-014.

**Observed:** One genesis/successor model and chain endpoint exist. Chain engine validates the whole chain before mutation and explicitly returns zero changes on a later conflict, contrary to accepted prefix semantics.

**Evidence:** [hmc.rs:244](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/hmc.rs:244), [engine.rs:1082](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:1082), [engine.rs:1180](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:1180).

**Remaining work / acceptance:** Durably preserve valid steps1–3 when step4 conflicts; stop4+ and return precise accepted-prefix/uncertainty result. Repeated batch recognizes that prefix idempotently. Validate required target ancestry/split/output/root binding and enforce count/bytes/hops/cryptographic-work bounds. Do not duplicate genesis/successor registries.

**Dependencies and scope:** A03 supplies per-step durability; final shared DTO and split proof are K2 integration, not a silent new payment round.

### A09 — Establish real wallet/PoS dispatch, recovery and release integration

**Priority:** P1; external scope. **Decisions:** DEC-009, DEC-010, DEC-017, DEC-020, DEC-021, DEC-042, DEC-060, DEC-068, DEC-071, DEC-072, DEC-073, DEC-079, DEC-080, DEC-082.

**Observed:** Inspected HMC request generation and outcome processing do not establish the host/Tauri HTTP send/persistence or merchant release boundary. HMC expressly delegates retry/failover to applications. Simulator sends and pure stateless routing are not production wallet integration.

**Evidence:** [conflicts.rs:178](/home/basti/Coding/humoco/human-money-core/src/app_service/conflicts.rs:178), [conflicts.rs:193](/home/basti/Coding/humoco/human-money-core/src/app_service/conflicts.rs:193), [latency_router.rs:1](/home/basti/Coding/humoco/human-money-core/src/services/latency_router.rs:1), [l2_gateway.rs:617](/home/basti/Coding/humoco/human-money-core/src/services/l2_gateway.rs:617).

**Remaining work / acceptance:** Locate and audit the actual application boundary first. Implement missing atomic exact signed bytes/T0+pending-output storage before first send, bounded retry/read-only follow-up, no automatic replacement payment, durable L1 voucher/purchase journal before release, recipient-selected independent observations with disagreement handling, provider-scoped credentials and bounded authenticated client-only cached-address fallback. Preserve existing durable wallet transactions rather than assume none exist.

**Dependencies and scope:** Parts are external-unverified, not proven absent globally. No carts/payment queues/cache-fallback logic in the node; no merchant historical receipt archive.

### A10 — Separate every private diagnostic route and alias from public ingress

**Priority:** P1; independent. **Decisions:** DEC-002, DEC-037, DEC-077, DEC-082, DEC-088.

**Observed:** Dashboard, metrics, peer topology, history/events and voucher/lock inspection are registered on the same router/public listener. Tokens on selected mutation routes do not protect diagnostic GETs or all aliases.

**Evidence:** [routes.rs:204](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:204), [routes.rs:217](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:217), [routes.rs:236](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:236), [daemon.rs:751](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:751), [server.rs:91](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/control/server.rs:91).

**Remaining work / acceptance:** Use the selected dedicated private operator/control authority, enforce socket permissions, and deny public access at every alias/listener/subroute. Public status/health expose only intended client fields. Retain useful bounded dashboard features; external SSH/control access and local logs follow the selected boundary. Add actual HTTP alias/permission tests.

**Dependencies and scope:** Can proceed independently of consensus proof. Keep public gateway directory separate A12; no public metric subset.

### A11 — Truthful bounded shutdown and verified stop completion

**Priority:** P1. **Decisions:** DEC-034, DEC-036, DEC-074, DEC-075, DEC-076, DEC-088.

**Observed:** Cancellation and ordering exist but daemon sequential joins can wait without an absolute internal deadline and failures are ignored. CLI returns success when the control socket disappears, which can precede storage drain/DB release.

**Evidence:** [daemon.rs:797](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:797), [daemon.rs:846](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:846), [client.rs:61](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/control/client.rs:61), [server.rs:134](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/control/server.rs:134), [humoco-node.service:16](/home/basti/Coding/humoco/human-money-node/deploy/systemd/humoco-node.service:16).

**Remaining work / acceptance:** One absolute internal deadline from the first signal covers admission stop, producers, joins and durable drain; repeated ordinary signals do not reset/shorten it. Report failed/incomplete teardown truthfully; keep a longer external supervisor fallback. CLI success requires verified clean process termination and independent DB reopen/lock release. Test stuck worker and repeated signals in real daemon processes.

**Dependencies and scope:** Existing systemd/Docker artifacts are useful, not a need to rebuild deployment. Deadline cannot make a stuck blocking write disappear.

### A12 — Advertise real public HTTP gateways instead of P2P-port URLs

**Priority:** P1. **Decisions:** DEC-078, DEC-079, DEC-082.

**Observed:** Existing /peers directory synthesizes https://known-P2P-address rather than reading explicit authenticated public HTTP advertisements. The required HTTP-ad metadata chain is not established.

**Evidence:** [routes.rs:520](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:520), [config.rs:1](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/config.rs:1).

**Remaining work / acceptance:** Add bounded validated explicit HTTP(S) advertisements, passive permitted propagation and a public client directory that exposes no internal topology/credentials. Preserve custom/bootstrap choices. Test that P2P QUIC endpoints are not invented as HTTPS URLs; cached fallback remains in the client A09.

**Dependencies and scope:** A10 isolates private /peers/topology functionality; a separate public directory does not reopen public metrics.

### A13 — Bound expiry processing and finish private metric retention

**Priority:** P1/P2. **Decisions:** DEC-003, DEC-035, DEC-070, DEC-088.

**Observed:** TTL+30s and RAM minute history exist. Expiry collects/processes entire expired sets and calls synchronous DB pruning from async code. Persistent hourly aggregates for a year and restart restoration are not implemented in the reviewed history collector.

**Evidence:** [engine.rs:2229](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:2229), [db.rs:186](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/db.rs:186), [history.rs:18](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/history.rs:18), [history.rs:49](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/history.rs:49).

**Remaining work / acceptance:** P1: bounded count/byte/time expiry chunks with guaranteed progress; move blocking DB work to the worker and coordinate lock/own-choice rootTTL+30s purge. Reject expired spending before physical cleanup. P2: bounded private hourly year aggregates, metric-appropriate aggregation and restart reload, keeping24h minute history. Measure metadata/disk/RAM costs.

**Dependencies and scope:** A03 supplies missing own choices; A10 keeps all diagnostics private. No manual prune buttons or permanent expired-lock tombstones.

### A14 — Provide actual-path adversarial and real-process acceptance evidence

**Priority:** P0/P1; continuous. **Decisions:** DEC-016, DEC-022, DEC-026, DEC-029, DEC-030, DEC-034, DEC-035, DEC-044, DEC-056, DEC-057, DEC-058, DEC-059, DEC-064, DEC-067, DEC-074, DEC-075, DEC-076, DEC-077, DEC-080, DEC-084, DEC-085, DEC-086, DEC-087, DEC-088, DEC-089.

**Observed:** Existing unit/wire tests are useful but several target helpers, manually toggle readiness, or abort a worker only after commit. They do not establish productive verifier wiring, complete automatic transfer or precommit outgoing-signature safety.

**Evidence:** [storage_tests.rs:644](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/tests/storage_tests.rs:644), [phase5_pull_sync_and_readiness.rs:546](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/tests/phase5_pull_sync_and_readiness.rs:546), [status_reconciliation_tests.rs:480](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/tests/status_reconciliation_tests.rs:480), [l2_gateway.rs:1718](/home/basti/Coding/humoco/human-money-core/src/services/l2_gateway.rs:1718).

**Remaining work / acceptance:** Before declaring each A01–A13 complete, add/regress its real production call path: QUIC receiver/collector, HTTP aliases, actual consumer outcome and real daemon kills at commit/release edges, independent storage/process observations. Cover concurrent identical retries, failed imports/long-lived missing locks,8+6+6, neutral cancellations, resource floods and DB reopen after stop. Record exact revision/command/environment/artifact; models remain complementary.

**Dependencies and scope:** No tests were run in this audit. Test existence is not a pass result; no large campaign is implicitly authorized by this plan.

### A15 — Bounded original-own-approval retrieval and legacy path cleanup

**Priority:** P2; exceptional path. **Decisions:** DEC-004, DEC-006, DEC-038, DEC-055, DEC-069, DEC-070, DEC-089.

**Observed:** Exact original own approval storage is missing (A03), and no complete exceptional retrieval RPC/client path was located. Several legacy DTO/statistical/alternate projection paths remain alongside newer shared helpers.

**Evidence:** [db.rs:61](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/db.rs:61), [hmc.rs:235](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/hmc.rs:235), [l2_gateway.rs:115](/home/basti/Coding/humoco/human-money-core/src/services/l2_gateway.rs:115), [verify.rs:22](/home/basti/Coding/humoco/humoco-proto/src/verify.rs:22).

**Remaining work / acceptance:** After A03/A01 establish the primary live path, implement the selected bounded exceptional original-approval lookup only for uncertain attempts, with exact context/size/auth/work limits. Current live-quorum clearance never requires original signers or historical bundle migration. Retire confirmed unused obsolete paths after caller inspection; preserve useful simulations as simulations.

**Dependencies and scope:** No compulsory second payment round or old-quorum archive. Do not implement rejected predecessor-baton/ordinary-crash quarantine proposals.

## Design/proof prerequisites, separate from code defects

The accepted requirements are not reopened. These gaps require technical closure,
not another preference vote or an invented implementation of an unselected scheme:

| Gate | What must be justified | Affected work |
| --- | --- | --- |
| G1 | Authenticated current roster/domain/admission despite subjective views and the conditional six-Byzantine target. A caller-supplied roster, gateway count or valid ticket alone is insufficient. | A01/A04/A05/A06 |
| G2 | Noncircular source continuity and complete full-live-root coverage through turnover, concurrent writes and8+6+6 support without 14 identical whole-state digests. | A02/A04 |
| G3 | Exact support admission, class priority, minimum live exclusion/descendant behavior and immutable own choices versus lawful current-state reports. | A03/A06 |
| G4 | Wallet-created signed T0, entry-only freshness, fixed5min bucket+30sseal, root expiry and passive three-miss/restart/reentry clocks compose safely. | A04/A05/A09 |
| G5 | Detectable actual storage loss/rollback/key duplication and justified same-key resumption. Durable ordering covers ordinary process crash with intact committed storage, not these losses. | A03/A04 |

DEC-028 suppression is deferred, DEC-039 fixed-context construction is reopened,
DEC-043 hourly cadence was tentative, DEC-062 early release is superseded by087,
and the ordinary-crash marker/quarantine alternatives are withdrawn. Do not build
them as if all historical discussion were current requirements. Q-S3.3-01 one/two
payment rounds remains parked/unanswered; broad trust research remains stopped.

## Decision-by-decision implementation matrix

A source reference is evidence of the inspected path or gap, not an executed
proof. A work-stream ID scopes remaining work; an em dash marks a documentary/permission
item with no independent missing runtime feature. Overlapping agent reviews are
reconciled here, especially DEC-070 own approval versus owner signature and the
unreviewed host-client boundaries of071/072/079.

| Decision / subject | Current implementation status | Evidence | Remaining work / qualification | Work streams |
| --- | --- | --- | --- | --- |
| DEC-001 — Node responsibility | Implemented in reviewed scope | [hmc.rs:186](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/hmc.rs:186), [engine.rs:120](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:120) | Reviewed node data path remains a blind collision service; billing ingress is peripheral. This is not a whole-program or deployment proof. | — |
| DEC-002 — Existing dashboard | Partial / divergent paths | [dashboard.rs:1594](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/dashboard.rs:1594) | Dashboard exists; isolate all operator routes and aliases. | A10 |
| DEC-003 — Metric history | Partial / divergent paths | [history.rs:18](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/history.rs:18) | Add persistent hourly aggregates for one year and restart recovery. | A13 |
| DEC-004 — Compatibility | Documentary / operating scope | [ARCHITECTURE_INTERVIEW_NOTES.md:184](/home/basti/Coding/humoco/human-money-node/docs/ARCHITECTURE_INTERVIEW_NOTES.md:184) | Permission to make coordinated breaking changes is a scope decision, not an unimplemented runtime feature. Actual obsolete-path retirement belongs to A01/A07/A15. | A15 |
| DEC-005 — Genesis versus successor locks | Implemented in reviewed scope | [hmc.rs:213](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/hmc.rs:213) | Genesis and successor are represented by is_genesis in one engine. | A08 |
| DEC-006 — Protocol reference | Partial / divergent paths | [hmc.rs:213](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/hmc.rs:213) | Finish canonical shared domain models and retire divergent productive verifiers. | A01, A15 |
| DEC-007 — Other applications | Implemented in reviewed scope | [routes.rs:207](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:207) | No application-origin whitelist in inspected ingress; deployment-wide configuration not audited. | — |
| DEC-008 — Checkout timing | Partial / divergent paths | [routes.rs:869](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:869) | Bind third background send to finite work/cancellation; measure end-to-end service target. | A07 |
| DEC-009 — Timeout and retry handling | Partial / divergent paths | [routes.rs:1928](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:1928) | Finish durable original client intent, bounded reconciliation and verified payment gate. | A09 |
| DEC-010 — New-payment submission | Partial / divergent paths | [routes.rs:207](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:207) | Direct write request generation exists without mandatory status preflight. Actual send/checkout orchestration belongs to host app outside inspected core; host behavior scope-unverified, not globally missing. | A08, A09 |
| DEC-011 — Reconciliation progress | Partial / divergent paths | [engine.rs:1082](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:1082) | Keep separately accepted records; implement within-batch prefix semantics. | A08 |
| DEC-012 — Reconciliation request size | Partial / divergent paths | [routes.rs:2257](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:2257) | Measure and enforce explicit chain byte/work/hop budgets. | A08 |
| DEC-013 — Reconciliation batch acceptance | Missing or contradicted in reviewed scope | [engine.rs:1180](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:1180) | Replace all-or-nothing collision handling with durable valid-prefix acceptance. | A08 |
| DEC-014 — Split-voucher reconciliation scope | Partial / divergent paths | [engine.rs:986](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:986) | Complete target/split/output binding; linear causality check alone is insufficient. | A06, A08 |
| DEC-015 — Ingress tiers and evidence | Partial / divergent paths | [routes.rs:2472](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:2472) | Common engine for ingress tiers exists; complete shared live-proof validation for all tiers. | A01 |
| DEC-016 — Coordinated attacker | Design/proof open | [quorum_assembly_tests.rs:99](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/tests/quorum_assembly_tests.rs:99) | Coordinated attacker is a threat-model obligation; complete adversarial combined scenarios. | A14 |
| DEC-017 — Recipient-selected verification sources | Partial / divergent paths | [routes.rs:1311](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:1311) | Establish recipient-selected justified committee and verification sources in actual consumer. | A01, A09 |
| DEC-018 — Ticket lifecycle per identity | Partial / divergent paths | [manager.rs:1130](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/manager.rs:1130) | Ticket ratchet/pending incubation implemented; committee peer/self bypasses and safe activation remain. | A05 |
| DEC-019 — Fresh cryptographic identity | Partial / divergent paths | [manager.rs:2010](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/manager.rs:2010) | No IP inheritance seen; peer committee bypass circumvents normal new-key incubation. | A05 |
| DEC-020 — Network-size observations for client statistics | Partial / divergent paths | [l2_gateway.rs:114](/home/basti/Coding/humoco/human-money-core/src/services/l2_gateway.rs:114) | Integrate independently selected multiple network-observation sources and freshness/cache handling. | A01, A09 |
| DEC-021 — Conflicting statistical observations | Partial / divergent paths | [l2_gateway.rs:114](/home/basti/Coding/humoco/human-money-core/src/services/l2_gateway.rs:114) | Add explicit disagreement/network-identity handling rather than gateway-count acceptance. | A01, A09 |
| DEC-022 — No single-source canonical takeover | Partial / divergent paths | [verify.rs:22](/home/basti/Coding/humoco/humoco-proto/src/verify.rs:22) | Canonical state takeover support/authority must be established by sync/merge implementation; cross-audit. | A06, A14 |
| DEC-023 — Unresolved conflicting slot | Partial / divergent paths | [conflicts.rs:295](/home/basti/Coding/humoco/human-money-core/src/app_service/conflicts.rs:295) | Preserve unresolved versus confirmed through productive client outcomes. | A06 |
| DEC-024 — Checkout versus background capacity | Partial / divergent paths | [routes.rs:869](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:869), [transport.rs:2306](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/transport.rs:2306), [daemon.rs:563](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:563) | Collector/stream limits exist; reserve separately bounded incoming shard-service and required sync capacity, not just a shared semaphore/public tier priority. | A07 |
| DEC-025 — Full shard-direct pool and work budget | Partial / divergent paths | [routes.rs:869](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:869), [tls.rs:261](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/tls.rs:261), [tls.rs:305](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/tls.rs:305), [transport.rs:1768](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/transport.rs:1768) | Separate an actual bounded shard-session pool from persistent F2F sessions: TLS configurations enable5s keepalive for all peers, outgoing connect has no corresponding pool admission/LRU eviction path. Existing inbound semaphores and neutral idle handling are useful but do not complete the selected lifecycle. | A07 |
| DEC-026 — Recovery signing readiness | Partial / divergent paths | [routes.rs:2429](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:2429) | Extend per-shard readiness to status self and QUIC status signing sites. | A02, A14 |
| DEC-027 — Checkout availability and dispatch | Partial / divergent paths | [routes.rs:970](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:970) | All-member frozen write dispatch implemented; bound third-send lifecycle and shared transport behavior. | A07 |
| DEC-028 — Possible checkout failure suppression | Deferred; no selected mechanism | [manager.rs:1778](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/manager.rs:1778) | Optional failure suppression has no selected algorithm; do not invent implementation duty. | A07 |
| DEC-029 — Durable signing before response | Partial / divergent paths | [engine.rs:880](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:880) | Close identical-pending retry bypass; persist immutable own decision atomically. | A03, A14 |
| DEC-030 — Persistent storage failure | Partial / divergent paths | [engine.rs:890](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:890) | Store-wide fail-closed signing gate after persistent failure; prevent undurable idempotent success. | A02, A03, A14 |
| DEC-031 — Automatic storage recovery | Partial / divergent paths | [daemon.rs:911](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:911) | Automatic sync exists; justified recovery and safe automatic readiness missing. | A02, A04 |
| DEC-032 — Lost signing choices | Missing or contradicted in reviewed scope | [daemon.rs:1017](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:1017) | Actual own-choice loss/rollback safety gate not found; ordinary intact-storage crash separate. | A03 |
| DEC-033 — Signing protection layout | Missing or contradicted in reviewed scope | [db.rs:61](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/db.rs:61) | Add immutable own-choice table and atomic lock+choice transaction. | A03 |
| DEC-034 — Graceful shutdown | Partial / divergent paths | [daemon.rs:846](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:846) | Bound complete shutdown by time and propagate drain/teardown failure. | A11, A14 |
| DEC-035 — Automatic expiry processing | Partial / divergent paths | [engine.rs:2229](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:2229) | Bound TTL cleanup by chunks and move blocking DB pruning off async runtime. | A03, A13, A14 |
| DEC-036 — Deployment default | Implemented in reviewed scope | [humoco-node.service:16](/home/basti/Coding/humoco/human-money-node/deploy/systemd/humoco-node.service:16) | Deployment templates exist; runtime behavior and performance not verified. | A11 |
| DEC-037 — Private operator access | Partial / divergent paths | [server.rs:91](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/control/server.rs:91) | Private operator HTTP listener and enforced access; socket chmod is currently best effort. | A10 |
| DEC-038 — Shared protocol library | Partial / divergent paths | [Cargo.toml:9](/home/basti/Coding/humoco/human-money-node/crates/humoco-sim-core/Cargo.toml:9) | Shared humoco-proto exists; consolidate productive domain DTOs and verifier callgraph. | A01, A15 |
| DEC-039 — Committee continuity design direction | Design/proof open | [daemon.rs:899](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:899) | Earlier fixed-context handoff mechanism reopened; continuity goal retained, no mandatory CEH construction. | — |
| DEC-040 — Operator reliability diagnostics | Partial / divergent paths | [manager.rs:1701](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/manager.rs:1701) | Local reliability diagnostics exist but RPC suspension affects direct authorization/routing. | A05 |
| DEC-041 — Handoff interruption preference | Partial / divergent paths | [routes.rs:1754](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:1754) | Temporary per-shard HTTP refusal exists; safe isolated activation incomplete. | A02 |
| DEC-042 — Requests during handoff | Partial / divergent paths | [routes.rs:1754](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:1754) | NOT_READY and no payment queue present; wallet bounded exact retry outside reviewed node scope. | A07, A09 |
| DEC-043 — Routine handoff cadence | Design/proof open | [daemon.rs:590](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:590) | Hourly cadence tentative/older handoff framing; current 60s sync not reason to implement arbitrary new timer. | — |
| DEC-044 — Byzantine tolerance target | Design/proof open | [manager.rs:2000](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/manager.rs:2000) | 14/20 target does not establish actual six-Byzantine bound across changing views. | A05, A14 |
| DEC-045 — Complete committee turnover | Partial / divergent paths | [daemon.rs:1295](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:1295) | No original-signer requirement but full turnover loses older unknown active locks under search heuristic. | A04 |
| DEC-046 — Handoff progress after contention | Design/proof open | [daemon.rs:590](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:590) | Retry ticker exists; safe automatic progress under competing transitions unproved. | A04 |
| DEC-047 — Intended network topology | Documentary / operating scope | [ARCHITECTURE_INTERVIEW_NOTES.md:227](/home/basti/Coding/humoco/human-money-node/docs/ARCHITECTURE_INTERVIEW_NOTES.md:227) | Operating goal of connected global mesh is not an implementation guarantee. | — |
| DEC-048 — FINAL threshold and organic-network assumption | Partial / divergent paths | [transport.rs:833](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/transport.rs:833) | FINAL threshold and stability logic present; dynamic committee authority proof remains separate. | A05 |
| DEC-049 — Client authorization terminology | Documentary / operating scope | [TRANSLATION_GLOSSARY.md:1](/home/basti/Coding/humoco/human-money-node/docs/TRANSLATION_GLOSSARY.md:1) | Naming adopted in the shared glossary; no identifier/wire migration was selected. Actual output binding remains separate A01/A06. | — |
| DEC-050 — Predecessor terminology | Documentary / operating scope | [TRANSLATION_GLOSSARY.md:1](/home/basti/Coding/humoco/human-money-node/docs/TRANSLATION_GLOSSARY.md:1) | Parent-record versus consumed-output terminology documented; exact split proof remains A06. | — |
| DEC-051 — Shard summary terminology | Documentary / operating scope | [TRANSLATION_GLOSSARY.md:1](/home/basti/Coding/humoco/human-money-node/docs/TRANSLATION_GLOSSARY.md:1) | Shard-summary terminology documented; it does not prove source completeness (G2/A04). | — |
| DEC-052 — Autonomous vocabulary maintenance | Documentary / operating scope | [TRANSLATION_GLOSSARY.md:1](/home/basti/Coding/humoco/human-money-node/docs/TRANSLATION_GLOSSARY.md:1) | Autonomous vocabulary maintenance is an ongoing workflow, not a pending feature to seek approval for again. | — |
| DEC-053 — Partition-resilient regional acceptance | Partial / divergent paths | [engine.rs:147](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:147) | Regional membership/minhash exists; production support admission and class handling incomplete. | A06 |
| DEC-054 — Regional eligibility, honest merge and merchant risk | Partial / divergent paths | [manager.rs:2010](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/manager.rs:2010) | Gossip tickets/incubation exist; committee peer bypass and support class checks remain. | A05, A06 |
| DEC-055 — Rejection of predecessor baton chaining and chained L2 receipts | Partial / divergent paths | [daemon.rs:899](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:899) | No required predecessor baton or historical certificate archive in recovery; passive presence inconsistent. | A05, A15 |
| DEC-056 — Passive presence exclusion | Missing or contradicted in reviewed scope | [manager.rs:33](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/manager.rs:33) | Two-hour freshness, RPC suspension and committee ignoring presence contradict three missed gossip heartbeats. | A05, A14 |
| DEC-057 — Mandatory restart sync-readiness; no empty-state disaster fallback | Partial / divergent paths | [daemon.rs:911](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:911) | Boot barrier exists but absent/failed sources can lead to READY. | A02, A04, A14 |
| DEC-058 — Quorum-backed verified digest-pull | Partial / divergent paths | [daemon.rs:1256](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:1256) | Digest pull exists; authenticated distinct identity/context, source coverage, verified durable installation missing. | A04, A14 |
| DEC-059 — Fixed snapshot with bounded deltas and bucket sealing | Partial / divergent paths | [framing.rs:456](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/framing.rs:456) | Buckets/paging present, no fixed snapshot plus no-gap bounded deltas and atomic install. | A04, A14 |
| DEC-060 — Exact-payload retries and three-send heuristic | Partial / divergent paths | [routes.rs:891](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:891) | Identical three-send payload exists; bind detached final send to bounded task lifecycle and durable client intent. | A07, A09 |
| DEC-061 — Wallet-bound creation time; fresh live ingress versus historical sync | Partial / divergent paths | [routes.rs:1639](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:1639) | Wallet created_at_ms gate present but zero auto-fill and encrypted_timestamp fallbacks remain. | A04 |
| DEC-062 — RAM-first response; entry-only freshness and nominal seal | Partial / divergent paths | [routes.rs:1639](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:1639) | Early-release ordering superseded by DEC087; retained entry-only freshness and fixed bucket rules partly aligned. | — |
| DEC-063 — Lost-choice safety gate | Design/proof open | [daemon.rs:1017](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:1017) | Ordinary process crash construction superseded by087; actual storage loss/rollback safe resumption unresolved. | A03 |
| DEC-064 — Strict confirmation-class priority before canonical hash | Partial / divergent paths | [engine.rs:147](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:147) | HMC sync merge minhash without verified class gate; core only FINAL-vs-nonFINAL, not full class2>class1>class0. | A06, A14 |
| DEC-065 — Minimal losing-branch retention | Partial / divergent paths | [engine.rs:184](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:184) | Winner/TTL present; authenticated minimal exclusions, descendants/promotions and immutable own choices incomplete. | A06 |
| DEC-066 — Inline compact conflict evidence | Partial / divergent paths | [routes.rs:1030](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:1030) | Inline owner-signed entry exists; finish compact confirmation/support/context evidence. | A06 |
| DEC-067 — No minority collision veto at checkout | Missing or contradicted in reviewed scope | [routes.rs:1920](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:1920) | Do not allow minority collision to override valid 14-vote completion. | A06, A14 |
| DEC-068 — Bounded automatic client reconciliation | Partial / divergent paths | [conflicts.rs:226](/home/basti/Coding/humoco/human-money-core/src/app_service/conflicts.rs:226) | Implement actual bounded automatic backoff/reconciliation and read-only-after-freshness orchestration. | A09 |
| DEC-069 — Read-only recovery of original checkout approvals | Missing or contradicted in reviewed scope | [routes.rs:207](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:207) | No original-approval retrieval protocol/client path located in inspected callgraph; supplement storage audit. | A15 |
| DEC-070 — Root-lifetime retention of original own approvals | Missing or contradicted in reviewed scope | [dto.rs:84](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/dto.rs:84), [db.rs:61](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/db.rs:61) | Exact original own approval/signature/context retention is missing from the reviewed node storage; owner signatures in lock records are not own approvals. Any retrieval is bounded and exceptional, never an archive prerequisite for current live clearance. | A03, A13, A15 |
| DEC-071 — Durable wallet intent before network dispatch | External host integration unverified | [conflicts.rs:193](/home/basti/Coding/humoco/human-money-core/src/app_service/conflicts.rs:193) | Request generator has no atomic exact-intent persistence step, but HMC delegates dispatch/retry to Tauri/application clients. Inspect the actual host pre-send transaction before asserting a global absence or implementing a duplicate wallet journal. | A09 |
| DEC-072 — Durable L1 voucher/purchase, ephemeral completed-checkout certificate | External host integration unverified | [conflicts.rs:295](/home/basti/Coding/humoco/human-money-core/src/app_service/conflicts.rs:295) | No recursive completed-checkout archive duty in reviewed node; actual merchant durable L1 voucher/purchase storage and physical release boundary lie in the unreviewed host PoS. | A09 |
| DEC-073 — No automatic substitute payment; strict client boundary | Partial / divergent paths | [conflicts.rs:295](/home/basti/Coding/humoco/human-money-core/src/app_service/conflicts.rs:295) | Node commercial boundary respected; explicit client uncertain/partial-payment policy not established. | A09 |
| DEC-074 — Idempotent repeated termination signals | Partial / divergent paths | [daemon.rs:797](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:797) | Explicit repeated-signal contract with unchanged original absolute deadline and process tests. | A11, A14 |
| DEC-075 — Internal shutdown deadline with outer supervisor margin | Missing or contradicted in reviewed scope | [daemon.rs:846](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:846) | Implement one internal absolute shutdown deadline covering all joins and persistence. | A11, A14 |
| DEC-076 — Stop CLI waits for verified completion and released DB | Missing or contradicted in reviewed scope | [client.rs:61](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/control/client.rs:61) | CLI success must prove clean completion and DB release rather than socket disappearance. | A11, A14 |
| DEC-077 — Operator-only metrics and diagnostic topology | Missing or contradicted in reviewed scope | [routes.rs:204](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:204) | Private metrics/dashboard/topology aliases; limit public status diagnostic disclosure. | A10, A14 |
| DEC-078 — Dynamic public gateway discovery | Partial / divergent paths | [routes.rs:520](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:520) | Advertise actual HTTP(S) endpoints instead of synthesizing HTTPS URLs from P2P addresses. | A12 |
| DEC-079 — Bounded last-known gateway fallback belongs to clients | External host integration unverified | [latency_router.rs:1](/home/basti/Coding/humoco/human-money-core/src/services/latency_router.rs:1), [conflicts.rs:178](/home/basti/Coding/humoco/human-money-core/src/app_service/conflicts.rs:178) | Accepted client-only fallback policy, not deferred or a missing node feature. Inspect actual host HTTP discovery/cache/credential scoping; HMC stateless routing and a simulator do not establish production behavior. | A09, A12 |
| DEC-080 — Quorum proof required for paid/goods release | Partial / divergent paths | [l2_gateway.rs:597](/home/basti/Coding/humoco/human-money-core/src/services/l2_gateway.rs:597) | Replace productive statistical plausibility with mathematical quorum verification; reject local-only final completion. | A01, A09, A14 |
| DEC-081 — Cheap ordinary lookup, explicit quorum-backed release verification | Partial / divergent paths | [hmc.rs:229](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/hmc.rs:229) | Default cheap read1 exists; read14 collection must be tied to fully verified release gate. | A01 |
| DEC-082 — Confirm derived implementation batch | Partial / divergent paths | [conflicts.rs:295](/home/basti/Coding/humoco/human-money-core/src/app_service/conflicts.rs:295) | Keep found versus confirmed distinct and preserve uncertainty; provider/privacy details delegated to sibling audit. | A01, A09, A10, A12 |
| DEC-083 — Current shard-state quorum, no inherited historical certificate archive | Partial / divergent paths | [transport.rs:1133](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/network/transport.rs:1133), [daemon.rs:1182](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:1182) | Current-state attestation exists without historical archive; qualify current authority and safe readiness. State digest avoids archive premise; qualified current authority and safe readiness still missing. | A01, A02, A04 |
| DEC-084 — Live-state verification implementation requirements | Partial / divergent paths | [routes.rs:555](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:555) | Implement separate read/write purpose, recipient challenge, context binding, justified committee and integrated payment verifier. | A01, A02, A14 |
| DEC-085 — Demand-triggered recovery of newly assigned shards | Partial / divergent paths | [routes.rs:1754](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/api/routes.rs:1754) | HTTP demand path exists; QUIC still global barrier and other scheduled sync path inconsistent. | A02, A04, A07, A14 |
| DEC-086 — Bounded demand-driven shard recovery requirements | Partial / divergent paths | [daemon.rs:28](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/daemon.rs:28) | Per-shard map/dedup exist; bounded scheduler, full lifetime, source qualification, cleanup and durable verified installation missing. | A02, A04, A07, A14 |
| DEC-087 — Durable-before-Release restored | Partial / divergent paths | [engine.rs:880](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:880) | New HMC writes await commit; identical pending writes bypass it and own choices are absent. | A03, A14 |
| DEC-088 — Bounded durable-pipeline operations | Partial / divergent paths | [engine.rs:414](/home/basti/Coding/humoco/human-money-node/crates/humoco-node/src/storage/engine.rs:414) | Add batch byte bounds, bounded coalescing/waiters, protected internal capacity and private diagnostics. | A03, A07, A10, A11, A13, A14 |
| DEC-089 — Specification cleanup and acceptance mapping | Documentary / operating scope | [ARCHITECTURE_CONSOLIDATION.md:1](/home/basti/Coding/humoco/human-money-node/docs/ARCHITECTURE_CONSOLIDATION.md:1), [INVARIANT_REGISTRY.md:1](/home/basti/Coding/humoco/human-money-node/docs/INVARIANT_REGISTRY.md:1) | Approved documentation and acceptance mapping delivered. Source compliance and executed evidence are separate; see A14/A15. | A14, A15 |

## Recommended delivery sequence

1. Reproduce the concrete P0 failures with narrowly targeted actual-path tests:
   parallel identical pending request, unsupported local confirmation, unready
   status/self vote, failed-source READY, omitted old live lock and minority409
   beating valid14. A14 starts with each fix; it is not a final simulation-only gate.
2. Integrate A01/A03 and the immediate fail-closed guards in A02. In parallel,
   separate private routes A10. Keep useful existing helpers and deployment work.
3. Close G1–G4 premises and finish A04/A05/A06 with explicit source/activation and
   timing contracts. Implement A07/A08 against those contracts, with boundedness
   verified at the real receiving shard.
4. Inspect the actual host application and finish only its missing A09 functions;
   complete truthful stop A11 and explicit public directory A12. Complete P1 expiry
   work in A13; its yearly metrics and A15 are lower-priority follow-ups.
5. Before accepting each stream, record actual revision, executed scenarios/results
   and limitations. Full wire/crash/resource acceptance is not claimed by this audit.

Only the requested static audit and plan were performed. Implementation and
runtime validation remain future work, organized by these streams without
repeating settled architecture choices.

## Source snapshot fingerprints

The following SHA-256 values identify key observed files, especially the dirty
HMC working tree. They do not replace revision-aware tests or establish absence
of concurrent changes elsewhere.

| Observed file | SHA-256 |
| --- | --- |
| `crates/humoco-node/src/api/routes.rs` | `e96253a1c35756c2c8a1b590afb91cbd123315bfcc067ffd2fdebd55187fbbf3` |
| `crates/humoco-node/src/network/transport.rs` | `fa8645c0781d8d3c58af183dce0e72ff39a0a51693fb0a46117930b0db50110b` |
| `crates/humoco-node/src/network/manager.rs` | `ab71ab959b7c56ad746fdac2d22e0bc50166b1dcd17e8417fa695d6282edebe9` |
| `crates/humoco-node/src/daemon.rs` | `6fa6434deb5de6f2cd2dbe46db3a148430a7b9b964023c3c5eb7b122da20ee7a` |
| `crates/humoco-node/src/storage/engine.rs` | `eebe967405d54b7e7a5273655bea3b4b58caa4d022fce6eb0185b82a4954550a` |
| `crates/humoco-node/src/storage/db.rs` | `9eb2bbbb579a7537c0fb49ed27530b551e72814c718547b0d0551769a7538226` |
| `../human-money-core/src/services/l2_gateway.rs` | `1f154374ec4b4ba011aca220b718e22cf5b75c01efa7f6425aecf5f97cef3f04` |
| `../human-money-core/src/app_service/conflicts.rs` | `d79acd5ce004987d316d9f99c6a99b2267369e710ac3281ddf08008476dda63b` |
| `../human-money-core/src/models/layer2_api.rs` | `51a9099f840fc98524666dd43b2d0043d73b9c9b787573d68ffd6ab8c416865c` |
| `../humoco-proto/src/verify.rs` | `b75d15b838703599dab9679a0fa56a3cb7e5ddb0d766d5690f6dfc3b9e4fa4f3` |
