# Architecture Consolidation — Approved Requirements and Acceptance Baseline

Date: 2026-10-20. Decisions: DEC-001–089. Documentary result of the five approved
work blocks, especially DEC-083–089 / DB2–DB5. Resume navigation remains solely in
[interview state](ARCHITECTURE_INTERVIEW_STATE.md); decision provenance remains in
[interview notes](ARCHITECTURE_INTERVIEW_NOTES.md#21-current-decision-register-and-provenance).
This is a reviewable consolidation artifact, not a third interview handoff.

## Outcome and evidence boundary

The approved specification cleanup and acceptance mapping are completed. The five
blocks define the selected requirements below. This does **not** declare unresolved
consensus/recovery mechanisms proved, current production code compliant, or tests
executed. A complete unconditional buildable security plan remains dependent on
the explicit proof gates. No new human choice is pending and settled decisions
are not reopened.

The [invariant registry](INVARIANT_REGISTRY.md) maps 115 owned definitions/topics to
canonical documents, enforcement interfaces and concrete acceptance scenarios.
Two old undefined references are retained explicitly as retired, without invented
meanings. The numbered corpus contains 25 physical files in 22 families; the two03
topics are complementary, English15/16 are canonical, and German15/16 paths are
redirects.18/19 provide informative analysis rather than consensus guarantees.
These are traceability counts, not a test-coverage or completeness percentage.

## The five approved requirement blocks

| Block | Selected result | Main owners | Delivery/acceptance boundary |
| --- | --- | --- | --- |
|1 — Current live proof | Separate original write approvals from current-state signatures; bind exact purpose/network/root/output/target/state/request/recipient challenge. Actually verify fourteen distinct authorized full-key signatures from one justified current frozen top20. Ordinary reads stay read_quorum=1 / INV-0310. | DEC-080–084; Specs03/04/06/10 | Membership justification, final shared encoding, collector and consumer verification remain proof/integration work. Matching one lock or trusting a gateway flag never means paid. |
|2 — Demand-triggered state transfer | Unknown/new shard starts NOT_READY. First legitimate need triggers at most one bounded pull job per shard, no eager65536 sweep or payment queue. Verify complete full-root-lifetime snapshot plus bounded gap-free deltas and durably install before every countable signature. Other ready shards continue; retained partial data may be served without a witness vote. | DEC-057–061/085/086; Specs03/07/08/14 | Source continuity, omission detection and safe concurrent activation remain G2.14 empty new replicas agreeing does not close this gate. |
|3 — Own-choice crash protection | Atomically durably persist exact lock and immutable own original decision before any binding approval escapes or self vote counts. RAM signature computation plus bounded background worker and exact async acknowledgment; no RAM guard across disk wait. | DEC-029 restored by DEC-087; Specs12/14 | Ordinary process crash with intact committed storage is covered by the selected ordering argument. All actual release paths and storage settings still need inspection/crash tests; lost/rolled-back/copied storage is separate G5. |
|4 — Bounded operation | Bound batch age/count/bytes, queue admission/ack waits, exact-operation coalescing/waiters, shutdown drain and diagnostics. Preserve late successful commits after timeout; no automatic rollback. Protect inbound shard and required P2P sync work from public ingress/read pressure. | DEC-074–079/088; Specs13/14/15/17/20 | Numeric sizing/performance and wire/process enforcement need evidence.1–5ms storage and<20ms local durable service are unmeasured targets;800ms bounds collection and never weakens durability. |
|5 — Specification and acceptance reconciliation | Remove old receipt archives, early release, third assurance/global-finality promises, rank21 substitutes, unsafe decoding and simulation-only acceptance. Give each invariant one qualified owner, canonical English references and actual-interface failure criteria. | DEC-089 / DB5; registry and Specs00–20/99 | Documentary reconciliation completed. Actual implementation, executed QUIC/HTTP/consumer/crash evidence and remaining design proofs are not completed by documentation. |

L1 retains the voucher/deed, transaction, owner authorization and causality. L2
retains active `parent_lock -> child_lock` exclusions and necessary local own-choice
safety records through authenticated `root.valid_until+30s`. The grace period does
not extend spending validity. Current qualified safely synchronized nodes attest
current state with their own keys. Departure of the original signers alone does
not invalidate an inherited lock. No original-quorum archive, recursive L2 receipt
chain, mandatory predecessor permission, root-risk markers, ordinary-crash identity
abandonment or third assurance tier is introduced.

Every checkout keeps one frozen<=20 electorate and requires14 valid votes in FINAL
mode; no rank21–40 replacement. NOT_READY, capacity refusals, cancellations and
ordinary idle closure remain neutral. All unavailable contributions share the same
six-member headroom. The800ms collection budget is not a guarantee of completion.
FINAL remains regional/revisable under DEC-053/054; class2>class1>class0 then
min(H_canon) within the highest admissible confirmed class governs merge.

## Specification coverage and reconciled conflicts

| Family/files | Reconciled contract and concrete boundary |
| --- | --- |
|00 | L1/L2 separation, binary regional status; cheap lookup is not payment proof. |
|01 | Keyless bootstrap and learned-peer transport versus voting authority; public discovery reveals only explicitly advertised HTTP gateways. |
|02 | Pending/durable original choice versus canonical state; class-aware conflict evidence, neutral refusal, no honest-loser sanction. |
|03 routing | Frozen membership,14/20/800ms, ordinary read1, passive presence, demand-triggered per-shard recovery. Old rank invitations/socket tenure are retired. |
|03 status/sync | LRC-002 current live proof, full-key/challenge binding, no old-quorum archives; safely installed state before live signing. |
|04 | Bounded semantic DTOs and canonical encodings, safe parsing, full proof bindings; fixed144-byte legacy budget distinct from variable HMC/proof/storage cost. |
|05 | Coordinated attack assumptions and bounded defenses, conditional quorum arithmetic; unsupported botnet/percolation immunity withdrawn. |
|06 | L1 custody/causality and actual recipient verification; exact retries, durable wallet/purchase ordering, no recursive L2 chains. |
|07 | Work-backed identity/ticket lifecycle, observed maturation, passive exclusion, safe readiness and first-party sanctions. |
|08 | Compatible-domain regional merge, class-first resolution and safe activation; founder manifests do not authenticate today's full electorate. |
|09 | Existing quota constants/physical-time EMA retained; quota zones are local diagnosis/backoff, never guilt/presence/ban. |
|10 | Safe explicit32-byte framing, complete purpose domains,0RTT write refusal, bounded learned-peer RPC and two F2F gossip streams. |
|11 | Hourly bounded F2F dissemination, three-miss exclusion, clock/domain verification; fits/timing sketches qualified and reentry proof retained. |
|12 | Atomic reserve-first RAM pending/idempotency and TTL; durable release cannot be bypassed by cached status or duplicates. |
|13 | Permissionless client tiers, random128-bit friend secrets, stateless direct work puzzle and protected internal budgets. |
|14 | Atomic lock+own-choice worker transaction/ack, bounded batch/wait/coalescing, intact-storage restart and actual-loss boundary. |
|15 English + German redirect | Persistent F2F versus bounded ephemeral shard LRU128–256/15s idle; neutral cancellation and exact collector/auth boundaries. |
|16 English + German redirect | Models plus actual receiver QUIC, HTTP/consumer and daemon-crash acceptance. Manual readiness toggles/test names prove no automatic recovery. |
|17 | All metrics/topology/dashboard aliases private; bounded non-authoritative diagnostics and legitimate multiple-node operation. |
|18 | Informative shard-capacity/quorum/percolation analysis with explicit assumptions; no expanded signer pool or universal fit guarantee. |
|19 | Informative local feedback/pacing analysis; correct INV-1307/1701 owners, no hearsay or rank21 replacement. |
|20 | Private control/diagnostics, real process/DB-release stop, public HTTP directory, client-only cached fallback, gated actual-loss recovery. |
|99 | Existing FAQ topics reconciled with selected contracts; historical claims cannot substitute for proof or actual enforcement. |

AGENTS.md and the glossary follow the same durable-release and vocabulary
boundaries. English canonical content replaces independent German rule copies;
existing paths remain usable. Historical interview records, P0 reports and legacy
handoff retain their original provenance; newer scoped qualifications take
precedence. No historical test report is relabeled as current production evidence.

Overloaded1402(size versus persistence),1302(privacy versus pacing),1501(early data
versus missing-count) and1502(priority versus rank replacement) are disambiguated
explicitly in the registry. New0404 owns evidence size and1307 owns pacing/protected
budgets.1101/1102 remain undefined retired references. Existing IDs with revised
meaning retain an explicit record of the retired claim, rather than silently
aliasing an incompatible policy.

## Remaining proof gates

These are technical obligations, not another approval package or an automatic
reopening of accepted requirements.

| Gate | Unresolved premise | Required closure artifact / counterexample |
| --- | --- | --- |
| **G1 — Justified current authority (S1/S2)** | Subjective living-mesh views can disagree; full signatures, HRW scores, recipient-selected gateways and a founding manifest do not themselves establish the current admissible electorate or<=6 Byzantine identities. | Explicit authenticated roster/domain/admission model, assumptions and adversarial view-divergence argument. Broad trust research remains stopped unless separately invoked. |
| **G2 — Complete transfer and safe activation (S3/S4)** | Current sources must cover all required live exclusions through turnover and concurrent writes; digest integrity alone is insufficient. | Noncircular source-continuity/coverage argument, exact bounded snapshot/delta/cursor/cutoff/install contract. Address8+6+6 independent-lock support with no 14 identical whole-state digest, agreeing incomplete new replicas, departing sources and writes during installation. No archive/predecessor veto shortcut. |
| **G3 — Support and merge composition (S5)** | Class-first selection, minimal live exclusions, descendants and immutable own choices need one justified evidence/activation rule. | Exact admissibility/support/descendant proof set plus schedules showing no unsupported takeover and no framing of lawful original losers/live reporters. |
| **G4 — Clock, slots and sealing** | WalletT0 entry freshness, RAM insertion, fixed nominal bucket seal, root expiry, passive three-hourly-miss boundaries and restart/reentry must compose safely. | One explicit clock/delay model, boundary schedules and persisted/reconstructed observation rules. Durable waiting does not introduce a second wallet freshness gate. Existing jitter/tolerance sketches do not constitute the proof. |
| **G5 — Actual storage loss/rollback/key duplication (O2)** | Durable-before-release preserves intact commits but cannot recreate a lost decision or distinguish an undetected stale clone alone. | Separate detectable-loss/rollback/identity-safety recovery model and fail-closed scope with actual failure evidence. Ordinary intact-storage process crash needs no marker/quarantine scheme. |

The parked **Q-S3.3-01** (one versus two payment rounds) remains unanswered; this
consolidation chooses neither. Shared exact schema/domain/limits and delivery audit
are engineering obligations alongside the proof gates. They must not silently
select a new consensus mechanism or weaken the accepted safety predicates.

## Prioritized dependency and acceptance plan

This is a dependency map for subsequent authorized work, **not** an unconditional
claim that all design leaves are closed. No implementation execution is authorized
by this document alone.

| Order | Work and decisions | Components/interfaces | Dependency and acceptance gate |
| --- | --- | --- | --- |
|1 | Close G1/G2 regional authority and recovery prerequisites without changing settled policies | Membership selection, shared proof context, digest-pull/install/readiness | Address the named counterexamples and state activation assumptions. G1/G2 block any unconditional safe-turnover claim. |
|2 | Close G3/G4/G5 and resolve only genuinely necessary remaining choices | Resolver/evidence, logical clock/buckets/presence, recovery/identity | Produce explicit arguments/contracts and counterexample schedules; preserve parked question status until a justified proposal is ready. |
|3 | Freeze shared canonical DTO/domain/limit contracts (DEC-038/084/089) | Shared library, HMC consumer, node HTTP/QUIC adapters | Bind all required fields; reconcile full-key proof bytes,1024-byte evidence cap and aggregate bounds. No independent incompatible schemas. |
|4 | Inspect/align every signing/recovery path and bounded worker operation (DEC-085–088) | RAM index/redb/worker, original/live/idempotent/self routes, inbound shard/sync quotas | Exact atomic durable ack before original release; safe per-shard readiness before any countable live/write signature; bounded backpressure/coalescing/drain. Preserve concurrent code until reviewed. |
|5 | Integrate recipient and operational behavior (DEC-060/068/071–079/084) | Wallet/PoS verification and journal, public ingress/directory, private diagnostics, CLI/control | Full mathematical proof before release; client-only cached fallback, every diagnostic alias private and truthful process/DB completion. |
|6 | Supply per-rule executed evidence with source revision and artifacts | Actual QUIC receiver/collector, HTTP, shared consumer, daemon/crash/storage plus models | Use registry scenarios and Spec16; include real automatic recovery, pre/postcommit process kills, neutral cancellations, resource floods and independent DB reopen. Passing models/HTTP alone cannot satisfy QUIC defenses. Measure declared latency/workload/hardware, never weaken durability to meet a target. |

## Checks performed for this documentary result

Only static document checks are claimed: ownership/ID census and scenario mapping,
relative-file links, code-fence structure, reconciliation searches and whitespace
validation. Detailed command/outcome evidence and the completion checkpoint are
recorded in §7.107 of the interview notes after final readback.

No cargo tests, real QUIC/HTTP/crash campaign, performance measurements, production
edits or commits were performed by this consolidation. Concurrent changes already
present in production/test files are preserved and are not attributed to this work.
Existing reports/tests are inspection candidates unless their exact revision,
execution and relevant assertions are independently established.
