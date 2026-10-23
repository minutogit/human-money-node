# Architecture Implementation Plan — Detailed Remaining Work

Current continuation: use the
[implementation completion plan](ARCHITECTURE_IMPLEMENTATION_CLOSURE_PLAN.md)
dated 2026-10-23 for current code findings, regressions and execution order. The
A01–A15 requirements and acceptance criteria below remain the original crosswalk;
this document's baseline observations are historical.

Date: 2026-10-20. Baseline: CP-0093 code audit; 89 existing interview decisions.
Status: **documented implementation backlog and acceptance plan**. No item is
marked implemented or tested by writing this document. 15 work-package IDs A01–A15
are retained from the audit so a later implementation can report progress without
renumbering the decisions or repeating accepted choices.

## 1. Decision source and how to use this plan

The primary source of the decisions is
**[ARCHITECTURE_INTERVIEW_NOTES.md](ARCHITECTURE_INTERVIEW_NOTES.md)**, especially
[§2.1, current decision register and provenance](ARCHITECTURE_INTERVIEW_NOTES.md#21-current-decision-register-and-provenance)
and each linked supporting §7 record. Every package below explicitly links the
DEC IDs in that source file. Those are the origin of the requirements; this plan
is an execution breakdown, not a second decision register.

Other documents have distinct roles:

| Document | Role |
| --- | --- |
| [ARCHITECTURE_IMPLEMENTATION_AUDIT.md](ARCHITECTURE_IMPLEMENTATION_AUDIT.md) | Observed implementation gaps, exact code locations/fingerprints and all 89 decision-status rows. Source findings, not newly selected policy. |
| [ARCHITECTURE_CONSOLIDATION.md](ARCHITECTURE_CONSOLIDATION.md) | Approved five-block baseline and G1–G5 proof gates. |
| [INVARIANT_REGISTRY.md](INVARIANT_REGISTRY.md) | Canonical invariant meanings, enforcement boundaries and per-rule acceptance scenarios. |
| [Spec16](16_chaos_testing_and_simulation.md) | Required actual QUIC/HTTP/consumer/process evidence and its limits. |
| [AGENTS.md](../AGENTS.md) and [glossary](TRANSLATION_GLOSSARY.md) | Applicable project rules and vocabulary. |
| [ARCHITECTURE_INTERVIEW_STATE.md](ARCHITECTURE_INTERVIEW_STATE.md) | Compact current navigation/checkpoint; not a substitute for decision rationale. |

Before touching a package, read its linked current DEC records and supersessions,
recheck the actual files/callers and compare the audit fingerprints. The node audit
baseline is 51347f6e5ef0a4753ce7c86781c3dbb079b6be7c; proto is 7d3dea75; HMC is
b9bbdf7 plus the recorded dirty working files. The 10 audited source fingerprints
still matched when this plan was prepared. Existing work must be reconciled and
reused; do not rebuild features merely because older notes said “pending”.

New struct/endpoint/schema names in an implementation are deliverables to define;
this plan does not pretend their exact formats already exist. Files named under
“Affected code” are implementation targets/candidates, while the linked audit
contains the concrete inspected evidence. Host-wallet/PoS files not yet located
remain explicitly unverified.

## 2. Scope and invariants that every package must retain

- L1 owns the voucher/deed, ownership, amounts and transaction history. L2 owns
  active collision state and necessary own signing-safety records. No purchase,
  cart, automatic substitute-payment or client cache policy enters the node.
- Ordinary status remains read_quorum=1 / INV-0310. Payment release requires actual
  full current quorum verification, not a single matching lock or gateway flag.
- FINAL uses14distinct authorized full keys in one frozen<=20 committee and an800ms
  collection budget; no rank21–40 replacement or availability-based threshold
  reduction. N<20 retains adaptive PROVISIONAL, separately classified. FINAL is
  regional/revisable, not global irreversibility.
- DEC-087 restores DEC-029: atomic durable lock+immutable original own-choice commit
  before signature release/self vote. It supersedes only DEC-062 early release;
  reserve-first RAM processing, entry-only wallet freshness and fixed seal remain.
  Worker I/O is asynchronous to the runtime; latency still counts and is measured.
- DEC-083/LRC-002 supersedes historical original-quorum archive premises. Current
  qualified synchronized nodes attest active state with their own keys. Departed
  original signers alone cannot invalidate a safely transferred lock. Retain each
  node's own choices, not inherited historical quorum bundles.
- Per-shard default NOT_READY, demand recovery, one bounded job per shard, safe
  verified installation before voting, no eager65536-shard preparation/payment
  queue. Keep required state through authenticated rootTTL+30s; grace is not an
  extension of spend validity.
- Exact original own decisions remain separate from lawful canonical/live reports;
  class2>class1>class0 then min-hash within the highest admitted confirmed class.
  Sanctions require verified incompatible first-party signatures, never hearsay,
  telemetry, lawful branch loss, quota/capacity refusal or cancelled stragglers.
- Dashboard/metrics/topology and aliases stay private. Explicit HTTP gateway
  discovery is public; stale-address fallback and provider credentials stay client-side.
- Keep checked safe parsing, bounded allocation/work, cheap-checks-first and actual
  receiving-shard QUIC verification. No unsafe pointer reinterpretation or new
  parser crate is needed to replace the existing safe header decoder.

Do not turn historical discussions into tasks: DEC-028 suppression has no selected
mechanism; DEC-039 fixed-context construction is reopened; DEC-043 hour was tentative;
mandatory predecessor baton, ordinary-crash risk markers/quarantine and original-
quorum archives are rejected/withdrawn. Q-S3.3-01 one/two payment rounds is still
parked. Broad trust research remains stopped. No package silently selects them.

## 3. Entry gates for unresolved design, separate from coding

Straightforward fail-closed fixes can proceed now. The following design deliverables
must exist before claiming full safety/progress for the dependent implementation.
Writing another interface, passing one test or remaining NOT_READY forever does
not close them. No specific new consensus mechanism is chosen in this plan.

| Gate | Concrete required output | Required counterexamples/assumptions | Dependent packages |
| --- | --- | --- | --- |
| G1 — Current authority | An explicit authenticated roster/domain/admission and snapshot-eligibility contract, with verifier inputs and disagreement behavior. | Divergent local views, invented gateway roster, connected peer without mature ticket, network adoption and conditional<=6 Byzantine scope. Work/topology alone do not prove the fault bound. | A01/A04/A05/A06 |
| G2 — Source completeness/activation | A justified source-continuity and omission-coverage argument plus stable cut/cursor/delta/install/activation contract and conditional progress conditions. | Repeated full turnover, concurrent old/new writes, all original signers gone, agreeing incomplete new sources, 8+6+6 supports with no 14 equal whole-state digest and permanent source loss. No archive/predecessor veto shortcut. | A02/A04/A07 |
| G3 — Support/merge/own-choice | Exact admitted support classes, protected original slot, minimum retained live exclusion/descendant evidence and proof of legal promotion/live reporting versus original equivocation. | Weak low hash, competing confirmed regions, later valid stronger evidence, descendants and honest A-original/B-live report; false accusation across network/purpose. | A01/A03/A06/A08 |
| G4 — Time and restart | One explicit logical-time/delay model and boundary rules for signed walletT0, entry freshness, fixed5min+30sseal, root expiry, passive hourly slots and restart/reentry. | Delay at entry/commit/seal, skew, clock correction, missing/reordered heartbeat, restart with observation history. No second wallet freshness gate after disk wait. | A04/A05/A09/A13 |
| G5 — Actual lost own history | A separate detectable-loss/rollback/key-copy safety and recovery contract stating affected scope, evidence needed for same-key resumption and unavailable outcomes. | Stale DB restore, damaged/deleted own history and copied key/state. Intact durable process crash is A03; current canonical-state copy alone cannot recreate unknown own choices. | A02/A03/A04 |

If a prerequisite cannot be justified under accepted constraints, record the
counterexample and exact unresolved design leaf. Investigate technical options;
ask a new A/B only for a genuine resulting user tradeoff, not for routine encoding,
limits or already approved safety ordering. Dependent safety completion stays open.

## 4. Work order and deliverable boundaries

The table gives a dependency order, not a promise of fixed calendar effort. Each
package is split below into concrete substeps and tests. A14 accompanies all waves.

| Wave | Work | Exit condition |
| --- | --- | --- |
| W0 — Establish actual boundary | Refresh source snapshot/call graph; A14 targeted reproductions; A09.1 locate real host dispatch/storage; start G1–G5 deliverables. | Each claimed defect has a production entry point and reproducible/inspectable condition; external host scope is named, not invented. |
| W1 — Close immediate bypasses | A03 durable pending/own-choice contract, A02 unconditional refusal on unjustified state, A01 shared field/consumer contract; early A07 lock/scheduler/ownership safeguards. A10 privacy may proceed independently. | No RAM/idempotent/self shortcut releases originals; unverified recovery cannot publish READY; old statistical checker cannot act as final payment gate. This is an interim safety boundary, not completed safe turnover. |
| W2 — Justified consensus integration | Close applicable G1–G4 outputs; finish A05 eligibility, A04 transfer and A06 supported merge; finish A01/A02 current live evidence integration. | Full authority/readiness/transfer/merge contract and associated real-interface scenarios pass under explicit assumptions. |
| W3 — Complete bounded flows | Finish A07 bounds/transport, A08 prefix batches, verified A09 host integration, A11 stop, A12 discovery and A13.1 expiry; carry A10 to full alias coverage. | All selected operational/client behavior has concrete tested ownership, bounds and error outcomes; shared formats agree across repositories. |
| W4 — Remaining retention/support | A13.2 persistent metric history, A15 exceptional own-approval retrieval/legacy retirement; close remaining evidence/measurement records. | Lower-priority requirements are implemented within bounds; no original-signer archive dependency returns. |

A package can have partial code delivered while a proof dependency remains open;
report that status explicitly. Do not mark A02 complete just because the no-source
fallback is removed, or A01 complete because a new helper exists. The detailed
package acceptance criteria below control completion.

### Dependency milestones: avoid waiting on mutually unfinished packages

Use small contract and enforcement milestones; a package's final integration
acceptance is not a prerequisite for starting every other package:

| Milestone | Needed before dependent coding | Can proceed meanwhile |
| --- | --- | --- |
| C1 — A01 shared purpose/field contract plus G3 protected original slot | A03 persistent key/value encoding and live producer/consumer adapters | A02 unsafe fallback removal, A07 lock/cancellation fixes, A10 privacy, A09.1 host tracing |
| C2 — A03 atomic storage/ack primitive | Original release-path integration, per-step A08 durable prefix and A11 worker drain | A05 admissible candidate predicate, A04 source/cursor design and A12 advertisement schema |
| C3 — G1/G2/G4 contracts, A05 selection, A07 bounded scheduler and A04 verified install | Automatic A02 READY activation and full current live-proof acceptance | Original non-conflicting durable-path and private-route regression work |
| C4 — G3 admitted support/descendant contract, A01 verified context and A03 immutable choices | A06 canonical replacement/fraud integration and final A04 merge-during-transfer verification | Finite deadline, batching, directory and client storage work using frozen contracts |
| C5 — A01 productive verification plus located A09 host durable dispatch/release | Final end-to-end payment outcome acceptance | A13.2 private history and A15 exceptional retained-own-approval service |

In particular, A04 uses the explicit G3 merge contract while A06 implements its
full enforcement; do not invent an A04/A06 circular “wait until both complete”
gate. Keep unsafe activation disabled until the combined conditions are verified.

## 5. Detailed packages

All implementation tasks below start **pending** in this plan; the audit records
which existing parts must be retained. Checkboxes describe future work, not work
performed during planning. Source DEC links always point to the primary interview
file named in section1. For code evidence, read the corresponding A section of the
[audit](ARCHITECTURE_IMPLEMENTATION_AUDIT.md).

<a id="a01"></a>
### A01 — Connect real live-proof verification to the productive consumer

**Priority:** P0. **Decision source:** `docs/ARCHITECTURE_INTERVIEW_NOTES.md` — [DEC-006](ARCHITECTURE_INTERVIEW_NOTES.md#dec-006), [DEC-015](ARCHITECTURE_INTERVIEW_NOTES.md#dec-015), [DEC-017](ARCHITECTURE_INTERVIEW_NOTES.md#dec-017), [DEC-020](ARCHITECTURE_INTERVIEW_NOTES.md#dec-020), [DEC-021](ARCHITECTURE_INTERVIEW_NOTES.md#dec-021), [DEC-038](ARCHITECTURE_INTERVIEW_NOTES.md#dec-038), [DEC-080](ARCHITECTURE_INTERVIEW_NOTES.md#dec-080), [DEC-081](ARCHITECTURE_INTERVIEW_NOTES.md#dec-081), [DEC-082](ARCHITECTURE_INTERVIEW_NOTES.md#dec-082), [DEC-083](ARCHITECTURE_INTERVIEW_NOTES.md#dec-083), [DEC-084](ARCHITECTURE_INTERVIEW_NOTES.md#dec-084).

**Deliverable:** One shared live-proof contract and one actual consumer acceptance path using it. The existing `humoco-proto` verifier is retained and integrated.

**Affected code:** `../humoco-proto/src/types.rs`, `../humoco-proto/src/verify.rs`; `../human-money-core/src/models/layer2_api.rs`, `../human-money-core/src/services/l2_gateway.rs`, `../human-money-core/src/app_service/conflicts.rs`; node `src/api/hmc.rs`, `src/api/dto.rs`, `src/api/routes.rs`, `src/network/framing.rs`, `src/network/transport.rs`; simulation-core `src/crypto.rs` and corresponding shared adapters. Node paths below are relative to `crates/humoco-node/` unless otherwise stated.

**Implementation steps:**

1. Write one field/encoding table for original write approval, fresh current-state response and sync evidence. Bind network/version, purpose, shard, authenticated root/lifetime, consumed output, exact successor, state/status, committee context and exact request. Add fresh unpredictable recipient challenge/freshness to the live response. Fix exact byte order, bounds, domain tags and error mapping in the existing shared crate before separately changing producers/consumers. Reconcile the existing 1024-byte per-evidence-packet cap and checked total envelope limits with full signed context; report a schema/limit conflict rather than truncate proof or silently enlarge limits.
2. Extend the actual status request/response DTOs and HTTP/QUIC adapters. The existing stable `challenge_ds_tag` lookup is not a fresh recipient challenge. Prevent read/write transplantation by distinct authenticated purposes; legal postmerge live-state observations must not look like new original write approvals.
3. In the application call chain `process_l2_verdict -> evaluate_quorum_certificate`, replace statistical plausibility as an acceptance predicate with actual shared verification of the expected digest, each full-key signature, distinct membership and the required threshold. A gateway-supplied roster does not establish G1 authority. Reject unjustified committee context instead of supplying a permissive fallback.
4. Keep FINAL at fourteen distinct members of one frozen at-most-twenty committee, including eligible self in the same selection. Short IDs, bitmap popcount, signatures from other ranks or an available minority cannot count. Preserve the existing separately classified adaptive PROVISIONAL mode; insufficient FINAL cannot silently downgrade.
5. Preserve separate local-found, provisional, final and uncertain outcomes through `conflicts.rs` and its callers. A local match or gateway `verified` flag must not become final paid confirmation. Actual merchant release belongs to A09.
6. Keep ordinary status at `read_quorum=1` / INV-0310. Full payment verification is explicit; do not add disk writes or a new original signing decision to every read. Bind challenge consumption to its intended checkout rather than relying on wall-clock age alone.
7. Remove or restrict legacy acceptance helpers only after the productive call graph uses the shared implementation. Preserve pure statistical observation functions as diagnostics where still useful, without allowing them to authorize payment.

**Required tests / acceptance:**

- A genuine matching 14/20 proof succeeds through the real application outcome path; 13 votes, fabricated signatures, duplicate keys, short-key collisions and unauthorized/rank21 votes fail there, not only in a helper test.
- Changing network, purpose, root, output, target, status, committee context, request or recipient challenge invalidates the proof. An old proof cannot authorize another checkout. Positive PROVISIONAL cases remain explicitly provisional.
- End-to-end HTTP/QUIC production paths produce the same shared digest as the consumer; ordinary read1 still performs one-source lookup and cannot mark payment complete. Oversized/truncated/overflowing new proof fields fail bounded cheap admission before costly verification or allocation.

**Dependencies / completion gate:** Field-contract work can start immediately. Final authority acceptance requires G1; producer signing requires A02/A03; complete checkout acceptance additionally requires A09. A helper-only integration is not completion.

<a id="a02"></a>
### A02 — One fail-closed per-shard gate at every signing and activation site

**Priority:** P0. **Decision source:** `docs/ARCHITECTURE_INTERVIEW_NOTES.md` — [DEC-026](ARCHITECTURE_INTERVIEW_NOTES.md#dec-026), [DEC-030](ARCHITECTURE_INTERVIEW_NOTES.md#dec-030), [DEC-031](ARCHITECTURE_INTERVIEW_NOTES.md#dec-031), [DEC-041](ARCHITECTURE_INTERVIEW_NOTES.md#dec-041), [DEC-057](ARCHITECTURE_INTERVIEW_NOTES.md#dec-057), [DEC-083](ARCHITECTURE_INTERVIEW_NOTES.md#dec-083), [DEC-084](ARCHITECTURE_INTERVIEW_NOTES.md#dec-084), [DEC-085](ARCHITECTURE_INTERVIEW_NOTES.md#dec-085), [DEC-086](ARCHITECTURE_INTERVIEW_NOTES.md#dec-086).

**Deliverable:** One enforceable readiness/assignment/storage-health predicate used at every countable signature site, with no optimistic READY fallback.

**Affected code:** node `src/daemon.rs` (`ShardReadinessManager`, bootstrap sync, `sync_single_shard`), `src/network/transport.rs` (`NodeRequestHandler`, write/status branches), `src/api/routes.rs` (write/chain/status/self collection), `src/storage/engine.rs`; readiness tests under `crates/humoco-node/tests/`.

**Implementation steps:**

1. Inventory original single/chain writes, idempotent responses, gateway self votes, live-state responses and any retained legacy signer. For each, name the exact current-assignment, per-shard recovered-state, committed-state and storage-health checks; use one shared contract rather than independent booleans with different meanings.
2. Make an unknown/newly assigned shard default NOT_READY. A global healthy daemon or another ready shard must not authorize this shard. Recheck the relevant predicate immediately before exposing a countable signature/self vote, including state/assignment changes during awaits.
3. Remove READY transitions caused solely by no peers, skipped connection/page failures or completion of a transfer loop. Propagate rejected imports, failed commits, truncation and cancellation; do not discard their results. A02 can immediately close these unsafe fallbacks even before a complete replacement transfer is ready.
4. Publish readiness only after A04's verified durable installation and current assignment checks. Make an obsolete recovery completion unable to reactivate a changed assignment. Keep any small local task/assignment token bounded and distinct from a new consensus epoch or rejected snapshot-version history subsystem.
5. Make QUIC and HTTP use the same per-shard gate. A NOT_READY response is neutral and returns promptly; it must neither queue a payment nor create a replacement vote. Unready sources may serve bounded retained data with explicit non-witness status.
6. Separate a genuinely new isolated network's explicitly justified initialization from restart/loss of an existing identity/history. Neither a blank database nor absence of peers establishes the former. Record the actual initialization predicate under G1/G5; do not add automatic empty-state recovery.

**Required tests / acceptance:**

- Global daemon-ready plus shard S NOT_READY: real QUIC/HTTP original, duplicate and live/self paths issue no countable vote; independent ready shard T continues.
- Missing sources, all-page failures, invalid record, failed import/commit, cancellation and stale completion leave S NOT_READY. A successful fully verified A04 install enables S automatically, without a test manually flipping the flag.
- An assignment change during recovery/signature preparation prevents a stale task from publishing ready or releasing an unauthorized signature. Normal neutral responses do not affect peer reputation/presence.

**Dependencies / completion gate:** Immediate refusal/guard fixes are independent work; justified activation depends on A03/A04/A05 and G1/G2. Reporting NOT_READY forever closes an unsafe fallback but does not fulfill the selected recovery/progress goal.

<a id="a03"></a>
### A03 — Atomic own-choice durability and a shared exact commit acknowledgment

**Priority:** P0. **Decision source:** `docs/ARCHITECTURE_INTERVIEW_NOTES.md` — [DEC-029](ARCHITECTURE_INTERVIEW_NOTES.md#dec-029), [DEC-030](ARCHITECTURE_INTERVIEW_NOTES.md#dec-030), [DEC-032](ARCHITECTURE_INTERVIEW_NOTES.md#dec-032), [DEC-033](ARCHITECTURE_INTERVIEW_NOTES.md#dec-033), [DEC-035](ARCHITECTURE_INTERVIEW_NOTES.md#dec-035), [DEC-063](ARCHITECTURE_INTERVIEW_NOTES.md#dec-063), [DEC-070](ARCHITECTURE_INTERVIEW_NOTES.md#dec-070), [DEC-087](ARCHITECTURE_INTERVIEW_NOTES.md#dec-087), [DEC-088](ARCHITECTURE_INTERVIEW_NOTES.md#dec-088).

**Deliverable:** Immutable local original signing decisions in redb, atomic lock+decision persistence and an operation-specific shared acknowledgment before every original approval release.

**Affected code:** node `src/storage/db.rs` (schema/atomic transaction), `src/storage/engine.rs` (admission, pending operations, worker, restart), `src/network/transport.rs`, `src/api/routes.rs`; shared original signature context from A01; existing `tests/storage_tests.rs` plus real-daemon/QUIC tests in A14.

**Implementation steps:**

1. Define the smallest persistent own-choice record containing full node identity, network, protected consumed-output slot, exact approved lock/payload, authenticated root lifetime and exact original approval/verification context required by DEC-070. Persist the actual original signature where needed for exact retrieval; computing it remains RAM work. Do not store fourteen-peer bundles or import another node's own-choice table.
2. Define the protected slot so a fresh bucket/session/nonce cannot permit incompatible original approvals of the same output. Original signing purposes, legal same-content promotion and live-state purposes must compose with G3; a later canonical winner cannot overwrite an existing original choice.
3. Reserve bounded persistence capacity before RAM mutation. Represent a new local operation as pending until its exact lock and own choice commit in one explicitly durable redb transaction. Dequeue, serialization and enqueue success are not acknowledgment.
4. For identical concurrent requests, join the same bounded in-flight operation and share its outcome. Bound operation entries and waiting consumers; reject excess before new work. A retry that sees a pending RAM record must not skip the commit wait through `is_new=false`.
5. Gate all original single/chain, duplicate, local/self and retained legacy release sites on the matching successful acknowledgment. Drop RAM/map guards before await and run blocking redb work in the bounded worker. Safely installed live reads do not require a new disk write or original decision per query; pending uncommitted state must not be promoted through a read.
6. On persistent storage failure, withhold signatures in all scopes depending on that store while leaving diagnosis/control available. Unknown/closed acknowledgments and requester timeout do not count as success. Preserve successful commits after caller cancellation/deadline; do not roll them back automatically or delete state that might already have a released effect.
7. Restore original choices before signing after restart; reconcile additional shared state through A04. Retain exact own approval/context with the authenticated root until `root.valid_until+30s`; coordinated deletion is A13. Record format/version and existing-development-state handling: missing historical own choices cannot be invented from the current canonical winner. DEC-004 permits coordinated breaking development changes, not an automatic unsafe reset of an existing identity.

**Required tests / acceptance:**

- Request A pauses before durable commit; identical B and a status/self request arrive. Observe actual network outputs: no original/countable pending approval escapes until the same transaction commits; waiter/memory limits hold.
- Kill a real daemon before commit, after commit before reply and after reply. Restart with intact durable storage, recover the exact own choice and reject an incompatible fresh original choice even in a later bucket. Observe both DB state and actual received signature bytes.
- Inject commit failure, dropped acknowledgment, late successful commit, cancellation and shared-store failure. No dependent path produces a vote; exact retry reconciles a committed outcome without a second original decision.

**Dependencies / completion gate:** Agree original context/key encoding with A01; bounds integrate with A07, purge with A13. G5 remains required for actual loss/rollback/key copies. Ordinary intact-storage crash needs no root-risk markers, quarantine or identity abandonment.

<a id="a04"></a>
### A04 — Complete authenticated active-state transfer and safe concurrent installation

**Priority:** P0. **Decision source:** `docs/ARCHITECTURE_INTERVIEW_NOTES.md` — [DEC-031](ARCHITECTURE_INTERVIEW_NOTES.md#dec-031), [DEC-045](ARCHITECTURE_INTERVIEW_NOTES.md#dec-045), [DEC-046](ARCHITECTURE_INTERVIEW_NOTES.md#dec-046), [DEC-057](ARCHITECTURE_INTERVIEW_NOTES.md#dec-057), [DEC-058](ARCHITECTURE_INTERVIEW_NOTES.md#dec-058), [DEC-059](ARCHITECTURE_INTERVIEW_NOTES.md#dec-059), [DEC-061](ARCHITECTURE_INTERVIEW_NOTES.md#dec-061), [DEC-083](ARCHITECTURE_INTERVIEW_NOTES.md#dec-083), [DEC-085](ARCHITECTURE_INTERVIEW_NOTES.md#dec-085), [DEC-086](ARCHITECTURE_INTERVIEW_NOTES.md#dec-086).

**Deliverable:** A justified, authenticated full-live-state transfer with a stable cut, bounded catch-up and atomic durable installation before activation.

**Affected code:** node `src/daemon.rs` (`run_shard_digest_pull_sync`, `sync_single_shard`), `src/network/framing.rs` (digest/pull/bucket DTOs), `src/network/transport.rs` (digest/paged service), `src/storage/engine.rs`, `src/storage/db.rs`; simulation-core digest grouping/types and shared encodings; `tests/phase5_pull_sync_and_readiness.rs`, `tests/created_at_bucket_decoupling_tests.rs` and additional actual transfer tests.

**Implementation steps:**

1. Produce the G2 design deliverable first: state exactly which currently qualified sources establish full active-exclusion coverage across turnover, what happens when they disagree, and which source/history loss leaves the shard safely unrecovered. Verify the selected conditional progress goal after communication stabilizes; never treat fourteen newly empty replicas as their own continuity proof.
2. Authenticate source full keys and bind votes to one justified shard/network/committee/request/digest/cut context. Remove local `idx as u16`, socket count and unqualified fallback-to-all-peers as vote identities/authority. Serving retained bytes and being an authoritative witness remain different permissions.
3. Enumerate all still-relevant root-bound records from justified source coverage, not the receiver's oldest local lock, a 24h heuristic, a 365-day clamp or one u16-sized bucket request. Support bounded continuation over the full lifetime. Authenticate root/lifetime and all semantic fields; include required exclusion/verification metadata without historical quorum bundle migration.
4. Replace live re-sorted offset pagination with a stable source cut and bounded no-gap concurrent deltas/continuations. Specify cursor binding, termination, maximum bytes/work, overflow/failure behavior and reconnect handling. Reuse the selected snapshot/delta mechanism; do not introduce a separate historical correction/version-chain subsystem or predecessor permission.
5. Validate every imported record and its owner/root/output/support context before durable application. Reconstruct/check the expected digest, count/range coverage and completion boundary. No ignored import errors, implicit zero-page success or observed transport EOF as completeness proof.
6. Atomically publish the verified installed state and readiness for the still-current assignment, preserving immutable local own choices. On any unknown gap/failed commit/obsolete assignment, keep NOT_READY and allow bounded retry. Partial retained data may remain serviceable, without a countable vote.
7. Unify wallet-signed `created_at_ms` / T0 through HTTP, QUIC, digest and bucket projection. Remove gateway fabrication of a missing signed time and fallback to `encrypted_timestamp`. Preserve 5min buckets, the selected 30s post-end seal and entry-only live freshness; durable waiting does not renew the wallet admission check. Root expiry is still enforced.

**Required tests / acceptance:**

- An empty new node recovers still-valid locks created more than 24h, 227d and 365d ago, using bounded multiple ranges. Expired roots cannot be made spendable by the purge grace.
- Concurrent inserts before/after a cursor, pruning, canonical changes, source departure, restart and reconnect yield complete verified installation or NOT_READY, never silent omission or mixed-cut READY.
- Exercise 8+6+6 independent-lock support with no 14 identical whole-state digest, agreeing incomplete new replicas, duplicate source identities, wrong shard/context and corrupt/truncated data. Demonstrate the chosen G2 coverage/progress conditions; matching bytes alone is insufficient.

**Dependencies / completion gate:** Requires G1/G2/G4 and A03/A05/A07/A02 integration. No algorithm is selected here to fill an unproved G2 premise. Finishing paging alone is not completion of safe turnover.

<a id="a05"></a>
### A05 — Unify eligible HRW selection, ticket admission and passive presence

**Priority:** P0. **Decision source:** `docs/ARCHITECTURE_INTERVIEW_NOTES.md` — [DEC-018](ARCHITECTURE_INTERVIEW_NOTES.md#dec-018), [DEC-019](ARCHITECTURE_INTERVIEW_NOTES.md#dec-019), [DEC-040](ARCHITECTURE_INTERVIEW_NOTES.md#dec-040), [DEC-044](ARCHITECTURE_INTERVIEW_NOTES.md#dec-044), [DEC-048](ARCHITECTURE_INTERVIEW_NOTES.md#dec-048), [DEC-054](ARCHITECTURE_INTERVIEW_NOTES.md#dec-054), [DEC-055](ARCHITECTURE_INTERVIEW_NOTES.md#dec-055), [DEC-056](ARCHITECTURE_INTERVIEW_NOTES.md#dec-056).

**Deliverable:** One candidate eligibility and frozen HRW selection contract used consistently by voting, reads, routing and recovery where applicable.

**Affected code:** node `src/network/manager.rs` (`shard_committee`, routing/presence/ticket paths), `src/network/peer.rs`, `src/network/clock.rs`, relevant identity/presence persistence; simulation-core committee selection; ticket/presence wire tests.

**Implementation steps:**

1. Specify the G1 candidate-admission basis and G4 hourly-slot/reentry boundaries. Identity/work-backed admission, observed ticket maturation, presence, transport health and per-shard readiness are independent facts; neither a valid signature nor a connected socket proves the whole set.
2. Reuse the full256-bit HRW/deterministic full-key tie break and deduplication. Require identity-bound verified mature Argon2d ticket and valid admission for self and remote members. Remove the connected-unknown-peer path substituting `NodePubKey` as `HrwRoutingId`; check self eligibility before including self.
3. Preserve at most one active and one announced stronger successor ticket per identity, including the monotonic work ratchet and reset maturation when replacing a pending ticket. Persist or safely reconstruct the observations required across restart; do not infer observed age from a self-signed old timestamp.
4. Implement three consecutive missed hourly F2F gossip heartbeats for later-snapshot exclusion. Unify paths that currently ignore presence or use a2h freshness filter. Define slot closing/freshness and reentry under G4; no new timing default is silently chosen by this plan.
5. Keep local RPC timeout/backoff/suspension diagnostic and independent from future committee presence. NOT_READY, nonmembership, overload, normal idle closure and quorum cancellation are neutral. F2F gossip remains friend-only; learned shard RPC authorization does not imply voting membership.
6. Freeze one at-most-twenty roster per checkout including eligible self. Apply only the existing separately justified network-mode stability rule. Ticket24h, accounting epoch_day and presence slots do not become daily committee terms or rank21 replacement permission.

**Required tests / acceptance:**

- Unknown connected peer, immature ticket, duplicate identity and ineligible self gain no seat. Valid ticket upgrade matures normally without losing identity-bound friendships.
- RPC misses/capacity/idle/cancellation leave candidate presence unchanged. Three missed hourly gossip slots affect later snapshots; an already frozen request is unchanged.
- Restart, boundary-skew and reentry follow the explicit G4 contract. Node/gateway/recovery routes derive the same selection from identical admissible inputs; tests do not claim global agreement from differing inputs.

**Dependencies / completion gate:** Candidate-filter corrections can start immediately; actual authenticated electorate/fault-bound claims require G1 and timing behavior G4. Tickets and operator belief are not proof of <=6 Byzantine identities.

<a id="a06"></a>
### A06 — Class-aware supported merge and correct conflict/quorum precedence

**Priority:** P0. **Decision source:** `docs/ARCHITECTURE_INTERVIEW_NOTES.md` — [DEC-014](ARCHITECTURE_INTERVIEW_NOTES.md#dec-014), [DEC-022](ARCHITECTURE_INTERVIEW_NOTES.md#dec-022), [DEC-023](ARCHITECTURE_INTERVIEW_NOTES.md#dec-023), [DEC-053](ARCHITECTURE_INTERVIEW_NOTES.md#dec-053), [DEC-054](ARCHITECTURE_INTERVIEW_NOTES.md#dec-054), [DEC-064](ARCHITECTURE_INTERVIEW_NOTES.md#dec-064), [DEC-065](ARCHITECTURE_INTERVIEW_NOTES.md#dec-065), [DEC-066](ARCHITECTURE_INTERVIEW_NOTES.md#dec-066), [DEC-067](ARCHITECTURE_INTERVIEW_NOTES.md#dec-067).

**Deliverable:** Authenticated class-aware canonical state and explicit precedence between valid completion proof, weak collision evidence and actual fraud.

**Affected code:** node `src/storage/engine.rs` (HMC sync/canonical replacement), `src/api/routes.rs` (collector and 409 branches), `src/network/transport.rs` (conflict/equivocation evidence), simulation-core `src/resolver.rs`, state/support types, shared verification; relevant wire merge/quorum and anti-framing tests.

**Implementation steps:**

1. Under G3 define admissible support and minimum live exclusion/descendant evidence. A peer carrying a valid proof is different from a single unsupported witness. State without sufficient justified support remains unresolved rather than acquiring a confirmed class from a low hash.
2. Make production HMC sync and the core resolver apply valid class2>class1>class0 consistently; min(H_canon) only compares admitted candidates in the highest confirmed class. Two class0 candidates cannot create a confirmed winner. Separate stored evidence from a self-asserted status byte.
3. Preserve original immutable own choices when canonical state changes. Define necessary losing-descendant/VOID/promotion effects and evidence retention, without storing the entire losing tree or inherited old quorums. Reconsider later admissible support under the selected class rule; never revive expired roots.
4. In every write/chain/status completion handler, verify the actual matching quorum before interpreting a weaker competing observation as a veto. Fourteen valid matching frozen-committee votes plus one unsupported collision must not produce409. A separately justified competing confirmed branch is evaluated by its own class/merge rules.
5. Return bounded authenticated collision context inline with 409: exact conflicting consumed output/root/lock and sufficient original authorization/support as required by the finalized format. Keep conflict and insufficient-quorum/unknown outcomes distinct; no mandatory extra cache/reference-fetch round.
6. Permit permanent node sanctions only for two genuine incompatible original approvals of the same full identity in the same protected network/slot/purpose context. Verify both signatures and context. Lawful original losers and later purpose-separated canonical live reports are not fraud; cross-domain messages, reporter claims and telemetry are not substitutes.

**Required tests / acceptance:**

- A lower hash with weaker/unconfirmed support cannot displace a confirmed branch; higher admitted class wins even with larger hash; equal highest class converges deterministically. Invalid/unsupported state remains unresolved.
- Actual HTTP/QUIC collection of 14 valid matching votes plus one weak 409 succeeds. 13 valid votes plus collision/invalid extras does not manufacture completion. Strong competing support is evaluated separately.
- Honest A-original then merged-B-live report is legal; actual incompatible same-slot originals are sanctionable; wrong key/network/purpose/reporter packets cannot frame a node. Descendant and expiry behavior follows G3.

**Dependencies / completion gate:** Requires G1/G3, A01 proof format/verification, A03 immutable choices and A04 authenticated state. The minority-veto branch can be corrected once the matching proof is genuinely verified; bare vote count is insufficient.

<a id="a07"></a>
### A07 — Bound worker, recovery, retry and transport lifecycles

**Priority:** P1. **Decision source:** `docs/ARCHITECTURE_INTERVIEW_NOTES.md` — [DEC-008](ARCHITECTURE_INTERVIEW_NOTES.md#dec-008), [DEC-024](ARCHITECTURE_INTERVIEW_NOTES.md#dec-024), [DEC-025](ARCHITECTURE_INTERVIEW_NOTES.md#dec-025), [DEC-027](ARCHITECTURE_INTERVIEW_NOTES.md#dec-027), [DEC-028](ARCHITECTURE_INTERVIEW_NOTES.md#dec-028), [DEC-042](ARCHITECTURE_INTERVIEW_NOTES.md#dec-042), [DEC-060](ARCHITECTURE_INTERVIEW_NOTES.md#dec-060), [DEC-085](ARCHITECTURE_INTERVIEW_NOTES.md#dec-085), [DEC-086](ARCHITECTURE_INTERVIEW_NOTES.md#dec-086), [DEC-088](ARCHITECTURE_INTERVIEW_NOTES.md#dec-088).

**Deliverable:** Bounded persistence/recovery/retry/connection resources with explicit admission, cancellation and independent internal service progress.

**Affected code:** node `src/daemon.rs` (task scheduling/readiness locks), `src/api/routes.rs` (trigger/collection/retries), `src/storage/engine.rs` (batch/ack/waiters), `src/network/transport.rs`, `src/network/manager.rs`, `src/network/tls.rs`, relevant configuration/private metrics.

**Implementation steps:**

1. Correct the readiness manager's opposite lock ordering; use one documented order or one small state boundary so trigger/complete/fail cannot deadlock. Guarantee cleanup on every return, error, panic-equivalent task failure and cancellation; a failed task must not leave a permanent untracked Syncing entry.
2. Put periodic repair and demand-triggered repair behind one bounded admission/dedup contract. At most one active job per shard, bounded total active shards/queued work/bytes and daemon-owned cancellation. Perform cheap authorization/rate/admission before creating recovery work. No eager sweep over all 65,536 assignments or node-side payment queue.
3. Define separately bounded budgets for locally originated gateway work, inbound shard service and required sync progress. Do not claim protection from a single shared semaphore or a VIP label. Reject excess promptly; never evict an active RPC to admit a newer request.
4. Implement time/item/byte-limited batch sealing, finite queue/ack wait and bounded identical-operation coalescing/waiters with A03. Single-load operations seal without waiting for a full batch. Measure all sizes before choosing defaults; original safety ordering is unconditional on disk speed.
5. Keep the conditional three-send policy on exactly the same serialized payload/T0. Own/track the third background attempt under a finite task/work/time/cancellation contract; quorum cancellation and shutdown reclaim it without peer malus. Preserve all-member initial dispatch,800ms collection and no checkout signer expansion.
6. Implement role-specific connection lifecycle: persistent F2F keepalive; shard-direct bounded idle-first LRU pool in the selected128–256 range,15s idle/no keepalive. Include outgoing sessions and concurrent RPC budgets rather than relying only on incoming handshake limits. Full active capacity refuses new work neutrally.
7. Add only bounded private diagnostics for queue/batch/commit/ack/recovery/socket/waiter behavior. Define measurements and overload outputs; avoid new high-cardinality/public metric or per-client historical state.

**Required tests / acceptance:**

- Retry/first-demand floods, many different shard IDs, slow disk and mixed public/read/QUIC load remain within declared memory/task/queue/connection bounds while protected service progresses under the stated workload.
- Concurrent trigger/completion/failure/stop cannot exercise the old lock inversion; no task or active-shard token leaks. Exact retries share one commit and bounded waiters.
- Single operation seals by time; byte/item thresholds seal correctly; post-quorum cancellation/idle/capacity are neutral. Shard connections idle out without pings; F2F stays persistent; active RPCs are not LRU victims.

**Dependencies / completion gate:** Scheduler/lock/cancellation/budget scaffolding starts early with A02/A03, not after safe recovery. Exact schema sizes from A01/A04 inform byte limits. DEC-028 suppression remains deferred; no new algorithm for it is selected.

<a id="a08"></a>
### A08 — Valid-prefix ancestry batches with explicit work/byte limits

**Priority:** P1. **Decision source:** `docs/ARCHITECTURE_INTERVIEW_NOTES.md` — [DEC-005](ARCHITECTURE_INTERVIEW_NOTES.md#dec-005), [DEC-010](ARCHITECTURE_INTERVIEW_NOTES.md#dec-010), [DEC-011](ARCHITECTURE_INTERVIEW_NOTES.md#dec-011), [DEC-012](ARCHITECTURE_INTERVIEW_NOTES.md#dec-012), [DEC-013](ARCHITECTURE_INTERVIEW_NOTES.md#dec-013), [DEC-014](ARCHITECTURE_INTERVIEW_NOTES.md#dec-014).

**Deliverable:** Durable valid-prefix ancestry reconciliation with exact consumed-output causality and bounded verification cost.

**Affected code:** node `src/api/hmc.rs` (chain DTO/contract), `src/api/routes.rs`, `src/storage/engine.rs` (`ingress_hmc_chain_lock*`, `verify_chain_causality`), transport chain adapters and shared/core chain-building models.

**Implementation steps:**

1. Replace the current all-or-nothing prevalidation/mutation contract. For an ordered causal path, validate and admit steps in order, preserve the successfully accepted prefix and stop at the first invalid/conflicting/unavailable step. A transport batch is not a distributed atomic transaction.
2. For each newly accepted original step use A03's exact atomic lock+own-choice transaction/release semantics. Already committed earlier steps survive a later failure or timeout. Report the known accepted boundary and uncertainty honestly; do not report unacknowledged steps as durably confirmed.
3. Return enough exact target/accepted-prefix/failing-step information for idempotent client reconciliation, with shared encoding and bounded inline conflict evidence. A retry recognizes previously committed prefix records and resumes safely without changing the original payload/T0.
4. Validate only the necessary path to the requested target, including required common ancestors and exact split/output/root/owner binding. Do not demand unrelated sibling subtrees or historical L2 receipt chains. Keep one model for genesis/successor cases.
5. Enforce explicit request byte, lock count, path/hop and verification-work bounds before expensive work. Reconcile existing 16-locator/64-lock batch limits and current implementation differences using the canonical Spec04 contract; do not silently raise limits or treat count as an aggregate byte cap. Invalid framing/whole-request admission may reject before processing; once an admitted ordered path is being processed, a later step failure cannot undo its committed prefix.

**Required tests / acceptance:**

- Steps1–3 valid and step 4 conflicting/invalid:1–3 remain durable;4and descendants are not accepted. Retry sees precisely the preserved prefix.
- Queue/storage failure midway reports committed versus pending/uncertain state accurately, with no original signature before its step commits.
- Wrong split output/root/owner, unrelated sibling dump and oversized/deep/malformed batch fail at the appropriate boundary without unbounded work. Genesis and successor positive cases remain supported.

**Dependencies / completion gate:** A03 durability, A01 DTO/verification and necessary G3 output/descendant rules. Within-batch prefix success is not final payment release without the required quorum evidence.

<a id="a09"></a>
### A09 — Establish real wallet/PoS dispatch, recovery and release integration

**Priority:** P1; external scope. **Decision source:** `docs/ARCHITECTURE_INTERVIEW_NOTES.md` — [DEC-009](ARCHITECTURE_INTERVIEW_NOTES.md#dec-009), [DEC-010](ARCHITECTURE_INTERVIEW_NOTES.md#dec-010), [DEC-017](ARCHITECTURE_INTERVIEW_NOTES.md#dec-017), [DEC-020](ARCHITECTURE_INTERVIEW_NOTES.md#dec-020), [DEC-021](ARCHITECTURE_INTERVIEW_NOTES.md#dec-021), [DEC-042](ARCHITECTURE_INTERVIEW_NOTES.md#dec-042), [DEC-060](ARCHITECTURE_INTERVIEW_NOTES.md#dec-060), [DEC-068](ARCHITECTURE_INTERVIEW_NOTES.md#dec-068), [DEC-071](ARCHITECTURE_INTERVIEW_NOTES.md#dec-071), [DEC-072](ARCHITECTURE_INTERVIEW_NOTES.md#dec-072), [DEC-073](ARCHITECTURE_INTERVIEW_NOTES.md#dec-073), [DEC-079](ARCHITECTURE_INTERVIEW_NOTES.md#dec-079), [DEC-080](ARCHITECTURE_INTERVIEW_NOTES.md#dec-080), [DEC-082](ARCHITECTURE_INTERVIEW_NOTES.md#dec-082).

**Deliverable:** Verified integration at the real host wallet/PoS boundary, implementing only gaps actually found there.

**Affected code:** known HMC entry points `../human-money-core/src/app_service/conflicts.rs`, `../human-money-core/src/services/l2_gateway.rs`, `../human-money-core/src/services/latency_router.rs` and wallet storage/callers. The actual host/Tauri HTTP transport, wallet-pending store and merchant journal files are **not yet located/audited**; finding their real paths is A09.1, not an assumption that they are missing.

**Implementation steps:**

1. Trace the actual production caller from prepare/generate request through durable wallet transaction, first HTTP dispatch, gateway choice, response processing and final user/merchant outcome. Record repository, revision, files and owner for each boundary; distinguish simulator and stateless helpers from production application code.
2. Reuse the host's existing durable transaction machinery. Before the first network send, atomically persist exact signed request bytes, wallet-created T0 and the consumed output's pending intent. A restart/retry/gateway change uses those same bytes; do not re-sign with a fresh T0 or create a second incompatible pending payment.
3. Implement missing bounded automatic retries/reconciliation using the selected conditional send policy and growing read backoff. A timeout is uncertain, not a free output. After the live freshness window, reconcile read-only; the node stores no pending-payment queue and does not manage purchase state.
4. Preserve local-found/provisional/final/uncertain distinctions from A01. The actual recipient verifies the proof before release and durably stores the received L1 voucher plus its purchase-journal binding. Do not require completed-checkout storage or back-fill of a historical fourteen-signature L2 bundle.
5. Keep uncertain components of multi-voucher purchases uncertain and completed components as partial payment. No automatic replacement payment/refund while an earlier spend is uncertain; changing tender for the remainder is a deliberate cashier/customer action outside node consensus.
6. Use recipient-selected gateways/justified evidence sources. For network statistics use multiple independently selected sources with network/freshness checking and explicit disagreement handling, not a precise average from incompatible observations. Statistics never authenticate a committee.
7. Integrate A12 public discovery and bounded last-known-address fallback inside the client only. Keep credentials scoped to their provider; a friend/VIP token is never forwarded to every discovered gateway. Authenticate endpoints and respect explicit revocations. Do not implement a server consensus/cache-fallback policy.

**Required tests / acceptance:**

- Kill the actual application around the pre-send transaction and response/purchase transaction. Restart recovers the exact intent/pending output or durable purchase; no double send with a newly constructed payload and no falsely final outcome.
- Gateway failure, stale directory, expired freshness and uncertain partial purchase follow finite retries/read-only recovery, preserve credentials and never automatically issue replacement tender.
- A local match, invalid proof, replay or source disagreement never releases goods as final. A verified acceptable current proof plus durable L1/purchase storage allows the intended release without receipt archives.

**Dependencies / completion gate:** First a bounded scope inspection, then only missing host changes. Depends on A01/A12 and G1/G4 for relevant semantics. External-unverified in the audit is not proof of global absence; this package cannot be marked done by only changing a generator or simulator.

<a id="a10"></a>
### A10 — Separate every private diagnostic route and alias from public ingress

**Priority:** P1; independent. **Decision source:** `docs/ARCHITECTURE_INTERVIEW_NOTES.md` — [DEC-002](ARCHITECTURE_INTERVIEW_NOTES.md#dec-002), [DEC-037](ARCHITECTURE_INTERVIEW_NOTES.md#dec-037), [DEC-077](ARCHITECTURE_INTERVIEW_NOTES.md#dec-077), [DEC-082](ARCHITECTURE_INTERVIEW_NOTES.md#dec-082), [DEC-088](ARCHITECTURE_INTERVIEW_NOTES.md#dec-088).

**Deliverable:** A genuinely private operator surface, retaining useful dashboard/control functions and separate public client routes.

**Affected code:** node `src/api/routes.rs` (`build_router`/aliases), `src/api/dashboard.rs`, `src/api/metrics.rs`, `src/api/history.rs`, `src/api/events.rs`, `src/daemon.rs` listener wiring, `src/config.rs`, control socket server/auth and operator documentation.

**Implementation steps:**

1. Enumerate every route, alias, nested route and listener exposing dashboard, metrics, topology/peers, history/events, lock/voucher inspection, queue/storage/quota diagnostics or mutations. Include public status/health fields that currently re-export those details.
2. Move operator functions behind the selected dedicated local/private operator listener and protected control-socket authority. Enforce intended filesystem/listener/auth permissions rather than treating failed chmod as an acceptable protection result. Preserve operator SSH-forwarded access and sovereignty.
3. Keep public lock/status/required health/work interfaces permissionless under their own admission rules and restrict their responses to intended client data. A token on an admin mutation does not protect the diagnostic GET tree; CORS is not authentication.
4. Remove public diagnostic aliases or make them deny access under the same private boundary. Retain a separate explicitly public HTTP gateway directory from A12, without making internal `/peers` topology public.
5. Preserve bounded useful dashboard functionality and private history. Keep OS logs outside in-memory dashboard log buffers; add no manual prune/backup orchestration or cosmetic controls prohibited by AGENTS.md.

**Required tests / acceptance:**

- Real requests to every public diagnostic route/alias/subroute/listener fail to obtain private data; an authorized private operator can use the intended features.
- Anonymous public lock/status and explicit gateway discovery still work under their admission rules. No guessed public key grants friend/VIP/admin authority.
- Failed permission setup and unintended bind address fail safely; remote private access works only through the configured protected operator boundary. Tests check returned fields as well as status codes.

**Dependencies / completion gate:** Independent of consensus design; can be implemented early in parallel. A12's explicit public directory and A13's private metric store must preserve the separation.

<a id="a11"></a>
### A11 — Truthful bounded shutdown and verified stop completion

**Priority:** P1. **Decision source:** `docs/ARCHITECTURE_INTERVIEW_NOTES.md` — [DEC-034](ARCHITECTURE_INTERVIEW_NOTES.md#dec-034), [DEC-036](ARCHITECTURE_INTERVIEW_NOTES.md#dec-036), [DEC-074](ARCHITECTURE_INTERVIEW_NOTES.md#dec-074), [DEC-075](ARCHITECTURE_INTERVIEW_NOTES.md#dec-075), [DEC-076](ARCHITECTURE_INTERVIEW_NOTES.md#dec-076), [DEC-088](ARCHITECTURE_INTERVIEW_NOTES.md#dec-088).

**Deliverable:** One bounded daemon stop lifecycle with truthful completion and a CLI that verifies the clean target process has exited and released its database.

**Affected code:** node `src/daemon.rs` (signals/teardown), `src/control/server.rs`, `src/control/client.rs`, `src/control/types.rs`, CLI stop entry points, `src/storage/engine.rs` worker lifecycle and existing systemd/Docker stop settings.

**Implementation steps:**

1. Define one absolute monotonic internal shutdown deadline at the first accepted ordinary stop signal/request. Repeated SIGTERM/SIGINT cannot shorten, reset or extend it. Document the longer supervisor fallback; numeric examples in the interview are not selected defaults.
2. Stop new admission, then stop/await producers and owned recovery/retry tasks before closing/draining accepted persistence work. Apply the same finite deadline to every join/drain/ack, and evaluate JoinErrors, flush failures and unfinished work instead of discarding them.
3. Keep durability unconditional: an uncommitted accepted request may remain uncertain, but no signature is manufactured to finish the drain. Preserve successful late commits; never roll back a committed lock because stop/client wait expired.
4. Define the smallest trustworthy local completion mechanism binding the target process instance, clean/incomplete result and completed storage teardown. Socket disappearance alone, PID reuse or a stop-request acknowledgment cannot certify clean completion. Do not add a new distributed coordinator or dashboard lifecycle service.
5. Make default stop wait boundedly for confirmed clean completion, actual target exit and released redb handle/lock. Return nonzero on timeout/failed/unknown/incomplete completion; daemon deadline remains independent of the CLI's own wait. A stuck blocking storage task cannot be declared gone merely by dropping its async handle.
6. Preserve the existing native systemd-first and optional Docker/Compose deployment artifacts. Align their outer stop margin with the chosen internal budget and ensure operator SIGKILL remains an explicit force-stop with unclean recovery semantics.

**Required tests / acceptance:**

- Actual daemon processes handle normal stop, repeated signals, saturated persistence and slow worker within the original deadline; injected failure produces an honest nonzero/incomplete result.
- Independently reopen the same DB from another process only after reported clean completion and verify the target process instance ended. Removing its socket early must not make stop succeed.
- A stalled blocking write, interrupted CLI and outer supervisor force-stop cannot bypass A03 durability or misreport a clean result; restart reapplies readiness/storage-safety gates.

**Dependencies / completion gate:** Integrates A03/A07/A02 task and storage lifecycle. Shutdown infrastructure can proceed before complete recovery, but end-to-end completion needs those producer/worker guarantees.

<a id="a12"></a>
### A12 — Advertise real public HTTP gateways instead of P2P-port URLs

**Priority:** P1. **Decision source:** `docs/ARCHITECTURE_INTERVIEW_NOTES.md` — [DEC-078](ARCHITECTURE_INTERVIEW_NOTES.md#dec-078), [DEC-079](ARCHITECTURE_INTERVIEW_NOTES.md#dec-079), [DEC-082](ARCHITECTURE_INTERVIEW_NOTES.md#dec-082).

**Deliverable:** Explicit bounded public HTTP gateway advertisements and discovery, independent of private topology and client cache policy.

**Affected code:** node `src/config.rs`, public-address advertisement DTOs/allowed heartbeat metadata in `src/network/framing.rs` and `src/network/manager.rs`, `src/api/routes.rs` directory, shared models if required; HMC/host discovery consumer is A09.

**Implementation steps:**

1. Add/validate explicit published HTTP(S) gateway endpoint metadata for operators choosing to expose client ingress. A known QUIC/P2P address is not an HTTPS endpoint and must never be converted by prepending `https://`.
2. Bind advertisements to the permitted authenticated identity/network metadata and reuse passive learned knowledge. Define bounded endpoint lengths/counts, deduplication, freshness/revocation handling and omission for nodes that publish no client ingress. Discovery is a candidate list, not current reachability or voting authority.
3. Expose a bounded read endpoint intended for public client discovery; exact route naming is an engineering choice. Return only explicit public HTTP endpoints/necessary public metadata, without peer friendship graph, internal addresses, private metrics or credentials.
4. Preserve bootstrap/custom gateway configuration and recipient choice. Do not automatically probe the entire mesh or add a new gossip stream. Ordinary directory load remains bounded under the public read policy.
5. Provide the client contract to A09. Server discovery does not implement client stale-cache fallback, store client payment state or select an authoritative committee for the recipient.

**Required tests / acceptance:**

- A node with P2P address only produces no invented HTTPS gateway; explicitly published HTTP endpoint round-trips through authenticated allowed metadata and directory filtering.
- Duplicate/oversized/malformed/wrong-network/revoked advertisements remain bounded and cannot expose private fields. Directory unavailability remains a client candidate-selection issue.
- Public directory is reachable under its intended read rules while A10 private topology/metric aliases remain inaccessible.

**Dependencies / completion gate:** Can proceed alongside A10 and A09 contract work. Authentication/freshness uses the agreed domain/admission context, never a new trust shortcut.

<a id="a13"></a>
### A13 — Bound expiry processing and finish private metric retention

**Priority:** P1/P2. **Decision source:** `docs/ARCHITECTURE_INTERVIEW_NOTES.md` — [DEC-003](ARCHITECTURE_INTERVIEW_NOTES.md#dec-003), [DEC-035](ARCHITECTURE_INTERVIEW_NOTES.md#dec-035), [DEC-070](ARCHITECTURE_INTERVIEW_NOTES.md#dec-070), [DEC-088](ARCHITECTURE_INTERVIEW_NOTES.md#dec-088).

**Deliverable:** Bounded automatic expiry work and complete bounded private metric retention. Treat these as separate subdeliverables so metrics do not delay safety cleanup.

**Affected code:** node `src/storage/engine.rs` (`prune_expired`/worker), `src/storage/db.rs` (expiry iteration/indexes), RAM expiry indexes, `src/api/history.rs`, `src/api/metrics.rs` and private loading/persistence lifecycle.

**Implementation steps:**

1. A13.1 / P1: replace whole-expired-set collection/scanning with bounded count/byte/time chunks and a continuation/progress contract. Keep short RAM mutation sections; execute blocking DB pruning through the bounded blocking worker, not directly on an async runtime thread.
2. Use authenticated `root.valid_until+30s` for physical purge of active locks and associated original own-choice/approval context. Logical expiry rejects spending immediately at validity end even when physical cleanup is delayed. Grace never authorizes a spend and no permanent expired-lock tombstone is introduced.
3. Coordinate RAM/DB/index/pending-task cleanup with A03 and installed-state reads, without erasing a still-required own choice or letting a late stale task resurrect an expired entry. Give expiry bounded progress capacity without starving checkout/sync.
4. A13.2 / P2: retain existing minute-resolution24h history and add bounded persistent hourly summaries for one year. Define aggregation per metric (for example counter deltas versus gauges and latency distributions) rather than blindly averaging all values; document reset/missing-sample behavior.
5. Restore retained summaries after restart, prune the history within a declared fixed storage budget and account for actual record/index metadata costs. Persist in background and expose only through A10 private diagnostics. No unbounded per-request/per-lock history or browser prune control.

**Required tests / acceptance:**

- Large expired populations are processed in bounded chunks with measurable progress; active requests/required sync continue and the async runtime performs no direct blocking prune.
- Older-than 24h unexpired root state/own choices survive; expired spending fails before deletion; all corresponding eligible RAM/DB records eventually disappear after grace without resurrection.
- History rolls minute/hour/year boundaries, survives process restart, handles counter resets/missing intervals under its documented aggregation and remains within measured fixed bounds; public aliases reveal none.

**Dependencies / completion gate:** A13.1 needs A03 own-choice lifecycle and G4 safe time; A13.2 needs A10 privacy. Expiry and history have distinct acceptance records and priorities.

<a id="a14"></a>
### A14 — Provide actual-path adversarial and real-process acceptance evidence

**Priority:** P0/P1; continuous. **Decision source:** `docs/ARCHITECTURE_INTERVIEW_NOTES.md` — [DEC-016](ARCHITECTURE_INTERVIEW_NOTES.md#dec-016), [DEC-022](ARCHITECTURE_INTERVIEW_NOTES.md#dec-022), [DEC-026](ARCHITECTURE_INTERVIEW_NOTES.md#dec-026), [DEC-029](ARCHITECTURE_INTERVIEW_NOTES.md#dec-029), [DEC-030](ARCHITECTURE_INTERVIEW_NOTES.md#dec-030), [DEC-034](ARCHITECTURE_INTERVIEW_NOTES.md#dec-034), [DEC-035](ARCHITECTURE_INTERVIEW_NOTES.md#dec-035), [DEC-044](ARCHITECTURE_INTERVIEW_NOTES.md#dec-044), [DEC-056](ARCHITECTURE_INTERVIEW_NOTES.md#dec-056), [DEC-057](ARCHITECTURE_INTERVIEW_NOTES.md#dec-057), [DEC-058](ARCHITECTURE_INTERVIEW_NOTES.md#dec-058), [DEC-059](ARCHITECTURE_INTERVIEW_NOTES.md#dec-059), [DEC-064](ARCHITECTURE_INTERVIEW_NOTES.md#dec-064), [DEC-067](ARCHITECTURE_INTERVIEW_NOTES.md#dec-067), [DEC-074](ARCHITECTURE_INTERVIEW_NOTES.md#dec-074), [DEC-075](ARCHITECTURE_INTERVIEW_NOTES.md#dec-075), [DEC-076](ARCHITECTURE_INTERVIEW_NOTES.md#dec-076), [DEC-077](ARCHITECTURE_INTERVIEW_NOTES.md#dec-077), [DEC-080](ARCHITECTURE_INTERVIEW_NOTES.md#dec-080), [DEC-084](ARCHITECTURE_INTERVIEW_NOTES.md#dec-084), [DEC-085](ARCHITECTURE_INTERVIEW_NOTES.md#dec-085), [DEC-086](ARCHITECTURE_INTERVIEW_NOTES.md#dec-086), [DEC-087](ARCHITECTURE_INTERVIEW_NOTES.md#dec-087), [DEC-088](ARCHITECTURE_INTERVIEW_NOTES.md#dec-088), [DEC-089](ARCHITECTURE_INTERVIEW_NOTES.md#dec-089).

**Deliverable:** Executed evidence for actual production enforcement of each completed package, not a standalone last-stage simulation report.

**Affected code/tests:** extend existing node tests in `crates/humoco-node/tests/`, actual node daemon process harnesses and HMC/shared consumer tests. Existing candidates include `quorum_assembly_tests.rs`, `status_reconciliation_tests.rs`, `phase5_pull_sync_and_readiness.rs`, `anti_self_slashing_wire_tests.rs`, `phase11_wire_level_adversarial_tests.rs`, `created_at_bucket_decoupling_tests.rs`, `subquorum_canonical_merge_tests.rs`, `storage_tests.rs`, `control_tests.rs`, `api_tests.rs`, `cluster_e2e_tests.rs`. New test files are implementation outputs, not claimed existing artifacts. The shared and HMC verifiers also need tests at their real callers.

**Implementation steps:**

1. Before each defect fix, identify the exact current production call path and smallest failing/relevant regression scenario from this plan. Reuse or strengthen existing tests after reading their assertions; do not duplicate a helper test that cannot observe the affected boundary.
2. Exercise actual authenticated QUIC against the receiving shard independently of HTTP filtering for network defenses, wrong context/replay, quotas, malformed frames, readiness and fraud. Include positive controls and state/queue effects, not only an error string.
3. For durability and stop, run real daemon subprocesses, synchronize at commit/release boundaries, observe actual outbound signatures and reopen durable storage from an independent process. A manually set readiness flag, worker-handle abort after commit or in-memory mock is not an automatic recovery/process-crash test.
4. Exercise the productive HMC/host result path for A01/A09: 14 valid versus 13/forged/duplicate/unauthorized, found versus paid, wrong challenge and durable local release ordering. Test a legitimate postmerge live response separately from incompatible original approvals.
5. Under explicit hardware/filesystem/durability/workload settings, measure collision CPU, batch/queue/commit/ack and end-to-end collection separately. Verify declared resource ceilings and protected progress. Targets including1–5ms storage and<20ms local service are not preexisting measurements; slow storage never relaxes durable-before-release.
6. Record per package: decision IDs, actual revisions including dirty-file fingerprints if relevant, scenario/input, expected wire/state/process outcome, exact executed command/environment, observed result and artifact. Keep selected requirement, justified design, source implementation and executed verification as four independent statuses.
7. Execute targeted relevant suites during implementation. For a completed coordinated change run each affected repository's required standard checks, including node workspace tests and strict Clippy as applicable. Do not rerun a large campaign merely because a documentation plan was written; failures and unresolved premises stay visible.

**Required tests / acceptance:**

- Every implemented task in A01–A13/A15 has its stated positive and negative boundary coverage with an actual result record. Broad preexisting green counts are not substituted for these scenarios.
- G1–G5 reasoning and counterexamples are linked where required; a passing test under weaker assumptions cannot close an unresolved safety premise.
- No network defense is accepted on simulation/HTTP-only evidence. No process durability claim relies solely on in-memory/worker-abort behavior. No helper-only full-key test certifies the unmodified productive outcome path.

**Dependencies / completion gate:** Starts in the first work wave and accompanies every package; no test execution is claimed in this planning deliverable. Avoid speculative test names/commands presented as already runnable or already passing.

<a id="a15"></a>
### A15 — Bounded original-own-approval retrieval and legacy path cleanup

**Priority:** P2; exceptional path. **Decision source:** `docs/ARCHITECTURE_INTERVIEW_NOTES.md` — [DEC-004](ARCHITECTURE_INTERVIEW_NOTES.md#dec-004), [DEC-006](ARCHITECTURE_INTERVIEW_NOTES.md#dec-006), [DEC-038](ARCHITECTURE_INTERVIEW_NOTES.md#dec-038), [DEC-055](ARCHITECTURE_INTERVIEW_NOTES.md#dec-055), [DEC-069](ARCHITECTURE_INTERVIEW_NOTES.md#dec-069), [DEC-070](ARCHITECTURE_INTERVIEW_NOTES.md#dec-070), [DEC-089](ARCHITECTURE_INTERVIEW_NOTES.md#dec-089).

**Deliverable:** Bounded exceptional access to retained original own approvals where useful for uncertain attempts, plus removal of proven-obsolete competing implementations.

**Affected code:** node own-choice storage/API and shared retrieval DTOs finalized during implementation; HMC/host reconciliation caller; existing `src/api/hmc.rs`, node/core adapter paths and `../human-money-core/src/services/l2_gateway.rs` legacy statistical acceptance helpers. No retrieval endpoint or schema is claimed already present.

**Implementation steps:**

1. After A03 retains exact original own approvals, define a read-only bounded request/response for one uncertain original checkout context. Query existing original decisions without changing T0, writing a new lock, requesting a replacement vote or selecting a different committee.
2. Bind exact identity/network/slot/target/original context and enforce caller admission, count/bytes/verification-work/time limits and common rootTTL+30s retention. An absent original signer/approval is an honest unavailable result, not evidence of fraud.
3. If sufficient original signatures are actually returned, verify them in the one original context. Otherwise preserve uncertainty or use the independently valid current live-proof path where available. Current qualified live clearance never requires original signers, a recursive receipt chain or migrated historical14-signature bundles.
4. Trace all callers of older DTOs, stat-based acceptance, alternate timestamp projections and duplicate verifier implementations. Migrate required callers to A01/A04 contracts; remove only confirmed obsolete production paths and stale claims after coverage exists. Keep useful CEH/P0/deterministic models clearly labelled as models, not mandatory production protocols.
5. Update current docs/decision-to-code/evidence mapping after actual implementation. Preserve historical interview questions/counterexamples and the fact that a withdrawn A/B was not selected. Naming decisions do not require arbitrary wire/identifier migrations.

**Required tests / acceptance:**

- Exact retained approval is retrievable within bounds through root TTL+30s; wrong context/oversize/unknown data cannot generate a new original approval. Retrieval alone never changes collision state/readiness.
- Current live-quorum clearance still works after original signer turnover and does not invoke an archive back-fill prerequisite. Completed merchants need not store historical L2 bundles.
- Production call-graph checks show removed unsafe acceptance alternatives have no remaining productive callers; shared/consumer/wire regressions remain passing at the actual implementation revision.

**Dependencies / completion gate:** Depends on A01/A03 and the A09 uncertain-attempt integration. Lower priority than the primary live path. This is exceptional own-approval service, not a revived historical quorum archival project.

## 6. Cross-cutting boundary checklist

Use this checklist when reviewing each implementation change. These are the
selected outcomes to cover, not a claim that a particular new architecture exists.

| Boundary | Must agree / fail safely | Main packages |
| --- | --- | --- |
| Shared schema -> HTTP/QUIC producer -> consumer | Identical canonical fields/purpose/domain/version; every full-key signature verified against justified context; unknown format cannot use a permissive legacy fallback. | A01/A05/A09/A15 |
| RAM -> pending operation -> worker -> network | Queue reservation before mutation; exact atomic durable lock+own-choice success before original approval; duplicates share bounded ack; no RAM guard over await; late commit retained. | A02/A03/A07 |
| Recovery source -> transfer -> durable install -> readiness | Full active-root coverage, actual authenticated sources, stable no-gap transfer, verified imports/complete cut and current assignment before activation; unknown state remains NOT_READY. | A02/A04/A05/A07 |
| Original choice -> canonical merge -> live response -> fraud | Immutable original decision survives merge; current state uses a separate purpose; admitted support/class rules govern replacement; only genuine incompatible originals sanction. | A01/A03/A06 |
| Wallet store -> first send -> retry -> merchant release | Exact durable intent/T0 and pending output before send; finite same-payload retries/read-only recovery; no substitute payment; full proof plus durable L1/purchase binding before release. | A01/A09 |
| Public ingress -> private operator / directory | No diagnostic alias leaks; explicit public HTTP advertisements only; private credentials/topology never used as public discovery data. | A09/A10/A12/A13 |
| First stop -> producers -> storage drain -> CLI result | Single absolute deadline, owned-task cancellation, truthful storage/teardown result, target-instance exit and DB release; repeated signal neutral. | A03/A07/A11 |
| Logical expiry -> background purge -> retained evidence | Spend expiry immediate; physical rootTTL+30s chunks bounded; own choice/context lives as long as required; no resurrection or permanent expired-lock tombstone. | A03/A04/A13/A15 |

## 7. Definition of done and implementation report format

For each package/subdeliverable, append or link a concise execution record with:

1. Package/substep and exact DEC links in **ARCHITECTURE_INTERVIEW_NOTES.md**;
   applicable invariant IDs and source revision in each affected repository.
2. The production entry/call path changed and old alternative paths retired or
   deliberately preserved; actual host scope where relevant.
3. Closed design prerequisites or their explicit remaining assumptions/counterexamples.
4. Positive/negative tests executed, command, environment, observed wire/state/process
   effects and artifact. Include workload/hardware/durability settings for measurements.
5. Remaining gaps and status separately: requirement selected, design justified,
   implementation present, actual verification executed. No simulated/manual-ready
   helper counts as a different category of evidence.

A package is complete only when its selected outcomes, applicable prerequisite
contracts, implemented enforcement and required actual-interface tests are all
accounted for. A source change alone is “implemented, verification pending”. A
passing bounded regression is evidence for that scenario, not an unconditional
proof about arbitrary topology, power loss or user application behavior.

Finish each implementation increment with relevant targeted checks and the
applicable required repository checks. The current AGENTS.md commands are backed
by [.cargo/config.toml](../.cargo/config.toml):

| Future implementation check | Command / meaning |
| --- | --- |
| Fast unit/library feedback | `cargo test-fast` (`cargo test --workspace --lib`); does not replace wire integration. |
| Required standard node suite | `cargo test-std` (`cargo test --workspace`); actual assertions must still cover the changed package. |
| Strict Rust lint check | `cargo clippy --workspace --all-targets -- -D warnings`. |
| Deep model scenarios when affected | `cargo test-deep` (ignored suites); use when justified by changed models/proof gaps, not to replace real QUIC/process evidence. |

Use each affected sibling repository's actual manifest/instructions for its tests;
the node workspace does not automatically verify the HMC host application. Re-read
current project instructions before execution. These commands are future acceptance
work and were **not executed while creating this plan**. No date estimate, measured
performance guarantee, new consensus algorithm or additional payment round is
selected by this document.

## 8. Coverage and intentionally non-feature decisions

The audit's [89-row decision matrix](ARCHITECTURE_IMPLEMENTATION_AUDIT.md#decision-by-decision-implementation-matrix)
remains the complete code-status crosswalk; it is not duplicated or silently
replaced here. A01–A15 retain that matrix's task IDs, with direct decision-source
links above. Existing implemented/directional/documentary items are not 89 new tasks:

- DEC-001/005/007 preserve blind service, the shared genesis/successor model and
  permissionless compatible-client ingress; retain them while modifying flows.
- DEC-004 is coordinated breaking-change scope. DEC-036 deployment artifacts
  already exist and need only A11 integration validation. DEC-047 is an intended
  operating topology; it is not a runtime guarantee produced by a timer.
- DEC-049–052 vocabulary/maintenance is documented. Code identifiers/wire formats
  are not arbitrarily renamed as a separate implementation project.
- DEC-016/039/043/044/046 and the G gates include assumptions, reopened/tentative
  mechanisms or proof obligations; implement the selected behavior once justified,
  not every historical candidate. DEC-028 stays deferred.
- DEC-071/072/079 host implementation scope is unverified until A09.1. Do not call
  existing wallet storage absent, or add duplicate node purchase/cache state.
- DEC-062 early release is superseded by DEC-087; original own-choice retention
  DEC-070 is distinct from rejected historical-quorum archives DEC-083. DEC-089
  documentary consolidation is delivered; actual enforcement/evidence follow here.

## 9. Planning validation and current status

This document was prepared from CP-0093 and the current decision register, with
current source fingerprint comparison. It creates no new decision ID. Only this
plan, its navigation links and the interview checkpoint are updated by this task;
production files, binding specifications and tests are unchanged.

Validation for this planning deliverable is static: all 15 stable package IDs,
all linked DEC anchors, affected-file references, source-link targets, audit
crosswalk coverage and staged dependency references are checked before saving CP-0094.
Actual code fixes, test execution and G1–G5 proof closure remain future work.
Concurrent AGENTS.md simplification and .agents file removals observed during
planning are outside this task and were preserved; current instructions were
re-read and the test-command aliases checked without executing them.


## 10. Implementation execution

The subsequent user-authorized implementation is tracked in
[ARCHITECTURE_IMPLEMENTATION_PROGRESS.md](ARCHITECTURE_IMPLEMENTATION_PROGRESS.md).
Section 9 describes the historical planning deliverable, not the current working-tree status.
No package is complete merely because code is present; use its proof and acceptance gates.

The current residual breakdown is in
[ARCHITECTURE_IMPLEMENTATION_REMAINING_PLAN.md](ARCHITECTURE_IMPLEMENTATION_REMAINING_PLAN.md).
It reconciles implemented portions, the completed wallet patch review, outstanding
acceptance and explicit approval before each further agent assignment.
