# Architecture completion plan for the implementing agent

Date: 2026-10-23 (Europe/Berlin). Status: **implementation incomplete; planning only**.
Requirement baseline: 89 interview decisions, DEC-001 through DEC-089, with their
supersessions. This plan adds no decision and grants no automatic agent-start,
deployment, publication or implementation approval.

## 1. Purpose and mandatory reading

This is the current continuation plan after the three-agent read-only audit of
2026-10-23. It covers the whole architecture, not just the last failed tests.
It supersedes **current-status and scheduling claims** in the older plans, while
retaining their original acceptance criteria wherever consistent with the interview.
Do not implement this document as a collection of helper functions and then infer
that the actual application and daemon call paths are finished.

Read these sources before editing:

1. Current `AGENTS.md` in every affected repository, nested instructions, and
   [glossary](TRANSLATION_GLOSSARY.md). Speak German to the maintainer; write code,
   documentation, comments and commits in English.
2. [Interview register and provenance](ARCHITECTURE_INTERVIEW_NOTES.md#21-current-decision-register-and-provenance),
   [refinements/withdrawals](ARCHITECTURE_INTERVIEW_NOTES.md#22-alternatives-refinements-and-superseded-proposals),
   [open leaves](ARCHITECTURE_INTERVIEW_NOTES.md#23-open-design-and-decision-inventory)
   and each relevant linked §7 rationale. These are the decision sources.
3. [Consolidation](ARCHITECTURE_CONSOLIDATION.md), [invariant registry](INVARIANT_REGISTRY.md)
   and applicable numbered specifications.
4. [Original A01–A15 plan](ARCHITECTURE_IMPLEMENTATION_PLAN.md),
   [earlier R1–R8 plan](ARCHITECTURE_IMPLEMENTATION_REMAINING_PLAN.md), and
   [detailed M0–M10 handoff](ARCHITECTURE_IMPLEMENTATION_HANDOFF_PLAN.md).
   Their baseline findings are historical: some are fixed, others remain, and
   some later changes introduced new defects.
5. [Execution record](ARCHITECTURE_IMPLEMENTATION_PROGRESS.md) and
   [G1–G5 document](SAFETY_AND_PROGRESS_CONTRACTS_G1_G5.md), critically. Neither a
   completion statement, a “canonical” heading nor a commit subject proves safety,
   implementation, productive integration or successful execution of tests.

All original A-package acceptance criteria remain required. If prose conflicts,
use the maintainer's actual selected decision and explicit later corrections.
Do not silently choose a new protocol to reconcile an unresolved premise.

## 2. Current inspected baseline and what to preserve

| Repository | Inspected revision | Observation |
| --- | --- | --- |
| `human-money-node` | `e585830137d947343e44c03aa164e2f7c419ff0f` | Tracked tree clean; new commit claims M2–M10 implementation |
| `humoco-proto` | `e119ee60f886facad60be325ad9d8e4227590b4b` | Tracked tree clean |
| `human-money-core` | `8265fd4ce2ba2e9e69710d08537090ee5478f4d7` | Tracked tree clean; generated fuzz/cache data may remain untracked |
| `human-money-app` | `1f0bd4ef5bcf44d27794951164aacf2c363996c4` | Tracked tree clean |

All four repositories are siblings under `/home/basti/Coding/humoco/`. Run a new
read-only HEAD/branch/status/diff inventory before implementation. Recheck symbols
and callers if newer changes exist. Line numbers below identify this baseline.
Historical source can be reproduced with `git show <revision>:<path>` in the
appropriate repository. Never depend on temporary chat memory or `/tmp` patches.

Inspect resolved dependency sources as well as HEADs: the App manifest requests
Git Core `master`, but ignored local Cargo patches select the sibling Core and its
lock entry has no Git source. A local pass does not certify the published/CI
dependency set. Follow App rules: no committed `[patch]` in `src-tauri/Cargo.toml`.

Preserve and extend these real improvements:

- Original FINAL write receipts now remain `Found`, and raw IPC `"Confirmed"`
  no longer grants automatic release. Keep the corresponding regressions.
- Proto fully checks distinct full-key Ed25519 signatures and context equality;
  original and current-live signature purposes are separated. It deliberately
  expects authority to be established independently by the consumer.
- Node original lock plus own-choice durability, exact ACKs, immutable choices,
  pending coalescing, root-based retention, per-shard signing checks and read1 exist.
- Digest storage errors now reject instead of becoming empty state; NOT_READY
  responses are explicitly marked and the requester rejects them.
- Quarantine retains TTL indexes and DB pruning now includes provisional tables.
  This repair does not fix classification, publication atomicity or RAM metadata.
- Original retrieval returns stored approval bytes, not just presence flags.
- Managed Core wallet recovery/OS lock/uncertain commit/fork-lock replay protection
  and temporary cleanup are implemented. Reuse them; do not reapply the old patch.
  Review direct-writer and supported-platform limits, including new backup restore.
- Bounded RAII QUIC pool, private operator surface, instance-bound shutdown and
  bounded private history are useful foundations, not features to rebuild.

## 3. Non-negotiable boundaries and known interpretation traps

- L1 owns monetary data, ownership, causal history and purchases. L2 remains a
  blind active `parent_lock -> child_lock` registry. No purchase queue in nodes.
- A verified **current** FINAL proof needs 14 distinct authorized identities in
  one frozen committee of at most20. No rank21 substitution or threshold reduction.
  Ordinary status remains read_quorum1. FINAL is regional/revisable (DEC-053).
- A single own approval proves neither FINAL nor generally a provisional quorum.
  An owner signature proves authorization, not committee support. A verified
  signature from an arbitrary key is not proof that the key is currently eligible.
- Commit exact original lock and own choice atomically/durably before release or
  self-vote. Reserve capacity before RAM mutation; no RAM guard across I/O.
- Recovery is per-shard, on demand, bounded and source-complete before readiness.
  Global network-size hysteresis is separate. Permanent NOT_READY is containment,
  not completion of safe automatic progress/full turnover.
- Class2 > class1 > class0 requires justified support. Hash is a tie-breaker in
  the highest admissible confirmed class, not authority for singleton takeover.
  Losing an honest merge or reporting its new winner is not equivocation.
- Keep original own choices separate from current canonical state. No historical
  quorum archives, recursive L2 receipts or predecessor committee permission.
  An old signer's retirement alone cannot make safely synchronized state unconfirmed.
- Exact signed wallet T0 and request bytes survive retries. Freshness30s is checked
  at ingress, not again after disk wait. PoW's10-minute window is a different clock.
  Root validity remains independent and grace30s does not extend spending.
- Unknown network outcome or uncertain local commit never frees an output for an
  automatic replacement/refund. Partial multi-voucher purchases stay client logic.
- Offline L1 import remains supported. No reachable L2 is honest unverified status,
  not invented quorum. Preserve explicit offline/provisional risk decisions without
  labelling them verified FINAL. A cached status/health dot cannot authorize release.
- Metrics/dashboard/topology are private. Public discovery is desired; cache
  fallback and provider-scoped credentials belong only in the client.
- Keep safe parsing, checked bounds and forbidden unsafe code. A time limit or
  number of tasks does not itself bound allocated bytes or verification work.

Supersessions: DEC-087 restores DEC-029 ordering and supersedes only DEC-062's early
release; entry-only freshness/reservation/fixed seal remain. DEC-083/LRC-002 withdraws
the archive question, neither A/B. DEC-039's mechanism is reopened, DEC-028 deferred,
DEC-043 cadence tentative, DEC-044 fault bound conditional. Broad trust research
and the extra-payment-round question stay stopped/parked. Do not implement them
merely because an old table mentions them.

The older handoff acquired small worker packages and offline UI additions. Their
labels/model commands are not correctness criteria or permission to spawn workers.
In particular, do not turn an unverified provisional flag into automatic online
release or submit an old offline lock as fresh ingress after reconnect. Reconcile
any such wording against the selected decisions and signed freshness contract.

## 4. Delivery discipline: prevent another false completion

Use this workflow for **each** work package below:

1. Identify the actual registered entry point, all callers and old bypass paths.
2. Record the DEC source, input trust boundary, affected state and failure schedule.
3. Add a regression with an independent expected outcome at that real boundary.
4. Implement a bounded, reviewable change. Reuse existing foundations.
5. Run targeted checks and record actual results at exact resolved revisions.
6. Search productive callers again; do not leave the old path able to authorize.
7. Record separately: selected requirement; justified design; implemented producer/
   consumer; executed evidence; remaining assumption. Leave incomplete rows open.

**A package is not complete because:** a helper exists, a boolean is set, a class
number is supplied to a test, a UI receives a prepared DTO, RAM buffering is called
staging, documentation states a theorem, or a unit test mirrors the implementation.

Z00–Z05 are baseline/containment/regression work. Z06 closes necessary contracts.
Z07–Z13 integrate complete behavior under those contracts. Z14 is independent final
acceptance. Operational evidence accompanies every package; do not postpone it all.
These15 packages are not15 promised agent runs or an effort percentage.

### 4.1 Subagent Execution & Orchestration Plan

When executing work packages via autonomous subagents (`invoke_subagent`),
the main agent acts as the **strict Conductor & Auditor** and delegates bounded code/test
changes to specialized subagents (`TypeName: "self"` or role-specific subagents like
`"Codebase Implementer"`, `"Security & Invariant Auditor"`, `"Test & Regression Engineer"`).

#### Execution Rules for Subagents:
1. **Isolated, Bounded Scope:**
   Each subagent is launched with a dedicated task prompt containing `[GOAL]`, `[TARGET FILES]`, `[GUARDRAILS / INVARIANTS]`, and `[DEFINITION OF DONE]`. Subagents focus strictly on their assigned package without out-of-scope edits.
2. **Mandatory Conductor Post-Inspection:**
   Never trust a subagent's completion claim blindly. After every subagent finishes, the main conductor agent MUST inspect `git diff`, verify callers via `view_file`, and run the repository test suite (`cargo test-fast` / `cargo test-std` / `./run-tests.sh`) before marking any sub-step done.
3. **No Shortcut Approvals:**
   Subagents are forbidden from satisfying tasks by inserting empty flags, stub booleans, or skipping assertions.
4. **Current Status:**
   - **`Z01` (Live verification & release trust boundary) is COMPLETED and verified**: `CheckoutReleaseVerdict::new` fail-closed in Core, `DurablePurchaseBinding` token introduced, `evaluate_checkout_release` and `verify_live_checkout_and_release` clamped in App, all 9 unit tests green.
   - **Remaining packages to implement**: `Z00`, `Z02` through `Z14`.

| Sub-Task | Package | Target Repo | Primary Files & Target Scope | Conductor Verification Oracle |
| --- | --- | --- | --- | --- |
| **SA-Z00** | Z00 | `human-money-node` | `docs/ARCHITECTURE_COMPLETION_MANIFEST.md`: Baseline manifest linking DEC-001..089, A01..A15, G1..G5, and E01..E15 to real production callers. | Manifest matches resolved Git revisions; no missing DEC links. |
| **SA-Z02** | Z02 | `human-money-node` | `daemon.rs` (~313/387/1014), `transport.rs` (~1303): Remove dead global `is_sync_ready` dependency from per-shard witness check; stop counting unready self digest (+1 vote at ~1115); exclude pending RAM from digest witness. | Ready shard serves witness, unready shard returns FLAG_NOT_READY; storage errors fail closed; no global readiness requirement. |
| **SA-Z03** | Z03 | `human-money-node` | `storage/engine.rs` (~118/734/878/909), `db.rs`: Remove `own vote => Class 2` promotion; introduce persisted verified support admission boundary; prevent restart from demoting confirmed locks to Class 0. | Single vote cannot create Class 2; low hash cannot displace higher confirmed class; verified support survives restart. |
| **SA-Z04** | Z04 | `human-money-node` | `storage/db.rs` (~564), `engine.rs` (~386/2290): Fix `confirmation_classes` memory leak in `prune_expired` (~407–419); protect confirmed/unknown-support rows from omission quarantine; move DB scan to worker. | Quarantine preserves unconfirmed status; confirmed rows never quarantined; `confirmation_classes` prunes with root+30s. |
| **SA-Z05** | Z05 | `human-money-node` | `network/transport.rs` (~139–192): Fix `verify_equivocation_first_party` so both signatures must verify under the same network ID and compatible original-approval context; add QUIC cross-network negative test. | Cross-network/context signatures cannot trigger fraud ban; genuine incompatible originals still slash. |
| **SA-Z06** | Z06 | `human-money-node` & `humoco-proto` | `SAFETY_AND_PROGRESS_CONTRACTS_G1_G5.md`, `humoco-proto/src/live.rs`, Node G5 storage state: Close G1–G5 contracts, implement real Node G5 `FAIL_CLOSED_CORRUPT`/generation detection, freeze wire worksheet & cross-repo vectors. | Enforceable contract specifications; cross-repo test vectors; real storage rollback detection. |
| **SA-Z07** | Z07 | `human-money-node` | `daemon.rs` (~1159–1279), `transport.rs` (~1411+): Replace mutable offset paging and unbounded RAM vectors with fixed snapshot cut + bounded staged delta install and atomic readiness publication. | Daemon+QUIC recovery succeeds under 8+6+6, repeated turnover, process cuts; staging bounded; atomic publication. |
| **SA-Z08** | Z08 | `human-money-core` & `human-money-app` | Core wallet intent/orchestrator/conflicts, App transfers/IPC: Persist exact signed bytes, `T0`, and pending output before HTTP send; implement durable recipient challenge creation/consumption and atomic L1 voucher + purchase commit. | Exact intent precedes send; restart retains pending; purchase durably committed before release; idempotent re-completion. |
| **SA-Z09** | Z09 | `human-money-node` | `engine.rs` (~1216/1339), `routes.rs` (~2079), `transport.rs` (~551/834): Enforce exact `ds_tag == bs58(prev.t_id)` causal path to target, sequential durable prefix retention, and receiving-shard check on signed wallet `created_at_ms`. | Valid prefix retained on bad suffix; fresh gateway envelope around stale wallet T0 rejected by receiving shard. |
| **SA-Z10** | Z10 | `human-money-node` & `human-money-core` | `routes.rs` (`get_retained_choice` at `/v1/retained-choice/:tag` ~2493): Offload DB read from runtime thread, sanitize 500 error, return full verifiable context, wire client pending reconciliation caller. | Pure read-only lookup; returns exact verifiable approval bytes; client reconciles pending state. |
| **SA-Z11** | Z11 | `human-money-node` & `human-money-app` | Node passive HTTP gateway advertisement + `/v1/gateways`; App gateway resolver, bounded cache fallback, and provider-scoped token isolation on failover/redirect. | Passive discovery roundtrip; client cache fallback; credentials never leaked across providers. |
| **SA-Z12** | Z12 | `human-money-node` | Persistence/transport admission separation across public ingress, shard RPC, and sync; verify 256 LRU pool, coalesced batch sealing, and no orphan tasks under QUIC flood. | Protected internal progress under mixed flood; memory/socket ceilings enforced; no task leaks. |
| **SA-Z13** | Z13 | `human-money-node` | `cli.rs`, `daemon.rs`, `routes.rs`, `db.rs`: Repeated-signal immutable shutdown deadline, real CLI stop + DB lock release verification, private operator surface audit, and backup/restore coverage for new stores. | Bounded clean shutdown; DB lock released before CLI exit 0; private endpoints inaccessible publicly. |
| **SA-Z14** | Z14 | All 4 Repositories | Independent full-plan audit, E01–E15 / V01–V15 execution at resolved revisions, spec/progress cleanup, and small dependency-ordered commits. | All final test suites green at matching revisions; no remaining open premise or unverified caller. |


## 5. Detailed implementation packages

### Z00 — Refresh baseline and build the completion manifest

**Source:** DEC-004/038/052/089; A14; M0/M10.

- Read all sources in §1 and create a current evidence manifest with one row per
  selected requirement and links to its A/G/Z ownership and real production caller.
- Reproduce the observations below in current code. Mark already fixed findings
  closed with evidence rather than reimplementing them. Keep generated/unrelated
  changes out of the patch and commits.
- Snapshot dependency pins/local patches/lockfiles, feature flags, platform and
  storage durability settings. Identify actual host HTTP adapter and daemon startup.
- Reconcile contradictory completion claims with dated evidence, preserving history.

**Done:** a new agent can locate current sources, reproduce each remaining gap and
distinguish missing mechanism from missing execution evidence. No safety claim yet.

### Z01 — Make live verification and release depend on trusted operation state

**Source:** DEC-017/072/080/083/084; A01/A09; M1/M6.
**Targets:** Core [conflicts.rs](../../human-money-core/src/app_service/conflicts.rs)
`verify_live_checkout_proof` (~389), [layer2_api.rs](../../human-money-core/src/models/layer2_api.rs),
App [transfers.rs](../../human-money-app/src-tauri/src/commands/transfers.rs)
`verify_live_checkout_and_release` (~368), Proto [live.rs](../../humoco-proto/src/live.rs).

**Failure schedule:** replay a previously valid proof together with its old
`expected_context_json`; the IPC has no stored open challenge to consume and can
append another random-UUID history entry and release again. Alternatively supply
20 attacker-chosen keys,14 genuine signatures and that same roster as `expected`.
Mathematical signature verification passes without independent current authority.

- Stop release-producing APIs from trusting caller-supplied expected authority,
  challenge, purchase identity or a public `Confirmed` constructor as proof.
  The IPC may transport proof bytes and a local operation ID; the backend loads
  trusted expected state and independently justified authority under Z06/G1.
- Until that application state exists, fail closed for automatic release while
  preserving mathematical verification as an observation/service and honest import.
- Establish durable recipient challenge creation/binding/consumption and same-
  operation idempotency in Z08. Distinguish a new purchase from duplicate completion.
- Never trust frontend counts/`isVerifiedCheckout`/DTO presence. Return actual
  backend assurance and committed release disposition. Preserve already repaired
  original-receipt and StringConfirmed paths.

**Acceptance:** actual registered IPC/backend tests reject self-chosen authority,
old receipt, raw flag, replay after spend/root expiry/restart and wrong purchase.
Repeated completion of one committed operation does not create new credit/history
or new release authorization. Positive release awaits Z08's durable boundary.

### Z02 — Correct per-shard witness readiness without inventing bootstrap safety

**Source:** DEC-026/045/046/057/083/086; A02/A04/A05; M2/M5.
**Targets:** Node [daemon.rs](../crates/humoco-node/src/daemon.rs) startup (~313/387),
`ShardReadinessManager`, `sync_single_shard` (~1014);
[transport.rs](../crates/humoco-node/src/network/transport.rs) digest branch (~1303).

**Current defect:** countable witnesses require per-shard readiness AND a global
flag that startup sets false and the production path never raises. Even a ready
shard cannot serve a usable witness. Tests manually setting both flags hide this.

- Audit every ready/invalidated state and signing/witness producer. Remove the
  unintended dependency on a permanently false global flag; do not set all flags
  true or accept unready witnesses as a shortcut.
- Preserve NOT_READY for unknown/restarted/changed assignments. Partial sources may
  serve bounded known data, but are not completeness witnesses solely by responding.
- Exclude pending RAM entries and propagate storage errors. A durable digest needs
  an exact qualified view, not the union of disk plus arbitrary pending RAM.
- Do not count this recovering node's unready local digest as the missing vote
  (`sync_single_shard` ~1115). Bind asynchronous completion to current assignment;
  checking membership in the earlier frozen list is not a current check.
- Add actual callers for invalidation/reentry when assignment or safety state changes.
  Define startup versus genuinely new-network initialization under Z06; absence of
  peers/storage is not proof that no earlier locks exist.

**Acceptance:** real daemon with one actually justified ready shard serves witnesses
while another remains unready; no global readiness requirement. Entire-network
restart cannot use fabricated ready seeds. Positive safe bootstrap/recovery needs
the G1/G2 contract; containment alone is explicitly not its completion.

### Z03 — Admit and recover authentic confirmation classes

**Source:** DEC-022/023/064/065/083; A03/A06; M3/M4-G3/M5.
**Targets:** [engine.rs](../crates/humoco-node/src/storage/engine.rs)
`promote_confirmation_class` (~118), `persist_original_approval` (~734), native
import/resolver (~878/909), `insert_recovered`; shared support representation.

**Current defects:** one own FINAL-capable vote promotes an entry to Class2;
classes live only in a RAM map; recovery/import defaults to Class0. Native import
uses an unproven transmitted status. This can protect unsupported state while
demoting genuinely confirmed state after ordinary restart.

- Remove the inference own durable vote => quorum confirmation. Durable-before-
  release is mandatory, but proves a different property.
- Define a verified support admission boundary under G1/G3, shared by HMC/native
  paths. Status/class integers cannot cross that boundary as evidence by themselves.
- Persist or safely reconstruct the necessary minimum current support/exclusion
  facts through restart and transfer. Missing justification remains unknown, not
  silently Class0 eligible for displacement. No historical bundle archive returns.
- Enforce class priority only after admission, then allowed same-class tie-breaking.
  Preserve own original choices, descendants, siblings and later stronger evidence
  according to the finalized G3 contract.
- Replace tests that expect a single own approval to establish Class2 with tests
  distinguishing durable original acceptance from justified confirmation.

**Acceptance:** one vote cannot create FINAL; unsupported status cannot promote;
weaker low hash cannot displace stronger support; restart/turnover does not demote
a safely inherited lock merely because original signers left. Test actual import,
storage reopen and HMC/native consumers, not only a class-injected comparator.

### Z04 — Make quarantine and all expiry state safe and bounded

**Source:** DEC-022/023/035/064/065/070/088; A06/A07/A13; M3/M5/M9.
**Targets:** [db.rs](../crates/humoco-node/src/storage/db.rs)
`quarantine_subquorum_locks` (~564–624), [engine.rs](../crates/humoco-node/src/storage/engine.rs)
quarantine (~2290), `HmcRamIndex::prune_expired` (~386), daemon call (~1255).

- Do not quarantine every locally omitted row: omission does not prove class0.
  Protect confirmed and unknown-support exclusions. Apply a verified G3 disposition
  only within a validated install, not before a candidate's final acceptance.
- Move blocking DB scans/writes to the existing bounded persistence/install worker.
  Bound count/bytes/work and continuation; no full-table clone under a long RAM guard.
- Specify atomic DB/index/RAM/readiness visibility and crash recovery. Separate DB
  commit followed by RAM removal is not a single atomic application transition.
- Keep the repaired TTL indexes/provisional deletion. Add deletion of the new
  `confirmation_classes` metadata on every ordinary expiry path; currently ~407–419
  leaves it behind. Inventory roots, classes, support, own choices, staging and
  quarantine indexes and handle replacements/old orphaned rows without data loss.

**Acceptance:** omitted confirmed/unknown records survive; invalid/failed installs
do not remove active protection; quarantine expires through root+30s; repeated
expiry leaves no class-map growth. Fault cuts cover DB/RAM/publication and root
expiry during transfer. Show bounded memory/work and progress under backlog.

### Z05 — Prevent cross-context false equivocation penalties

**Source:** DEC-019/054/064/065; G3; A06; M5 fraud acceptance.
**Target:** [transport.rs](../crates/humoco-node/src/network/transport.rs)
`verify_equivocation_first_party` (~139–192) and both receiving fraud branches.

**Failure schedule:** two genuine same-key/same-parent originals belong to different
networks. The verifier tries each signature independently against all four
network/class domains, then accepts both without requiring one compatible context.

- Retain/derive the actual authenticated context for each signature and require
  the same protected network/slot/compatible original purpose before alleging fraud.
- Do not merely verify that each signature is valid in some accepted domain.
  Define legitimate provisional/final transitions and do not falsely equate lawful
  current-live reporting with incompatible original approvals.
- Preserve complete signature verification before any ban/ticket loss/WoT severance.
  Unverified reporter claims, telemetry and ordinary canonical loss remain neutral.

**Acceptance:** real receiving QUIC path rejects cross-network/context framing and
lawful original-A/live-B reports; genuine incompatible originals in the protected
context still trigger exactly the intended sanctions. Check downstream state effects.

### Z06 — Close G1–G5 with enforceable contracts, not assertions

**Source:** DEC-016–023/039/044–048/053–065/080–087; A01–A06; M4.

For each gate deliver assumptions, authenticated inputs, retained evidence, allowed
transitions, failure outcomes, counterexample schedules, positive progress argument,
actual enforcement owner and tests. A new document does not close a gate.

| Gate | Required deliverable and prohibited shortcut |
| --- | --- |
| G1 authority | Independent backend source of current network/admission/mature-ticket/presence/HRW context. State the conditional fault bound and different-view behavior. A roster supplied alongside its own signatures, TLS identity, ticket maturity or Same20 intersection arithmetic does not establish all premises. |
| G2 coverage/activation | Explain omission coverage and continuity over repeated full turnover, concurrent old/new writes and the8+6+6support case without14equalwhole-state digests. Define fixed snapshot, bounded deltas, final cut and safe positive progress. Neither all-empty agreement nor perpetual refusal completes it. |
| G3 support/merge | Authenticated class admission, protected original slot, minimum current exclusion/descendant facts, legal promotion/live changes and exact fraud context. Retired original signers alone cannot revoke inherited support; no historical bundle migration. |
| G4 time/reentry | Signed walletT0/30sentry, median time, monotonic waits,5minbuckets/fixedseal,rootexpiry,24hticket observation and3missedhourlyslots across restart/reentry. No second wallet-freshness gate or arbitrary rewritten old T0. |
| G5 actual own-history loss | Detectable corruption/rollback/clone cases, independently available evidence, blocked scope and justified same-key resumption. A counter rolled back with its DB cannot detect arbitrary rollback; later remote hints do not retroactively prevent earlier conflicting release. Ordinary intact crash is different. |

The Node still lacks the generation/`FAIL_CLOSED_CORRUPT` mechanism described in
the G document. Do not substitute a similarly named bool or Core wallet generation.
Implement only a defensible achievable contract. If a premise is genuinely
unselected or incompatible with selected constraints, show the precise counterexample
and ask the maintainer one A/B with a recommendation. Do not silently add a global
authority, TPM requirement, permanent log, predecessor veto or new payment round.

Freeze an actual encoding worksheet for original/live/support/sync/conflict/
retrieval/discovery messages: purpose, version, network representation, root/output/
split/target, shard derivation versus scalar serialization, signed time, roster,
challenge, byte/work limits and error outcomes. Current Proto uses network `u8`;
prose still mentions32bytes. Derive authoritative bytes from producers/consumers;
do not arbitrarily migrate signed formats. Provide cross-repository test vectors.

**Done:** required gate arguments and inputs are justified or explicitly blocked.
No downstream task can treat a blocked gate as closed by a comment/config switch.

### Z07 — Implement source-complete bounded snapshot/delta installation

**Source:** DEC-039/041–046/057–059/064/083/085/086; A02/A04/A05/A06/A07;
M5. Depends on Z02–Z04 and applicable Z06 contracts.
**Targets:** daemon recovery (~1159–1279), transport ActiveSync (~1411+), framing,
source storage sessions, durable install/publication and readiness manager.

- Replace offset paging over a rebuilt mutable global list with the justified
  fixed cut plus bounded delta/cursor contract. Authenticate shard/source/session/
  cut and enforce strict page/context/dedup/continuation semantics.
- Request and accept only authorized relevant data. Current staging pushes every
  peer record despite filtering only keep-sets by shard. Bound total staging
  records/bytes/disk/work/session time, including32concurrentjobs. Timeout is not
  memory admission. Do not scan/sort the entire peer database for every page.
- Stage validation/support resolution without changing active collision state.
  A pair of unbounded RAM vectors followed by single-record live imports is not
  an atomic candidate installation.
- Catch all changes including admitted-before-cut/committed-after-cut writes,
  canonical changes and expiry. Revalidate source/assignment context at publication;
  checking only this node's current seat is not full context validation.
- Commit install/support/exclusion/indexes/quarantine disposition with defined
  crash-atomic visibility; publish RAM/readiness only for that exact durable state.
  Leave own immutable original choices untouched.
- Failure/cancel/overflow/stale assignment leaves active safety intact, staging
  bounded and the affected shard unready. No node payment queue. Safely recover
  interrupted installs and clear task reservations on every outcome.

**Acceptance:** actual daemon+QUIC recovery succeeds under justified conditions;
rejects incomplete/empty/omitted sources; covers8+6+6, full repeated turnover,
source loss, malformed pages, inserts before cursor, late commits, competing
classes, descendant changes, root expiry, assignment changes and process cuts.
Manually ready two-node empty fixtures cannot serve as the positive proof.

### Z08 — Complete real wallet intent, network dispatch and purchase release

**Source:** DEC-009/010/017/042/060/068/071–073/079–084; A01/A09/A12; M6.
Depends on Z01, relevant Z06/07 contracts and existing managed wallet storage.
**Targets:** Core conflicts/orchestrator/wallet/persistence; App real Send/Receive
actions, transfers IPC, host HTTP adapter, state/history and UI mapping.

**Sender transitions (local notation):** Prepared -> IntentDurable -> Dispatched/
Uncertain -> Reconciled, with explicit conflict/provisional/expired-unresolved cases.

- Create one owner-signed request and persist exact bytes, signed T0, operation
  identity and pending consumed output atomically before any HTTP send. The current
  byte generator alone is not storage. Prevent competing concurrent operations.
- Own finite retries/background work/cancellation. Keep the original checkout
  electorate/context and exact original bytes across transport retries; never
  expand or mix signer sets to reach quorum. A fresh independent live check has
  its own current justified context; it is not a replacement original vote.
- On timeout/unknown/uncertain local commit retain pending state. Reopen after
  restart and reconcile with bounded backoff; after30s use reads/historical sync
  as selected, never a newly timestamped replacement. Single lookup/404 is not a
  final release verdict or proof the output can be reused.

**Recipient transitions:** AwaitingProof -> ProofVerified -> PurchaseDurable ->
ReleaseAuthorized, with durable idempotency and explicit unavailable/conflict cases.

- Backend creates and stores an unpredictable challenge bound to a real purchase,
  exact network/root/output/target and independently justified current authority.
  IPC supplies operation ID/proof, not authority to define expected security state.
- Verify shared14/20 proof plus exact L1 ownership/ancestry/split/output relation.
  Matching only a voucher root is insufficient. An absent L1 voucher must not
  become an empty history record plus successful release.
- Atomically durably store received L1 voucher, purchase binding, challenge
  disposition and release/idempotency state in the managed wallet transaction.
  Current `build_verified_checkout_record` (~286–364) and separate generic history
  append (~401) do not implement this. Do not hide failed lookups with defaults.
- Return automatic release only after confirmed durable success. Uncertain marker
  commit retains recoverable result/operation and blocks release until reconciled.
  Same-operation replay is idempotent; different purchase/challenge replay fails.
- Wire real normal user actions to this backend path. `receive_bundle` returning
  `checkout_verdict: None` and an unused service wrapper do not complete integration.
  Display actual verified counts and assurance, not fixed14/20orcallerflags.
- Preserve offline L1 import with honest unverified L2 state and explicit merchant
  risk action; do not add a mandatory online preflight to L1. Late reconnect cannot
  freshen an expired original. Multi-voucher partial completion never auto-replaces
  or refunds an uncertain component; no cart/purchase state enters L2.
- Completion retains L1/purchase data, not a required historical quorum archive.
  State clearly that software authorization cannot guarantee exactly-once physical
  delivery through an uninstrumented external cashier action.

**Acceptance:** actual host/Core/HTTP/QUIC14success and13fail; arbitrary IPC context,
forged/duplicate/nonmember/wrong-purpose/root/output/target/network proofs; unknown
L1, wrong split, repeat purchase/nonce after restart; kills before/after intent,
send, response, purchase, uncertain commit and release acknowledgement. Verify
reopen, partial purchase, offline import and unchanged-payload failover. No DTO-only
tests or isolated stateless helper counts as this end-to-end result.

### Z09 — Enforce causal prefixes and signed freshness at receiving boundaries

**Source:** DEC-005/010–014/059–062/066–068/087; A08/A01/A07; M9.1/G4.
**Targets:** engine `verify_chain_causality` (~1216–1270), chain loop (~1339),
HTTP routes chain prechecks (~2079–2107), QUIC LockVerify (~551/834), HMC adapters.

- Validate the needed ancestry path to the target, exact consumed split output,
  predecessor/owner authorization and root inheritance. Same voucher plus individual
  signatures is not a causal proof; do not admit unrelated sibling dumps as the path.
- Keep whole-frame cheap size/admission checks before processing. After an admitted
  ordered batch begins, apply per-hop semantic/freshness/conflict checks sequentially
  so a later invalid hop does not undo the durable valid prefix. The existing HTTP
  all-hop prevalidation must be reconciled with that contract.
- Enforce count/aggregate bytes/verification work/time bounds and exact accepted/
  failed/uncertain boundary in response and retries. Preserve late commits; no
  terminal success for a failed dependent suffix.
- At the receiving QUIC shard verify the actual signed wallet `created_at_ms`, not
  just the gateway envelope timestamp. A known hostile gateway can rewrap an old
  authentic lock in a fresh envelope. Treat historical sync separately with its
  own proof/authorization; do not use it as a live freshness bypass.
- Audit legacy signature fallback that omits T0 or replaces missing T0 with now.
  Reproduce real network/mode reachability before changing compatibility. Never
  add a second wallet freshness gate after durable commit wait.
- Provide bounded authenticated inline409evidence and preserve actual14quorum
  precedence over weaker minority collisions.

**Acceptance:** real HTTP/QUIC valid prefix + stale/bad-signature/conflicting suffix,
wrong owner/split/root/sibling, excessive bytes/work and storage failure. Retry sees
the exact durable prefix. Fresh gateway envelope around stale signed walletT0 is
rejected by the receiving shard; delayed commit of timely admitted input stays legal.

### Z10 — Finish exceptional original-approval retrieval

**Source:** DEC-069/070/083; A15; M7.
**Targets:** routes `get_retained_choice` (~2493–2525), own-choice storage and client
pending reconciliation. Inspect the actual registered route rather than copying
the commit subject's `/v1/own-choice` spelling blindly.

- Preserve byte-for-byte stored approval return. Complete one exact verifiable
  identity/network/root/output/child/purpose/original-context response contract.
  The original client context may supply fields, but the combination must verify.
- Add real read admission, bounded DB work off runtime, count/byte/deadline and
  total reconciliation budgets. Do not expose internal storage errors publicly.
- Integrate the pending client caller, not only the endpoint. Missing signer/data
  is honest unavailable; retrieval never creates new original votes or requires
  retired signers for a valid current live proof.

**Acceptance:** real HTTP/QUIC as applicable with genuine signatures and actual
client verification, wrong context/expired/oversize/quota/deadline negatives and
unchanged state. Current tests using `b"sig_final"` prove bytes only.

### Z11 — Complete authenticated passive discovery and client fallback

**Source:** DEC-017/020/021/078/079/082; A12/A09; M8.
**Targets:** node config/framing/manager/public directory; App settings resolver,
HTTP client/cache/provider authentication and actual payment adapters.

- Current directory merges only configured public URLs and bootstrap URLs. Extend
  explicit public HTTP publication through existing authenticated passive mesh
  metadata with bounded count/length/freshness/withdrawal semantics.
- Never derive HTTPS from QUIC addresses, publish private topology/credentials,
  create a third gossip stream or perform active mesh-wide reachability scans.
- Add the actual host `/v1/gateways` consumer; integrate existing Seed/Custom/Cache
  selection with bounded refresh, explicit revocation and recipient source choice.
- Scope tokens to their issuer/endpoint; test redirects and cross-provider failover.
  Preserve exact payment bytes/T0 and total retry budget. Stats stay diagnostic,
  disagreement is explicit and does not establish committee authority.

**Acceptance:** passive authenticated publication roundtrip and real client lookup;
wrong-domain/replay/oversize/withdrawal, stale directory/cache, outage and credentials
never forwarded to another provider. P2P-only nodes produce no invented HTTP URL.

### Z12 — Prove protected capacity and bounded production work

**Source:** DEC-008/012/015/024/025/027/060/085/086/088; A07/A08; M9.1.

- Inventory shared persistence queue and transport stream permits across public
  gateway work, receiving shard RPC and background sync. Provide separately bounded
  admission or a justified minimal scheduling contract preserving required internal
  progress. A shared semaphore or VIP label alone is not the selected guarantee.
- Preserve256idle-firstLRU, active leases, pending RAII and neutral local/remote
  rotation. Verify reverse RPCs, replacements, cancellation and shutdown ownership.
- Keep bounded coalesced waiters/ACKs/batch age/count/bytes; a singleton seals on
  time. Distinguish pre-admission failure, unsent work, NOT_READY and remote faults.
- Bound frame allocation/parsing/signature work before expensive operations and
  enforce receiving-server quotas, not only gateway checks. No stale orphan third
  send or repair task after successful quorum/cancellation.

**Acceptance:** real QUIC floods and mixed public/read/write/internal/sync traffic
with slow storage; measured memory/work/socket/queue ceilings and actual protected
progress under a stated offered load. Count/time limits alone are not byte evidence.

### Z13 — Complete shutdown, private diagnostics, history and lifecycle evidence

**Source:** DEC-002/003/034–037/040/070/074–077/088; A10/A11/A13; M9.2–M9.4.

- Preserve instance-bound completion plus process exit and the original daemon
  shutdown deadline; repeated signals must not change it. Use the remaining client
  deadline rather than adding fresh full wait budgets after previous waits.
- Audit no-socket => already-stopped shortcuts against live-process identity;
  socket disappearance alone is not clean completion. Test the real CLI, not an
  empty placeholder file. Confirm database resources released after actual exit;
  independent reopen is strong acceptance evidence, not a substitute for process
  validation or an invented requirement for a new coordination service.
- Exercise stalled fsync, quota/flush/join errors, startup failure, early unlink,
  stale completion/PID reuse, repeated signals and outer supervisor kill. Do not
  claim an async abort interrupts kernel I/O. Keep supervisor fallback longer.
- Review every public/private alias and field, loopback/Host/Origin/socket modes,
  SSH/proxy deployment. Preserve public permissionless client routes and private
  metrics/topology/history. No web logs, browser backup orchestration/manual prune.
- Recheck hourly/minute retention/counter deltas/gauges/reset/gap/crash replacement,
  bounded write cost and TTL across every new class/support/staging store. Preserve
  automatic root+30s cleanup; do not retain permanent tombstones.
- Include own choices/support/quarantine/install state in node backups. Core's new
  differential wallet backup is not Node G5 rollback protection; verify how new
  intent/challenge/purchase records restore and avoid duplicate credit/release.
  Maintain explicit Unix/direct-writer/platform limits until implemented otherwise.

**Acceptance:** real process/CLI/reopen and fault tests, hostile HTTP boundaries,
history replacement crash tests, expiry pressure and restore/reconciliation. Actual
process-kill evidence is not arbitrary filesystem/controller power-loss proof.

### Z14 — Independent full-plan acceptance and delivery

**Source:** DEC-004/038/052/089 and every package acceptance; A14; M10.

- Independently inspect final callers and reproduce every remaining audit failure
  schedule above, including positive progress. An implementation author checking
  their own constants is not a sufficient independent review.
- Close all applicable A/DEC/G/Z/evidence rows at matching resolved revisions, or
  explicitly report the blocked premise/unimplemented behavior/unexecuted scenario.
- Run required commands below after targeted checks. Do not skip/relax assertions,
  fabricate ready nodes or quietly reduce quorum to make the suite green.
- Update English specs/progress/decision-to-code references and remove current
  false claims while preserving historical question/decision provenance.
- Deliver small reviewed commits per repository in dependency order, with compatible
  pins/lockfiles and a reproducible four-repo integration record. Stage explicit
  task-owned paths. No push/tag/deploy is implied. Apply the current user request
  for commits; this planning request itself creates no commit.

**Done:** all selected outcomes, applicable safety premises and real-interface
acceptance are evidenced. A scoped safe increment is useful but must not be
reported as full architecture completion while a relevant gate remains open.

## 6. Required verification ledger and anti-forgetting matrix

No runtime tests were run to write this plan. Check current manifests/instructions
before executing commands; add targeted filters only after the tests exist.

| Repository | Final checks |
| --- | --- |
| Proto | `cargo test`; `cargo clippy --all-targets -- -D warnings`; canonical negative/positive vectors |
| Node | `cargo test-std`; `cargo clippy --workspace --all-targets -- -D warnings`; targeted real QUIC/HTTP/process cases |
| Node models | `cargo test-deep` only for justified affected assumptions; never replaces wire/process evidence |
| Core | `cargo nextest run --status-level fail`; `cargo test --doc`; current applicable strict lint and managed wallet crash/restore tests |
| App | `./run-tests.sh --quiet` for integrated frontend/backend work; isolated flags only when scope is actually isolated |
| Integration | Actual host -> Core -> HTTP -> authenticated QUIC shards -> shared verification -> durable purchase -> release/restart |

For each evidence item record command, feature flags, platform/durability mode,
all dependency revisions/patches, scenario/expected state and observed outcome,
artifact and exclusions. Keep useful bounded reports in a durable project path,
not just temporary logs. Never enable test hooks/test-utils in production release.

| Evidence | Owner | Required oracle; do not substitute |
| --- | --- | --- |
| E01 | Z01/Z08 | Arbitrary roster/expected JSON and old nonce cannot release; actual legitimate14 succeeds only through durable purchase |
| E02 | Z01/Z08 | One completed purchase remains idempotent across replay/restart; absent/wrong L1/split cannot become empty successful history |
| E03 | Z02 | Real ready shard produces witness with other shards unready; real daemon globalfalse and stale assignment cases covered |
| E04 | Z06/Z07 | All-empty/partial/8+6+6/full-turnover/cut/delta/restart schedules; actual positive recovery, no manually seeded ready shortcut |
| E05 | Z03/Z04 | One own vote is not class2; verified class survives restart/import; omission cannot erase stronger/unknown support |
| E06 | Z05 | Two genuine cross-network/context signatures cannot ban; genuine incompatible protected originals still do |
| E07 | Z08 | Durable exact intent precedes first send; retries/restart keep bytes/T0 and pending outputs; no automatic substitute |
| E08 | Z09 | Real HTTP/QUIC causal/split/prefix boundary, stale suffix and stale walletT0 in fresh gateway envelope |
| E09 | Z10 | Genuine retained signature/context verifies through actual client; quota/deadline/read-only behavior; live proof independent of old signers |
| E10 | Z11 | Passive authentic publication plus actual client refresh/cache/revocation/redirect/token isolation |
| E11 | Z04/Z07/Z12 | Aggregate staging/frame/work bounds and protected internal progress under explicit mixed load/slow disk |
| E12 | Z04/Z13 | Every metadata/index inclclasses disappears with expiry; quarantine/replacement/backup/restore/crash paths checked |
| E13 | Z13 | Real repeated-signal/early-unlink/stall/error CLI exit/process/DB-release evidence; no placeholder-only success |
| E14 | Z13 | Every operator alias/field/listener/private history and Host/Origin/proxy boundary; legitimate public ingress preserved |
| E15 | Z06/Z13 | Detectable own-choice loss with explicit independent evidence versus ordinary intact crash; limitations remain honest |

The older V01–V15 matrix remains the more detailed original evidence inventory;
map both to final tests. A green helper suite or a pre-change log closes neither
the current failure schedule nor a whole G gate.

## 7. Complete A01–A15 and prior-plan ownership

| Original package | Current work | Mandatory final boundary |
| --- | --- | --- |
| A01 | Z01/Z06/Z08/Z09 | Independent current authority + challenge + real consumer, full signatures |
| A02 | Z02/Z06/Z07 | Every signature/witness/activation/reentry site, exact qualified per-shard state |
| A03 | Z03/Z04/Z06/Z13 | Atomic immutable own decision, correct support restoration, loss distinct from crash |
| A04 | Z02/Z06/Z07 | Complete bounded no-gap durable installation and conditional progress |
| A05 | Z02/Z06/Z07 | Eligible full-key HRW, passive presence/mature tickets and current assignment |
| A06 | Z03/Z04/Z05/Z06/Z07 | Authenticated class/descendants, lawful live reporting, no framing |
| A07 | Z07/Z09/Z12/Z13 | Byte/work/task/socket/storage limits and protected progress |
| A08 | Z08/Z09/Z12 | Exact causal path, durable valid prefix, honest error boundary |
| A09 | Z01/Z06/Z08/Z11 | Actual intent/send/restart/challenge/L1/purchase/release flow |
| A10 | Z11/Z13 | All private operator surfaces/aliases/fields and public boundary |
| A11 | Z13 | Truthful bounded stop, actual instance exit/resources and failure cases |
| A12 | Z06/Z11 | Passive authenticated explicit HTTP discovery + client-only fallback |
| A13 | Z04/Z07/Z13 | All root-bound state/index expiry + private bounded persistent history |
| A14 | Z00/Z14 and E01–E15 | Actual revision-specific real-interface acceptance, all remaining gates |
| A15 | Z01/Z06/Z10/Z14 | Genuine bounded optional original retrieval, obsolete bypass retirement |

Prior M0–M10: M0 -> Z00; M1 -> Z01; M2 -> Z02; M3 -> Z03/Z04;
M4 -> Z06; M5 -> Z03–Z07; M6 -> Z08; M7 -> Z10; M8 -> Z11;
M9 -> Z09/Z12/Z13; M10 -> Z14. Z05 explicitly tracks the newly demonstrated
cross-context sanction risk. Prior R1 wallet fixes are preserved/retested, not
reapplied; R2 baseline -> Z00/Z14; R3–R6 -> Z06/Z07/Z03/Z10/Z08;
R7 -> Z04/Z09/Z12/Z13; R8 -> Z14. Do not omit operation R7 again.

## 8. Mandatory finish checklist and agent workflow

- [ ] Every DEC in §10 has a current selected/deferred/reopened classification.
- [ ] Every A package has a productive caller, applicable G premise and executed
      evidence, or an explicit remaining blocker; no “done by helper/commit title”.
- [ ] E01–E15 and original V01–V15 are linked to real assertions/results at resolved
      revisions; positive progress and negative refusal are both covered.
- [ ] No original receipt/string/DTO or self-selected expected authority can release.
- [ ] No source-completeness, support class or loss detector is inferred from a flag.
- [ ] Exact intents/challenges/purchase state survive crash/restore and bound retries.
- [ ] No signed-before-commit, discarded committed prefix, unsafe substitution,
      stale-response replay, false sanction or confirmed-row omission bypass remains.
- [ ] Every new state/index participates in TTL, backup, bounds and failure recovery.
- [ ] Actual app/daemon/CLI paths are tested; no manual-ready fixture is mislabelled.
- [ ] Final documentation is reconciled with selected decisions and recorded evidence.

Before **every** further agent start or reassignment, obtain the maintainer's
confirmation, naming the assignment and provisional number planned afterward.
No hidden nested workers. A suggested German prompt is: “Agent X soll Z01
umsetzen. Danach sind noch Y Agenteneinsätze geplant. Start freigeben?” Counts
are provisional and must change openly if proof gates need further work.

For a genuinely new unresolved tradeoff ask one A/B with recommendation and exact
reason. Already selected behavior is not asked again. Small derivable details
are a short problem–solution batch for sign-off. Silence is not required approval.
This plan was written without starting another agent.

## 9. Copy-paste starter instruction for the implementing agent

```text
Use docs/ARCHITECTURE_IMPLEMENTATION_CLOSURE_PLAN.md as the current continuation
plan for the entire HuMoCo architecture. Read the current AGENTS.md in all four
repos, all89InterviewDECwithsupersessions, the original A01–A15 acceptance plan
and the older M0–M10 handoff. This closure plan reconciles the2026-10-23 audit.
Recheck current HEAD/status/resolved dependencies before editing; baseline is
Nodee585830,Protoe119ee6,Core8265fd4,App1f0bd4e. Preserve unrelated work.

Communicate in German; write code/docs/commits in English. Start with Z00 and
small reviewed containment/regression work Z01–Z05, then close applicable G1–G5
contracts in Z06. Integrate complete bounded transfer, authentic class admission,
actual wallet intent/send/restart/challenge/L1purchase/release, retrieval/discovery
and operation in Z07–Z13. Use Z14 for independent combined acceptance.
Do not redo fixed originalReceipt/StringConfirmed bypasses, wallet crash fixes,
quarantine TTL repair or stored approval-byte return; preserve their regressions.

Never mistake one own vote for quorum support,14sameemptydigests for coverage,
RAMVecs for atomic snapshot installation, supplied expected JSON for authority,
Historyappend for durable L1/purchase transaction, or an old proof for fresh
release. No false completion from a helper/DTO/test name/doc/commit message.
Preserve14/20/800ms/read1,per-shard demand readiness,atomic durable own choices,
class-before-hash,regional-revisableFINAL,rootTTL+30s,zerohistoricalquorumarchives,
no predecessor veto/payment queue/automatic replacement/hearsay sanction.

Offline L1 import remains honest unverified L2; no fabricated online assurance.
Do not invent missing authority/coverage/rollback mechanisms or broaden parked
trust research. Ask A/B+recommendation for actual unselected tradeoffs; batch
routine details for sign-off. Before any further subagent start or
reassignment ask the user and state how many provisional assignments remain.
No hidden nested workers.

Execute bounded work packages via autonomous subagents (`invoke_subagent` with
`TypeName: "self"` and focused prompts containing [GOAL], [TARGET FILES],
[GUARDRAILS], and [DEFINITION OF DONE], as mapped in §4.1). After every
subagent invocation, independently inspect `git diff`, check callers via
`view_file`, and execute targeted tests before accepting the subagent output.

For each package follow actual registered callers, write meaningful real-interface
regressions, enforce limits, run targeted tests and record assumptions/results.
Finish all applicable A/DEC/G/Z/E/V rows at matching four-repo revisions and
required final checks. Report blockers honestly. Commit only if authorized in
the execution request; do not push/tag/deploy. This document itself authorizes
planning, not blanket implementation or automatic agent starts.
```

## 10. Complete decision ownership crosswalk

Every ID below links to the authoritative interview row and its rationale.
Ownership is a checklist, not a claim of implementation/test completion. Read
supersessions; documentary/deferred/reopened entries are not invented features.

| Decision and authoritative topic | Work ownership | Qualification |
| --- | --- | --- |
| [DEC-001](ARCHITECTURE_INTERVIEW_NOTES.md#dec-001) — Node responsibility | Z14 | Preserve blind L2; no purchase/monetary state in node. |
| [DEC-002](ARCHITECTURE_INTERVIEW_NOTES.md#dec-002) — Existing dashboard | Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-003](ARCHITECTURE_INTERVIEW_NOTES.md#dec-003) — Metric history | Z04 / Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-004](ARCHITECTURE_INTERVIEW_NOTES.md#dec-004) — Compatibility | Z00 / Z14 | Coordinated compatibility scope, not arbitrary wire migration. |
| [DEC-005](ARCHITECTURE_INTERVIEW_NOTES.md#dec-005) — Genesis versus successor locks | Z09 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-006](ARCHITECTURE_INTERVIEW_NOTES.md#dec-006) — Protocol reference | Z00 | Read with DEC-038 shared-library refinement. |
| [DEC-007](ARCHITECTURE_INTERVIEW_NOTES.md#dec-007) — Other applications | Z14 | Permissionless compatible public ingress is retained. |
| [DEC-008](ARCHITECTURE_INTERVIEW_NOTES.md#dec-008) — Checkout timing | Z12 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-009](ARCHITECTURE_INTERVIEW_NOTES.md#dec-009) — Timeout and retry handling | Z08 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-010](ARCHITECTURE_INTERVIEW_NOTES.md#dec-010) — New-payment submission | Z08 / Z09 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-011](ARCHITECTURE_INTERVIEW_NOTES.md#dec-011) — Reconciliation progress | Z09 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-012](ARCHITECTURE_INTERVIEW_NOTES.md#dec-012) — Reconciliation request size | Z09 / Z12 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-013](ARCHITECTURE_INTERVIEW_NOTES.md#dec-013) — Reconciliation batch acceptance | Z09 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-014](ARCHITECTURE_INTERVIEW_NOTES.md#dec-014) — Split-voucher reconciliation scope | Z08 / Z09 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-015](ARCHITECTURE_INTERVIEW_NOTES.md#dec-015) — Ingress tiers and evidence | Z01 / Z12 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-016](ARCHITECTURE_INTERVIEW_NOTES.md#dec-016) — Coordinated attacker | Z06 | Coordinated adversary; do not multiply independent-fault assumptions. |
| [DEC-017](ARCHITECTURE_INTERVIEW_NOTES.md#dec-017) — Recipient-selected verification sources | Z01 / Z06 / Z08 / Z11 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-018](ARCHITECTURE_INTERVIEW_NOTES.md#dec-018) — Ticket lifecycle per identity | Z06 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-019](ARCHITECTURE_INTERVIEW_NOTES.md#dec-019) — Fresh cryptographic identity | Z05 / Z06 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-020](ARCHITECTURE_INTERVIEW_NOTES.md#dec-020) — Network-size observations for client statistics | Z06 / Z08 / Z11 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-021](ARCHITECTURE_INTERVIEW_NOTES.md#dec-021) — Conflicting statistical observations | Z06 / Z08 / Z11 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-022](ARCHITECTURE_INTERVIEW_NOTES.md#dec-022) — No single-source canonical takeover | Z03 / Z04 / Z06 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-023](ARCHITECTURE_INTERVIEW_NOTES.md#dec-023) — Unresolved conflicting slot | Z03 / Z04 / Z06 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-024](ARCHITECTURE_INTERVIEW_NOTES.md#dec-024) — Checkout versus background capacity | Z12 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-025](ARCHITECTURE_INTERVIEW_NOTES.md#dec-025) — Full shard-direct pool and work budget | Z12 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-026](ARCHITECTURE_INTERVIEW_NOTES.md#dec-026) — Recovery signing readiness | Z02 / Z07 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-027](ARCHITECTURE_INTERVIEW_NOTES.md#dec-027) — Checkout availability and dispatch | Z12 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-028](ARCHITECTURE_INTERVIEW_NOTES.md#dec-028) — Possible checkout failure suppression | Z12 | Deferred optimization: no suppression mechanism is selected. |
| [DEC-029](ARCHITECTURE_INTERVIEW_NOTES.md#dec-029) — Durable signing before response | Z03 | Durable ordering restored by DEC-087. |
| [DEC-030](ARCHITECTURE_INTERVIEW_NOTES.md#dec-030) — Persistent storage failure | Z02 / Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-031](ARCHITECTURE_INTERVIEW_NOTES.md#dec-031) — Automatic storage recovery | Z02 / Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-032](ARCHITECTURE_INTERVIEW_NOTES.md#dec-032) — Lost signing choices | Z03 / Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-033](ARCHITECTURE_INTERVIEW_NOTES.md#dec-033) — Signing protection layout | Z03 / Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-034](ARCHITECTURE_INTERVIEW_NOTES.md#dec-034) — Graceful shutdown | Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-035](ARCHITECTURE_INTERVIEW_NOTES.md#dec-035) — Automatic expiry processing | Z04 / Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-036](ARCHITECTURE_INTERVIEW_NOTES.md#dec-036) — Deployment default | Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-037](ARCHITECTURE_INTERVIEW_NOTES.md#dec-037) — Private operator access | Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-038](ARCHITECTURE_INTERVIEW_NOTES.md#dec-038) — Shared protocol library | Z00 / Z14 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-039](ARCHITECTURE_INTERVIEW_NOTES.md#dec-039) — Committee continuity design direction | Z06 / Z07 | Mechanism reopened; continuity goal remains, no mandatory old sketch. |
| [DEC-040](ARCHITECTURE_INTERVIEW_NOTES.md#dec-040) — Operator reliability diagnostics | Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-041](ARCHITECTURE_INTERVIEW_NOTES.md#dec-041) — Handoff interruption preference | Z02 / Z07 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-042](ARCHITECTURE_INTERVIEW_NOTES.md#dec-042) — Requests during handoff | Z07 / Z08 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-043](ARCHITECTURE_INTERVIEW_NOTES.md#dec-043) — Routine handoff cadence | Z07 | Cadence tentative; never a daily committee term or activation proof. |
| [DEC-044](ARCHITECTURE_INTERVIEW_NOTES.md#dec-044) — Byzantine tolerance target | Z06 / Z07 | Conditional fault target, not enforced by ticket maturity or belief. |
| [DEC-045](ARCHITECTURE_INTERVIEW_NOTES.md#dec-045) — Complete committee turnover | Z02 / Z06 / Z07 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-046](ARCHITECTURE_INTERVIEW_NOTES.md#dec-046) — Handoff progress after contention | Z02 / Z06 / Z07 | Positive safe progress after stabilization required, not permanent refusal. |
| [DEC-047](ARCHITECTURE_INTERVIEW_NOTES.md#dec-047) — Intended network topology | Z06 / Z14 | Operating goal, not proof that honest HRW views are identical. |
| [DEC-048](ARCHITECTURE_INTERVIEW_NOTES.md#dec-048) — FINAL threshold and organic-network assumption | Z02 / Z06 / Z14 | Retain regional FINAL regime; do not repeat the threshold question. |
| [DEC-049](ARCHITECTURE_INTERVIEW_NOTES.md#dec-049) — Client authorization terminology | Z00 / Z14 | Documentary terminology; no arbitrary signed-format rename. |
| [DEC-050](ARCHITECTURE_INTERVIEW_NOTES.md#dec-050) — Predecessor terminology | Z00 / Z14 | Terminology plus exact consumed split-output binding. |
| [DEC-051](ARCHITECTURE_INTERVIEW_NOTES.md#dec-051) — Shard summary terminology | Z00 / Z14 | Terminology; digest integrity is not omission coverage. |
| [DEC-052](ARCHITECTURE_INTERVIEW_NOTES.md#dec-052) — Autonomous vocabulary maintenance | Z00 / Z14 | Autonomous vocabulary maintenance, not a new consensus choice. |
| [DEC-053](ARCHITECTURE_INTERVIEW_NOTES.md#dec-053) — Partition-resilient regional acceptance | Z03 / Z06 / Z07 | Regional/revisable acceptance qualifies earlier global-finality wording. |
| [DEC-054](ARCHITECTURE_INTERVIEW_NOTES.md#dec-054) — Regional eligibility, honest merge and merchant risk | Z03 / Z05 / Z06 / Z07 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-055](ARCHITECTURE_INTERVIEW_NOTES.md#dec-055) — Rejection of predecessor baton chaining and chained L2 receipts | Z06 / Z07 / Z14 | Rejected predecessor baton, recursive receipts and active ping storms. |
| [DEC-056](ARCHITECTURE_INTERVIEW_NOTES.md#dec-056) — Passive presence exclusion | Z02 / Z06 / Z07 / Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-057](ARCHITECTURE_INTERVIEW_NOTES.md#dec-057) — Mandatory restart sync-readiness; no empty-state disaster fallback | Z02 / Z06 / Z07 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-058](ARCHITECTURE_INTERVIEW_NOTES.md#dec-058) — Quorum-backed verified digest-pull | Z02 / Z06 / Z07 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-059](ARCHITECTURE_INTERVIEW_NOTES.md#dec-059) — Fixed snapshot with bounded deltas and bucket sealing | Z06 / Z07 / Z09 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-060](ARCHITECTURE_INTERVIEW_NOTES.md#dec-060) — Exact-payload retries and three-send heuristic | Z06 / Z08 / Z09 / Z12 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-061](ARCHITECTURE_INTERVIEW_NOTES.md#dec-061) — Wallet-bound creation time; fresh live ingress versus historical sync | Z06 / Z08 / Z09 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-062](ARCHITECTURE_INTERVIEW_NOTES.md#dec-062) — RAM-first response; entry-only freshness and nominal seal | Z06 / Z08 / Z09 | Early release superseded by DEC-087; other selected timing rules remain. |
| [DEC-063](ARCHITECTURE_INTERVIEW_NOTES.md#dec-063) — Lost-choice safety gate | Z06 / Z13 | Actual loss gate retained; ordinary-crash risk-marker construction withdrawn. |
| [DEC-064](ARCHITECTURE_INTERVIEW_NOTES.md#dec-064) — Strict confirmation-class priority before canonical hash | Z03 / Z04 / Z05 / Z06 / Z07 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-065](ARCHITECTURE_INTERVIEW_NOTES.md#dec-065) — Minimal losing-branch retention | Z03 / Z04 / Z05 / Z06 / Z07 / Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-066](ARCHITECTURE_INTERVIEW_NOTES.md#dec-066) — Inline compact conflict evidence | Z09 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-067](ARCHITECTURE_INTERVIEW_NOTES.md#dec-067) — No minority collision veto at checkout | Z09 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-068](ARCHITECTURE_INTERVIEW_NOTES.md#dec-068) — Bounded automatic client reconciliation | Z08 / Z09 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-069](ARCHITECTURE_INTERVIEW_NOTES.md#dec-069) — Read-only recovery of original checkout approvals | Z10 | Exceptional original recovery, not a mandatory current-clearance dependency. |
| [DEC-070](ARCHITECTURE_INTERVIEW_NOTES.md#dec-070) — Root-lifetime retention of original own approvals | Z03 / Z04 / Z10 / Z13 | Own originals through root+30s, distinct from archived inherited quorums. |
| [DEC-071](ARCHITECTURE_INTERVIEW_NOTES.md#dec-071) — Durable wallet intent before network dispatch | Z08 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-072](ARCHITECTURE_INTERVIEW_NOTES.md#dec-072) — Durable L1 voucher/purchase, ephemeral completed-checkout certificate | Z01 / Z08 | L1/purchase-before-release; completed quorum certificate is ephemeral. |
| [DEC-073](ARCHITECTURE_INTERVIEW_NOTES.md#dec-073) — No automatic substitute payment; strict client boundary | Z08 | No automatic substitute; partial purchase/tender are client policy. |
| [DEC-074](ARCHITECTURE_INTERVIEW_NOTES.md#dec-074) — Idempotent repeated termination signals | Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-075](ARCHITECTURE_INTERVIEW_NOTES.md#dec-075) — Internal shutdown deadline with outer supervisor margin | Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-076](ARCHITECTURE_INTERVIEW_NOTES.md#dec-076) — Stop CLI waits for verified completion and released DB | Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-077](ARCHITECTURE_INTERVIEW_NOTES.md#dec-077) — Operator-only metrics and diagnostic topology | Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-078](ARCHITECTURE_INTERVIEW_NOTES.md#dec-078) — Dynamic public gateway discovery | Z11 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-079](ARCHITECTURE_INTERVIEW_NOTES.md#dec-079) — Bounded last-known gateway fallback belongs to clients | Z08 / Z11 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-080](ARCHITECTURE_INTERVIEW_NOTES.md#dec-080) — Quorum proof required for paid/goods release | Z01 / Z06 / Z08 | Current verified quorum, not bare lookup or caller flag, for FINAL release. |
| [DEC-081](ARCHITECTURE_INTERVIEW_NOTES.md#dec-081) — Cheap ordinary lookup, explicit quorum-backed release verification | Z01 / Z06 / Z08 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-082](ARCHITECTURE_INTERVIEW_NOTES.md#dec-082) — Confirm derived implementation batch | Z01 / Z06 / Z08 / Z11 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-083](ARCHITECTURE_INTERVIEW_NOTES.md#dec-083) — Current shard-state quorum, no inherited historical certificate archive | Z01 / Z03 / Z06 / Z07 / Z08 / Z10 | LRC-002 replaces archive premise; withdrawn question chose neither A nor B. |
| [DEC-084](ARCHITECTURE_INTERVIEW_NOTES.md#dec-084) — Live-state verification implementation requirements | Z01 / Z06 / Z08 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-085](ARCHITECTURE_INTERVIEW_NOTES.md#dec-085) — Demand-triggered recovery of newly assigned shards | Z02 / Z06 / Z07 / Z12 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-086](ARCHITECTURE_INTERVIEW_NOTES.md#dec-086) — Bounded demand-driven shard recovery requirements | Z02 / Z06 / Z07 / Z12 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-087](ARCHITECTURE_INTERVIEW_NOTES.md#dec-087) — Durable-before-Release restored | Z03 / Z06 / Z09 | Atomic lock+own choice before release; no ordinary-crash quarantine. |
| [DEC-088](ARCHITECTURE_INTERVIEW_NOTES.md#dec-088) — Bounded durable-pipeline operations | Z04 / Z12 / Z13 | Preserve selected behavior; verify actual productive path and evidence. |
| [DEC-089](ARCHITECTURE_INTERVIEW_NOTES.md#dec-089) — Specification cleanup and acceptance mapping | Z00 / Z14 | Document/spec reconciliation plus real evidence; no proof by prose. |

## 11. Planning validation and limits

The 2026-10-23 audit supplied the source findings; code paths were rechecked for
this plan. The89decision ownership rows,15original A packages,15Zpackages and
15evidence groups form the anti-forgetting checklist. Static link/anchor/coverage/
whitespace checks validate navigation only. No production code, test, binding
specification or commit is changed by this planning deliverable; no runtime tests
were executed. A later implementing agent must supply the actual safety arguments,
productive integration and executed acceptance evidence.
