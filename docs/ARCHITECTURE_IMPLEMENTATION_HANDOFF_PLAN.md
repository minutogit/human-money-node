# Complete Architecture Implementation Handoff Plan

**Historical detailed handoff.** Continue with
[the 2026-10-23 completion plan](ARCHITECTURE_IMPLEMENTATION_CLOSURE_PLAN.md).
The later audit verified real fixes but found remaining/new release, readiness,
class-admission, quarantine, framing and resource defects. Baseline findings,
worker-package labels and completion assumptions below are not current status;
retain their applicable original acceptance criteria and decision provenance.

Date: 2026-10-21 (Europe/Berlin). Requirement baseline: **89 decisions,
DEC-001–DEC-089**, CP-0095, with their recorded refinements and withdrawals.
Status: **planning only; implementation and final acceptance are incomplete**.

This document is an implementation handoff for a new AI with no access to the
preceding chat, temporary patches or agent memory. It covers the **entire original
A01–A15 plan**, including R1–R8, existing implementations, regressions introduced
after those plans, unresolved safety premises and final operational acceptance.
It does not authorize implementation by itself or select a new consensus policy.
This planning deliverable changes this plan and documentation/navigation links
qualifying the earlier completion claims. No code, tests, binding specifications
or commits were changed; no runtime tests were executed.

## 1. Read this before changing anything

### 1.1 Requirement authority and documentary conflicts

Read, in order:

1. Current `AGENTS.md` in each affected repository, applicable nested instructions,
   and [the translation glossary](TRANSLATION_GLOSSARY.md). Communicate with the
   maintainer in **German**; write code, documentation and commits in **English**.
2. [The interview state](ARCHITECTURE_INTERVIEW_STATE.md), then the **complete
   decision register and provenance** in [notes §2.1](ARCHITECTURE_INTERVIEW_NOTES.md#21-current-decision-register-and-provenance),
   [refinements/withdrawals §2.2](ARCHITECTURE_INTERVIEW_NOTES.md#22-alternatives-refinements-and-superseded-proposals),
   and [open leaves §2.3](ARCHITECTURE_INTERVIEW_NOTES.md#23-open-design-and-decision-inventory).
   Read the linked §7 selection rationale before implementing an affected DEC.
3. [The approved consolidation](ARCHITECTURE_CONSOLIDATION.md),
   [invariant registry](INVARIANT_REGISTRY.md), and applicable numbered specs.
4. [Original A01–A15 implementation plan](ARCHITECTURE_IMPLEMENTATION_PLAN.md),
   [earlier R1–R8 plan](ARCHITECTURE_IMPLEMENTATION_REMAINING_PLAN.md), and
   [execution record](ARCHITECTURE_IMPLEMENTATION_PROGRESS.md), distinguishing
   historical findings from current code.
5. [G1–G5 contract document](SAFETY_AND_PROGRESS_CONTRACTS_G1_G5.md), **with the
   unresolved contradictions below**. Its “canonical” heading is not evidence of
   maintainer selection, proof closure, production enforcement or executed tests.

The execution record's final “Subagent execution and completion ledger” states
that R1–R6/R8 and G1–G5 are implemented/audited/verified. The checked production
paths contradict that broad claim; R7 is absent from that declaration. Do not use
it to mark any package complete. Conversely, the earlier R1 description of an
unapplied wallet proposal is now outdated: the corrected transaction mechanism
is present in Core. Reconcile these statements after actual work, preserving
historical provenance rather than rewriting the interview's answers.

Use **five independent statuses** per requirement: selected requirement;
justified design and assumptions; productive implementation/call path; executed
verification at matching revisions; remaining limitation. A document, helper,
status byte, test name or green unrelated suite cannot substitute for another
status. This plan is a backlog/closure map, not a new approved safety proof.

### 1.2 Exact inspected repository baseline

All code observations in this document are static observations at these commits:

| Repository | Inspected HEAD | Working tree observed |
| --- | --- | --- |
| `human-money-node` | `fea98c7993011062c439c9dc4537f17b73c3cb34` | No tracked or untracked changes before this plan |
| `humoco-proto` | `e119ee60f886facad60be325ad9d8e4227590b4b` | Clean |
| `human-money-core` | `bf6da00bc3a94e33292d131f1a2b85574218bbae` | Untracked `fuzz/corpus/`, `fuzz/target/`, `tools/simulations/offline-gossip/__pycache__/` |
| `human-money-app` | `7d3bb8cebce2b013867a12f71a0891cf6ab3e78c` | Clean |

Sibling repositories share the parent directory. They are not subdirectories of
the node repository. Obtain a **new** `git status --short`, `git rev-parse HEAD`,
branch and dependency/lockfile snapshot in every repository before implementation.
Newer commits and user changes take precedence over stale line numbers; verify
symbols and actual callers anew. Do not revert, stage or overwrite unrelated
edits or generated data. Do not rely on `/tmp` patches or old logs for this handoff.

Reproduce a historical finding portably with Git, for example, from the node root:

```bash
git show fea98c7993011062c439c9dc4537f17b73c3cb34:crates/humoco-node/src/daemon.rs
git -C ../humoco-proto show e119ee60f886facad60be325ad9d8e4227590b4b:src/live.rs
git -C ../human-money-core show bf6da00bc3a94e33292d131f1a2b85574218bbae:src/app_service/conflicts.rs
git -C ../human-money-app show 7d3bb8cebce2b013867a12f71a0891cf6ab3e78c:src-tauri/src/commands/transfers.rs
```

Check local Cargo patches and **resolved dependency revisions**, not just each
repository's HEAD: an app built against a different Core or a node using a
different protocol crate is not a combined revision acceptance test. No `[patch]`
belongs in the app's committed `src-tauri/Cargo.toml`; follow its agent rules.

### 1.3 Non-negotiable settled behavior

- L1 owns transactions, monetary amounts, ownership, causal voucher history and
  purchase records. L2 remains a blind active `parent_lock -> child_lock` service.
- Current qualified nodes attest their **safely synchronized live state**. No
  original-quorum bundle migration, receipt chain or historical quorum archive;
  original signers leaving alone does not invalidate a synchronized lock.
- Ordinary status stays cheap `read_quorum=1` / INV-0310. Payment release requires
  the actually verified current FINAL proof, not a matching lock, gateway flag,
  original receipt, requested quorum number or user-supplied outcome string.
- One frozen eligible committee, at most 20 distinct full identities; FINAL needs
  14; no rank-21 replacement, weak-conflict veto or available-minority downgrade.
  N<20 retains its explicit adaptive PROVISIONAL policy. FINAL is **regional and
  revisable**, not globally irreversible. The 800 ms budget bounds collection.
- Own original signing decisions are immutable across canonical changes. Reserve
  worker capacity before RAM mutation; commit exact lock and own choice atomically
  and durably before any original signature escapes or self vote counts. Never
  hold a RAM guard across persistence. Slow storage cannot weaken this order.
- Unknown/restarted/newly assigned shards are NOT_READY until justified recovery.
  Readiness is **per shard**; FINAL network-size hysteresis does not require all
  shards globally ready. Recovery is demand-triggered, coalesced, bounded; no eager
  65,536-shard sweep or node-side pending-payment queue.
- Class2 > class1 > class0; min(H_canon) is a tie-breaker within the highest
  admissible confirmed class. Claimed status alone is not support. Lawful losing
  original voters and later current-state reporters are not automatically fraud.
- Retain required live exclusions/own choices through authenticated root expiry
  plus 30 s; grace does not extend spending. No permanent tombstones/full losing
  tree archive. Privacy and bounds apply equally to provisional/quarantined data.
- Wallet T0 is signed public `created_at_ms`, distinct from encrypted time; exact
  bytes and T0 survive retries/failover. Entry freshness is 30 s; do not add a
  second wallet-freshness gate at delayed durable completion. Recheck actual root
  usability and current signing eligibility as required by the existing contract.
- No automatic replacement spend/refund after uncertainty. Multi-voucher partial
  purchases and tender changes are client business logic. Do not add amounts or
  purchase IDs to node consensus.
- Only two verified incompatible personal approvals in the protected context can
  justify fraud sanctions. No hearsay/telemetry bans or new reputation gossip.
- Metrics/topology/dashboard remain private. Public gateway discovery is desired;
  cached-address fallback and provider credentials belong solely to clients.
- Zero-server / offline deployment reality: in current practice and offline P2P usage,
  zero public L2 servers exist. Layer 1 voucher authenticity (ProofChain, cryptographic
  signatures and balance) is 100% mathematically valid offline. On Layer 2, absence of
  reachable servers must be represented truthfully as 'unverified' / 'offline' with
  level dots '○○' (two empty circles) and an explicit merchant warning; software must
  NEVER fake a 14/20 server quorum, show green level-2 indicators, or mint automatic
  goods release when zero servers respond. Goods release in offline mode is an explicit
  merchant trust decision, not a cryptographic finality verdict.

### 1.4 Supersession traps to avoid

| Historical item | Current interpretation |
| --- | --- |
| DEC-006 reference packaging | DEC-038 selects a shared Rust protocol crate; Core remains domain authority. Do not copy multiple divergent verifiers. |
| DEC-039 continuity construction | Mechanism reopened; full-turnover/progress goals remain. No approved fixed founder/handoff history mechanism. |
| DEC-027 single application attempt | DEC-060 refines it with bounded conditional exact-payload three-send behavior; frozen membership/all-member dispatch remain. |
| DEC-029/033/034 → DEC-062 | DEC-087 restores durable-before-release; DEC-062's entry-only freshness, reserve-first handling and nominal seal survive. |
| DEC-063 ordinary-crash containment proposals | DEC-087 removes the released-but-volatile choice window for intact storage. Actual storage loss/rollback remains G5; no ordinary-crash risk markers or identity abandonment. |
| Old global-finality/mandatory predecessor interpretations | Qualified by DEC-053/054/055; no predecessor-quorum veto or recursive L2 receipt chain. |
| LRC-001 / §7.92 historical proof continuity | LRC-002 / DEC-083 replaces archive prerequisites. Q-C4-ACTIVE-PROOF-CONTINUITY-01 is withdrawn; neither A nor B selected. |
| Early merchant certificate-storage proposal | DEC-072 requires durable L1 voucher plus purchase binding before release; no completed-checkout certificate archival duty. |
| DEC-028; DEC-043 | Suppression remains deferred; hourly routine cadence is tentative, not authority or an implemented timer requirement. |
| Q-S3.3-01; Q-S2.2-01; broad trust research | Payment-round question stays parked, premature authority question withdrawn; broad trust research stays stopped unless expressly invoked. |

## 2. Current code map and verified gaps

Paths below are clickable relative to this file. Line numbers quoted in prose
identify the inspected commit, not a promise that future lines remain stable.

| ID | Static finding and actual productive path | Required response |
| --- | --- | --- |
| F01 | Core [conflicts.rs](../../human-money-core/src/app_service/conflicts.rs) `process_l2_response_internal`, around 310, promotes an original `ConfirmFinal` to `Confirmed` when authority is supplied. `verify_checkout_response_with_authority` then constructs goods release. [layer2_api.rs](../../human-money-core/src/models/layer2_api.rs) `CheckoutReleaseVerdict::new`, around 612, makes any `Confirmed` automatic release. | M1: separate original receipt observation from fresh current checkout authorization. |
| F02 | App [transfers.rs](../../human-money-app/src-tauri/src/commands/transfers.rs) `evaluate_checkout_release`, around 229, accepts a frontend string including `Confirmed`; it is registered in [lib.rs](../../human-money-app/src-tauri/src/lib.rs), around 141. Live verification also accepts caller-supplied expected context; it is not backed by independent persisted recipient state. | M1/M6: remove untrusted release minting; backend derives proof expectations. |
| F03 | Core `verify_live_checkout_proof(&self, ...)` verifies bytes then returns authorization without L1/purchase commit or challenge consumption. App `receive_bundle`, around 138, returns `checkout_verdict: None`. [transferService.ts](../../human-money-app/src/services/transferService.ts) exposes verification wrappers but no productive UI caller was found. | M6: actual sender/recipient/release state machine, not another unused helper. |
| F04 | [ReceiveSuccessView.tsx](../../human-money-app/src/components/ReceiveSuccessView.tsx), around 67/78/131, trusts DTO outcome/presence and constructs fixed 14/20 display; `Boolean(checkoutVerdict)` is passed as verification. | M1/M6: render only actual backend transaction results; no invented proof facts. |
| F05 | Node [daemon.rs](../crates/humoco-node/src/daemon.rs) `sync_single_shard`, around 1099–1106, marks READY when quorum-reported digest equals local digest. Later branch also marks READY after pull/quarantine, around 1218. | M2/M5: agreement alone is insufficient; require proved source coverage and no-gap durable activation. |
| F06 | [transport.rs](../crates/humoco-node/src/network/transport.rs) `NodeRequestHandler` digest branch, around 1193–1204, uses disk error → empty defaults and merges RAM without exact durable/readiness witness qualification. Unready partial state may consequently count as recovery agreement. | M2: partial data serving must be explicitly non-witness; errors never attest empty state. |
| F07 | `ActiveSyncRequest` branch, around 1371, reconstructs/sorts whole live state for every offset page, with no fixed cut/delta completeness. [daemon.rs](../crates/humoco-node/src/daemon.rs) imports directly into productive storage before final verification. | M5: bounded stable snapshot/delta transfer, staged validation and atomic visibility; assignment fence. |
| F08 | [engine.rs](../crates/humoco-node/src/storage/engine.rs) `HmcRamIndex` PartitionSync conflict branch, around 164–205, uses hash alone. [resolver.rs](../crates/humoco-sim-core/src/resolver.rs) compares status-derived classes but does not itself authenticate support. | M3/M5: one supported class rule through production paths, including HMC. |
| F09 | [db.rs](../crates/humoco-node/src/storage/db.rs) `quarantine_subquorum_locks`, around 535–610, moves all omitted rows without proving class0, removes TTL indexes, and is called before final digest validation. [engine.rs](../crates/humoco-node/src/storage/engine.rs), around 2212, does blocking DB work in async context and separate RAM scans/mutations. | M3/M5/M9: protect confirmed/unknown support; transactional quarantine/install and bounded TTL/progress. |
| F10 | [routes.rs](../crates/humoco-node/src/api/routes.rs) `get_retained_choice`, around 2465, returns child plus `has_*` booleans, not original signature/context. Tag length is bounded, but useful proof retrieval and its dedicated admission/deadline contract are missing. | M7: exact retained original approvals, optional exceptional path only. |
| F11 | `public_gateways`, around 2459, returns only local configured URLs. | M8: authenticated passive published endpoint discovery; separate client fallback. |
| F12 | G5 generation/rollback mode described in G document has no matching implemented node mechanism found. Local durable commit cannot detect every full-directory rollback/key clone. | M4/M9: explicit achievable detection/scope contract; do not assert universal detection. |
| F13 | Current safety document disagrees with selected freshness, no-payment-queue, readiness and actual field encodings; its listed tests do not establish G1–G5. | M0/M4/M10: reconcile requirements, implement and evidence actual contracts. |

### 2.1 Reuse existing work; do not reimplement completed foundations

- Proto [live.rs](../../humoco-proto/src/live.rs), [verify.rs](../../humoco-proto/src/verify.rs):
  separate length-prefixed original/live domains, exact context binding, distinct
  full-key verification and bounded FINAL proof structure. These expect independently
  established authority; they do not establish it themselves.
- Node [storage/db.rs](../crates/humoco-node/src/storage/db.rs),
  [storage/engine.rs](../crates/humoco-node/src/storage/engine.rs): atomic durable
  original lock/own-choice records, exact retained approvals, bounded commit ACKs,
  pending coalescing, storage-health latch, durable RAM-version metadata and
  durable valid-prefix chain infrastructure.
- Node [api/live.rs](../crates/humoco-node/src/api/live.rs): fresh proof collection
  and signer checks. Audit every caller/gate after recovery fixes; do not replace
  this with gateway booleans or full quorum on normal status.
- Per-shard readiness, passive/mature HRW eligibility, demand-repair job scaffolding,
  [network/pool.rs](../crates/humoco-node/src/network/pool.rs) lease-based idle LRU,
  neutral capacity errors, private operator router/browser boundary, bounded hourly
  history and instance-bound stop completion already exist. Complete composition
  and missing evidence rather than adding a second subsystem.
- Core [wallet_transaction.rs](../../human-money-core/src/storage/wallet_transaction.rs),
  [orchestrator.rs](../../human-money-core/src/app_service/orchestrator.rs): authenticated
  undo/commit records, recovery-before-managed-write/login, post-marker
  `UncertainCommit` handling, stale-journal/fork-lock rejection, recognized temporary
  cleanup and process-kill test code are now present. The old R1 proposal is not
  still waiting in `/tmp`. Reverify the final revision and integrate new payment
  records into this existing transaction boundary. Supported recovery is Unix;
  direct low-level writers/platform behavior still require an explicit scope audit.

## 3. Dependency and delivery order

Do not code a complete unproved recovery protocol merely to turn READY green.
First make concrete unsafe paths fail closed, while reporting the resulting
availability limit honestly. Then close the necessary design leaves and restore
safe progress. Indefinite NOT_READY is containment, not completion of DEC-045/046.

| Milestone | Scope | Depends on | Exit condition |
| --- | --- | --- | --- |
| M0 | Snapshot, source reconciliation, reproducible gap/evidence inventory | Read-only start | Current baseline and true statuses, no assumed completion |
| M1 | Close untrusted/original-receipt release bypasses and misleading UI | M0 | No non-current-proof path creates automatic release |
| M2 | Stop unjustified recovery witnesses/activation and stale completion | M0 | No readiness from incomplete/undurable/error-as-empty state |
| M3 | Stop destructive unsupported merge/quarantine and TTL loss | M0 | Confirmed/unknown support and retained safety data preserved |
| M4 | Explicit G1–G5 closure artifacts and one field/encoding contract | M0, regression findings | Required premises justified or precise blocked leaves recorded |
| M5 | Supported merge plus complete staged transfer/atomic activation | M2/M3, applicable M4 gates | Safe automatic progress demonstrated under stated conditions |
| M6 | Productive wallet/recipient/purchase/release integration | M1, relevant M4/M5, existing wallet transaction | Exact durable intent and L1/purchase-before-release end to end |
| M7 | Optional bounded retained-original-proof recovery | Existing durable choices, M4 format, M6 uncertainty | Read-only authentic retrieval; never required by current live path |
| M8 | Passive public gateway discovery and client fallback | M4 advertisement context, M6 client budget | Authenticated bounded candidates, credential isolation |
| M9 | All operational/resource/TTL/shutdown/history composition | Applies throughout; G4/G5 and M5/M6 for integrated cases | Measured bounded behavior and honest failure outcomes |
| M10 | Independent full-plan acceptance, docs, dependency delivery | All applicable above | DEC/A/G evidence matrix at matching revisions, explicit exclusions |

These are reviewable deliverables, **not a fixed number of agents or a time/percent
estimate**. M4's genuine unresolved choices can change the implementation order.
M9 evidence accompanies each change; it is not postponed until everything else
is merged. No new automatic agent assignment is authorized by this table.

### 3.1 Bite-Sized Worker Packages (Orchestration for Model-Router / Muse Spark)

To ensure reliable, focused execution without context degradation or hallucinations,
the implementation is subdivided into self-contained, bite-sized tasks tailored for
`model-router run "..." -m muse`:

| Package ID | Target Repo | Primary Files | Focused Scope |
| --- | --- | --- | --- |
| **M1.1** | `human-money-core` | `src/app_service/conflicts.rs`, `src/models/layer2_api.rs` | Disallow automatic release from original write receipt; restrict `CheckoutReleaseVerdict` to live proofs only. |
| **M1.2** | `human-money-app` | `src-tauri/src/commands/transfers.rs`, `src/components/ReceiveSuccessView.tsx` | Eliminate string-based release bypass in Tauri; enforce 2-level dots status (`○○` for 0 servers / offline) and add settings link + trust override. |
| **M2.1** | `human-money-node` | `crates/humoco-node/src/daemon.rs` | Prevent empty-state / unverified digest agreement from marking shards `READY` ([DEC-057](ARCHITECTURE_INTERVIEW_NOTES.md#dec-057)). |
| **M2.2** | `human-money-node` | `crates/humoco-node/src/network/transport.rs` | Fail closed on storage read errors; eliminate `.unwrap_or_default()` empty witness spoofing. |
| **M3.1** | `human-money-node` | `crates/humoco-node/src/storage/engine.rs` | Enforce confirmation-class precedence ($\text{Class 2} > \text{Class 1} > \text{Class 0}$) before hash comparison in HMC RAM index ([DEC-022](ARCHITECTURE_INTERVIEW_NOTES.md#dec-022), [DEC-064](ARCHITECTURE_INTERVIEW_NOTES.md#dec-064)). |
| **M3.2** | `human-money-node` | `crates/humoco-node/src/storage/db.rs`, `engine.rs` | Preserve TTL index on quarantined records (prevent state bloat); move blocking DB work off runtime threads. |
| **M4.1** | `human-money-node` / `proto` | `docs/SAFETY_AND_PROGRESS_CONTRACTS_G1_G5.md`, `humoco-proto/src/live.rs` | Reconcile G1–G5 contracts: enforce 30s wallet entry freshness (revert 600s), specify endianness and honest rollback limits. |
| **M5.1** | `human-money-node` | `crates/humoco-node/src/network/transport.rs`, `daemon.rs` | Implement stable snapshot cursor paging for `ActiveSyncRequest`; stage candidate records before active store publication. |
| **M6.1** | `human-money-core` / `app` | `human-money-app/src-tauri/src/commands/transfers.rs` | Wire `resolve_active_l2_nodes_internal()` into transfer flow; implement fast-fail on 0 reachable servers and sender durable intent. |
| **M6.2** | `human-money-app` | `src-tauri/src/commands/transfers.rs`, Core conflicts/orchestrator | Wire recipient live checkout verification and durable purchase binding before goods release. |
| **M7.1** | `human-money-node` | `crates/humoco-node/src/api/routes.rs` | Extend `/v1/own-choice/{tag}` to return verifiable Ed25519 signature bytes and context instead of booleans. |
| **M8.1** | `human-money-node` / `app` | `crates/humoco-node/src/api/routes.rs`, App `settings_cmd.rs` | Expose passive mesh-discovered gateways in `/v1/gateways`; auto-populate client cached peers. |
| **M9.1** | `human-money-node` | `crates/humoco-node/src/cli.rs`, `daemon.rs` | Enforce stop CLI exit0 only after verified process termination and redb file lock release ([DEC-076](ARCHITECTURE_INTERVIEW_NOTES.md#dec-076)). |
| **M10.1** | All Repos | Tests & docs | Run cross-repo end-to-end integration and produce definitive verification ledger. |

## 4. Detailed implementation work

### M0 — Establish a trustworthy starting point

**Sources:** DEC-004/038/052/089, original A14/A15; earlier R2/R8.
**Owners:** all four repositories; node interview/navigation/progress documents.

1. Snapshot current heads, diffs, nested rules, Cargo patches/resolved libraries,
   package versions, supported platforms and test commands. Preserve unrelated work.
2. Reproduce each F01–F13 observation by symbol/call graph. Search both definitions
   and callers; identify routes/commands actually registered and UI actions actually
   invoked. Preserve useful code, remove only demonstrated obsolete alternatives.
3. Build an evidence ledger with columns: DEC; A package; milestone; required gate;
   source symbol; production caller; requirement/design/code/test statuses; exact
   revision/command/result/artifact; limitation. Mark old completion claims disputed,
   not silently verified. Preserve the original89 IDs and supersession record.
4. Reconcile the new G document's unsupported wording against interview selections:
   600 s entry freshness versus30 s; in-memory payment queue versus DEC-042/085;
   immediate restart readiness versus DEC-057; class0 tie-breaking and supported
   class transitions versus DEC-022/064; ordinary crash versus actual loss.
5. Prepare targeted regressions before fixes, and state which are not yet runnable
   until an implementation interface exists. Do not add meaningless tests asserting
   constants or reproduce an unsafe implementation as the expected result.

**Done:** an independently reproducible baseline and test/evidence plan. This task
does not alter consensus semantics, deploy, push or start further agents.

### M1 — Make checkout authorization originate at the real trusted boundary

**Sources:** DEC-017/038/053/054/072/080–084; A01/A09/A14, R6.
**Owners/callers:** Core `src/{models/layer2_api,services/l2_gateway,app_service/conflicts}.rs`;
App `src-tauri/src/{commands/transfers,lib}.rs`, frontend DTOs,
`src/services/transferService.ts`, `ReceiveSuccessView.tsx`, `ui/L2QuorumBadge.tsx`.

**Current problem:** F01–F04 permit an old receipt or untrusted outcome/context
to create a release indication. A public constructor with a caller-selected
`Confirmed` enum does not establish proof verification or purchase durability.

Implementation:

1. Separate **original write accepted/observed**, **current live proof verified**,
   **L1/purchase durably committed**, and **release decision**. Do not overload one
   deserializable `Confirmed` value for all four meanings. Preserve read `Found`
   and explicit provisional/uncertain/conflict outcomes throughout adapters.
2. Original-receipt verification may record original acceptance/reconciliation,
   but cannot itself mint current paid status. Remove its route to automatic
   release, including `verify_checkout_response_with_authority` and helper callers.
3. Remove/restrict the registered Tauri command that turns arbitrary strings into
   release, or make it accept only a backend-owned operation identifier and load
   the actual state. Caller-selected `Confirmed`, `isVerified`, signer counts,
   committee JSON or proof-matching expected JSON must never bypass verification.
4. Keep stateless cryptographic verification as a reusable Core service. Reserve
   release-producing application mutation for the M6 transaction boundary. An
   internal verified result/capability must not be forgeable by IPC deserialization
   or an unrestricted public constructor. A capability name alone is no protection;
   inspect all constructors and production paths.
5. Until M6 is integrated, return honest unverified/pending results. The normal
   offline import may remain available under its existing contract, but must not
   falsely announce verified online payment. Preserve existing explicit merchant
   risk decisions without laundering them into cryptographic FINAL. Do not invent
   a new override policy; conflicts/quarantine remain blocked as already required.
6. Render actual backend transaction disposition, assurance and release state.
   Remove `Boolean(checkoutVerdict)` as proof and hardcoded 14/20; show only verified
   counts when available. Keep “received/imported” separate from “paid/released”.
   A frontend test injecting a forged DTO cannot certify the backend.
   Specifically enforce the 2-level dots status indicator (`L2QuorumBadge` & `ReceiveSuccessView`):
   - `●●` (**Level 2 / Final**): 14/20 verified live quorum on active mature network ($N \ge 20$).
     Automatic goods release authorized.
   - `●○` (**Level 1 / Provisional**): $Q(N)$ verified provisional quorum in small island mesh ($N < 20$).
     Automatic goods release authorized under provisional terms.
   - `○○` (**Level 0 / Offline / Zero Servers**): No L2 servers configured or reachable (current real-world
     status and direct P2P offline transfer). Pillar 1 (L1 Voucher Authenticity) is verified GREEN
     (100% offline mathematical proof); Pillar 2 (L2 Network Protection) displays `○○` ("Keine Server
     verfügbar" / "Offline-Zahlung"). Automatic goods release is disabled (`can_release_goods_automatically: false`).
     The UI displays an honest merchant hint: "Keine Server-Verbindung. Zahlung wurde direkt übertragen;
     Warenfreigabe auf Vertrauensbasis." Explicit merchant override button is provided.
   - `●` / 🔴 (**Conflict**): Double spend detected; goods release hard-blocked.

**Error contract:** malformed/untrusted input rejects; zero servers or unreachable gateway yields
honest `OfflineUnverified` (`○○`); old receipt/lookup remains observed/found; insufficient or
wrong-context proof stays unresolved; purchase storage failure/uncertainty cannot release.
No fabricated success, no false 14/20 green dots, and no replacement.

**Acceptance:** real registered command/application-path tests for stringConfirmed,
original valid14/20 receipt, arbitrary expected roster/nonce, boolean/count spoof,
13 votes and malformed proof; none automatically releases. Positive current
verification must still work as a service, but automatic release's positive case
waits for M6 durable commit. Follow UI types from backend mapping to component.

**Done:** all release minting paths inventoried and constrained. This closes a
regression, not yet the missing productive payment workflow or G1.

### M2 — Contain unsafe recovery agreement and readiness

**Sources:** DEC-026/030–032/041/057/058/083–087; A02/A04/A05/A14, R4.
**Owners/callers:** node `daemon.rs` readiness manager and `sync_single_shard`;
`network/{transport,framing,manager}.rs`; `api/{routes,live}.rs`; storage engine.

Implementation:

1. Enumerate every `mark_shard_ready`/equivalent and original/live/self/idempotent
   signing site. A complete predicate includes current assignment, source-complete
   installed durable state, storage health and own-choice safety where applicable.
   Preserve per-shard isolation and network-size-only FINAL hysteresis.
2. Stop converting disk read errors into an attested empty snapshot. Propagate
   storage failure; do not mix pending RAM rows into a durable recovery witness.
   Explicitly distinguish a bounded partial-data response from a **countable**
   qualified source response. NOT_READY sources may help transport retained data,
   but fourteen unready/empty sources cannot bootstrap one another into readiness.
3. Remove activation based solely on matching whole-state digest/transfer-loop
   completion until the M4/M5 completeness predicate exists. Do not call the
   containment a finished safe-turnover implementation.
4. Prevent incomplete imports/quarantine from mutating active collision state while
   an unproved repair is running. Keep the shard unready; stage safely or disable
   that mutation temporarily without deleting already retained data. Never erase
   own original choices to make a digest match.
5. Bind recovery completion and final signature exposure to the current assignment
   observation. A small bounded local task token/fence is permitted engineering;
   it is not a new protocol epoch, rejected version-history subsystem or daily
   committee term. Cancellation/error/stale completion clears its job honestly.
6. Do not infer genuinely new-network initialization from blank storage, missing
   peers or first demand. Separate its justified policy under G1/G5 from recovery.

**Acceptance:** actual QUIC digest/data requests and HTTP/live/write/self paths:
all20 unready/empty peers,14agreeing incomplete peers, disk error, pending RAM row,
failed import, timeout, cancellation and changed assignment cannot activate or
issue a vote. Another ready shard continues; neutral outcomes do not penalize peers.
Automatic success test belongs to M5, not a manual READY toggle.

**Done:** unsafe readiness shortcuts and witness ambiguity removed with recorded
availability limitation. G2/progress remains open until M5 positive evidence.

### M3 — Protect supported state before implementing the final merge contract

**Sources:** DEC-022/023/035/064/065/070/087; A03/A06/A13, R5/R7.
**Owners/callers:** node storage engine/DB and daemon quarantine call;
`humoco-sim-core/src/{resolver,types}.rs`; native/HMC support adapters.

Implementation:

1. Reproduce the HMC lower-hash singleton takeover and omitted confirmed-row
   quarantine. A row being absent from a candidate download does **not** establish
   it is an unconfirmed minority lock; its class may be unknown or confirmed.
2. Restrict unsafe canonical replacement/quarantine pending authenticated support.
   Preserve confirmed/unknown evidence and own choices rather than assigning class0
   by default. An affected unresolved slot may block; unaffected slots continue.
3. Prevent quarantine from removing TTL coverage. Include provisional/native/HMC
   data, support metadata and inherited root validity in the expiry inventory.
   Quarantined successors cannot fall back to a missing genesis or arbitrary TTL.
4. Move synchronous quarantine DB work off runtime threads into the existing bounded
   persistence/install boundary; never await while holding RAM guards. Chunk scans
   by declared byte/count/time work with continuation, not a whole-state clone.
5. Define how active DB, RAM views, indexes, durable-version cache and quarantine
   become consistent on success, crash and failure. Until M5 atomic installation
   exists, do not claim separate disk-then-RAM mutations are atomic merely because
   each individual DB transaction is ACID.

**Acceptance:** confirmed and unknown-support rows survive omission, class0 cannot
displace stronger support, failed candidate does not alter active state, original
choices stay immutable, quarantined records expire after root+grace, process crash
between persistence/RAM publication cannot yield signing on an inconsistent view.

**Done:** destructive regressions contained. Authenticated class admission,
descendant semantics and justified quarantine integration are finished in M4/M5.

### M4 — Close G1–G5 premises and freeze one actual field contract

**Sources:** DEC-016–023/039/044–048/053–065/080–087; A01–A06, R3.
**Owners:** shared protocol crate and actual Node/Core/App consumers; numbered docs
only after selected semantics and demonstrable contracts are reconciled.

This is a required design deliverable before dependent activation/release. Do not
write “canonical specification” and count its paragraphs as implementation. Each
gate needs: assumptions; authenticated input source; exact output checked by code;
retained local evidence; allowed transitions; failures; counterexample schedules;
positive progress conditions; and a clear argument for what remains conditional.

#### G1: current regional authority

- Define how an independent recipient obtains and authenticates eligible network,
  admission, mature ticket and passive-presence observations. Trace the actual
  host source of expected committee; do not accept the proof's roster as its own
  justification or assume every wallet maintains a full F2F table without code.
- State the per-view/time fault assumption and how differing honest mesh views
  affect receipt validity. Two14subsets of the **same**20 intersect in8; this does
  not prove agreement across different20sets or over turnover. Offline nodes are
  a liveness limitation, not automatically Byzantine fraud.
- Argon2d maturity, friendship and provider multiplicity do not prove at most6
  Byzantine identities or eliminate all grinding/Sybil strategies. Preserve the
  conditional six-fault target and regional/revisable semantics.
- Supply forged-roster, immature/replaced-ticket, suspended/reentry, eclipse and
  honest-view-divergence schedules. If an authority mechanism or trust input is
  genuinely unselected, present the exact leaf to the maintainer; do not silently
  install a global coordinator, founder authority or broaden stopped trust research.

#### G2: complete source coverage and no-gap activation

- Explain why sources cover every required live exclusion across changing
  membership, including old partial original choices needed for safe future votes.
  Digest integrity is not omission detection. Fourteen incomplete new replicas
  agreeing on empty state is the explicit negative case.
- Address the **8+6+6** witness: different honest subsets can hold valid locks with
  no fourteen identical whole-state digest. A strict identical-digest condition
  may fail progress; removing it or taking unions without justified support may
  break safety. Supply a justified resolution consistent with DEC-058/064, or name
  the remaining decision; do not silently replace the selected recovery contract.
- Define fixed snapshot cut, bounded delta coverage/cursor, final catch-up/old-write
  cutoff and current-assignment publication. A monotonic offset over a freshly
  sorted mutable list does not establish a fixed snapshot or complete deltas.
- Handle departed sources, interrupted pages, writes admitted before cut, late
  durable completions, competing canonical updates, expiry and repeated full
  turnover. State exactly when automatic progress is promised under stabilization.
- Retain no old-quorum bundle chain or mandatory predecessor permission. Separate
  current objective state, support admission and original immutable local choices.

#### G3: supported class/descendant merge and legal signing

- Specify what authenticated evidence admits class2, class1 and class0 under G1.
  Neither owner authorization, a status byte nor a single transport source gives
  quorum confirmation. One source may carry a valid multi-signer proof.
- Reconcile minimal current support with DEC-083: no historical bundle migration
  or loss of confirmation solely because original signers left. Specify exactly
  how current qualified state witnesses support the admitted class during merge.
- Define descendant invalidation, independently usable siblings, promotions/late
  stronger evidence, minimum exclusion evidence and root lifetime. Two class0
  candidates cannot manufacture a confirmed winner.
- Give the exact fraud predicate distinguishing two incompatible personal original
  approvals from lawful original-A then current-live-B after merge. Purpose
  separation alone does not prove any two same-purpose live observations are fraud;
  temporal/request semantics matter. Do not extend bans to lawful live changes.
- Demonstrate original-choice immutability and safe live reporting together. No
  rewriting original choice to the winner, retry-generated conflicting vote or
  whole losing-tree archive as a shortcut.

#### G4: clock, freshness, fixed seal, expiry and reentry

- Establish one table of clocks/units: wallet signed public T0; network median;
  monotonic local wait deadlines; 5-minute bucket projection; 30-second entry gate;
  nominal bucket-end+30s seal; authenticated root expiry; ticket24h observation;
  three missed hourly heartbeat slots. Distinguish each from calendar quota day.
- Resolve the G document's600s contradiction using the interview's30s selection;
  never substitute the10-minute stateless PoW window for wallet freshness.
- Show schedules for entry just inside freshness followed by late commit after
  nominal seal, targeted historical sync, root expiry during wait, skew/jump,
  missed-heartbeat boundaries, restart observation reconstruction and reentry.
- No second wallet-freshness check, variable seal, correction/version history or
  timer-based restoration of missing own choices. A local assignment/task fence
  is not the rejected protocol history mechanism.

#### G5: actual missing/rolled-back decisions and key duplication

- Inventory node durable original-choice data, startup store/identity binding,
  backups and corruption/error paths. Distinguish ordinary intact-storage crash
  from deleted decisions, selective stale records, whole-directory rollback and
  concurrently copied identity. Core wallet generations are not a node mechanism.
- State which loss can be detected with which independently retained evidence.
  A counter inside the same fully rolled-back directory cannot detect every
  rollback alone; absence of a higher remote observation proves nothing. Do not
  add a new gossip stream or permanent node transaction log to satisfy a fictional
  universal-detection promise.
- Specify fail-closed scope once loss is known, operator visibility, and justified
  recovery prerequisites under the existing identity. Canonical lock sync cannot
  recreate all uncommitted-to-quorum personal original decisions.
- Ordinary crash with intact durable state still requires DEC-057 per-shard P2P
  readiness; do not conflate “no lost-choice quarantine” with “immediately READY”.
  No new root-risk markers/ordinary-crash identity abandonment. If external anchor
  or operating policy is necessary, expose the genuine tradeoff explicitly.
- Verify actual duplicate original signatures before fraud penalties. A duplicate
  instance is a risk scenario, not permission to ban without first-party evidence.

#### Shared producer/consumer encoding worksheet

For original approval, current live context, transfer/source witness, compact409
evidence, retained-original response and public advertisement, record:

| Required field property | Questions the implementation must answer |
| --- | --- |
| Purpose/version/network | Exact length-prefixed domain, version, domain identifier representation, cross-network rejection and compatibility behavior |
| Root/output/target | Authenticated root TTL, consumed output including split position, lookup tag, parent derivation, successor identity, canonical state bytes |
| Shard | Domain shard derivation versus wire integer encoding; one mapping across all adapters |
| Time | Unit, signed T0, bucket derivation, root validity, request deadline semantics |
| Authority | Ordered full-key roster and independent justification; current assignment reference; fixed checkout electorate |
| Challenge/state | Backend-created recipient challenge, exact operation/purchase binding, canonical digest and replay lifecycle |
| Bounds | Length/count/bytes/work, incremental allocation, evidence1024-byte cap versus complete proof envelope; no truncation |
| Error | Invalid versus unavailable versus capacity versus uncertain versus authenticated conflict; no silent defaults |

Concrete baseline conflicts: Proto `LiveStateContext.network` is `u8` with0/1;
the G document says32-byte `network_id`. Current Node shard selection commonly
uses big-endian first bytes of parent/tag hash (see `api/routes.rs`,
`network/transport.rs`, `humoco-sim-core/src/types.rs`); G1 says little-endian
consumed-output bytes. Proto serializes its shard integer little-endian; integer
**serialization** is separate from **shard selection**. The G document says
exactly14 signatures; shared FINAL verification supports a bounded sufficient set
from20. Document existing producers/consumers before deciding a coordinated
compatibility change. Do not arbitrarily change wire bytes or signed Core
serialization because a newer prose file differs. For unresolved semantic choices,
present A/B with recommendation; routine derivable repairs go into a short
problem–solution batch for sign-off as requested by the maintainer.

**Done:** each required gate has a defensible scoped contract/counterexample result,
shared byte vectors and actual consumers identified. Unresolved leaves remain
explicitly blocked; downstream code cannot infer closure from documentation.

### M5 — Finish supported merge and stable durable shard activation

**Sources:** DEC-022/023/026/031/041–046/053–065/083/085–087;
A02/A04/A05/A06, R4/R5. **Dependencies:** relevant G1–G5 parts of M4, M2/M3.
**Owners/callers:** `daemon.rs`, `network/{framing,transport,manager}.rs`,
`storage/{db,engine}.rs`, sim-core resolver/state, shared admissibility verifier.

Implementation sequence:

1. Define a **typed verified input** for canonical/support admission. Validation
   authenticates identity/domain/root/owner signature, causal relation and admitted
   support before any canonical replacement. Native and HMC use the same policy.
2. Apply justified class2>class1>class0, then same-highest-confirmed-class min-hash.
   Preserve unresolved states, original own choices, supported descendants and
   minimum exclusion evidence. Class cannot be promoted by data transport alone.
3. Implement bounded source sessions over a fixed admitted snapshot cut; authenticate
   source and bind requested shard/cut/cursor/context. Pages/deltas have declared
   record/byte/work/time bounds, strict continuation validation, deduplication and
   complete final coverage. Bound staging disk/memory and session cleanup too.
4. A source that is unready may serve partial retained data but contributes no
   complete-state witness. Check durable versions and propagate storage failures.
   Avoid whole-store scan/clone and disk reads on runtime threads per request/page.
5. Stage and verify all candidate records, root inheritance, support and deltas
   without corrupting active state. Reconcile candidates by the selected class
   rule. Quarantine only **proved eligible unconfirmed minority** state, preserving
   its root TTL/index and client reconciliation access. Missing != unconfirmed.
6. Establish the G2 no-gap cutoff including writes that entered before the cut but
   commit later. Recheck assignment and health before install/publication. Install
   records/support/minimum exclusions/indexes/quarantine disposition durably under
   one specified atomic visibility contract; publish RAM/readiness only for that
   exact installed state. Recover interrupted installs without countable votes.
7. Keep root TTL and own-choice state separate: importing a canonical winner does
   not overwrite this node's original losing choice. A current live response may
   lawfully report the winner after all readiness/durability checks.
8. On failure/cancel/stale assignment/insufficient proof/overflow, discard or safely
   retain bounded staging according to contract, clear the one-per-shard job, keep
   NOT_READY and return honest temporary unavailability. No payment queue or rollback
   of committed original locks. Do not let expired staging resurrect a root.
9. Demonstrate actual automatic readiness after justified recovery and continued
   progress after stabilized membership, including repeated complete turnover.
   Preserve passive heartbeat exclusion/ticket maturation and in-flight frozen
   checkout membership; no old-group signing permission or24hcommittee term.

**Required real-interface scenarios:** all-empty/unready quorum; valid partial
sources with no14identicaldigest; source departure midway; malformed/duplicate/
missing/out-of-order/truncated page; snapshot/delta omission; insert sorting before
cursor; late pre-cut commit; class2vsclass1vsclass0; two equal-class regional branches;
unsupported low hash; missing genesis; descendant on loser; late stronger support;
expiry during install; cancellation; DB error; kill before/after install; assignment
change; concurrent duplicate demand. Add positive controls proving actual daemon
recovery, not fixtures with `mark_shard_ready` called manually.

**Fraud acceptance:** actual same-slot incompatible original approvals sanction;
honest originalA then canonical/liveB, different network/purpose, lawful later live
state and reporter claims do not. Verify both signatures before any penalty.

**Done:** documented G assumptions, bounded automatic safe installation/merge,
correct signed outputs and measured progress at actual daemon/QUIC boundaries.
Neither digest equality alone nor perpetual NOT_READY meets this definition.

### M6 — Integrate the actual wallet-to-checkout application flow

**Sources:** DEC-009–014/017/020/021/042/060–062/068/071–073/079–084;
A01/A08/A09/A14, R6. **Dependencies:** M1, relevant M4/M5 proof availability;
reuse the productive Core wallet transaction mechanism.

**Owners and real callers:** Core `app_service/{conflicts,orchestrator,lifecycle}.rs`,
wallet transfer APIs and persistence; stateless `services/l2_gateway.rs`; App
`commands/transfers.rs`, state/history adapters, `transferService.ts`, real Send/
Receive actions, frontend DTOs and release display. Inspect actual entry points
before adding any new module. Network I/O belongs in the host/adapter, not pure
Core services; purchase state belongs in wallet/PoS, never the node/proto consensus.

#### Sender state machine and durable dispatch

Proposed state names below are implementation notation, not a new protocol:
`Prepared -> IntentDurable -> Dispatching/Uncertain -> Reconciled`, with explicit
conflict/provisional/expired-unresolved dispositions and no automatic free-slot
inference. State transitions must use the existing transaction boundary.

1. Build exactly one owner-signed request and immutable T0 from validated L1 output
   and root. Persist exact serialized signed bytes, identity/context and atomically
   reserved/pending consumed output **before first network dispatch**. No network
   request may escape on failed/uncertain pre-send commit.
2. Use a stable local operation identity and enough bounded durable state to resume
   after crash. Concurrent clicks/retries cannot create another successor for the
   same output. Never regenerate T0/signature/payload to bypass freshness.
3. Implement conditional three-send with finite overall attempts/time/work, exact
   bytes, the original checkout's frozen committee/context, an owned background
   attempt and cancellation cleanup. Transport retries cannot rotate or expand
   the signer pool to reach quorum, mix incompatible contexts or change signed
   originals. A separate fresh current-state check has its own justified current
   authority/challenge context; it is not a replacement original write approval.
4. Timeout/cancel/unknown network result remains uncertain, even if a later commit
   may have succeeded. Use bounded growing-backoff reconciliation; after the30s
   entry window use reads only. A single matching lookup or404 is not payment proof
   or permission for replacement. Budget exhaustion remains unresolved.
5. Reopen pending operations after restart, including `UncertainCommit` from wallet
   storage. Inspect every direct writer; use the sealed orchestration transaction
   for new safety-relevant records. Bound record retention by state/lifetime rather
   than logging every retry forever. Do not invent certificate archival duty.

#### Recipient challenge, verification, purchase and release

Proposed local transitions: `Receiving -> AwaitingProof -> ProofVerified ->
PurchaseDurable -> ReleaseAuthorized`, with failure/uncertain branches. Local
phase names may change; required ordering may not.

1. Generate unpredictable challenge in the trusted recipient backend for an exact
   local purchase/attempt. Bind network/root/output/target/expected state and the
   independently established current authority. Frontend/sender may supply data,
   never the security basis. Persist challenge/operation lifecycle sufficiently to
   prevent reuse after restart; it need not become an L2 historical proof archive.
2. Obtain fresh current proof through recipient-chosen gateways/sources. Use shared
   verifier over actual fields/signatures and justified frozen roster:14distinct
   eligible full keys, correct purpose/domain/challenge/state, no rank21 substitute.
   A single transport response can carry the proof; multiple gateways do not by
   themselves prove authority or independence.
3. Validate L1 voucher ownership/causality and exact consumed split/output-to-target
   relation. The mathematical live proof and L1 ownership validation are separate
   required inputs; neither substitutes for the other.
4. Atomically durably store received L1 voucher and **purchase-journal binding**,
   relevant challenge disposition and release/idempotency state through the existing
   managed wallet commit. Existing separate history append is not assumed atomic.
   Only after confirmed durable success return the goods-release result.
5. On uncertain post-marker storage outcome, preserve operation and in-memory state
   according to the implemented `UncertainCommit` contract; block release pending
   safe reconciliation. Do not retry by creating a new payment, lose the only
   response/bundle, roll back a committed spend or clear the pending output.
6. Make challenge reuse against a different purchase fail. For the same operation,
   duplicate completion is idempotent and must not duplicate purchase credit or
   physical release. Software can persist authorization/ack state; it cannot claim
   exactly-once physical goods delivery through an uninstrumented external action.
7. After completed checkout, retain L1 custody/purchase state as required, discard
   ephemeral proof when safe; do not require14oldsignatures for later spending or
   restart. A still-pending operation may retain bounded reconciliation context.
8. Multi-voucher purchase retains durable completed components and uncertain ones;
   no auto substitute/refund or double counting. Deliberate tender change stays
   explicit client/cashier policy. No cart data enters node state.
9. Wire the real send/receive UI action through these backend calls. Reassurance
   labels must derive from committed operation state, not independently editable
   DTO props. Keep explicit offline/provisional merchant decisions visibly distinct
   from verified FINAL; do not invent new override authority.

#### Zero-Server / Offline Deployment Reality & Fallback Handling

Since zero public Layer 2 servers exist in current real-world deployment, and direct P2P transfers
must function seamlessly offline without network connectivity:

1. **Layer 1 Autonomy Preserved:**
   Voucher transfers are 100% self-custodial negotiable instruments (`ProofChain`). Offline direct
   transfers (via QR code, BLE, NFC, file or direct local network) validate all owner signatures,
   transaction causal chains, split ratios, and root anchors completely locally without any server access.
2. **Layer 2 Absence Detection & Fast-Fail:**
   When no L2 gateway URL is configured, or all discovered/configured gateways fail health probes
   (DNS failure, connection refused, or 800 ms timeout), the client immediately transitions L2
   status to `OfflineUnverified` (`○○`). It must NOT hang in endless retry loops or block the L1 import.
3. **Recipient / POS UX Presentation:**
   - **Säule 1 (Gutschein-Echtheit L1):** 🟢 "Echt & gültig (100 % offline mathematisch geprüft)".
   - **Säule 2 (Netzwerkschutz L2):** ⚪ `○○` ("Keine Server verfügbar / Offline-Direktübertragung").
   - **Merchant Advisory Text:** "Keine Server-Verbindung. Zahlung wurde direkt von Gerät zu Gerät übertragen.
     Empfohlen bei persönlichem Vertrauen (z. B. Stammkunden, Kleinstbeträge)."
   - **Release Gating:** `can_release_goods_automatically` is `false`. A prominent, explicit merchant action
     button ("Warenfreigabe auf Vertrauensbasis bestätigen" / "Trotzdem annehmen") is rendered, allowing
     the merchant to consciously accept the risk of potential double spending.
4. **Deferred Reconciliation / Replay on Network Reconnect:**
   When a node or gateway later becomes reachable, the wallet can opportunistically submit its retained
   pending L2 lock to register collision protection without invalidating the already completed L1 transaction.

**Acceptance:** actual host/Core HTTP/QUIC producer-to-consumer14success and13fail;
wrong key/network/purpose/output/root/shard/challenge/state/committee; duplicate
identity/rank21/short-ID collision; stale receipt; arbitrary IPC outcome; replay
after completion/restart; invalid L1 ancestry; split sibling mismatch. Subprocess
kill/fault barriers around intent commit, send, response, proof, purchase commit,
uncertain marker, release authorization/ack and partial multi-voucher completion.
Use real durable reopen, not only an in-memory state machine test. Verify supported
platform scope before advertising the flow beyond Unix managed storage.

**Done:** actual normal user flow plus restart recovery uses the verified and
durable boundary; no helper-only/constructor-only authorization. Remaining physical
release uncertainty and regional proof assumptions are documented honestly.

### M7 — Finish bounded optional original-approval retrieval

**Sources:** DEC-069/070/083; A03/A15, R5/R6.
**Owners/callers:** `routes.rs::get_retained_choice`, own-choice DB/engine, shared
original approval DTO/verifier, client uncertain-attempt reconciliation.

1. Return the exact already-retained own original signature bytes and sufficient
   original verification context, not merely child/`has_final` flags. Do not issue
   a new original vote, current-live signature or replacement committee vote.
2. Bind request/response to network/full node identity/root/output/child/purpose/
   original context. Query only retained decisions; enforce bounded count/bytes/
   verification/admission/DB work/deadline, using bounded blocking I/O off runtime.
   Review public read quota for this route explicitly rather than assuming it is
   covered by another handler. Keep private diagnostics/storage errors private.
3. A client may recover enough original evidence from the original frozen committee
   within the same total reconciliation budget. Insufficient/unavailable/expired
   originals stay honest unresolved results; this route cannot authorize a fresh
   current payment by itself. Integrate it only for appropriate pending attempts.
4. Preserve own approvals to root+30s, purge with other safety records, and never
   migrate whole historical quorum bundles through shard generations. Normal live
   verification must succeed after original signer retirement without this route.

**Acceptance:** exact byte-for-byte retained approval verifies; malformed/wrong
context/oversize/unknown/expired calls do not mutate locks/readiness/own choices;
no new signature generated; full budget and quota enforced over real HTTP/QUIC as
applicable. Current live checkout works with all original signers gone.

**Done:** useful verifiable optional recovery rather than metadata-only endpoint;
no revived archive prerequisite or second mandatory checkout round.

### M8 — Complete passive gateway discovery and client-only fallback

**Sources:** DEC-017/020/021/078/079/082; A12/A09, R6/R7.
**Owners:** node `config.rs`, allowed heartbeat metadata/framing/manager and public
directory; host discovery/connection adapter/config/cache, Core pure policy only.

1. Retain explicit HTTP(S) operator publication, endpoints-per-node/URL-length
   bounds and no invented HTTP endpoints from QUIC addresses. Add authenticated
   network/identity-bound publications through **existing passive** mesh knowledge.
   No third gossip stream, lock gossip or mesh-wide active ping crawler.
2. Define bounded deduplication, freshness, signed withdrawal/revocation semantics,
   replacement and stale/unverifiable-publication handling. Reuse G1 identity/domain
   rules without turning a candidate gateway list into voting authority. Do not
   leak friendship graph, internal QUIC addresses, credentials or metrics.
3. Make `/v1/gateways` expose actual known explicit publications as well as the local
   publication under bounded read admission. Include only public metadata necessary
   for client authentication/selection. Directory freshness does not prove reachability.
4. In host, retain bootstrap/custom choices, recipient-selected providers and bounded
   local last-known candidate fallback on stale/unavailable directory. Respect
   explicit revocations; cache policy never becomes a node consensus rule.
5. Scope friend/VIP credentials to their issuing provider/authenticated endpoint;
   never forward a token to an unrelated discovered gateway or unsafe redirect.
   Preserve TLS/endpoint authentication, unchanged payment bytes/T0 and total
   retry/deadline budgets across failover. Confirm HTTP clients' redirect behavior.
6. Network-size statistics use independently selected sources, cached background
   observations and honest disagreement; do not average incompatible values into
   a false confidence/authority claim. These remain diagnostics, not proof gates.

**Acceptance:** actual authenticated passive advertisement round trip; P2P-only
node omitted; duplicate/oversized/wrong-domain/replayed/withdrawn endpoints bounded;
directory outage/stale cache/revocation/cross-provider redirect and credential tests
in the real host client. Public discovery works while private topology stays absent.

**Done:** dynamic additional public candidates and actual client fallback integrated,
not only a configured local URL array or another server cache subsystem.

### M9 — Complete operational composition, expiry and failure recovery

**Sources:** DEC-002/003/008/012–015/024/025/027–037/040–043/060/065/070/074–079/085–088;
A03/A07/A08/A10/A11/A12/A13/A14, R2/R7. This work accompanies other milestones.

#### M9.1 Protected capacity, batching, retry and causal prefix

- Audit separate inbound shard, locally originated gateway and background recovery
  budgets; count byte/work/task/concurrent-RPC limits as well as queue/socket
  counts. A single shared semaphore or VIP label does not prove protected progress.
- Reuse bounded own-choice worker/coalescing; verify batch age/count/bytes, singleton
  sealing, exact ACK, waiter limits, cleanup and late commit retained after timeout.
  No new unbounded wait queue. All neutral NOT_READY/NOT_IN_SHARD/capacity/idle/
  quorum-cancellation paths must remain neutral to peer malus and committee presence.
- Keep F2F keepalive separate from the bounded128–256shardidleLRU/15s/no keepalive;
  never evict an active lease/RPC. Test simultaneous reverse RPC and session
  replacement/stale cleanup, not only outbound request completion.
- Verify actual conditional retry ownership/cancellation; no orphaned third send
  after quota exhaustion/shutdown/quorum success. All initial eligible members are
  attempted within bounded admission; resource limits never expand the electorate.
- Causal batches preserve durable valid prefix and reject dependent suffix at first
  invalid/conflict/deadline/capacity step. Enforce **bytes and verification work**
  in addition to existing hop/time limits. Inline compact authenticated409evidence,
  including needed root/output/context, stays within declared envelope limits.
- Preserve correct201new/200idempotent/409conflict,400invalid,429capacity,503durability/
  unavailable mapping and private rejection counters; a rejection cannot fall
  through to200. Valid14proof outranks weaker collisions, never invalid signatures.

**Evidence:** real receiving-shard QUIC floods/quota/malformed/oversize tests plus
HTTP chain/prefix and mixed slow-disk/read/public-write/internal-sync load. Measure
declared memory/queue/work ceilings and protected progress under an explicit offered
load. Direct-handler quota tests and manual-ready cluster fixtures remain labelled
as such, not receiving-server/recovery evidence.

#### M9.2 Durable node failure, lost state, quarantine TTL and backup

- Retest every original/self/duplicate/live release site against exact durable
  committed state. Inject commit error and kill before/after commit/outbound
  release. Reopen redb independently; no released-but-uncommitted signature.
- A persistent shared-store failure disables every dependent signing shard while
  keeping private diagnosis available. Resume only after healthy storage plus
  required state/choice recovery and operator veto checks. Implement G5's justified
  detectable-loss behavior; never restore missing own choices from winners alone.
- Cover active/native/HMC/provisional/quarantined/support/own-choice/approval indexes
  and staging expiry in one lifecycle inventory. Preserve root inheritance and
  exact root+30s physical retention. No premature pruning, indefinite orphaned
  provisional rows, stale TTL deletion of a replacement or late-task resurrection.
- Bound expiry passes by count/bytes/time with continuation and guaranteed offered
  background progress. Logical expiry rejects immediately, independent of physical
  backlog. Protect destructive pruning against uncorroborated clock jumps under G4.
- Backup/restore must include relevant original own choices, support/quarantine
  state, root/TTL indexes and interrupted-install semantics. A backup restoring
  missing signing decisions is a G5 recovery case, not automatically ordinary boot.

**Evidence:** full-root-lifetime state older than24h; large expiry backlog under
load; loss/corruption/selective rollback/whole-store clone within declared detection
limits; backup round trip; crash during quarantine/install/prune; no permanent
tombstones. Process kill proves process-crash behavior, not arbitrary power-loss
durability of filesystem/controller hardware.

#### M9.3 Shutdown, startup cleanup and operator boundary

- Retain instance-bound clean completion and process-identity checks. First ordinary
  stop signal fixes the absolute deadline; repeats neither reset nor shorten it.
  Stop admission/producers/QUIC handlers before accepted persistence drain; inspect
  join failures, VIP quota writes, flush errors and background producers.
- CLI exit0 requires clean completion, actual target-process exit and external DB
  reopen, not socket disappearance or shutdown-request acceptance. Slow/stuck fsync
  cannot be killed by dropping an async handle or reported clean. Supervisor's
  fallback remains longer than internal budget; native systemd is primary, Docker
  optional. Preserve operator force-stop/veto and honest unclean restart semantics.
- Review every public/private route/alias, body field, CORS, listener, Host/Origin,
  local socket mode and deployment proxy/SSH-forward boundary. Default operator
  HTTP is opt-in loopback; no public base metrics subset, log ring, browser backup
  orchestration or manual prune button. Public service metadata cannot re-export
  private queue/storage/quota/peer details under a new name.

**Evidence:** actual daemon startup failure releases sockets/tasks/DB; repeated
signals, saturated persistence, forced quota/flush/join errors, early socket unlink,
stale/PID-reused completion, CLI interruption and outer kill. Independent process
DB reopen after clean stop. Real HTTP hostileHost/Origin/preflight plus protected
local/SSH access and every diagnostic alias/returned-field review.

#### M9.4 Private history and useful direct diagnostics

- Reuse24hminute ring and one-year hourly bounded persistence. Verify each metric's
  aggregation: counter deltas, gauges, missing/reset intervals; do not invent latency
  distributions or average counters. Keep fixed record and serialization budgets.
- Demonstrate hourly rollover, persisted replacement/crash recovery, retention,
  restart gaps, reset handling and bounded write cost. Source reliability is this
  observer's diagnostic experience, never global badness or automated sanction.
- Classify sent deadlines versus NOT_READY/cancel/not-sent/local-capacity correctly.
  Diagnostic observations do not suppress required checkout dispatch or add gossip.

**Done for M9:** declared limits and measured behavior across combined production
paths, full cleanup/retention and truthful stop. A small latency sample or existing
unit test count is not proof of all these operational properties.

### M10 — Independent full-plan acceptance and coordinated delivery

**Sources:** DEC-004/038/052/089; A14 and all package acceptance; R8 including R7.

1. Repeat the entire DEC/A/G crosswalk against final code, actual callers and
   executed tests. Check positive progress as well as refusal. A gate is closed
   only with its assumptions/argument and production enforcement; retain explicit
   unsupported-platform/environment/external-physical-delivery limitations.
2. Independently inspect combined producer/consumer fields, authorization origin,
   durable identity/choice state, source coverage, merge/quarantine, final activation,
   client intent/challenge/purchase commit and release. Reproduce F01–F13 regressions
   at the final resolved dependency revisions. Review changed tests for weakened
   assertions, skipped failures, permissive fixtures and manual readiness shortcuts.
3. Run required full checks below after relevant targeted tests. Record exact
   revisions, feature flags, local patches, platform/durability mode and expected
   versus observed outcome. Keep preexisting failures and unexecuted scenarios
   explicit. Do not treat an earlier log from another commit as final evidence.
4. Update English specs, invariant ownership, implementation/progress and checkpoint
   navigation after verifying actual behavior. Correct overstated completion
   entries with dated evidence; do not relabel old model reports as live production
   evidence or erase historical withdrawn questions.
5. Deliver small reviewed commits per affected repository in dependency order with
   compatible pinned versions/lockfiles. Record hashes and reproducible build
   relationship in the node delivery. Preserve unrelated edits/generated data;
   no broad `git add .`. No push, tag, release or production deployment is requested
   by this plan. Follow the user's current commit authorization when executing.
6. Report selected requirement/design/code/test separately with explicit remaining
   blockers. If a gate remains unresolved, scoped commits may be useful, but the
   result must not say “entire architecture implemented” or “production-ready”.

## 5. Verification and evidence matrix

No commands in this section were executed for plan creation. Commands are entry
points to be checked against current manifests/rules. Add new targeted test filters
only after the tests exist; report unsupported/missing tooling honestly.

| Repository/check | Required final command or action | What it proves / does not prove |
| --- | --- | --- |
| Proto | `cargo test`; `cargo clippy --all-targets -- -D warnings` | Shared encoding/negative verification vectors; not authority discovery, node readiness or actual goods release |
| Node inner loop | `cargo test-fast` and targeted integration binaries as appropriate | Local state/worker regression; not a replacement for required standard or QUIC tests |
| Node final | `cargo test-std`; `cargo clippy --workspace --all-targets -- -D warnings` | Workspace compatibility at resolved revisions; individual security assertions still need real boundary coverage |
| Node deep models | `cargo test-deep` only when changed assumptions/scenarios justify it | Conditional model counterexamples/progress; never alone certifies production QUIC/recovery |
| Core final | `cargo nextest run --status-level fail`; `cargo test --doc`; applicable strict lint per current repo/CI | Complete Core regressions/doc examples; not host network producer/consumer integration |
| Core wallet recovery | Target actual `wallet_transaction` subprocess/kill/fault tests with required nonrelease `test-utils` feature if needed | Authenticated managed Unix recovery and uncertain commit; not unconverted writers/other platforms/arbitrary hardware power loss |
| App frontend/backend | `./run-tests.sh --quiet` for integrated changes; `--frontend-only`/`--backend-only` only for isolated scope | Tauri sync/types/lint/Vitest/backend gates actually selected by script; not automatically end-to-end live payment |
| Four-repo integration | Real host/Core → HTTP gateway → authenticated QUIC shards → verified backend → durable purchase/release | Exact composed checkout at declared fault/authority/storage assumptions |
| Documentation | Source/anchor/ID coverage, referenced paths, whitespace, obsolete-claim search | Traceability and honest navigation only; no runtime guarantee |

### 5.1 Required evidence groups and test ownership

Existing files below are **starting points to inspect**, not claims that the
required assertions already exist or passed. Add focused tests near the actual
owner as needed; avoid duplicating simulations as false wire proof.

| Evidence ID | Required scenarios/boundary | Existing starting points / required additions |
| --- | --- | --- |
| V01 | Real live14success;13/forged/duplicate/nonmember/wrong-domain/purpose/context/nonce/state fail | Proto `src/live.rs`, `src/verify.rs`; Node `current_proof_boundaries_tests.rs`, `status_reconciliation_tests.rs`; Core/App actual caller tests |
| V02 | Original/lookup/string/DTO cannot create release; valid proof still waits for purchase commit | Core `conflicts.rs` tests; App registered command/backend tests and `ReceiveSuccessView`/badge tests; add true productive call chain |
| V03 | No vote from pending RAM, wrong shard, NOT_READY, failed store or stale assignment; independent ready shard works | `interview_recovery_membership_tests.rs`, `phase5_pull_sync_and_readiness.rs`, `own_decision_durability.rs`, real self/duplicate/live QUIC cases |
| V04 | Actual automatic source-complete snapshot+delta recovery; all-empty trap,8+6+6,turnover,writes/cursor/assignment cuts | Real daemon harness plus `phase5_pull_sync_and_readiness.rs`, `cluster_e2e_tests.rs`; manual readiness fixtures cannot satisfy positive recovery |
| V05 | Class/support/descendants, quarantine invariants/expiry and anti-framing | `subquorum_canonical_merge_tests.rs`, `anti_self_slashing_wire_tests.rs`, production HMC/native merge tests; core resolver unit tests supplemental |
| V06 | Atomic node choice/lock before released signature, late ACK/cancel/error/backup | `own_decision_durability.rs`, storage tests plus real daemon deterministic commit/release process cuts |
| V07 | Intent-before-send, exact retries/restart/read-only after30s, purchase/challenge-before-release, uncertain local commit, partial purchase | Core managed transaction subprocess tests; real App/Core HTTP/QUIC harness added at actual dispatch/receive boundaries |
| V08 | Quotas/parsing/byte-work limits/priority under real receiving QUIC load; idle pool/cancel neutral | `phase11_wire_level_adversarial_tests.rs`, `phase4_net_time_and_quotas.rs`, `shard_pool_lifecycle_tests.rs`, actual mixed-load harness |
| V09 | Durable valid prefix, inline409evidence, bad suffix/timeout/bytes/roots/splits | API/cluster/time-bucket tests and actual QUIC chain receiving path; inspect direct-handler-only fixtures |
| V10 | Repeated-signal original deadline, startup teardown, honest failure/exit/external DB reopen | `operator_lifecycle_tests.rs`, `startup_cleanup_tests.rs`, `control_tests.rs`, forced-I/O/quota/error subprocess tests |
| V11 | Private diagnostics all aliases/fields and browser/proxy boundary | `operator_browser_boundary_tests.rs`, API/control tests and deployment configuration inspection |
| V12 | TTL all stores/indexes/quarantine, safe clock/reentry, history persistence/bounds | Storage/history unit tests plus real process restart/prune pressure and corrupted history cases |
| V13 | Exact retained original signatures/context, read-only bounds, live works without original signers | Retained-choice HTTP/QUIC/client integration additions; presence flags alone are insufficient |
| V14 | Authenticated passive discovery, stale/revoked endpoints, client cache/credential isolation | Allowed heartbeat advertisement and public directory tests, real host client tests |
| V15 | Detectable own-choice loss/rollback/clone versus ordinary intact crash | Node G5-specific failure harness; do not cite startup cleanup alone as rollback-safety proof |

For each executed evidence item record: command, heads/resolved dependencies,
scenario, expected rejection/state effect, observed result, duration where useful,
artifact under a durable repository-owned report path, feature/platform/durability
assumptions and exclusions. Keep only useful bounded artifacts, no secrets/raw
wallet data. Test hook features must not be enabled in production release builds.

## 6. Full original-plan and remaining-plan coverage

| Original package | Current handoff work | Completion boundary |
| --- | --- | --- |
| A01 Productive live verification | M1/M4/M6, V01/V02/V07 | Authority-backed current proof through actual durable application caller |
| A02 Per-shard gate | M2/M4/M5/M9.2, V03/V04/V15 | Every signing/activation site, including self/duplicates; justified positive recovery |
| A03 Own-choice durability | M2/M3/M7/M9.2, V03/V06/V13/V15 | Reuse atomic worker/ACK; all paths, immutable decisions, actual loss distinct |
| A04 Active-state transfer | M2/M4/M5, V04/V05/V06 | Source completeness, bounded no-gap staged durable install/current assignment |
| A05 HRW/presence/tickets | M4/M5/M9.2, V03/V04/V12 | Common eligible full-key selection and qualified G1/G4 reentry |
| A06 Supported merge | M3/M4/M5, V01/V05/V09 | Authenticated class and descendants, conflict/quorum precedence, no framing |
| A07 Bounded lifecycles | M2/M5/M6/M9.1/M9.3, V06/V08/V10 | Budgets and protected progress, bounded retries/sync/pool/worker/drain |
| A08 Causal prefixes | M6/M9.1, V07/V09 | Durable exact prefix, path/output proof, byte/work/time and honest response |
| A09 Wallet/PoS | M1/M4/M6/M8, V01/V02/V07/V14 | Real host intent/send/recovery/challenge/purchase/release; existing wallet crash fix reused |
| A10 Private operator | M8/M9.3/M9.4, V11 | All aliases/fields, deployed listener/socket/browser/proxy boundary |
| A11 Shutdown | M9.3, V10 | Original finite deadline, failures, actual process exit and DB release |
| A12 Gateway discovery | M4/M8, V14 | Passive authentic explicit HTTP publications; client fallback separate |
| A13 Expiry/history | M3/M5/M9.2/M9.4, V12 | All root-bound stores/quarantine + bounded persistent private history |
| A14 Actual acceptance | M0–M10, V01–V15 | Exact final code/revision evidence, not simulation-only or completion prose |
| A15 Original retrieval/legacy cleanup | M1/M4/M7/M10, V02/V13 | Authentic bounded optional recovery and no productive bypass/obsolete verifier |

| Earlier remaining block | Current disposition |
| --- | --- |
| R1 Wallet proposal | Corrected code now present. Preserve/reverify managed transaction and integrate new records in M6/M9; do not reapply obsolete temporary patch. |
| R2 Baseline repairs | Some code/translation fixes exist; refresh whole final-revision evidence in M0/M9/M10 rather than assume an old green sample covers new changes. |
| R3 Contracts | M4; the existing G document is a candidate with contradictions/unproved assumptions, not closure. |
| R4 Recovery | M2 containment then M5 complete activation, gated by M4. |
| R5 Merge/retrieval | M3 containment, M4 support contract, M5 production merge and M7 useful retrieval. |
| R6 Host checkout | M1 bypass removal then M6 actual workflow and M8 client discovery. |
| R7 Operation | M9 in full; never omit it from final acceptance. |
| R8 Final acceptance | M10 plus continuous evidence per milestone. |

## 7. Decision-by-decision ownership crosswalk

Every ID below links to the authoritative register row; read its linked rationale
and limits, not just this short label. “Preserve/verify” does not declare complete
implementation. “Documentary”/“deferred”/“reopened” must not become invented runtime
features. This crosswalk assigns work; final status/evidence belongs in M10's ledger.

| Decision / authoritative topic | Handoff owner and preserved qualification |
| --- | --- |
| [DEC-001](ARCHITECTURE_INTERVIEW_NOTES.md#dec-001) — Node responsibility | All: preserve blind-service boundary; M10 audit |
| [DEC-002](ARCHITECTURE_INTERVIEW_NOTES.md#dec-002) — Existing dashboard | M9.3: preserve useful private diagnostics |
| [DEC-003](ARCHITECTURE_INTERVIEW_NOTES.md#dec-003) — Metric history | M9.4: verify bounded retention/restart |
| [DEC-004](ARCHITECTURE_INTERVIEW_NOTES.md#dec-004) — Compatibility | M0/M8/M10: coordinated compatibility scope; not a new feature |
| [DEC-005](ARCHITECTURE_INTERVIEW_NOTES.md#dec-005) — Genesis versus successor locks | M5/M6/M9.1: shared genesis/successor and root checks |
| [DEC-006](ARCHITECTURE_INTERVIEW_NOTES.md#dec-006) — Protocol reference | M4/M10: canonical domain reference and shared encodings |
| [DEC-007](ARCHITECTURE_INTERVIEW_NOTES.md#dec-007) — Other applications | M9.1: preserve permissionless compatible-client ingress |
| [DEC-008](ARCHITECTURE_INTERVIEW_NOTES.md#dec-008) — Checkout timing | M6/M9.1: collection versus end-to-end timing evidence |
| [DEC-009](ARCHITECTURE_INTERVIEW_NOTES.md#dec-009) — Timeout and retry handling | M6: durable uncertainty and exact retries |
| [DEC-010](ARCHITECTURE_INTERVIEW_NOTES.md#dec-010) — New-payment submission | M6: direct idempotent write; no mandatory free-slot preflight |
| [DEC-011](ARCHITECTURE_INTERVIEW_NOTES.md#dec-011) — Reconciliation progress | M6/M9.1: preserve committed reconciliation progress |
| [DEC-012](ARCHITECTURE_INTERVIEW_NOTES.md#dec-012) — Reconciliation request size | M9.1: bounded byte/count/verification-work causal batches |
| [DEC-013](ARCHITECTURE_INTERVIEW_NOTES.md#dec-013) — Reconciliation batch acceptance | M9.1: durable valid-prefix behavior |
| [DEC-014](ARCHITECTURE_INTERVIEW_NOTES.md#dec-014) — Split-voucher reconciliation scope | M5/M6/M9.1: exact ancestry/split-output path |
| [DEC-015](ARCHITECTURE_INTERVIEW_NOTES.md#dec-015) — Ingress tiers and evidence | M1/M6/M9.1: identical proof requirements across ingress tiers |
| [DEC-016](ARCHITECTURE_INTERVIEW_NOTES.md#dec-016) — Coordinated attacker | M4/M10: coordinated-attacker assumption and adversarial schedules |
| [DEC-017](ARCHITECTURE_INTERVIEW_NOTES.md#dec-017) — Recipient-selected verification sources | M4/M6/M8: recipient-selected security sources |
| [DEC-018](ARCHITECTURE_INTERVIEW_NOTES.md#dec-018) — Ticket lifecycle per identity | M4/M5: one active/pending ticket and monotonic work ratchet |
| [DEC-019](ARCHITECTURE_INTERVIEW_NOTES.md#dec-019) — Fresh cryptographic identity | M4/M5: new identity requires fresh admission/incubation |
| [DEC-020](ARCHITECTURE_INTERVIEW_NOTES.md#dec-020) — Network-size observations for client statistics | M4/M8/M9.4: independent cached statistical observations |
| [DEC-021](ARCHITECTURE_INTERVIEW_NOTES.md#dec-021) — Conflicting statistical observations | M4/M8: honest disagreement; no invented confidence/authority |
| [DEC-022](ARCHITECTURE_INTERVIEW_NOTES.md#dec-022) — No single-source canonical takeover | M3/M4/M5: no unsupported lower-hash takeover |
| [DEC-023](ARCHITECTURE_INTERVIEW_NOTES.md#dec-023) — Unresolved conflicting slot | M3/M5/M6: affected-slot unresolved and safe late re-evaluation |
| [DEC-024](ARCHITECTURE_INTERVIEW_NOTES.md#dec-024) — Checkout versus background capacity | M9.1: protected inbound/checkout/sync progress |
| [DEC-025](ARCHITECTURE_INTERVIEW_NOTES.md#dec-025) — Full shard-direct pool and work budget | M9.1: idle-first pool; no active eviction/waiting queue |
| [DEC-026](ARCHITECTURE_INTERVIEW_NOTES.md#dec-026) — Recovery signing readiness | M2/M5: per-shard loss/assignment gate |
| [DEC-027](ARCHITECTURE_INTERVIEW_NOTES.md#dec-027) — Checkout availability and dispatch | M6/M9.1: all-member dispatch; DEC-060 refines attempts |
| [DEC-028](ARCHITECTURE_INTERVIEW_NOTES.md#dec-028) — Possible checkout failure suppression | Deferred: no suppression algorithm selected; preserve negative scope |
| [DEC-029](ARCHITECTURE_INTERVIEW_NOTES.md#dec-029) — Durable signing before response | M2/M9.2: durable release restored by DEC-087 |
| [DEC-030](ARCHITECTURE_INTERVIEW_NOTES.md#dec-030) — Persistent storage failure | M2/M9.2: store failure stops dependent signing, not diagnosis |
| [DEC-031](ARCHITECTURE_INTERVIEW_NOTES.md#dec-031) — Automatic storage recovery | M4/M5/M9.2: justified automatic recovery; no digest-only shortcut |
| [DEC-032](ARCHITECTURE_INTERVIEW_NOTES.md#dec-032) — Lost signing choices | M4 G5/M9.2: actual lost-choice same-key safety gate |
| [DEC-033](ARCHITECTURE_INTERVIEW_NOTES.md#dec-033) — Signing protection layout | M7/M9.2: immutable own-choice atomic layout/retention |
| [DEC-034](ARCHITECTURE_INTERVIEW_NOTES.md#dec-034) — Graceful shutdown | M9.3: bounded truthful drain; durable ordering restored |
| [DEC-035](ARCHITECTURE_INTERVIEW_NOTES.md#dec-035) — Automatic expiry processing | M3/M9.2: all-store bounded root-grace expiry |
| [DEC-036](ARCHITECTURE_INTERVIEW_NOTES.md#dec-036) — Deployment default | M9.3: systemd-first deployment validation; preserve Docker option |
| [DEC-037](ARCHITECTURE_INTERVIEW_NOTES.md#dec-037) — Private operator access | M9.3: private operator access/socket/SSH boundary |
| [DEC-038](ARCHITECTURE_INTERVIEW_NOTES.md#dec-038) — Shared protocol library | M0/M4/M10: shared crate and coordinated consumer migration |
| [DEC-039](ARCHITECTURE_INTERVIEW_NOTES.md#dec-039) — Committee continuity design direction | Reopened mechanism: M4/M5 continuity obligations; no fixed-context design assumed |
| [DEC-040](ARCHITECTURE_INTERVIEW_NOTES.md#dec-040) — Operator reliability diagnostics | M9.4: bounded first-party direct diagnostics, no sanctions |
| [DEC-041](ARCHITECTURE_INTERVIEW_NOTES.md#dec-041) — Handoff interruption preference | M2/M5: scoped temporary write pause; no duration promise |
| [DEC-042](ARCHITECTURE_INTERVIEW_NOTES.md#dec-042) — Requests during handoff | M5/M6: client exact-intent retry; no node payment queue |
| [DEC-043](ARCHITECTURE_INTERVIEW_NOTES.md#dec-043) — Routine handoff cadence | Tentative cadence: M4/M5; time/maturity never authorizes activation |
| [DEC-044](ARCHITECTURE_INTERVIEW_NOTES.md#dec-044) — Byzantine tolerance target | M4 G1: conditional six-Byzantine target, not enforced by declaration |
| [DEC-045](ARCHITECTURE_INTERVIEW_NOTES.md#dec-045) — Complete committee turnover | M4 G2/M5: repeated full turnover without founding signers |
| [DEC-046](ARCHITECTURE_INTERVIEW_NOTES.md#dec-046) — Handoff progress after contention | M4 G2/M5: safe automatic progress after stabilization |
| [DEC-047](ARCHITECTURE_INTERVIEW_NOTES.md#dec-047) — Intended network topology | Operating goal: M4/M10; connected network is not a view-consistency proof |
| [DEC-048](ARCHITECTURE_INTERVIEW_NOTES.md#dec-048) — FINAL threshold and organic-network assumption | M4/M5/M6: retain regional FINAL regime; do not re-ask threshold preference |
| [DEC-049](ARCHITECTURE_INTERVIEW_NOTES.md#dec-049) — Client authorization terminology | Documentary: M0/M10 glossary; no arbitrary signature/wire rename |
| [DEC-050](ARCHITECTURE_INTERVIEW_NOTES.md#dec-050) — Predecessor terminology | Documentary plus M4/M6: parent/output terminology and exact split binding |
| [DEC-051](ARCHITECTURE_INTERVIEW_NOTES.md#dec-051) — Shard summary terminology | Documentary: M4/M10 digest terminology; digest is not coverage proof |
| [DEC-052](ARCHITECTURE_INTERVIEW_NOTES.md#dec-052) — Autonomous vocabulary maintenance | M0/M10: autonomous English vocabulary maintenance, not new protocol policy |
| [DEC-053](ARCHITECTURE_INTERVIEW_NOTES.md#dec-053) — Partition-resilient regional acceptance | M4/M5/M6: regional revisable acceptance; qualifies older finality claims |
| [DEC-054](ARCHITECTURE_INTERVIEW_NOTES.md#dec-054) — Regional eligibility, honest merge and merchant risk | M4/M5/M6: admission, honest-merge and merchant-risk guardrails |
| [DEC-055](ARCHITECTURE_INTERVIEW_NOTES.md#dec-055) — Rejection of predecessor baton chaining and chained L2 receipts | All: no predecessor baton/recursive receipts/active ping storms |
| [DEC-056](ARCHITECTURE_INTERVIEW_NOTES.md#dec-056) — Passive presence exclusion | M4 G4/M5: three consecutive missed hourly heartbeat boundaries/reentry |
| [DEC-057](ARCHITECTURE_INTERVIEW_NOTES.md#dec-057) — Mandatory restart sync-readiness; no empty-state disaster fallback | M2/M4/M5: mandatory restart P2P readiness; no empty-state fallback |
| [DEC-058](ARCHITECTURE_INTERVIEW_NOTES.md#dec-058) — Quorum-backed verified digest-pull | M2/M4 G2/M5: justified quorum digest-pull and omission coverage |
| [DEC-059](ARCHITECTURE_INTERVIEW_NOTES.md#dec-059) — Fixed snapshot with bounded deltas and bucket sealing | M4 G2/G4/M5: fixed snapshot plus bounded deltas and nominal seals |
| [DEC-060](ARCHITECTURE_INTERVIEW_NOTES.md#dec-060) — Exact-payload retries and three-send heuristic | M6/M9.1: bounded conditional three-send, unchanged payload/T0 |
| [DEC-061](ARCHITECTURE_INTERVIEW_NOTES.md#dec-061) — Wallet-bound creation time; fresh live ingress versus historical sync | M4 G4/M5/M6: signed public T0; fresh ingress versus historical sync |
| [DEC-062](ARCHITECTURE_INTERVIEW_NOTES.md#dec-062) — RAM-first response; entry-only freshness and nominal seal | Partly superseded: M4/M9 preserve entry-only freshness/reserve-first; DEC-087 replaces early release |
| [DEC-063](ARCHITECTURE_INTERVIEW_NOTES.md#dec-063) — Lost-choice safety gate | M4 G5/M9.2: actual loss gate; ordinary-crash containment superseded |
| [DEC-064](ARCHITECTURE_INTERVIEW_NOTES.md#dec-064) — Strict confirmation-class priority before canonical hash | M3/M4 G3/M5: supported class priority before same-class hash |
| [DEC-065](ARCHITECTURE_INTERVIEW_NOTES.md#dec-065) — Minimal losing-branch retention | M3/M5/M9.2: minimum live exclusion/descendant evidence; no full losing archive |
| [DEC-066](ARCHITECTURE_INTERVIEW_NOTES.md#dec-066) — Inline compact conflict evidence | M4/M9.1: inline compact authenticated409evidence |
| [DEC-067](ARCHITECTURE_INTERVIEW_NOTES.md#dec-067) — No minority collision veto at checkout | M5/M9.1: valid14proof not vetoed by weaker collision |
| [DEC-068](ARCHITECTURE_INTERVIEW_NOTES.md#dec-068) — Bounded automatic client reconciliation | M6: bounded automatic backoff/reconciliation, reads after30s |
| [DEC-069](ARCHITECTURE_INTERVIEW_NOTES.md#dec-069) — Read-only recovery of original checkout approvals | M7/M6: optional original-context retrieval, not current clearance prerequisite |
| [DEC-070](ARCHITECTURE_INTERVIEW_NOTES.md#dec-070) — Root-lifetime retention of original own approvals | M7/M9.2: exact own approvals through root+30s |
| [DEC-071](ARCHITECTURE_INTERVIEW_NOTES.md#dec-071) — Durable wallet intent before network dispatch | M6: exact signed durable intent/output pending before dispatch |
| [DEC-072](ARCHITECTURE_INTERVIEW_NOTES.md#dec-072) — Durable L1 voucher/purchase, ephemeral completed-checkout certificate | M6: durable L1 voucher/purchase before release; completed proof ephemeral |
| [DEC-073](ARCHITECTURE_INTERVIEW_NOTES.md#dec-073) — No automatic substitute payment; strict client boundary | M6: no automatic substitute/refund; partial purchases strictly client-side |
| [DEC-074](ARCHITECTURE_INTERVIEW_NOTES.md#dec-074) — Idempotent repeated termination signals | M9.3: repeated signals retain first deadline |
| [DEC-075](ARCHITECTURE_INTERVIEW_NOTES.md#dec-075) — Internal shutdown deadline with outer supervisor margin | M9.3: internal deadline and longer external supervisor fallback |
| [DEC-076](ARCHITECTURE_INTERVIEW_NOTES.md#dec-076) — Stop CLI waits for verified completion and released DB | M9.3: clean target exit and DB release before stop success |
| [DEC-077](ARCHITECTURE_INTERVIEW_NOTES.md#dec-077) — Operator-only metrics and diagnostic topology | M9.3/M9.4: all metrics/topology aliases private |
| [DEC-078](ARCHITECTURE_INTERVIEW_NOTES.md#dec-078) — Dynamic public gateway discovery | M8: dynamic explicitly published HTTP candidates from passive knowledge |
| [DEC-079](ARCHITECTURE_INTERVIEW_NOTES.md#dec-079) — Bounded last-known gateway fallback belongs to clients | M6/M8: bounded client cached-address fallback and credential scope |
| [DEC-080](ARCHITECTURE_INTERVIEW_NOTES.md#dec-080) — Quorum proof required for paid/goods release | M1/M4/M6: real quorum required for paid/release |
| [DEC-081](ARCHITECTURE_INTERVIEW_NOTES.md#dec-081) — Cheap ordinary lookup, explicit quorum-backed release verification | M1/M6/M9.1: cheap read1 plus explicit strong payment verification |
| [DEC-082](ARCHITECTURE_INTERVIEW_NOTES.md#dec-082) — Confirm derived implementation batch | M1/M4/M6/M8/M9: accepted DB1 detail requirements, no implementation-by-sign-off |
| [DEC-083](ARCHITECTURE_INTERVIEW_NOTES.md#dec-083) — Current shard-state quorum, no inherited historical certificate archive | M4/M5/M6/M7: current qualified state proof; archives withdrawn, neither A/B |
| [DEC-084](ARCHITECTURE_INTERVIEW_NOTES.md#dec-084) — Live-state verification implementation requirements | M1/M2/M4/M6: accepted DB2 full current verification/purpose/challenge/readiness |
| [DEC-085](ARCHITECTURE_INTERVIEW_NOTES.md#dec-085) — Demand-triggered recovery of newly assigned shards | M2/M5/M9.1: demand-only coalesced recovery trigger |
| [DEC-086](ARCHITECTURE_INTERVIEW_NOTES.md#dec-086) — Bounded demand-driven shard recovery requirements | M2/M5/M9: accepted DB3 isolated bounded complete recovery requirements |
| [DEC-087](ARCHITECTURE_INTERVIEW_NOTES.md#dec-087) — Durable-before-Release restored | M2/M4/M9.2: durable lock+own choice before release; rejects ordinary-crash markers |
| [DEC-088](ARCHITECTURE_INTERVIEW_NOTES.md#dec-088) — Bounded durable-pipeline operations | M6/M9: accepted DB4 bounded batching/coalescing/late commits/priority |
| [DEC-089](ARCHITECTURE_INTERVIEW_NOTES.md#dec-089) — Specification cleanup and acceptance mapping | M0/M10: documentary reconciliation and actual-interface acceptance; no prose proof closure |

## 8. Commit, compatibility and failure policy for the implementing AI

- Make containment changes reviewable independently of feature completion: separate
  commits for release bypasses, unsafe readiness witnesses, and destructive merge/
  TTL handling; document their temporary availability effects. Do not combine a
  reviewable fail-closed fix with an unproved replacement protocol.
- Freeze shared encodings/negative vectors before changing both producer and
  consumer. Use coordinated dependency pins/lockfiles and reject incompatible
  versions explicitly. Do not accept unsigned/missing fields to hide a migration.
- Suggested order after contracts: shared protocol change; Node/Core consumers;
  host integration; matching cross-repo evidence/docs. Actual compile dependencies
  may require smaller coordinated increments; record the compatible set.
- Removing code is preferred where a bypass/duplicate is unnecessary, after caller
  migration. No new coordinator, daily committees, reservation service, historical
  receipt archive, broad trust research or obligatory second payment round is
  authorized by this plan.
- Feature disablement/fail-closed fallback must preserve committed spends and
  immutable choices. Never “roll back” actual accepted payments, clear pending
  outputs on timeout or restore an old database as an ordinary code rollback.
  Any on-disk format change needs honest older-binary/recovery compatibility notes.
- Recheck status before each commit; stage explicit task-owned paths and preserve
  current user edits. Earlier chat authorized commits, not arbitrary publication.
  Ask/obey any actual access-review restriction; do not bypass sibling filesystem
  permissions or weaken safety to obtain approval.

## 9. Human questions and agent-start protocol

This handoff was explicitly requested with **one** subagent. It authorizes no
additional agent start. Before **each** later activation, including reassignment
of an existing idle agent, obtain the maintainer's confirmation. Use a short
German message, for example:

> Agent X soll M1 prüfen/umsetzen. Danach sind noch Y Agenteneinsätze geplant.
> Start freigeben?

Y is the then-current **provisional** queue count, not a promise that all design
gates can be closed in that many calls. Explain revised estimates before expanding
the queue; no hidden nested agents. The main agent may perform authorized work
without treating this plan as permission to spawn a team automatically.

For a genuine unresolved product/security tradeoff, present **one A/B question
with a recommendation**, explaining exactly which open premise needs selection.
Do not ask again about settled DEC-083 archives, DEC-085 demand trigger, DEC-087
durable release, read1,14/20,per-shard readiness or private metrics. Small derivable
implementation choices should be a short problem–solution list for sign-off,
not many individual choices. Neither a timeout nor silence is approval for a
required pending decision or agent start.

## 10. Copy-paste starter prompt for the next AI

```text
Continue the complete HuMoCo architecture implementation using
docs/ARCHITECTURE_IMPLEMENTATION_HANDOFF_PLAN.md, not just the older remaining plan.
User communication must be German; repository code/docs/commits English.

First read current AGENTS.md in human-money-node and affected sibling repositories,
the complete89-decision register and supersessions in ARCHITECTURE_INTERVIEW_NOTES,
the compact interview state, original A01–A15 plan, consolidation/invariant registry
and this handoff. The G1–G5 document and completion ledger have known contradictions;
their headings and claims do not prove implementation or safety. Recheck current
code and actual registered production callers. The handoff baseline is Nodefea98c7,
Protoe119ee6, Corebf6da00, App7d3bb8c; obtain fresh heads/status/resolved dependencies.
Preserve unrelated edits and generated data. Do not reuse temporary patches blindly.

Report requirement selection, justified design, production code and executed evidence
separately. Reuse the implemented Core wallet transaction/crash fixes and Node shared
proof/durable-own-choice/pool/operator/stop/history foundations. First contain the
concrete release bypasses, unjustified readiness witnesses and destructive quarantine
regressions with meaningful tests. Then close the applicable G1–G5 design leaves,
integrate source-complete snapshot/deltas/supported merge and the real durable
intent -> send/recovery -> recipient proof -> L1/purchase commit -> release flow.
Do not manufacture a roster authority, source-completeness proof or rollback detector.

Keep14/20frozencommittee/800ms/read1,regional-revisableFINAL,immutableoriginalchoices,
durable-before-release, per-shard on-demand readiness, rootTTL+30s, no historical
quorum archives/predecessor permission/payment queue/replacement spend, private
metrics and client-only cached gateway fallback. New G-doc prose does not authorize
600s wallet freshness, arbitrary wire migration or immediate restart readiness.

Before every further agent start or reassignment, ask for explicit user confirmation
in German and state which agent starts and how many provisional assignments remain.
No hidden nested agents. Ask A/B+recommendation only for genuine unresolved tradeoffs;
batch routine derivable details for sign-off. Do not claim final completion while
any applicable gate or actual production caller/required evidence remains absent.
Run targeted real HTTP/QUIC/process/fault tests alongside each fix, final required
checks at matching revisions, and record artifacts/assumptions and unresolved cases.
Do not push, deploy or change business/protocol policy merely to close a checkbox.
```

## 11. Planning validation and limits

This plan's source findings were rechecked statically at the four listed heads.
All89 stable decision IDs and all15 original packages are mapped; all8 remaining
blocks and5 safety gates are covered, including documentary/deferred limits.
File/anchor existence, decision coverage and whitespace are planning checks only.
No production behavior, performance result, green suite or proof closure is claimed
by writing this document. The implementing AI must provide that evidence.
