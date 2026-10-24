# Architecture audit remediation handoff — 2026-10-24

**Status: implementation plan, not an implementation or completion certificate.**

This plan addresses F01–F07 in [the independent audit](ARCHITECTURE_IMPLEMENTATION_AUDIT_2026-10-24.md). It retains the approved architecture and the original Z00–Z14 / G1–G5 / E01–E15 acceptance criteria. The current request authorized preparation of this document only. No production source was changed, no tests were rerun for this documentation change, and no commit was created. A subsequent implementing AI must receive an instruction to execute the plan before editing production code. This document does not authorize deployment, push, commits or subagent starts.

Communicate with the maintainer in **German**. Write source, tests, documentation and any later explicitly authorized commits in **English**.

## 1. Start here: baseline, instructions and evidence

Use `/home/basti/Coding/humoco/human-money-node` as the starting directory. The other repositories are siblings under `/home/basti/Coding/humoco/`.

| Repository | Audited branch | Audited full HEAD |
| --- | --- | --- |
| human-money-node | dev | `c6813ee2d9d9b0a3c99dee08729423a4919176c6` |
| human-money-core | live | `a5709b0f9df0e40121faa1bd122238bd7bb3dc59` |
| human-money-app | dev | `1b32ff7deaebe901cb8d522a447bceaa39ef7dc6` |
| humoco-proto | dev | `3fc5dd87c82b91e7b682eabcf88e5b5ce23e7c32` |

These are observations, not instructions to checkout/reset those revisions. Reinspect current HEAD, branch, tracked diffs, untracked files, ignored Cargo overrides and applicable AGENTS.md before any implementation. Preserve newer work. The audit initially saw Node `987b0f1` and four modified files; an external commit produced the final audited Node revision during the audit. Treat concurrent edits as a real possibility.

At handoff, the audit report and `docs/evidence/audit-2026-10-24/` are uncommitted audit-owned additions. Preserve them. Core has preexisting untracked fuzz corpus/build files and offline-gossip Python caches; they are unrelated and must not enter changes or commits. Recheck actual status rather than assuming this list is exhaustive.

### Required reading

1. Applicable AGENTS.md in Node, Core and App, plus any new nested instructions.
2. [Independent audit](ARCHITECTURE_IMPLEMENTATION_AUDIT_2026-10-24.md), including all matrices and test limitations.
3. [Closure plan](ARCHITECTURE_IMPLEMENTATION_CLOSURE_PLAN.md), [completion manifest](ARCHITECTURE_COMPLETION_MANIFEST.md), [progress record](ARCHITECTURE_IMPLEMENTATION_PROGRESS.md) and [invariant registry](INVARIANT_REGISTRY.md).
4. [Root/causality/bootstrap contract](ROOT_CAUSALITY_AND_BOOTSTRAP_CONTRACT.md), [regional authority/signing history contract](REGIONAL_AUTHORITY_AND_SIGNING_HISTORY_CONTRACT.md), [G1–G5 contracts](SAFETY_AND_PROGRESS_CONTRACTS_G1_G5.md), [PoS trust plan](POS_CHECKOUT_TRUST_AND_CROSS_CHECK_PLAN.md).
5. [Historical remaining-work handoff](ARCHITECTURE_REMAINING_WORK_HANDOFF_2026-10-23.md). Its “remaining” wording is historical; check the current implementation before repeating work.
6. Relevant selected decisions and numbered specifications for the package being changed. Later explicit decisions override older competing prose.

The audit's [evidence directory](evidence/audit-2026-10-24/) contains source fingerprints, resolved dependency summaries, logs and independent defect probes. Read each probe before running it. The probes intentionally **pass when the audited defect is present**. Do not treat their exit 0 as a post-fix acceptance result. Convert them into maintained regressions with the required corrected oracle, and preserve the historical probe/log unchanged.

The tested App dependency is sibling Core through ignored local Cargo patches, despite a Git `master` dependency in its release manifest. Node and Core resolve sibling `humoco-proto`. Record the actual resolved graph for every final run; a local pass does not certify a published Git/CI graph. Do not add release-manifest patch blocks or update dependencies unnecessarily.

## 2. Fixed architecture and implementation guardrails

Do not reopen these decisions or replace the system with another architecture:

- Preserve L1 schemas, canonical serialization, SST signatures and transaction hashes. `ds_tag` remains the existing Core length-prefixed SHA3 formula over the previous canonical transaction hash and sender ephemeral public key. It is not Base58(previous transaction ID).
- Preserve independent receiver/change outputs and separately signed versioned L2 causal metadata.
- Genesis is exclusively a Voucher Root Anchor in `voucher_roots`, never a new spend/original vote in `locks`.
- Every new binding original/response requires exact durable commit before release. Pending RAM, signature generation capability or a healthy global boolean is insufficient.
- FINAL remains fourteen distinct authorized identities from one frozen top20; no rank21 substitution, threshold reduction, accumulated cross-committee votes or caller-invented authority.
- G1 remains explicitly configured authenticated regional views with documented fault assumptions and rejection of unresolved disagreement. Renew them on the cold path; introduce no checkout membership round or multi-gateway hot-path cross-check.
- G2 requires explicit operator bootstrap for a new region; normal joins/restarts cannot infer completeness from emptiness. N=2 fail-closed containment must not be removed to make a test progress.
- G5 covers detectable inconsistency and contradictory first-party evidence. Complete internally consistent offline-directory rollback without independent evidence stays outside the local guarantee. No TPM, notary or extra pre-signing network call.
- Do not introduce lock gossip, a third mesh gossip stream, inherited historical quorum-signature chains, node-side purchase queues, financial staking or hearsay bans.
- Admission and parsing remain bounded and safe. Reserve before allocation/RAM mutation. Do not hold RAM guards over disk I/O. Do not add unmanaged blocking I/O on runtime paths or unsafe production code.
- Keep business rules and managed wallet state in Core; App owns host transport/lifecycle and translates DTOs. Keep Core stateless services network-free and preserve supported offline L1 operation.
- A fresh recipient challenge for a new current-state verification attempt is not a new signed spend. Never regenerate original signed wallet T0, transaction bytes or request bytes to escape uncertainty.
- Same-operation release is idempotent after crash/restart. No automatic replacement payment or refund on unknown outcome. A network or storage failure may not be hidden by success flags.

## 3. Work order and ownership

The packages below are work boundaries, not requests to create agents. Execute sequentially by default. F02/F03 share protocol/storage semantics and must be designed together before either is declared closed. F04 and F05 can be implemented independently once their ownership contracts are written; F06 depends on their stable lifecycle interfaces.

| Order / package | Findings | Original ownership | Required result |
| --- | --- | --- | --- |
| R00 — capture and reproduce | All | Z00/Z14 | Exact current graph, reproducible defect/evidence ledger. |
| R01 — remove status signing bypass | F01 | Z01/Z02/Z03/Z06/Z12; E03/E07/E15 | Ordinary status cannot mint a binding original through any input format. |
| R02 — justify and preserve inherited support | F02 | Z03/Z04/Z06/Z07; G3/E05 | A fresh recipient preserves admitted support without trusting raw class fields. |
| R03 — complete recovery coverage/progress | F03 | Z02/Z06/Z07; G2/G3/E04 | Correct source coverage under distributed support, fixed cuts and turnover. |
| R04 — recipient lifecycle and capacity | F04 | Z08/Z13; E02/E12 | Safe expired-attempt renewal/retirement and continued purchase service beyond 256 lifetime operations. |
| R05 — cold authority lifecycle | F05 | Z08/Z11; G1/G4/E10 | Bounded renewal across expiry, login, profile/network/config changes. |
| R06 — productive intent reconciliation | F06 | Z08/Z10/Z13; E07/E09/E12 | Automatic bounded continuation, verified resolution and safe delayed cleanup. |
| R07 — real boundary/fault acceptance | F07 | Z07/Z08/Z12/Z13/Z14 | Merge, real IPC/frontend, process cuts, repeated signals and measured mixed-load evidence. |
| R08 — final acceptance and evidence reconciliation | All | Z00/Z14; all G/E | Exact-source reruns, honest matrix and remaining assumptions. |

For each package: identify the real entry point and consumers; reproduce the baseline; write an independent expected outcome; implement the smallest coherent fix; execute targeted checks; re-search callers/bypasses; update the ledger. Never close a package from helper tests alone.

## 4. Detailed execution packages

### R00 — refresh baseline and reproduce findings

**Actions**

1. Record paths, branches, full hashes, dirty/new paths, per-file fingerprints, toolchain, platform, Cargo configuration and resolved packages/features for all four repositories. Inspect current diffs before editing. Bind every test result to the actual working tree, including uncommitted source.
2. Reproduce F01 and F02 first, using the saved status/native/HMC probes as reference. Record whether a newer implementation already repairs a finding; do not reintroduce the old code just to reproduce it.
3. Reproduce F04's capacity and expired-attempt behavior and inspect all callers for F05/F06. Separate behavior proven by an executable test from missing-call-path evidence.
4. Run the three formerly ignored merge tests individually to capture their first failing prerequisite and response payload. The audit observed assertion failures, but did not establish their root causes. Do not label them a consensus failure without that investigation.
5. Open an execution ledger, for example `docs/ARCHITECTURE_AUDIT_REMEDIATION_PROGRESS_2026-10-24.md`, with one row per R/F item and links to original Z/G/E ownership. Save logs under a new remediation evidence directory; do not overwrite historical audit evidence.

**Done:** each finding is either still reproduced, specifically repaired by newer code with evidence, or explicitly qualified. The reproduction setup states prepared maturity/readiness/support assumptions. No implementation claim follows from a baseline pass.

### R01 — close the legacy StatusQuery producer

**Inspect**

- Node `crates/humoco-node/src/network/transport.rs`: `StatusQuery` decoding near 1218, RAM/disk matching near 1440 and fresh attestation near 1532.
- New guarded `api/live.rs::sign_current_state`; exact original durability APIs in `storage/engine.rs` near 776/850/953; immutable own-choice storage.
- Every request producer/consumer of `StatusQueryPayload`, the legacy tuple, `StatusResponse`, original attestations and `create_attestation_for_network`.
- Public `/v1/status`, retained-choice retrieval and Core/App conversion of observations into assurance.

**Implementation steps**

1. Build a producer table: message type, purpose, input authorization, durable prerequisite, returned bytes, consumer and whether it can count toward a quorum. Include all legacy payload formats and header-flag combinations.
2. Make ordinary status a bounded read observation. Prefer removing its new original-signature production and adjusting actual consumers accordingly. A client-supplied FINAL flag cannot create final authority.
3. Keep retained original retrieval as a distinct read of already committed exact bytes. Do not “repair” status by creating/persisting a new original during a read. Clarify historical retrieval versus a new binding release without accidentally making reconciliation impossible while a shard is recovering.
4. If any original producer remains outside the main write path, it must use the same immutable choice and exact durable acknowledgment contract, plus applicable health/readiness/committee checks. Reusing a signing helper alone is insufficient.
5. Check that diagnostics cannot be mistaken for current payment proof and that no consumer starts collecting cheap status originals as a substitute for the challenge-bound current proof.

**Required real-QUIC regressions**

| Input/state | Required outcome |
| --- | --- |
| RAM-only lock, disk row/choice absent | No new valid original approval. |
| Signing-failure latch or persistent corrupt history | No new binding signature through status, write, duplicate or live paths. |
| Unready shard / wrong current committee / ineligible signer | No new countable approval. |
| Legacy tuple, current payload, arbitrary status bits | No bypass through compatibility decoding or caller-selected class. |
| Earlier original A, current canonical B after lawful merge | A read does not produce a new incompatible original B; retained original A remains exact where allowed. |
| Valid committed record and ordinary status request | Diagnostic lookup still works within its read admission contract. |
| Valid current challenge and fourteen authorized ready nodes | New live-proof checkout still works. |

Test pending persistence with a controlled worker barrier as well as the prepared RAM premise, then release it and check late-commit/retry behavior. Assert state effects and independently verify any returned signature purpose. Confirm no extra disk/write-queue reservation was introduced into ordinary read ingress.

**Done:** F01's historical defect oracle no longer succeeds; maintained Q tests establish the corrected behavior and positive diagnostic/current-proof paths. No binding producer bypass remains in caller search.

### R02 — preserve support at a fresh recipient through justified admission

**Inspect**

- `daemon.rs::sync_single_shard` current class selection.
- `storage/db/install.rs` native overwrite near 194 and HMC support construction near 221.
- `storage/db/support.rs::VerifiedSupport`, `ConfirmationSupport`, objective snapshot/framing and restart recovery.
- The real HMC audit probe and the existing same-destination preservation test. Keep both native and HMC paths in scope.

**First deliver a short contract worksheet, shared with R03**

Define exactly what a current authenticated source can attest about an inherited exclusion: network, shard, collision slot, exact child/state identity, admitted support class, root expiry, cut identity, current source context, and completeness versus existence. State which evidence admits the fact and under which existing regional fault assumptions. Bind any new assertion to a distinct canonical purpose/version; it must not be usable as an original spend approval or ordinary live-checkout proof.

Distinguish source-reported class, source-local verified class, support witnessed by the receiving qualified set, and a destination's earlier local fact. Raw `status=2`, `sigs=14`, copied bitmaps or an arbitrary source integer cannot establish class 2. Conversely, the receiving mesh's smaller current threshold cannot silently erase valid inherited class 2. Do not archive or recursively transport departed original signers' certificates.

**Implementation steps**

1. Establish a bounded authenticated admission mechanism for the minimum inherited support facts within the accepted G1/G3 model; use the existing cold sync/direct RPC boundary. Do not assume that agreeing only on an objective digest proves agreement on support metadata if the digest does not commit to that metadata.
2. Keep the objective active-state digest and support-evidence commitment unambiguous. Any change to encoding needs explicit versioning, parser bounds and matching producers/consumers.
3. Validate inherited facts before staging installation; preserve exact root lifetime and protected original choice. Reject ambiguous, foreign, stale or unsupported facts before active-state mutation.
4. Commit the resulting support, locks/roots, quarantine and indexes atomically; publish the same durable state to RAM before readiness. Cover replacement and support upgrades without downgrade.
5. Handle unknown/legacy support conservatively. Do not turn missing justification into either fabricated class 2 or freely replaceable class 0. Define migration/recovery behavior without inventing retrospective proof.

**Required regressions**

- Genuine class-2 HMC sources -> fresh four-node island recipient -> durable class 2 -> reopen still class 2.
- Native equivalent, with support established through the actual producer/admission boundary rather than only prepared status fields.
- Repeat transfer to a second fresh recipient; the first recipient's local preservation branch must not be the only reason the test passes.
- Class-0 and class-1 sources cannot fabricate class 2; forged/cross-network/wrong-slot/expired support rejected over Q.
- A lower-hash weaker competitor cannot displace inherited stronger support; equal highest confirmed classes follow the selected canonical tie-breaker.
- A failed install leaves the prior active state/indexes/support intact; root expiry removes every new root-bound metadata record; backup/reopen preserves the admitted facts.

**Done:** fresh-recipient native/HMC tests prove preservation, negative tests prove no raw-class promotion, and the trust argument supports those exact tests. If the required evidence cannot be justified under the approved assumptions, keep this gate open with a concrete counterexample; do not hide the gap by copying integers.

### R03 — complete source coverage, distributed support and turnover

**Inspect**

- `daemon.rs::sync_single_shard` grouping by full-state digest and its source/committee rechecks.
- `storage/db/snapshot.rs`, `storage/db/install.rs`, `storage/engine/recovery.rs`, activity fencing and task ownership.
- The test named `asymmetric_partition_8_6_6...`, which actually uses 8/7/5 and manual equal-state copying.
- G2 acceptance and the existing explicit bootstrap and peerless/N=2 negative controls.

**First resolve the actual proof obligation**

Write a scenario worksheet for two compatible exclusions A and B distributed as AB on eight qualified holders, A on six and B on six. Existence support for each is not identical-whole-state agreement. Also define omission/completeness evidence, conflicts, descendants, expiry, source failures and the target's transition into a new committee. List actual identities, full HRW scores, frozen top20 and available source witnesses at each step.

Do not accidentally construct twenty source voters plus a target and count twenty-one committee members. Do not count recovering self, replace missing members with rank21, or assume that sixteen reachable sources necessarily preserve fourteen supporters of every fact. If membership change removes a necessary witness, distinguish that unsupported case from the intended positive scenario. State precise safe-progress premises instead of promising progress with no surviving evidence.

**Implementation steps**

1. Extend the selected bounded cold recovery mechanism to reconcile admissible distributed active facts and establish omission coverage without requiring fourteen identical complete data digests in every supported case. Do not implement an unconditional union, majority-of-whatever-responds or hash-only authority rule.
2. Use R02's verified support semantics to resolve conflicts. Keep unknown/confirmed exclusions protected; an omitted key is not by itself proof of class 0 or nonexistence.
3. Bind source assertions to fixed cuts and the frozen qualified context. Cover writes admitted before freeze but committed afterward, canonical replacement, descendant changes and TTL changes while transferring.
4. Reuse bounded disk staging and a single durable installation transaction. Account for metadata, pages, verification work and installation buffers before allocation. Never rebuild whole-shard in-memory vectors to make the new algorithm convenient.
5. Maintain source fencing through the exact target durable commit/RAM/readiness point or a justified equivalent within the approved contract. Absolute lease expiry, source loss and committee change invalidate unsupported publication.
6. Track/cancel blocking work honestly. A late install must not reopen signing against inconsistent RAM; an ordinary validation rollback must not be confused with uncertain commit. Review the current conservative global signing latch on any install error and preserve safety while documenting its availability effect.
7. Keep explicit operator bootstrap and closed normal restart. A complete network restart with no ready justified witnesses is not automatically solved by a matching empty digest.

**Required scenarios over real Q and durable storage**

| Scenario | Oracle |
| --- | --- |
| Genuine supported distributed AB/A/B case | Installs the correct admitted state and progresses under explicitly justified available-source premises. No manual target readiness. |
| Missing necessary evidence / all-empty new sources / target N=2 | Remains unready; no invented original, promotion or empty bootstrap. |
| Asymmetric 10/3 merge and admissible equal-class stalemate | Correct class-aware result; minority quarantine preserves data without poisoning active digest. |
| Repeated complete signer turnover with surviving transferred facts | Exclusions/support survive; no need for departed original signature archives. |
| Same-slot conflicting choices and descendant branches | Selected class precedence/tie-breaker, no unlawful original re-signing. |
| Insert before cursor, delete/expire between pages, late pre-cut commit | Fixed-cut/coverage semantics hold; no skipped exclusion or stale publication. |
| Lease expiry, source disconnect, assignment change, cancellation | No unjustified readiness; reservations/tasks clean up; late workers cannot change that verdict. |
| Crash around staged/committed/RAM/ready transitions | Reopen safely reconstructs exact durable state; unfinished target is unready. |
| Authenticated repeated freeze requests | Per-shard lease/cooldown and resource bounds hold; other shards remain available; measured same-shard service impact is reported honestly. |

**Done:** true distributed-support and turnover positive scenarios pass without prepared target readiness, all required containment negatives remain, and proof premises are documented. A permanent NOT_READY result alone does not close the positive-progress obligation. If a selected requirement needs a premise not present in the approved contract, record the precise incompatibility and leave that row open; continue independent fixes rather than silently adding a new trust service.

### R04 — repair purchase attempt lifetime and durable capacity

**Inspect**

Core `src/app_service/checkout.rs` and `models/profile.rs`; managed wallet transaction/recovery and bundle replay history; App `src-tauri/src/checkout.rs`, `commands/transfers.rs`, `ReceiveView.tsx`, `ReceiveSuccessView.tsx` and transfer DTOs. The UI's generated `pos-${Date.now()}` fallback must not accidentally become a new purchase on every retry/restart.

**Required state contract**

Separate an active verification attempt (short-lived nonce/context) from durable completed-purchase/replay identity. An active-attempt admission limit must not be a lifetime limit on all merchant purchases. Define retirement of expired or abandoned attempts and retention of completed evidence. Completed records may be compacted only if durable replay protection and truthful same-operation results remain available; increasing 256 or deleting completed IDs wholesale is not a fix.

**Implementation steps**

1. Preserve stable purchase/cart ID and immutable bundle binding through user retries and app restart. Reusing an ID with different bytes fails.
2. Reuse a still-valid attempt's nonce. If a pending attempt expires while its root is live, safely create a new CSPRNG verification attempt for the same purchase/bundle under current authenticated authority. Atomically retire the old attempt so an old proof cannot complete the new one.
3. Do not renew the signed spend, original T0 or original send bytes. Current-state verification has its own fresh recipient challenge. Never renew against an expired root or unresolved authority.
4. Prune/retire bounded expired pending attempts before capacity refusal and during a real maintenance lifecycle; avoid unbounded per-request scans/writes.
5. Preserve atomic L1 import + challenge consumption + purchase/release disposition. Keep uncertain commit blocked until recovery decides it. Return success only after the managed commit succeeds.
6. Replaying a completed operation must return `newly_committed=false` without a network requirement, including after reopening. Safe retention/compaction must prevent a forgotten ID/bundle from authorizing another release.
7. Add compatible private-state migration. Do not change signed L1 profile/voucher serialization or silently discard old completed/pending records.

**Required tests**

- More than 256 distinct completed purchases over time continue safely; capacity remains bounded by the documented active-work contract.
- More than 256 sequential expired/abandoned attempts do not permanently disable the wallet. Truly simultaneous active-work exhaustion rejects boundedly.
- Same purchase retry before expiry reuses context; after expiry receives a fresh attempt; old proof rejected; new valid proof succeeds once.
- Changed bundle, wrong target/root/network/challenge, expired root and unknown L1 cannot commit/release.
- Completed replay offline and after restart remains idempotent, including after maintenance/compaction.
- Process cuts before/after attempt replacement, L1 import, purchase commit and uncertain fsync/marker commit preserve the required state.
- Receive UI retains operation identity across retry/navigation/restart and suppresses replay release. Assert the actual command and persisted backend result, not only a prepared verdict DTO.

**Done:** F04's permanent-capacity/expired-context failure is gone without weakening replay safety, and the lifecycle is productive and crash-tested.

### R05 — renew authenticated regional views on the cold path

**Inspect**

App `checkout.rs::{refresh_views,cached_views}`, `AppState`, login/logout/unlock/profile lifecycle, settings save/network switch, `Login.tsx`, `SettingsView.tsx`, session hooks and Tauri task registration. Proto's sixty-second lifetime and Core's verification remain authoritative.

**Implementation steps**

1. Choose one host-owned lifecycle task as renewal owner. Avoid duplicate timers in Login, settings and receive components. Keep business validation in Core/Proto.
2. Renew before the earliest accepted configured source expiry, with bounded request count/bytes/time, cancellation, deduplication and backoff. Keep the existing view lifetime; do not solve this by accepting stale views or extending their signed TTL.
3. Trigger cold refresh after authenticated login/unlock, authenticated source-policy/configuration/network change, and recovery from connectivity loss. Stop/invalidate on logout, lock, profile change and app shutdown.
4. Scope cache/task to owner, network, policy and a lifecycle generation. Recheck those after each await before publication; an old task cannot populate a new profile/network cache even if endpoints are equal.
5. Fetch every configured source and verify its pinned key, signature, time and committee agreement. Missing/disagreeing source is unavailable authority, not lower quorum or best-effort roster selection.
6. Handle saving empty sources/revocation explicitly: settings and persisted authority must not silently disagree. Maintain origin-scoped credentials and redirect rejection for renewal traffic.
7. Checkout consumes a verified fresh cache snapshot and fails closed if it is unavailable; it may request background recovery but must not add a blocking membership lookup to the checkout hot path.
8. Show actionable renewal/configuration state in the UI without authorizing release or silently swallowing persistent refresh failures. Do not print tokens into logs or public discovery.

**Required tests**

- Backend timer/injected-clock lifecycle renews before 60s expiry and allows repeated purchases beyond several view lifetimes.
- Real source responses verify; wrong key, future/stale/replayed/missing view and disagreeing sources remain rejected.
- In-flight refresh followed by profile/network/policy change or logout cannot publish stale-owner state.
- Settings save clears and repopulates the correct cache; source removal revokes authority.
- Repeated failures use bounded backoff and one worker; shutdown cancels ownership; no mutex held across network calls.
- Frontend lifecycle/IPC integration tests verify registration and state display, plus at least one actual host-runtime renewal test. Fake timers prove scheduling, not real network authentication.

**Done:** automatic cold renewal is productive, owner/network-safe and bounded; a long-lived terminal does not require manual refresh each minute. All prior freshness/authority negatives still pass.

### R06 — make intent reconciliation a real supervised lifecycle

**Inspect**

App `commands/transfers.rs::submit_l2_send_intent`, exact initial dispatch, `gateway_resolver::{fetch_retained,fetch_live_proof}`, session lifecycle and frontend `transferService.ts`. Core `app_service/l2_intents.rs`, `wallet/l2_intents.rs`, input exclusion checks and wallet transaction APIs.

**Implementation steps**

1. Enumerate committed unresolved intents after login/restart and after initial dispatch. Own one bounded cancellable host scheduler; schedule each intent no earlier than its original T0+30s. Prevent overlapping work for the same intent.
2. Scheduler authorization must fit the existing unlocked/authenticated wallet model. Do not persist plaintext passwords, place them in frontend timers or bypass transactional authentication to enable background work. Define lock/logout suspension and unlock resumption.
3. Capture owner/network/policy/lifecycle generation and exact intent identity before network I/O. Revalidate after awaits before mutating state, as for R05. Never apply a response to a different wallet with a coincidentally equal local ID.
4. Before thirty seconds, any allowed retry uses exact saved request/chain bytes and unchanged T0. After the window, use the selected read-only retained/current-state continuation rather than resubmitting a newly timestamped original.
5. Treat a retained original as verified first-party observation only. Missing/404/timeout is unavailable, not proof of non-spend. A mismatch is not automatically a terminal conflict or a ban.
6. Define a verified terminal-resolution boundary for matching current quorum and admissible conflicting current evidence. The existing `record_intent_conflict(local_id, child_string, ...)` must not become an unvalidated string-to-terminal-state shortcut. Verify purpose, authorized committee, parent/child/root/network, challenge and evidence under the stored intent.
7. Use independently authenticated fresh authority and a stored CSPRNG current-verification challenge. Commit its consumption and resolution atomically. Reject replay/wrong context. Preserve original signed bytes/T0 exactly.
8. Root expiry can end further live verification, but cannot authorize an automatic replacement/refund. Define terminal states and UI outcomes explicitly.
9. Run cleanup later when retention actually expires, including terminal/expired early-return paths, idle/login maintenance and restart. Do not rely on cleanup called immediately after a fresh resolution. Preserve whatever spent-output exclusion/replay state is still needed before deleting an intent; freeing a map entry must not resurrect a consumed input.
10. Bound concurrent jobs, retained/live requests, retries, backoff, bytes, per-intent deadlines and aggregate work. Keep core networking out of stateless services. Expose pending/conflict/expired outcomes truthfully.

**Required tests**

- Initial dispatch times out; original UI/session remains idle; the scheduler starts continuation at T0+30s without a button/API call from the test.
- Restart with an unresolved intent resumes at the correct age; no renewed T0/request bytes and no accidental second transfer.
- Genuine single original remains pending; fourteen correct current votes resolve once; thirteen, duplicate, nonmember and old challenge do not.
- Conflicting evidence, missing data, stale authority and network outage follow their explicit safe state transitions. No arbitrary child string clears or terminally condemns an intent.
- Two simultaneous callbacks, profile/network switch, lock/logout and cancelled/late network responses cannot mutate the wrong operation.
- Terminal intents are eventually cleaned under the documented policy; repeated use beyond 256 lifetime sends stays bounded without restoring spent funds. Include independent receiver/change use and offline L1 paths.
- Real retained HTTP -> App consumer -> Core verification and real current HTTP/QUIC resolution are exercised; unit calls alone do not close this package.

**Done:** ordinary productive operation, restart and delayed cleanup drive reconciliation; exact original state and uncertainty protection remain intact.

### R07 — replace evidence shortcuts with actual boundary/fault acceptance

This package owns test quality, not permission to weaken production checks. Track subitems separately so one successful E2E cannot close all of F07.

| Subitem | Execution and independent oracle | Completion evidence |
| --- | --- | --- |
| R07a — failing merge tests | Reproduce each sim_07 failure individually. Capture actual verdict, readiness, context and first failing prerequisite. Repair obsolete fixtures to establish valid source premises, or fix a reproduced product defect. Never preauthorize the target or change expected `Verified` to arbitrary success. | All three intended scenarios pass, or exact unsupported premise remains explicitly open. Add true R03 8+6+6/turnover tests rather than renaming 8/7/5. |
| R07b — real product IPC | Exercise actual registered Tauri send/receive commands from frontend/host tests, through Core, HTTP, authenticated Q and durable purchase. Keep existing direct-module harness as a separate tier. | Fourteen valid/13 invalid threshold, wrong authority/purpose/root/output, same cart replay and profile/network switch; actual command name/DTO registration verified. If a platform cannot launch GUI/IPC, label that boundary not tested. |
| R07c — wallet process cuts | Use child processes and test-only compile-time hooks around real intent/purchase transactions and transport edges. Reuse managed transaction fault facilities; no unsafe global environment mutation or public production fault flag. | Kill before intent commit, after durable intent before send, during send, after remote commit before response, before/after purchase commit, during uncertain marker/fsync and before UI release acknowledgment. Reopen asserts exact bytes, pending input, imported value and release disposition. |
| R07d — recovery process cuts | Crash source/target around lease acquisition, final cut, install transaction, commit, RAM publication, readiness and blocking-worker completion. | No incomplete readiness, no erased exclusion, no class downgrade, no orphan reservation; reopen and late worker observed. |
| R07e — shutdown | Launch the real daemon. Send repeated actual supported OS stop signals/control requests while persistence/sync is busy and while test storage is stalled/failing. Run actual CLI stop, not only ControlClient or token cancellation. | One immutable deadline, truthful incomplete/nonzero outcome on timeout, clean exit only after process/resource completion, independent open of the existing actual redb file. Early socket unlink cannot spoof success. Do not claim abort interrupts kernel fsync. |
| R07f — resource isolation | Declare hardware/platform/offered load; combine real public ingress/read, shard RPC and low-priority sync with slow storage and repeated authenticated freezes. Measure task/queue/socket peaks, allocated/page bytes, process RSS, staging disk and successful internal commits/latency. | Bounds and protected progress under the declared workload, preallocation >64KiB rejection, reclaimed permits/tasks after cancellation. A 32-semaphore assertion is not RSS or disk evidence. |
| R07g — metadata lifecycle/restore | Inventory each root, support, index, quarantine, own choice, stage, wallet intent and purchase record introduced/changed by R01–R06. Test expiry/replacement/reopen/backup/restore and interrupted cleanup. | Root+grace physical cleanup where required; durable client purchase history follows its own justified replay policy; no Node permanent per-lock tombstones. |

Keep preparation honest: source readiness, mature tickets and fault bounds can be explicit premises of an integration test; automatic bootstrap/reentry and true production UI require their own evidence. Assertions must check externally meaningful signatures, durable state and outcomes rather than only implementation constants or set booleans.

### R08 — exact-source final acceptance and documentation

1. Reinspect every producer and consumer affected by R01–R07 and search for old compatibility paths. Review the complete diffs, including any test lint cleanup and migrations. Ensure no unrelated files were changed.
2. Run the mandatory commands below after implementation stabilizes. Targeted development runs do not substitute for final suites. Run timing-sensitive E2E/load checks in a declared environment; retain both initial failures and isolated repetitions rather than erasing contention evidence.
3. Recheck HEAD, dirty files, manifest/lock/config fingerprints, actual resolved features and source hashes after the commands. Document any concurrent edit; rerun affected checks rather than attaching new source to an old green result.
4. Update current manifest/progress/contracts and Core/App STATUS where applicable. Preserve dated historical reports. Remove contradictory current completion claims; mark every selected Z/G/E row with source, producer/consumer, test, executed command and remaining premise.
5. Provide a final English remediation report and concise German user summary: fixed findings, unresolved findings, exact test totals/skips/failures, graph, platform and limits. “Complete” requires every relevant criterion, not merely every finding title, to have adequate productive evidence.
6. Do not commit, push or deploy unless the current user explicitly requests it. Do not create new chats or start agents from this document.

## 5. Required verification commands and environment handling

Run from each repository's actual root unless stated otherwise. Prefer offline/locked execution where dependencies are available and the lockfile is intended to remain fixed; record exact flags and any necessary deviation. Never auto-update a lockfile to make a local check pass.

| Repository | Required final commands |
| --- | --- |
| Node | `cargo test-std`; `cargo clippy --workspace --all-targets -- -D warnings` |
| Node affected deep scenarios | `cargo test -p humoco-node --test sim_07_network_growth_and_merge_scenarios -- --ignored`; relevant additional turnover/partition/load simulations; report which remaining ignored tests were not run |
| Core | `cargo nextest run --status-level fail`; `cargo test --doc`; `cargo clippy --all-targets -- -D warnings`, plus any newly applicable instructions |
| App | `./run-tests.sh --quiet`, including version synchronization, both TypeScript configs, ESLint, Vitest/i18n, backend Clippy and Cargo tests; add real IPC/lifecycle acceptance beyond the script |
| Proto | `cargo test`; `cargo clippy --all-targets -- -D warnings`; canonical positive/negative/version vectors for any changed DTO |
| Cross-repository | `scripts/run-architecture-e2e.sh` against the exact final sibling graph; run new actual host/IPC/fault tests as a separately named evidence tier |

The audit baseline is Node **664 passed / 14 ignored**, Core **825 passed / 7 skipped**, Proto **17 passed**, App **184 frontend tests in 23 files plus successful backend checks**; strict lints passed. Three manually executed ignored merge tests failed. E2E failed once under concurrent load and passed isolated. These are historical observations, not expected totals to hardcode into tests or substitutes for new runs.

Real QUIC/HTTP/UNIX sockets and writable sibling build caches may require environment approval. A failed bind or read-only cache is not proof of a product bug. Request the specific tool capability if needed, retain the failed attempt, and rerun appropriately. Conversely, an assertion failure with functioning sockets must not be dismissed as environmental without evidence. Do not loosen deadlines/quorums merely to turn a loaded test green.

Core `test-utils` is for test/debug acceptance only; do not enable it in release. A new versioned L2 DTO must have matching Node/Proto/Core/App producers and consumers. Preserve all existing L1 canonical vectors unchanged.

## 6. Finding closure ledger and stopping rules

Maintain this table with concrete artifacts; the initial state is deliberately open.

| Finding | Must-have closure artifact | Initial state |
| --- | --- | --- |
| F01 | Maintained real-Q negative regressions for every status format/gate and positive diagnostic/live path; producer/consumer audit | Open |
| F02 | Fresh recipient native/HMC inherited support proof + real-Q multi-transfer/restart/competing-class tests | Open |
| F03 | Correct distributed-support/coverage worksheet + genuine positive recovery/turnover and unsupported-premise negatives | Open |
| F04 | Productive purchase attempt/retention migration and >256 lifetime/idempotent expiry/restart/crash evidence | Open |
| F05 | One bounded cold-renewal owner with expiry/profile/network/config/cancellation/authentication tests | Open |
| F06 | Automatically driven timed/restart reconciliation and verified conflict/expiry/delayed cleanup through actual consumers | Open |
| F07 | Green diagnosed merge scenarios plus separately recorded R07a–g evidence and honest remaining limits | Open |

Continue routine implementation autonomously once execution is authorized. Do not ask the user to choose ordinary helper names, module placement, test organization or equivalent reversible implementation details. Do not treat old planning prose as fresh permission for commits or delegation.

If a proof requirement cannot be met within the approved architecture, document the minimal counterexample, exact affected requirement, missing premise and safe current behavior. Do not silently add external trust, fabricate evidence, lower quorum, or relabel containment as positive progress. Ask for a decision only if resolution would actually change an already selected architecture/guarantee; continue unrelated authorized packages meanwhile.

Do not declare completion while a confirmed binding-signature bypass, inherited-support loss, required unimplemented consumer or essential unexecuted acceptance remains. A documented excluded case, such as fully consistent offline rollback without independent evidence, is not a reason to expand scope.

## 7. Starter instruction for the implementing AI

> Execute the architecture-audit remediation handoff in `docs/ARCHITECTURE_AUDIT_REMEDIATION_HANDOFF_2026-10-24.md`, after reading current AGENTS.md and refreshing all four repository states. Preserve existing changes and the audit evidence. Address F01–F07 in R00–R08 order, reproducing each finding and adding maintained tests at the real boundary before claiming closure. Preserve all approved L1/L2 decisions, explicit bootstrap and G1/G5 assumption limits. Do not use raw imported classes, fake readiness, reduced quorums, regenerated original T0/bytes or historical quorum archives as shortcuts. Complete productive callers and lifecycle integration, run final exact-source suites and record failures, skips, prepared premises and untested boundaries honestly. Respond in German and save English progress/evidence. Do not commit, push, deploy or start agents without explicit authorization in the current session. If a required proof is incompatible with the approved premises, present the precise blocker and keep that gate open while completing independent work.
