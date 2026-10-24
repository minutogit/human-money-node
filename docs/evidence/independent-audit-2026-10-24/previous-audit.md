# Architecture implementation audit — 2026-10-24

**Verdict: partially implemented.** The approved architecture cannot be certified complete within its stated assumptions. The current production code contains a reachable original-signature bypass and loses previously established confirmation class during transfer to a fresh island node. Recipient and sender lifecycle integration also remains incomplete. Successful mandatory suites and a successful isolated cross-repository checkout do not close these defects or the unexecuted recovery/crash/load obligations.

This is an independent read-only product audit. No production source was edited, no commit was created, and no existing work was reset. The only repository additions are this report and its audit evidence. Communication was German; this saved report is English.

## 1. Findings, ordered by severity

Priority P1 denotes a release-blocking safety or required recovery defect; P2 denotes a functional, operational or evidence defect. “Confirmed” means the stated behavior was reproduced or follows directly from the complete inspected caller chain. It does not imply that monetary loss was demonstrated.

### F01 — P1 / confirmed: legacy StatusQuery mints original approvals outside every signing gate

**Requirements:** Z01/Z02/Z03/Z06/Z12, G2/G5, E03/E07/E15; Durable-before-Vote, INV-1405/1406, and the separation of cheap status from original acceptance.

**Locations:** Node `crates/humoco-node/src/network/transport.rs:1218`, `:1440`, `:1533`; the signing-health predicate is in `storage/engine.rs:762`. Compare the guarded new producer in `api/live.rs:21`.

**Failure path:** an authenticated learned peer sends a legacy `StatusQuery` tuple `(lock_id,parent_lock,shard_id)` with the low header flag selecting FINAL. The receiver accepts this tuple, looks up RAM before disk, and calls `create_attestation_for_network` for a matching row. This branch checks neither exact durable publication nor stored original choice, shard readiness, current committee eligibility, or engine signing health. The returned signature uses the actual original-approval domain; it is not merely an unsigned status observation or a challenge-bound live vote.

**Reproduction:** [probe-status-signing.sh](evidence/audit-2026-10-24/probe-status-signing.sh) runs the production receiving handler over real authenticated QUIC. It prepares a RAM-only native record, leaves the shard unready, sets the existing signing-failure gate, asserts the disk row is absent, sends `StatusQuery`, and independently verifies the returned Ed25519 signature with Proto's FINAL original digest. All assertions passed. The preparation injects the pending RAM premise; it does not claim to reproduce a physical disk failure. [Log](evidence/audit-2026-10-24/probe-status-signing.log).

**Impact:** a binding original can escape before its lock/own choice is committed and after signing has been disabled. The endpoint also cannot guarantee immutable original-choice reuse after canonical replacement. This violates the approved boundary even though the new recipient live-proof flow refuses an arbitrary single original. No forged 14/20 purchase or monetary-loss exploit was demonstrated.

### F02 — P1 / confirmed: fresh island recipients downgrade inherited class 2 to class 1

**Requirements:** Z03/Z06/Z07, G3, E05; confirmed support survives restart/transfer and retiring signers do not revoke that support.

**Locations:** Node `daemon.rs:1211` selects class from current network size/stability; `storage/db/install.rs:194` overwrites native status; `:221` creates HMC support using that current class. Preservation at `:200` and `:223` only consults the destination's existing state. `storage/db/snapshot.rs:131` streams objective data without an independently inherited HMC class fact.

**Failure path:** sources already hold admitted class-2 support. A fresh destination joins a four-node island, obtains the required three equal ready-source cut witnesses, and installs the cut as class 1 because the current mesh is small. The existing class-2 preservation branch cannot run at a fresh destination. The same issue affects native and HMC installation.

**Reproduction:** [probe-hmc-inheritance.sh](evidence/audit-2026-10-24/probe-hmc-inheritance.sh) first establishes class 2 on three source nodes using the actual 20-node manager and real >=14-witness QUIC recovery. It then restricts their passive-presence views to a four-node island with a fresh fourth target. That target becomes ready with class 1. No class-2 support integer was injected into these three sources. Source maturity, initial ready cut holders and presence changes are explicit fixture premises. [HMC log](evidence/audit-2026-10-24/probe-hmc-inheritance-final.log). A separate native reproduction also passed, with prepared FINAL source records: [native log](evidence/audit-2026-10-24/probe-inheritance.log).

**Impact:** a transferred confirmed choice loses class precedence and can later lose a comparison that its original class would have won. The existing `fourteen_live_cut_witnesses_establish_hmc_support_without_history_and_island_sync_preserves_class_two` test (`cluster_sync_recovery_tests.rs:360`) resyncs the same already-class-2 destination; it misses this fresh-destination failure. No historical quorum archive is proposed or required by this finding.

### F03 — P1 / confirmed missing recovery case: whole-digest quorum is still required; distributed support/full turnover is not closed

**Requirements:** Z06/Z07, G2/G3, E04; closure-plan §5 explicitly requires the 8+6+6 support case without 14 identical whole-state digests and positive justified progress.

**Locations:** Node `daemon.rs:1204` groups by an identical digest and `:1211` returns false unless one group reaches quorum. `tests/cluster_sync_recovery_tests.rs:461` is named `asymmetric_partition_8_6_6_blocks_finality_until_14_quorum_reunited`; at `:471` it actually describes groups of 8/7/5, and at `:505` manually loads the same state and readiness into additional sources before retrying.

**Failure path:** for states AB on eight members, A on six and B on six, each exclusion can have fourteen supporting holders while no complete state digest has fourteen holders. The implementation has no merge/coverage construction for this case: the digest grouping returns NOT_READY. Repeated full turnover with mixed cuts is likewise not demonstrated. This is a positive-progress gap, not evidence of unsafe automatic empty bootstrap.

**Evidence:** complete productive function inspection, inspection and execution of the existing misleadingly named test (standard suite passed). No independent real-wire 8+6+6 distributed-support reproduction was added in this audit. The existing test does not simulate the promised case or an autonomous partition heal. This limitation is explicit rather than attributed to an excluded global-consensus guarantee.

**Impact:** the selected recovery acceptance cannot be marked complete. The two-node fail-closed case is correctly implemented and is not itself a defect; an automatic empty-state fallback would violate the approved G2 decision.

### F04 — P2 / confirmed: purchase reservations permanently exhaust the recipient and expired challenges cannot resume

**Requirements:** Z08/Z13, E02/E12; bounded purchase lifecycle, retry/restart and durable idempotency.

**Locations:** Core `src/app_service/checkout.rs:97` returns any existing context; `:103` rejects a table of 256 entries; `:176` stores 30-second challenge expiry; `:223` refuses an expired challenge. The only production uses of `l2_checkout_purchases` create, look up or complete entries; no pruning/retirement path exists. App `src-tauri/src/checkout.rs:102` starts this reservation before the gateway request.

**Failure path:** successful purchases and failed/abandoned attempts all consume this same permanent 256-entry allowance. There is no cleanup even when a pending challenge or its root expires. A retry of the same pending purchase after 30 seconds returns the old context, which completion can no longer accept. Changing purchase IDs consumes more entries.

**Reproduction:** [probe-checkout.sh](evidence/audit-2026-10-24/probe-checkout.sh) extends the unchanged productive E2E modules in a temporary crate. After one real completed purchase, 255 additional distinct reservations succeed, the next fails with `purchase capacity exhausted`, an expired reservation returns its expired challenge, and all 256 records survive wallet reopen. Reusing a valid test bundle for reservations is intentional; reservation does not reject previously imported bundles. [Log](evidence/audit-2026-10-24/probe-checkout-isolated.log).

**Impact:** a terminal eventually cannot begin any new purchase; network failure alone can consume capacity. This does not authorize a second goods release. Any remediation must preserve completed-purchase replay protection while retiring unusable pending challenges safely.

### F05 — P2 / confirmed: the cold authority cache expires without a productive renewal lifecycle

**Requirements:** Z08/Z11, G1/G4, E10; cold refresh on login/config/network lifecycle and periodic renewal outside checkout.

**Locations:** Proto `src/mesh.rs:68`, `:121` bounds view lifetime to <=60 seconds and rejects expiry. App `src/components/Login.tsx:112` starts a single background refresh; `SettingsView.tsx:167` provides a manual refresh. Backend `commands/settings_cmd.rs:34` clears the cache on every settings save, while the UI save path (`SettingsView.tsx:111`) schedules no replacement. `src-tauri/src/checkout.rs:64` returns cached views and Core correctly rechecks their expiry.

**Failure path:** after login/manual refresh, a terminal remains open beyond sixty seconds; its next purchase fails on stale authority. Saving configuration invalidates the cache without automatically repopulating it. Full frontend/backend caller search found no interval or lifecycle task renewing these views. Existing heartbeat intervals renew other state, not regional authority.

**Evidence:** source/caller inspection plus the checkout probe passing `now+61_000` into the actual Core entry point, which returns `untrusted or stale regional view`. This is a deterministic verifier-time probe, not a 61-second graphical-app endurance test. Owner/policy checks are present and fail closed; this finding is availability/integration, not acceptance of a stale roster.

### F06 — P2 / confirmed: terminal intent reconciliation is an orphaned manual command, with incomplete conflict and cleanup consumers

**Requirements:** Z08/Z10/Z13, E07/E09/E12; unresolved intents are revisited after thirty seconds without new bytes/T0, with terminal conflict/expiry and bounded retention.

**Locations:** App `src-tauri/src/commands/transfers.rs:847` registers `submit_l2_send_intent`; `:888` handles the thirty-second branch and `:903` tries a live proof. Frontend `src/services/transferService.ts:165` merely exports a wrapper. No frontend or backend scheduler calls that wrapper/command after the initial send, on login/restart, or when thirty seconds elapse. Core `src/app_service/l2_intents.rs:316` provides `record_intent_conflict`, but it has no productive consumer; at App `transfers.rs:895` mismatched retained evidence is only logged. Cleanup is called only immediately after successful live reconciliation (`:913`), with a sixty-second retention window; terminal/expired early-return branches do not invoke it.

**Failure path:** a normal send atomically creates an intent and makes its bounded initial HTTP attempt. A timeout leaves it pending, as required, but the normal product never initiates its later reconciliation. Even a direct manual invocation cannot terminally process contradictory retained choice through the unused conflict API; network unavailability or the unrenewed cold cache retains pending state. Expired or old terminal records can accumulate to Core's 256-intent bound (`wallet/l2_intents.rs:13`).

**Evidence:** exhaustive symbol/caller searches over App frontend/backend and Core, plus the passing Core terminal-reconciliation unit test. That unit test explicitly invokes cleanup at a later simulated time; the productive command does not. No graphical timed reconciliation reproduction was run. The missing callers are confirmed; no loss/reuse of an uncertain output was demonstrated. Retained originals correctly remain observations and do not count as a current quorum.

### F07 — P2 / confirmed evidence defect: required merge and composed fault acceptance is not green or complete

**Requirements:** Z07/Z08/Z12/Z13/Z14, E04/E07/E11/E13 and final-source acceptance.

**Locations:** Node `tests/sim_07_network_growth_and_merge_scenarios.rs:292`, `:478`, `:572`; `tests/adversarial_acceptance_tests.rs:471`; `scripts/architecture-e2e/main.rs:9`, `:31`; Core `src/storage/wallet_transaction.rs:749`.

**Observed results:** the three ignored merge tests were explicitly run and all failed, at lines 409, 531 and 643 respectively, before establishing their intended merge/reconciliation outcomes. Some fixtures manually make every shard ready (`sim_07...rs:188`); they are not automatic bootstrap evidence. These assertion failures are confirmed test failures, not a proven product consensus bug or an environment socket rejection. Their precise underlying causes remain unresolved.

The “repeated shutdown signals” adversarial test only cancels the same `CancellationToken` three times and drops storage. It does not deliver repeated OS signals to a daemon/CLI or stall fsync. A separate process test does demonstrate ordinary daemon exit and real DB reopen. The E2E harness calls App Rust modules directly, uses test utilities and prepared maturity/readiness, and does not execute React -> Tauri IPC. The wallet kill-cut tests exercise the generic transaction engine, not complete intent/send/purchase/release crash schedules. No RSS/slow-disk mixed-load measurement was performed.

**Impact:** the manifest's broad “verified” statements overstate the available oracles. A happy-path green run cannot certify all E01–E15 obligations. Detailed incomplete cases are identified below; this finding does not impose an architecture outside the approved plan.

## 2. Requirement and evidence matrices

Status vocabulary: **fulfilled**, **partially implemented**, **missing**, **not tested**, **conditionally fulfilled**. These correspond to the requested erfüllt / teilweise / fehlt / nicht geprüft / bedingt erfüllt. Conditional means an explicit accepted premise is required; it is not a failure merely because that premise exists. A package status covers its full acceptance definition, not just the existence of its main helper.

Source abbreviations used below: **N** `/home/basti/Coding/humoco/human-money-node`; **C** sibling `human-money-core`; **A** sibling `human-money-app`; **P** sibling `humoco-proto`. Paths and line numbers refer to the final audited source snapshots in §6. **STD**, **CORE**, **APP**, **PROTO**, **E2E** refer to actual commands in §3. **Q** = real QUIC integration with prepared premises; **U** = unit/in-memory; **PROC** = real child-process/CLI/storage lifecycle. None is silently upgraded to a full graphical production E2E result.

### 2.1 Z00–Z14

| Package | Concrete acceptance / production path and implementing locations | Existing and executed evidence | Status / remaining qualification |
| --- | --- | --- | --- |
| Z00 | Current graph, changes, contract ownership. N manifests and `scripts/run-architecture-e2e.sh:16`; A `src-tauri/src/lib.rs:143`; cargo metadata and file fingerprints. | New four-repository inventory, resolved host-platform metadata and source stability comparison. | Fulfilled for this audit snapshot. Historical manifest itself is contradictory and stale. |
| Z01 | Trusted purchase state, independent committee and challenge; no raw IPC flag release. C `app_service/conflicts.rs:454`, `:492`, `:543`; `checkout.rs:83`, `:193`; A `checkout.rs:81`; P `live.rs:88`. | CORE quorum/release negatives and purchase unit; APP backend; E2E positive atomic purchase and replay. | Partially implemented: F01 leaves a binding-signature bypass; full IPC/crash/replay matrix not executed. |
| Z02 | Each witness/signature/readiness transition uses the requested shard and committed state; no unready self. N `daemon.rs:1168`, `:1204`, `:1256`; `transport.rs:1578`, `:1632`. | STD `interview_recovery_membership_tests`, `phase5_pull_sync_and_readiness`, explicit bootstrap PROC. | Partially implemented: digest path repaired, but F01 bypasses the signature gates; turnover remains qualified. |
| Z03 | Verified support distinct from one own vote, persistent classes and class-first conflict handling. N `storage/engine.rs:1200`, `db/support.rs:27`, `db/install.rs:194`, `:221`; sim-core resolver. | STD support/durability/restart tests; native and HMC audit Q probes. | Partially implemented: F02 reproduces fresh-recipient downgrade. Comparator/unit results alone do not close G3. |
| Z04 | Safe omission quarantine, atomic commit/indexes and root-bound physical expiry. N `db/install.rs:115`, `:138`, `:175`; HMC prune/index code in `storage/engine.rs`; DB expiry. | STD omission rollback unit, support TTL/adversarial test, quarantine and expiry suites. | Partially implemented: local known support guarded, complete inherited/unknown-support/crash/pressure matrix unproved; F02. |
| Z05 | Compatible same-network originals before fraud sanctions; live reports are a distinct purpose. N `transport.rs:114`, `:387`, `:1771`; P original/live domains. | STD `cross_context_equivocation_tests` and `phase10_wire_level_tests`, including real wire framing/control cases. | Conditionally fulfilled for executed contexts; exhaustive network/class/purpose combinations not certified. |
| Z06 | Enforceable G1–G5, canonical signed bytes and loss gate. P `mesh.rs:109`, `live.rs:42`, `:109`, `causal.rs`; N `db/signing.rs:46`, `:180`; A cold authority; C policy. | PROTO/CORE/STD authority, checkpoint, root/causal vectors; audit probes. | Partially implemented: F01/F02/F03; G4 composition and all producers not closed. Accepted rollback/source premises retained. |
| Z07 | Fixed authenticated MVCC cut, bounded disk stage, one atomic durable install, exact RAM/readiness and no-gap fence. N `db/snapshot.rs:47`; `db/install.rs:29`, `:108`; `engine/recovery.rs:49`, `:92`; `daemon.rs:1156`. | STD cluster sync tests: fixed cursor Q, >10k rows, corrupt later page, freeze/release/cooldown, N=2 and prepared 14-source success. | Partially implemented: F02/F03; real crash/late worker/lease expiry/turnover schedules missing; three deep merge failures. |
| Z08 | Real send action -> atomic transfer+intent -> exact transport; receive action -> CSPRNG challenge -> exact proof -> atomic L1/purchase -> one release. A `transfers.rs:72`, `:94`, `:986`, `ReceiveView.tsx:263`, `ReceiveSuccessView.tsx:68`; C `transactions.rs:63`, `checkout.rs:83`, `:193`. | CORE exact intent/restart and purchase; APP frontend/backend; E2E actual HTTP+QUIC modules. | Partially implemented: F04–F06, no actual graphical IPC/fault acceptance. Offline import API remains present. |
| Z09 | Unchanged SST, signed causal output/path, independent split branches, durable prefix and receiving-shard original T0. N `engine.rs:1610`, `:1631`, `:1777`, `:1792`; `api/hmc.rs:453`; C `services/l2_causality.rs:17`, `:68`; P `causal.rs`. | STD seven `chain_causality_and_prefix_tests` (HTTP/Q plus engine/split tests), wallet freshness and root tests; CORE real split; E2E. | Conditionally fulfilled for tested paths; physical-clock/reentry composition, all oversized/storage-fault combinations and SLA remain unproved. |
| Z10 | Bounded exact retained original retrieval and safe terminal client consumption after 30s. N `api/routes.rs:2988` registered `get_retained_choice`; C `l2_intents.rs:66`, `:77`, `:164`, `:239`; A `transfers.rs:888`, gateway `fetch_retained:205`. | STD `retained_choice_tests` genuine signature/quota; CORE original-observation and terminal unit test. | Partially implemented: F06. Independent current quorum is correctly distinguished; real after-restart scheduled consumer missing. |
| Z11 | Authenticated passive advertisements, explicit HTTP directory, bounded client fallback, origin credentials, cold authority lifecycle. N `network/discovery.rs`, manager advertisement methods; A `gateway_resolver.rs:43`, `:258`, `:282`; `checkout.rs:49`. | STD passive advertisement Q and token/redirect adversarial tests; APP transport tests. | Partially implemented: F05; wrong-owner/network-change races not composed end to end. Tokens use matching origin and redirects are disabled. |
| Z12 | Separate bounded public/shard/sync work, reservation before allocation, 64KiB preallocation rejection and protected progress. N `network/framing.rs` read_frame; `transport.rs:2008`, `:2109`; `daemon.rs:54`, `:1238`; engine queue `:688`. | STD header-only oversized Q, stalled-32-sync Q with reserved status progress, pool/quotas and staging tests. | Partially implemented: no process-RSS/disk/work ceiling or actual mixed public+RPC+sync slow-storage measurement; F01 and F07. |
| Z13 | Fixed shutdown deadline, real process and redb release, private diagnostics, bounded metadata/history/backups. N `daemon.rs:303`, `cli.rs:2122`, `:2207`; DB signing/root/support and operator router. | STD real process shutdown/DB reopen, CLI lock probe unit, private HTTP boundaries/history/backup/TTL. CORE transaction crash tests. | Partially implemented: F04/F06 lifecycle gaps, repeated-signal/stalled-I/O/restore composition untested; F07. |
| Z14 | Independent all-package final-source acceptance and honest evidence. This report; scripts/main harness. | All mandatory checks attempted/executed; failures, skips, probes and source graph recorded. | Partially implemented as architecture acceptance: this audit is delivered but cannot close the remaining product gates. No commit/delivery implementation was authorized here. |

### 2.2 Guarantees G1–G5

| Guarantee | Actual mechanism, authority and test | Status |
| --- | --- | --- |
| G1 regional authority | Recipient-owned persisted policy -> every pinned source's signed, fresh view -> equal ordered HRW top20 -> distinct 14 signatures. P `mesh.rs:109`; C `checkout.rs:147`, `:225`; N operator export; A `checkout.rs:49`. Wrong key/expiry/missing/disagreeing view tests run. Source truth, conditional <=6 faulty committee members and configured regional scope remain assumptions. | Conditionally fulfilled cryptographic boundary; lifecycle partially implemented (F05). No global membership proof or hot-path multi-gateway round is demanded. |
| G2 completeness/readiness | Explicit new-region one-shot bootstrap, normal boot unready, qualified remote-only cut quorum, fenced writes -> immediate install -> RAM -> digest -> ready (`daemon.rs:1168`–`:1266`). Bootstrap/restart Q/PROC and bounded snapshot Q tests run. | Partially implemented: F01 gate bypass; F03 positive distributed-support/full-turnover gap. N=2 refusal is correct containment, not proof of general progress. |
| G3 support/merge | Verified compact support and class precedence, local omission protection, exact original choice separate from current state. `db/support.rs:27`, `db/install.rs:138`, `:221`; resolver. | Partially implemented: F02 downgrade reproduced for genuinely admitted HMC support; broad merge compositions remain unproved. |
| G4 time/reentry | Signed wallet T0 checked at admission; historical path only with whole-path crypto; P2pClock, passive presence, monotonic lease/shutdown timers, immutable root TTL. `engine.rs:1777`, manager `:29`, `:226`; source views <=60s. | Conditionally fulfilled for tested freshness/root cases; not fully tested across clock jumps, persistent reentry, bucket/seal and ticket renewal. F05 shows consumer renewal gap, not an invalid-time acceptance. |
| G5 detectable local history inconsistency | Immediate choice+generation/XOR commitment, startup stream validation, own signed checkpoint comparison and persistent local latch (`db/signing.rs:46`, `:180`; `transport.rs:1841`). Intact reopen/retry/backup/deleted-row and forged/foreign/wrong-network/newer-checkpoint real Q tests run. | Partially implemented across all signing producers: normal paths gate correctly but F01 signs with unhealthy gate. Complete consistent offline-directory rollback without independent evidence remains expressly excluded, not a missing feature. Raw disk truncation/power-loss cases not demonstrated here. |

### 2.3 E01–E15 operational evidence

| Evidence | Required oracle / actual production owners | Executed result and evidence quality | Status |
| --- | --- | --- | --- |
| E01 | Trusted authority/challenge, arbitrary roster/nonce cannot release; real 14 only after purchase. Z01/Z08; C conflicts/checkout, P live/mesh, A checkout. | CORE/PROTO negatives; E2E positive at `main.rs:69` onward. Backend-module integration, not graphical IPC. | Partially implemented / tested. |
| E02 | Real L1/split required; purchase replay survives restart with no second import/release. C checkout, A checkout/Receive. | E2E same-ID replay and persisted purchase; CORE wrong bundle/proof tests; audit capacity/expiry probe. | Partially implemented: F04; no UI-actuator crash/restart test. |
| E03 | Ready shard witness with other shards unready, exact current assignment, no unready self. N daemon/transport. | STD real Q tests and bootstrap PROC pass. Audit StatusQuery bypass passes its defect oracle. | Partially implemented: F01; arbitrary turnover not covered. |
| E04 | Empty/partial/distributed 8+6+6/full turnover/cut/delta/crash, with autonomous positive recovery. N sync/install/readiness. | Prepared sources' Q recovery passes; no peerless/N=2 fallback; three ignored merge tests explicitly fail. Misnamed 8+6+6 manually reunites equal data. | Partially implemented: F03/F07; full turnover not tested. |
| E05 | One own vote not class2, verified support survives restart and fresh import, omission preserves stronger/unknown. N support/install/resolver. | STD local support/restart/omission passes; genuine HMC fresh-island inheritance Q probe fails required preservation. | Partially implemented: F02. |
| E06 | Real cross-context framing cannot sanction; genuine protected incompatible originals do. N fraud receiving paths. | STD cross-context/phase10 Q negatives and positives pass. | Conditionally fulfilled for executed cases; exhaustive testnet/class/live matrix not established. |
| E07 | Exact durable intent precedes send, same bytes/T0 after restart, no automatic replacement; crash schedule. C transactional sender -> A dispatch. | CORE intent/restart plus E2E production-module send pass; generic wallet kill cuts pass in CORE. Full actual-intent crash cuts absent. | Partially implemented: F06 and composed crash evidence gap. |
| E08 | HTTP/Q causal ownership/split/prefix and stale signed T0 under fresh envelope. N engine/routes/transport, C sidecars. | STD chain/freshness tests and CORE split/real L1 E2E pass. Some split/math cases are U; storage failure/clock composition not exhaustive. | Conditionally fulfilled scoped evidence. |
| E09 | Actual client verifies exact retained original; bounded read/quota/deadline; current live proof independent of retired originals. N retained route (`api/routes.rs:2988`) -> C observation/reconciliation -> A command. | STD retained HTTP cryptographic/quota tests and CORE observation U pass. No scheduled production consumer after 30s. | Partially implemented: F06. |
| E10 | Passive authentic publication, client cache lifecycle/revocation/redirect/token isolation. N discovery -> A resolver/authority. | STD passive Q and adversarial transport; APP resolver tests pass. Cold-cache renewal and config lifecycle incomplete. | Partially implemented: F05. |
| E11 | Aggregate bytes/work/staging bounds and internal progress under declared mixed load/slow disk. N framing/transport/worker/install. | Header-only real Q rejects >64KiB; 32-sync stall allows status; >10k native rows stage to disk. No RSS, disk ceiling or genuine mixed persistence load measurement. | Partially implemented; measurements not tested. |
| E12 | All metadata/index/quarantine expire; backup/restore/crash replacement. N prune/root/support, C intents/purchases. | STD support/class/quarantine/root TTL/backup and CORE transaction recovery pass. Audit shows purchase retention defect; intent cleanup consumer missing. | Partially implemented: F04/F06; exhaustive per-store expiry/restore not tested. |
| E13 | Real repeated signals, early unlink, stall/error, actual CLI/process/DB release before success. N daemon/CLI/control. | Ordinary real process exit/reopen and CLI DB-lock probe pass; token-cancel-three-times test is narrower than OS signal acceptance. | Partially implemented; repeated real signal/stalled-I/O schedule not tested. |
| E14 | Every private alias/listener/Host/Origin boundary, legitimate public ingress. N public/operator routers/config/history. | STD `current_proof_boundaries_tests`, operator lifecycle, regional export and public API suites pass. | Conditionally fulfilled for local tested listeners; SSH/proxy deployments and every production configuration not tested. |
| E15 | Detectable own history loss vs intact crash with independent evidence, every signing route closed. N signing journal/checkpoints/engine/transport. | STD signing-history Q/deleted-row/reopen/backup pass. StatusQuery defect reproduced. Complete consistent rollback excluded by design. | Partially implemented: F01. |

### 2.4 Explicit requested boundary checklist (A–E)

This checklist prevents package-level wording from hiding individual untested cases. References above supply exact tests and source locations; additional locations below identify the relevant subpath.

| Requested requirement | Productive mapping / tested boundary | Assessment |
| --- | --- | --- |
| A: fixed cut and cursor without offset races | N `db/snapshot.rs:47`, fixed read transaction/owner/filter/cursor; `cluster_sync_recovery_tests:15` concurrent insert/delete Q. | Conditionally fulfilled. |
| A: bounded jobs, pages, reservations before buffers | N `daemon.rs:54`, `:1226`, `:1238`; `db/install.rs:29`; 32 slots and 500-page limits inspected/tested. | Partially implemented: no aggregate process-memory/disk/work measurement. 10,000 is an in-flight entry permit pool, not a maximum shard size. |
| A: atomic roots/locks/quarantine/indices/support installation | N `db/install.rs:108`–`:230`, one immediate transaction; rollback omission unit, >10k Q installation. | Conditionally fulfilled atomic DB transaction; crash at each publication cut not tested. |
| A: durable commit + consistent RAM before readiness | N `engine/recovery.rs:102`, `daemon.rs:1259`–`:1266`. | Partially tested; new live path guards exact durable RAM; F01 bypasses gates. |
| A: no source-to-ready gap | N source close/fence, remote lease, pre/post committee/digest checks. | Partially implemented/tested; exact lease-expiry/process-cut/delayed worker composition not tested. |
| A: lease/committee change/cancel/crash/late worker | N `engine/recovery.rs:18`, `:49`; task tracker; daemon deadline rechecks. | Cancellation guard inspected; complete real crash/late-worker/expiry schedule not tested. Ordinary rejected install conservatively latches global signing failure; no availability proof asserted. |
| A: authenticated freeze abuse and other shards | Q freeze blocks same-shard engine ingress and permits another shard; cooldown test waits 2.1s. | Partial. Repeated 25s freezes separated by 2s are possible; no sustained checkout-service guarantee measured. |
| A: no unjustified import class | Whole cut current witness count used; incoming historical signers cleared. | Partial: data existence quorum is implemented; full G3 transfer semantics fail F02 and distributed evidence remains open. |
| A: no confirmed loss/downgrade on restart/merge | Local reopen tests pass; fresh-recipient HMC Q audit loses class. | Not fulfilled in full: F02. |
| A: small networks/turnover/asymmetric partitions | Explicit N=2 refusal, ready-source fixtures, three deep merge attempts. | Partial: F03/F07; repeated full turnover not tested. |
| B: cryptographic predecessor/output binding, unchanged SST | N `engine.rs:1631`, C causal proof and `crypto/utils.rs:225`; P causal digest. | Conditionally fulfilled tested format/path; no L1 serialization migration introduced. |
| B: genesis is root-only and no self-collision | N `db/roots.rs:5`, `:9`, engine root branch; root tests/E2E actual first spend. | Fulfilled for exercised new-root paths; legacy migration exhaustive crash matrix not tested. |
| B: independent receiver/change | Core real split and N chain tests at `:328`, `:577`. | Conditionally fulfilled. |
| B: valid durable prefix on bad suffix | N per-hop loop `engine.rs:1792`; HTTP `chain...tests:139`, Q `:217`, reopen assertion. | Fulfilled for executed bad-signature/causal/future cases; all storage fault cuts not tested. |
| B: signed T0 checked at receiving shard | N LockVerify -> chain ingress; stale-envelope real Q and HTTP freshness tests. | Conditionally fulfilled, no regenerated T0 observed. |
| B: historical predecessors cannot legalize stale/invalid terminal | `historical_prefix` requires whole-chain crypto and fresh terminal (`engine.rs:1777`); per-hop terminal freshness still runs. | Conditionally fulfilled tested stale/future/invalid contexts. |
| B: immutable root TTL and all-store purge | N roots deed comparison `roots.rs:75`, support TTL tests. | Partially tested. No complete new-store pressure/expiry inventory execution; client purchase lifecycle F04 separate. |
| C: exact signed bytes/outputs/T0 before HTTP; transfer+intent atomic | C `wallet/l2_intents.rs:7`, `app_service/transactions.rs:81`; A `transfers.rs:72`–`:94`. | Conditionally fulfilled on actual module E2E/reopen; intent-specific process kills not tested. |
| C: uncertain outcome cannot reissue, retry same bytes | C pending input check `wallet/transactions.rs:989`; A dispatch exact body. | Scoped tests pass; F06 progress/cleanup missing. No observed automatic replacement. |
| C: challenge from CSPRNG bound to purchase/receive | C `checkout.rs:155`, stored bundle hash/network/root/target/nonce. | Fulfilled scoped CSPRNG and exact-context tests; challenge lifecycle F04. |
| C: local top20, >=14 distinct correct members | P `mesh.rs:109`, `live.rs:88`; C purchase uses policy, not payment roster. | Conditionally fulfilled under G1 source/fault assumptions. |
| C: authenticated consistent fresh regional views | P signatures and per-source exact committee agreement; actual operator source in E2E. | Security checks fulfilled scoped; product refresh F05. |
| C: atomic L1 import/challenge use/purchase | C `checkout.rs:209`–`:266` managed transaction. | Conditionally fulfilled functional/reopen; exact purchase fsync uncertainty cuts not tested. |
| C: release after verified durable commit, no repeated release | Backend returns after managed commit; A ReceiveSuccess excludes `newlyCommitted=false`. | Conditionally fulfilled module E2E/same purchase. No physical actuator attached; UI replay-IPC crash test missing. |
| C: actual frontend/Tauri/Core path | React `ReceiveView.tsx:263` -> service `:157` -> registered IPC `lib.rs:143` -> checkout. Send similarly connected. | Productive source wiring exists. APP tests mock services; actual graphical IPC path not executed by E2E. |
| C: cache/profile/network lifecycle | owner/policy rechecked after async fetch; settings save clears; login one refresh. | Partial: F05; switch races not tested. |
| C: offline L1 survives | C offline create/receive APIs and App ordinary receive branch exist; offline tests in CORE/APP pass. | Conditional. App exclusive-custom mode with zero configured candidates refuses send (`transfers.rs:28`), and sends always create bounded intents. Unlimited long-running offline App operation not certified (F06). |
| D: thirty-second retained-choice continuation | C threshold+observation and App manual command exist. | Partially implemented: no normal scheduled caller, F06. |
| D: originals distinct from live quorum | C observation verifies genuine original but does not clear; live context has separate purpose. | Fulfilled for inspected recipient/intents; F01 still mints originals improperly. |
| D: terminal conflict/expiry/cleanup | C APIs `l2_intents.rs:239`, `:316`, `:349`, `:375`. | Partial; conflict API unused; mismatch logged; delayed cleanup caller absent. |
| D: no fresh bytes/T0 to evade uncertainty | stored immutable request/transaction/chain, exact transport. | Conditionally fulfilled inspected/tested retries; scheduling missing. |
| E: passive authenticated gateway discovery | existing heartbeat extension -> manager verify -> directory -> A resolver. | Conditionally fulfilled real Q advertisement and HTTP client tests. |
| E: origin-bound tokens including redirect/failover | A `gateway_resolver.rs:43` matches origin; redirect none. | Fulfilled for executed real HTTP positive/negative cases; no cross-origin token transmission observed. |
| E: separate ingress/RPC/sync resources | separate stream semaphores, public ingress admission; shared bounded persistence queue. | Partially demonstrated, not a slow-storage mixed-load guarantee. |
| E: reject >64KiB before matching allocation | framing header check, actual Q header-only regression; also Cursor U test. | Fulfilled for exercised QUIC receive path. |
| E: real QUIC protection tests | STD actual framing/auth/quota/pool/fraud/ready/sync suites. | Many executed; complete invariant registry's full wire matrix not certified. |
| E: fixed deadline despite repeated signals | daemon owns one deadline; three token cancellations are not three OS signals. | Source inspected, ordinary stop tested; repeated-signal/stalled-fsync combination not tested. |
| E: CLI success after actual redb release | `cli.rs:2207` opens actual database with same deadline; process exits/reopen test. | Conditionally fulfilled tests; kernel-I/O deadline extremes unproved. |
| E: corruption/truncation/contradictory self evidence closes signing | generation integrity and real own-checkpoint Q tests. | Partial across all producers, F01. Raw redb file truncation and all first-party-original self-evidence variants not tested. Consistent offline rollback remains excluded. |

## 3. Executed commands and results

All command logs, including failures, are saved in [the evidence directory](evidence/audit-2026-10-24/). No test was edited to pass. Initial commands ran concurrently across independent repositories; elapsed times under that offered load are not production SLA measurements. Build cache locking/CPU/I/O contention is relevant to the first E2E failure.

| Working directory / command | Result | Artifact / limitation |
| --- | --- | --- |
| N `cargo test-std` (initial sandbox) | Exit 101; node lib 143 pass / 3 socket failures, further targets not run. | `node-test-std.log`; EPERM bind restrictions, environmental. |
| C `cargo nextest run --status-level fail` (initial sandbox) | Exit 101 opening read-only sibling target lock. | `core-nextest.log`; environmental. |
| A `./run-tests.sh --quiet` (initial sandbox) | Exit 1 at Vitest configuration startup: EROFS writing its generated configuration module; backend steps not reached. | `app-tests.log`; environmental. |
| P `cargo test --offline` (initial sandbox) | Exit 101 opening read-only sibling target lock. | `proto-tests.log`; environmental. |
| N `cargo test-std --offline --no-fail-fast` (socket-enabled) | **Exit 0; 664 passed, 0 failed, 14 ignored**, across 90 target summaries including zero-test/doc targets. | `node-test-std-sockets.log`; no RUST_TEST_THREADS override was added. |
| N `cargo clippy --offline --workspace --all-targets -- -D warnings` | Exit 0. | `node-clippy.log`. |
| C `cargo nextest run --offline --status-level fail` | **Exit 0; 825 passed, 7 skipped**, 26 binaries. | `core-nextest-enabled.log`; Nextest summary, generic managed-wallet child-process kill tests included. |
| C `cargo clippy --offline --all-targets -- -D warnings` | Exit 0. | `core-clippy.log`. |
| C `cargo test --offline --doc` | Exit 0; 4 passed. | `core-doc.log`. |
| A `./run-tests.sh --quiet` (cache/socket-enabled) | Exit 0; **184 frontend tests, 23 files passed**. Version sync, both TypeScript configurations, ESLint, i18n, backend Clippy and backend Cargo tests run by script. | `app-tests-enabled.log`. Script hides successful backend detail/counts; frontend warnings are printed. No actual browser/Tauri automation. |
| P `cargo test --offline` (cache-enabled) | Exit 0; 17 passed, no doctests. | `proto-tests-enabled.log`. No AGENTS.md/README/CI-specific additional protocol instructions were found in this repository. |
| P `cargo clippy --offline --all-targets -- -D warnings` | Exit 0. | `proto-clippy.log`. |
| N `scripts/run-architecture-e2e.sh`, first run | Exit 101, no transport response within dispatch budget; harness assertion at generated `src/main.rs:69`. | `architecture-e2e.log`; overlapped other suites. This alone is not attributed to a product defect. |
| Same script, isolated repetition after full suites | **Exit 0**, real module transport -> Core intent -> HTTP -> real QUIC -> atomic purchase -> idempotent restart. | `architecture-e2e-isolated.log`; 53 harness unused-code/import warnings, prepared maturity/readiness, no IPC/GUI. Failure under contention remains recorded. |
| N `cargo test --offline -p humoco-node --test sim_07_network_growth_and_merge_scenarios -- --ignored` | **Exit 101; 0 passed, 3 failed**. | `deep-merge.log`; genuine assertions, not socket restrictions. Entire `cargo test-deep` was not run. |
| `bash .../probe-status-signing.sh` | Exit 0; confirms F01 defect oracle over real Q and verifies signature independently. | `probe-status-signing.log`. |
| `bash .../probe-inheritance.sh` | Exit 0; confirms native F02 downgrade with prepared FINAL source records. | `probe-inheritance.log`. |
| `bash .../probe-hmc-inheritance.sh` final run | Exit 0; confirms HMC F02 downgrade after real 14-witness support admission. | `probe-hmc-inheritance-final.log`. Two earlier harness compile attempts lacked direct dependencies/import path; `probe-hmc-inheritance.log` and `...-fixed.log` retain those audit-harness errors. Only temporary harness dependencies/imports were corrected. |
| `bash .../probe-checkout.sh` first run | Exit 101 at the original transport budget, before audit probes. | `probe-checkout.log`. |
| Same probe, isolated | Exit 0; original E2E plus stale-view, 256-capacity, expired-challenge and persisted-reservation checks. | `probe-checkout-isolated.log`; supplied verifier times, no wall-clock UI endurance claim. |
| `cargo metadata --offline --format-version 1` in N/C/A | Node resolved; initial unfiltered Core/App attempts encountered unavailable/read-only foreign-platform crate extraction. | Repeated with `--filter-platform x86_64-unknown-linux-gnu` for Core/App: exit 0. Captured exact local packages/features in `*-dependencies.json`. No dependency update requested or performed. |
| `git status`, branch/HEAD/log, per-file SHA-256 capture and final comparison; `rustc --version`, `cargo --version`, `uname -srmo`; repository-wide `rg`/source reads | Completed. | `repository-summary.json`, compressed full `source-inventory.json.gz`, §6. |

### Skips and test-quality limits

Node STD ignores fourteen long-running simulations: the six `sim_01`–`sim_06` scenarios, three `sim_07` cases, and five `realistic_protocol_simulation_tests` cases. The three sim_07 cases were separately run and failed; the other eleven ignored scenarios were not executed. No ignored result is counted as passed.

Core's seven skips are `security_audit_module_02_crypto.rs:493` and `:975` (pending architecture/protocol decisions), `security_audit_wave4_cel.rs:450` and `:500` (host TOFU store), `services/flexible_encryption.rs:18`, and `core_logic/wot_conformance.rs:18` and `:135` (external specification checkout). These are not all L2 defects; they still limit a blanket “all tests” claim.

The principal prepared premises are `tests/common/recovery.rs:38`–`:43` (direct trust and 25-hour observation injection), source `mark_shard_ready` calls, `set_ge20_anchor_for_test`, and E2E `main.rs:31`. The E2E explicitly documents them. This audit uses those fixtures only to inspect behavior given qualified sources, never as proof of autonomous admission or actual 24-hour observation. The new HMC audit probe obtains its class-2 facts through the real recovery consumer; it does not establish the regional Byzantine bound.

`adversarial_acceptance_tests.rs:340` uses a memory Cursor for one oversized frame test; a separate cluster test sends only the oversized header over real QUIC and therefore supplies the required wire rejection evidence. The stalled-sync test uses a `HoldSync` request handler and demonstrates stream admission isolation, not protected disk commit latency. TTL support tests create prepared records/certificates; they do not cover every store or process cut. ReceiveSuccess frontend tests pass prepared verdict DTOs; no new PoS invocation/replay assertion appears in ReceiveView tests. No payload-byte, queue-count or CPU timing assertion was interpreted as an RSS or fsync bound.

## 4. Differences between documentation and current production code

All eight user-named baseline documents exist at the requested paths. No missing/renamed document was silently substituted. Additional governing sources inspected include root AGENTS.md in Node/Core/App, the glossary, G1–G5 contract, relevant package definitions, protocol source and test instructions. No nested AGENTS.md was found under the affected source repositories; Proto has none. The parent directories had no additional AGENTS.md in the checked ancestry.

The 2026-10-23 handoff is historical and was treated accordingly. Since that checkpoint, disk staging, source fences/cooldown, atomic installation, expanded causal HTTP tests, actual merchant receive wiring and terminal-reconciliation APIs have been committed. They were reviewed as current code, not assumed missing because the handoff said “remaining”.

The current completion manifest nevertheless contradicts itself. Its package table claims Z03 native/import class verification, Z04 asymmetric 8+6+6 recovery, Z07 recovery verification, Z10 a complete terminal lifecycle and Z13 triple-signal verification. Later G/E rows and its closing paragraphs still list open support/recovery/refresh/acceptance work. The new F01/F02 probes and F04/F06 caller inspection contradict broad completion of those rows. The 8+6+6 test's real group sizes/manual state copying and the token-only shutdown test do not establish the table's stronger claims.

The root/causality and G1/G5 contracts also contain stale “UI/disk staging not implemented” or “automatic release disabled” descriptions; current code has those mechanisms and productive module release. Conversely, those additions do not close the lifecycle/fault matrix. The main execution-progress document ends with an earlier 643-pass / Core lint-failure increment and does not certify the current 664-pass / clean-lint snapshot. Historical completion or pending wording is not used as the present verdict.

The older G2 prose's “1 MiB page” differs from the implemented 48KiB snapshot byte budget / 64KiB framing ceiling; the implemented stricter bound is not a product failure. The 10,000-entry semaphore controls concurrent page reservations, while disk-backed cuts can exceed 10,000 rows (the 10,050 native-row test does so); it is not a total database/staging-disk ceiling. No process-memory or arbitrary-large-shard completion SLA is inferred from those constants.

The final externally created Node commit changes heartbeat jitter to 55–65 minutes and presence freshness to 195 minutes. Its tests were included in the socket-enabled STD pass. That is an explicit current implementation detail, not an epoch/committee tenure or a 24-hour liveness delay. No new architecture was inferred from the wording “three missed hourly heartbeats”.

## 5. Remaining work, in practical order

1. Close every binding producer under the same exact durable/original-choice/health/readiness rules, beginning with F01's reachable StatusQuery branch. Add a real-QUIC regression for absent disk choice, pending state, unhealthy history, unready shard, wrong committee and canonical replacement. Preserve cheap diagnostic status and distinguish original/live purposes.
2. Correct support inheritance for fresh recipients (F02) within the approved compact-support architecture. Exercise real admitted class-2 sources -> fresh island target -> restart -> competing-class merge for native and HMC, without importing historical quorum chains or trusting an unauthenticated class integer.
3. Finish the selected G2/G3 recovery acceptance for genuinely distributed support, omission coverage, assignment change and repeated turnover. Replace the misleading 8/7/5/manual-copy acceptance claim with the actual selected scenario and demonstrate positive progress under justified premises. Preserve explicit operator bootstrap and N=2 containment.
4. Complete recipient lifecycle: pending challenge expiry/retry and bounded retirement, while preserving durable completed-purchase replay protection (F04); then cold-cache periodic/lifecycle renewal with owner/network cancellation and visible failure (F05). Keep renewal outside the checkout hot path.
5. Connect normal send/restart lifecycle to retained-choice plus current-quorum reconciliation after thirty seconds, including conflict/expiry and later bounded cleanup (F06). Reuse exact original signed bytes/T0. Do not turn a single original, 404 or a mismatch into spend clearance or automatic replacement.
6. Diagnose the three failing deep merge tests without weakening quorum/readiness requirements. Execute real intent/send/response/purchase/commit-uncertainty crash cuts through the actual IPC/frontend path, repeated real shutdown signals with stalled/error I/O, and mixed public/shard/sync pressure with measured bytes/RSS/work/disk/latency. No blanket SLA is established by the current runs.
7. Reconcile the dated manifests/contracts with actual callers, retest the final dependency graph after repairs, and rerun independent E01–E15 acceptance. Dependency release/pinning and any commits are future work outside this audit's authorization.

## 6. Audited repositories, dependency graph and boundaries

### Revisions and changes

| Repository / absolute path | Branch | Full audited HEAD | Working state at source-hash capture |
| --- | --- | --- | --- |
| `/home/basti/Coding/humoco/human-money-node` | `dev` | `c6813ee2d9d9b0a3c99dee08729423a4919176c6` | Tracked tree clean. Only this report/evidence were added afterward. |
| `/home/basti/Coding/humoco/human-money-core` | `live` | `a5709b0f9df0e40121faa1bd122238bd7bb3dc59` | No tracked modifications. Existing untracked `fuzz/corpus/`, `fuzz/target/`, `tools/simulations/offline-gossip/__pycache__/`; not touched or compiled as product source. |
| `/home/basti/Coding/humoco/human-money-app` | `dev` | `1b32ff7deaebe901cb8d522a447bceaa39ef7dc6` | Tracked/untracked product tree clean; ignored local Cargo overrides inspected. |
| `/home/basti/Coding/humoco/humoco-proto` | `dev` | `3fc5dd87c82b91e7b682eabcf88e5b5ce23e7c32` | Clean. This is the actual dependency; other sibling directories were not assumed to be the protocol. |

At initial inventory Node HEAD was `987b0f10f199708f391d4e1656a99c8434967536`, with modifications in `network/manager.rs`, `network/mod.rs`, `tests/audit_hardening_tests.rs` and `tests/interview_recovery_membership_tests.rs`. During document inspection an external actor committed them as `c6813ee...`. This audit did not create that commit or discard those edits. The final authoritative source capture followed that change and preceded all successful acceptance results. The initial restricted sandbox test is not used to certify the initial dirty source tree.

The full compressed [inventory](evidence/audit-2026-10-24/source-inventory.json.gz) contains per-tracked-file SHA-256, exact untracked path listings, branch/HEAD/status and ignored Cargo configuration contents. [Summary](evidence/audit-2026-10-24/repository-summary.json) records no tracked source change between capture and the post-test comparison. The saved `final-source-verification.json` repeats that comparison after report generation; report/evidence are the only audit-owned additions. Any later external edit invalidates source-specific conclusions for that edit.

### Actually resolved dependencies

Node resolves `humoco-node 0.1.3` -> local `humoco-sim-core 0.1.3`, sibling `humoco-proto 0.1.0`, and local `crates/clap_complete`. Core `human_money_core 0.4.1` also resolves sibling Proto. The App manifest declares Git `human-money-core`, branch `master`, but both ignored `.cargo/config.toml` and `src-tauri/.cargo/config.toml` patch that URL to the sibling Core. Host-platform Cargo metadata confirms the App/Core/Proto packages have **no Git source** in this tested graph. [Node graph](evidence/audit-2026-10-24/node-dependencies.json), [Core graph](evidence/audit-2026-10-24/core-dependencies.json), [App graph](evidence/audit-2026-10-24/app-dependencies.json) include actual dependency declarations, manifests, selected IDs and features; manifest/lockfile hashes are in the inventory.

The architecture harness generates a temporary crate using absolute path dependencies and compiles the production App `settings`, `models`, `state`, `gateway_resolver` and `checkout` modules. It uses Core `test-utils` in a debug acceptance build. It does not run a Tauri window, the registered commands, or the React UI; no production release with test utilities is certified. No release-manifest patch, dependency update, push or published CI build was performed.

### Accepted decisions retained and audit limits

The inspected L1 SST function remains Base58(SHA3-256(length-prefixed previous canonical transaction hash, sender ephemeral public key)); it is not Base58(previous transaction ID). Core's `services/crypto/utils.rs:225` and Node's causal check agree. Separate versioned author-signed `CausalOutputProof` carries L2 output/root metadata. Real split/E2E tests exercised existing L1 transactions without a serialization/signature format change. Genesis stays in `voucher_roots`, never a newly created spend/original vote. Legacy migrations and old unsigned sidecars remain qualified.

Explicit authenticated recipient-selected regional sources and their documented fault assumptions are accepted. No source signatures are claimed to prove source honesty or global membership. Explicit operator-only new-network bootstrap is accepted; ordinary joins/restarts stay unready. A complete internally consistent offline directory rollback without independent contradictory evidence is outside G5's local promise and is **not** a finding. No TPM, notary, additional pre-signing network call, lock-gossip stream, archived historical quorum chain or hearsay ban is proposed.

The tests ran on Linux x86_64 (`Linux 7.0.0-38-generic`), Rust `1.94.1 (e408947bf 2026-03-25)`, Cargo `1.94.1 (29ea6fb6a 2026-03-24)`, with current local sibling dependencies and immediate redb durability on inspected binding paths. The audit does not certify Windows/macOS/WASM, a published dependency graph, real-world power loss/storage firmware behavior, global Byzantine bounds, operational regional-source correctness, every numbered invariant's exhaustive workload matrix, or an external physical goods actuator. No <1µs RAM, <20ms durable, <1ms verification or universal 800ms service claim is made from these runs.

The conclusion is therefore partial implementation with confirmed defects and explicitly bounded evidence, rather than “everything finished” or a rejection of the approved architecture.
