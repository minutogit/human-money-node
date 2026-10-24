# Architecture audit remediation progress — 2026-10-24

## Current scope and verdict

R01/F01 and R02/F02 are closed. The inherited-support contract remains conditional on the documented current-region honest-quorum premise. R03–R08 and F03–F07 remain open. No global architecture-completion claim follows.

## Historical R01 increment scope and verdict

This increment executes **R00 for F01 and R01 only**, authorized by the maintainer's request to start the first part in a subagent. It does not close the architecture audit. Product source in Core, App and Proto is unchanged; no commits, resets, pushes or deployment were performed. Historical audit evidence is preserved.

| Package / finding | Status | Ownership and evidence |
| --- | --- | --- |
| R00 scoped baseline/F01 | Completed | Four current branch/HEAD/status inventories and host-resolved graphs; independently reproduced F01 over authenticated real QUIC before modification. Full R00 reproduction of other findings is deferred with their packages. |
| R01 / F01 | Completed for this increment; F01 closed by maintained boundary regressions | Z01/Z02/Z03/Z06/Z12; E03/E07/E15. New maintained real-QUIC negatives plus positive diagnostics/current-proof tests; see below. |
| R02 / F02 | Completed; F02 closed by maintained boundary regressions | Z03/Z04/Z06/Z07; G3/E05. Fresh recipient native and HMC tests prove preservation of class 2, negative tests prove no raw status promotion, 5/5 boundary tests passed, full suite passed (674 passed, 0 failed, 14 ignored), historical defect probe fails on assertion (installed == 2 != 1). |
| R03 / F03 | Not started | Distributed support/coverage and positive recovery remain open. |
| R04 / F04 | Not started | Recipient attempt lifecycle/capacity remains open. |
| R05 / F05 | Not started | Cold authority renewal remains open. |
| R06 / F06 | Not started | Automatic reconciliation remains open. |
| R07 / F07 | Not started | Full fault/resource/IPC acceptance remains open. |
| R08 | Not started | Global final acceptance remains open; this increment runs its applicable Node checks. |

## Exact source baseline and resolved graph

| Repository | Branch | Full HEAD |
| --- | --- | --- |
| `/home/basti/Coding/humoco/human-money-node` | `dev` | `c6813ee2d9d9b0a3c99dee08729423a4919176c6` |
| `/home/basti/Coding/humoco/human-money-core` | `live` | `a5709b0f9df0e40121faa1bd122238bd7bb3dc59` |
| `/home/basti/Coding/humoco/human-money-app` | `dev` | `1b32ff7deaebe901cb8d522a447bceaa39ef7dc6` |
| `/home/basti/Coding/humoco/humoco-proto` | `dev` | `3fc5dd87c82b91e7b682eabcf88e5b5ce23e7c32` |

[Baseline inventory](evidence/remediation-r01-2026-10-24/baseline.json) records exact tracked SHA-256, all dirty/untracked paths and local Cargo configurations. Existing Node audit/handoff files and evidence were untracked; Core's unrelated fuzz corpus/build artifacts and Python caches remain untouched. App/Proto had no changes. All four host-filtered offline/locked metadata runs succeeded; [resolved summary](evidence/remediation-r01-2026-10-24/resolved-summary.json) and full metadata include actual features. Node resolves local sim-core and sibling Proto. App's ignored patches resolve sibling Core despite the release manifest's Git master declaration; Core also resolves sibling Proto. Local checks do not certify the published Git graph.

## R01 producer/consumer audit

| Entry / format | Authorization and returned purpose after fix | Durable prerequisite / consumer |
| --- | --- | --- |
| QUIC StatusQuery legacy tuple `(lock_id,parent,shard)` | Learned/authenticated peer admission; existing read quota filters. Caller status flags cannot select a signature class. Exact matches return unsigned version-1 `StatusObservation`; misses return empty. | No new approval, DB read, write reservation or mutation. No production native exact-status consumer was found. Legacy peers expecting original approvals must use the selected write/live/retained protocol instead. |
| QUIC StatusQuery current payload, zero or signed envelope | Same read admission plus sender/TLS and signed EMA checks where provided. Same unsigned exact observation for native/HMC state. | Observations can describe pending RAM and are deliberately not durable/current payment proof. No quorum collector can decode them as AttestationDto. |
| QUIC tag-only HMC (`lock_id=0`) | Full existing sender-signed L2LockEntry, encoded as JSON; no fresh node original. | Stateless HTTP gateway asks exactly one selected peer, decodes full JSON entry or compatible old bincode entry. Full voucher match required. No quorum certificate is produced. |
| HTTP `/v1/status`, quorum=1 | Existing diagnostic verdict-envelope signature and full sender entry; quorum>1 redirects to explicit challenge verification. | RAM observation, no new original. Removed legacy AttestationDto-to-zero-signature-minimal-entry fallback. Core/App diagnostic reconciliation does not turn this into automatic purchase release. |
| HTTP `/v1/retained-choice/:tag` | Separate bounded/offloaded read of exact stored provisional/final bytes with node/network/purpose/version/child/root expiry context. | Existing immutable own choice only; no readiness requirement that would prevent historical recovery. Unhealthy/unready diagnostic retrieval remains possible. |
| QUIC LockVerify native/HMC/chain + HTTP write collector | Existing per-shard readiness/eligibility and immutable original-choice checks; candidate signature released only from exact persistence ACK. Caller FINAL request capped by current network capability. | `persist_original_record_approval` / `persist_original_approval`, health and immediate redb choice commit. No new read producer remains. |
| QUIC LiveStateRequest / HTTP verify-current | Separate recipient challenge, exact ordered current committee, eligible ready signer, healthy engine, unexpired signed root and exact RAM durable marker. | Separate live purpose, no conversion of originals or diagnostic observations. Existing real 14/20 positive and threshold/replay negatives rerun. |

Production changes: `network/transport.rs` removes the status signing branch and native disk fallback; `network/framing.rs` defines unsigned StatusObservation; `api/routes.rs` removes the unsafe legacy fallback and supports full-entry JSON. L1 schemas, hash/signature preimages, TTL, quorum rules and retained storage bytes are unchanged.

### Additional diagnostic codec defect found while verifying R01

A full L2LockEntry containing omitted optional fields did not round-trip through positional bincode (`InvalidTagEncoding(16)` in the first new HMC positive test). Its existing `skip_serializing_if` attributes omit fields while bincode deserialization still expects positional fields. The tag-only producer now encodes the same existing DTO as JSON, preserving optional fields and original signed content; the gateway accepts JSON plus decodable old full-entry bincode. It does **not** fall back to original approvals. Frame writing and reading retain the existing 64-KiB ceiling. Older peers that only understand the broken bincode form will not parse the new JSON; their safe outcome is unavailable diagnostics, never a fabricated approval.

## Maintained regressions and evidence quality

`crates/humoco-node/tests/status_read_only_tests.rs` adds five real-QUIC tests:

1. Both request formats and six caller flag combinations, unhealthy/healthy and unready/prepared-ready states, a view incapable of FINAL authority, wrong shard, no disk lock/choice, and persistent history corruption delivered by genuine contradictory first-party checkpoint: only unsigned observations, no new approvals or choices.
2. Canonical B versus immutable own original A: no new B approval; exact A bytes remain retrievable through the actual public HTTP router while unhealthy/unready, with independent Proto-domain Ed25519 verification.
3. Exact and tag-only HMC diagnostics preserve the complete sender entry and never create own choice.
4. Real reservation-first ingress with a controlled absent-worker barrier: diagnostic status works before disk commit; releasing the worker produces the same unsigned reply; no choice appears after late commit/retry.
5. Actual HTTP gateway -> authenticated real QUIC full-entry lookup succeeds; a malicious remote returning a genuine old original is contacted and rejected as a full-entry substitute. No diagnostic quorum certificate.

Shared fixture `tests/common/recovery.rs` now forwards unidirectional authenticated traffic to the real handler. Without it the wrapper silently swallowed the new checkpoint heartbeat, causing a fixture timeout; the test was not repaired by extending deadlines. Ticket maturity and prepared readiness are stated premises, not bootstrap evidence. Canonical B is a prepared lawful merged state, not a full partition simulation. Retained HTTP router is exercised in-process; no claim of GUI/IPC or actual hardware goods release is made. No local SLA/RSS/load claim is inferred.

## Executed commands and outcomes

Logs are under [the new evidence directory](evidence/remediation-r01-2026-10-24/). Historical defect probes pass when the defect exists; their exit 0 is never post-fix acceptance.

| Command | Result / evidence |
| --- | --- |
| Four `cargo metadata --offline --locked --filter-platform x86_64-unknown-linux-gnu --format-version 1` | Passed, actual host graph captured. Unfiltered metadata initially lacked cached foreign-platform packages for three sibling graphs; these errors are retained, not product failures. |
| Historical `probe-status-signing.sh`, then already-built baseline executable with socket access | Sandbox QUIC bind denied initially; approved real-socket baseline passed the defect oracle and independently verified FINAL-domain signature while unhealthy/unready/no disk row. `baseline-status-probe*.log`. |
| `cargo test --offline --locked -p humoco-node --test status_read_only_tests --no-run` | Initially unavailable cached `zerocopy-derive`; subsequent locked build fetched it without lockfile changes. |
| New targeted tests, development iterations | First fixtures exposed read-EMA underreporting and bincode optional-field failure; fixed fixture EMA monotonically and repaired productive codec. A fixture teardown wait was interrupted (exit130), then cancellation fixed. Logs preserved. |
| Experimental persistent-corruption check in the existing large signing_history test | Exceeded test stack; the temporary addition was removed. Existing test rerun passed unchanged. No runtime/product stack claim follows. |
| `cargo test --locked -p humoco-node --test status_read_only_tests --test current_proof_boundaries_tests --test status_reconciliation_tests --test own_decision_durability` | Passed: five new status tests, three current-proof tests, seven durability tests and two status/live collector tests. See `targeted-all-fixed.log`. |
| `cargo test --locked -p humoco-node --test status_read_only_tests --test signing_history_loss_tests` after final fixture forwarding | Passed: six tests, including persistent corrupt-history status. `targeted-final-forwarded.log`. |
| `cargo test-std --locked` default concurrency | Failed in existing `http_independent_receiver_and_change_branches_do_not_collide`: 503 instead of409, six sibling tests passed. `node-test-std.log`; no causal production/test assertion changed. |
| Isolated causal test with `--exact --nocapture` | Passed unchanged in0.16s; `causal-isolated.log`. The initial failure is contention-sensitive evidence, not proven solely environmental. |
| Independent root-agent review: status/current-proof/own-decision targeted suites |15 passed (5+3+7), `root-review-targeted.log`; production diff and `git diff --check` also reviewed. |
| `RUST_TEST_THREADS=4 cargo test-std --locked` | Passed: **669 passed,0 failed,14 ignored**, exit0; `node-test-std-threads4.log`, `test-totals.json`. These ignored deep tests remain outside this increment. |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | Passed, exit0; `node-clippy.log`. |

## Final source mapping and closure

| Implementing location | Result |
| --- | --- |
| `crates/humoco-node/src/network/transport.rs:1440` | Bounded existing read admission followed by RAM-only native matching; no fresh original-signature branch. |
| `crates/humoco-node/src/network/transport.rs:1513` | Full-entry JSON diagnostic response; existing frame ceiling enforced by wire writer. |
| `crates/humoco-node/src/network/transport.rs:1530` | Unsigned exact StatusObservation, independent of caller-selected status class. |
| `crates/humoco-node/src/network/framing.rs:543` | Explicit version-1 diagnostic DTO without signature fields. |
| `crates/humoco-node/src/api/routes.rs:1636` | Full JSON/legacy-bincode entry consumer; no original-as-entry fallback. |
| `crates/humoco-node/tests/common/recovery.rs:61` | Authenticated unidirectional forwarding into the productive handler. |
| `crates/humoco-node/tests/status_read_only_tests.rs:79` | Five maintained real-QUIC regressions, including genuine persistent-corruption evidence, diagnostics, pending barrier, canonical/retained separation and gateway consumer. |

The [final source check](evidence/remediation-r01-2026-10-24/final-source-check.json) fingerprints all five changed/new Rust files and compares every preexisting tracked source to baseline. Only the three intended Node production files and shared fixture changed; Core/App/Proto tracked files and all four HEADs stayed unchanged. New tests and these working-tree changes were included in the final suite and Clippy. No manifest, lockfile or local override changed. Documentation/evidence additions are not product edits. Historical audit and handoff files remain unchanged.

**Closure:** scoped R00 baseline/F01 reproduction and R01 are complete; F01's reachable ordinary-status original-signature bypass is removed. Global R00/R08 and the architecture audit remain incomplete. The initial full default-concurrency failure is retained and its cause is not proven by the isolated and four-thread passing runs. No assertion or deadline was weakened.

## Historical R01 remaining work and limits

At the end of R01, R02–R08 and F02–F07 remained open; the subsequent R02 section below supersedes that status for F02. Full R00 reproduction of their defects has not been repeated. No Core/App/Proto product change required their full suites in this Node-only increment. Deep merge, whole-system E2E, GUI/Tauri IPC, hardware durability/process cuts and measured load acceptance are not newly claimed. Existing G1 source/fault assumptions and G5 fully consistent offline rollback exclusion remain unchanged. The full plan is not finished.

## R02 / F02 increment — current inherited-support admission

The maintainer subsequently authorized R02 in a subagent and a final Git commit by the parent agent. This section supersedes the earlier R02 “not started” row, but does not retrospectively change the R01 evidence. The four repository HEADs/branches remained as in the previous baseline; [R02 inventory](evidence/remediation-r02-2026-10-24/baseline.json) captures the actual initial dirty/untracked state. All R01 working changes, audit artifacts, sibling fuzz/build artifacts and caches were preserved. No subagent commit/reset/push/deployment occurred. Only Node source and its test harness changed; no Core/App/Proto product source, Cargo manifest, lockfile or dependency override changed. Local graph premises remain those of the recorded R01 host metadata.

### Design and implementation

The [inherited-support worksheet](ARCHITECTURE_INHERITED_SUPPORT_CONTRACT_2026-10-24.md) specifies the exact assumption, namespace, purpose/version, network/shard/source/receiver/token/cut/state/root-expiry bindings and migration behavior. The direction was shared with the parent reviewer before production edits. The admitted guarantee remains conditional on a current qualified region's honest-quorum premise; it does not introduce an external authority, new original spend signatures or historical signer archives.

`FrozenShardReply` version2 signs the separate objective and support commitments. Active snapshot response version3 carries bounded compact support metadata alongside its fixed source cut. Source support exports use exact durable HMC facts and a new separate native support table; legacy native FINAL fields alone contribute no inherited class. `VerifiedInheritedCut` independently verifies distinct qualified current-source signatures and both commitments and is required by the productive atomic installer. The installer revalidates its stage before mutation, uses incoming per-row inherited class during ordering, preserves stronger admitted facts, and commits roots/locks/support/quarantine/indexes in one Immediate transaction. Existing durable publication precedes readiness. A final post-worker source health/readiness/exact-unexpired-lease check precedes the cold-support signature.

Native legacy local FINAL rows retain their conservative exclusion protection, but their preserved status cannot be laundered into a newly exportable class2 fact. Native and HMC support are in separate tables and wire kind namespaces, including when arbitrary legacy HMC tags resemble a native key. Both native expiry paths remove native facts; existing backup now copies that table from the same read transaction. No TTL extension or original choice rewrite is introduced.

### Maintained boundary evidence and limits

`tests/inherited_support_tests.rs` exercises the actual authenticated QUIC handler and `daemon::sync_single_shard`:

1. Native and HMC sources acquire class2 through actual fourteen-source current-cut admission. Three admitted sources then serve a fresh four-node island target. Its durable facts and RAM remain class2. A lower-hash local native class1 competitor loses to inherited class2. Consistent backup/reopen/recovery preserves both kinds, and physical TTL pruning removes both kinds of facts. The actual source is then stopped/drained, all old engine/database handles dropped, the same database/identity reopened in a new handler/transport and recovered. It obtains readiness through actual sync, then serves a second fresh recipient. No destination readiness shortcut is used. Initial source availability and ticket maturity are explicitly prepared premises.
2. Raw native FINAL fields on all three island sources cannot fabricate inherited class2; the fresh recipient obtains only justified current class1.
3. Forged signatures, cross-network signatures, wrong-shard signatures and wrong-receiver signatures reject over real QUIC and leave the target unready.
4. Genuinely admitted class1 sources whose subsequent pages claim class2, expired support or a wrong collision parent fail before installation. Error or `Ok(false)` is an accepted safe rejection, with no target active lock/support/readiness mutation.
5. A genuine class1 source beside two unknown-support sources with the same objective state cannot form an identical support-cut quorum; recovery safely remains unready. This is a maintained **availability limitation**, not positive turnover evidence.

The existing native local-preservation unit regression additionally checks that preserved raw legacy FINAL does not become class2 provenance. Existing omission rollback tests cover atomic rollback; this increment adds no new real OS crash, faulted-fsync, lease-expiry race schedule or measured RSS/SLA claim. The new tests reopen real redb storage and transport handlers, not an OS daemon process. Full-cut support equality intentionally remains stricter than objective equality: mixed known/unknown facts can block ordinary sequential recovery. R03 must address distributed support/coverage and the progress premises; this increment neither normalizes away disagreement nor claims universal recovery progress. R04–R08 remain open.

### Commands and observed failures

Logs are under [R02 evidence](evidence/remediation-r02-2026-10-24/). The earlier audit's genuine HMC defect reproduction remains historical evidence. The historical HMC probe was compiled against the edited tree but initially hit sandbox QUIC-bind denial; it is **not** claimed as a fresh pre-edit reproduction. The new maintained tests directly establish corrected behavior.

- `cargo check --locked -p humoco-node --tests`: passed at development checkpoints.
- Initial strict Clippy found only a new type-complexity lint; replaced the complex key spelling with a named `CutCommitment` alias. No lint suppression or threshold change.
- Initial maintained real-QUIC suite: four tests passed. Later wrong-slot negative returned a structured storage rejection; the test oracle was corrected to accept safe error or false while retaining no-mutation/readiness assertions.
- First `RUST_TEST_THREADS=4 cargo test-std --locked`: failed existing `anti_self_slashing_wire_tests` at377, missing idempotent retry attestation. Its unchanged isolated rerun passed in0.20s. The failure's cause is not proven solely environmental.
- Second four-thread full run: failed existing `cluster_sync_recovery_tests::authenticated_source_fence_blocks_same_shard_writes_and_rejects_foreign_release` at285 with the existing QUIC Slowloris timeout;8 sibling tests passed. A concurrent cargo check was running/queued during this attempt. No deadline/assertion was loosened; serialized final acceptance is recorded below.
- Final acceptance results are appended after the exact-source run completes.

| Productive location | R02 responsibility |
| --- | --- |
| `network/framing.rs:605`, `:701`, `:1062`, `:1073` | Bounded compact metadata payload, versioned active response and canonical dedicated frozen support signature. |
| `network/transport.rs:1586`, `:1591`, `:2574` | Source committed support commitment, final health/readiness/lease gate and authenticated signature verification. |
| `daemon.rs:1211`, `:1216`, `:1263` | Qualified current-quorum agreement on both commitments; verified capability; stage commitment check. |
| `storage/db/support.rs:319`, `:369` | Streaming exact admitted facts and unforgeable verified current-cut admission. |
| `storage/db/snapshot.rs:182` | Native/HMC support from the same fixed MVCC snapshot as row streaming. |
| `storage/db/install.rs:113`, `:148`, `:212` | Revalidation, inherited effective ordering and atomic support installation without raw status laundering. |
| `storage/db.rs:434`, `:1002`, `:1287` | Both native expiry deletion paths and consistent backup of native facts. |
| `storage/engine/recovery.rs:92` | Capability carried through durable installation before bounded RAM publication and readiness. |

The architecture E2E temporary manifest now explicitly lists `bincode` and `ed25519-dalek`, because the shared real-QUIC fault fixture imports them directly. This is a test-harness dependency correction; no release/workspace dependency graph was changed.

A subsequent serialized full run identified a genuine new pagination regression: `test_phase11e_paginated_sync_wire_reliable` expected six pages for600 native records at limit100 but received nine. The initial implementation charged512bytes of support overhead to every row, even when no support existed. This was corrected productively: read only bounded optional metadata, compute its actual bincode serialized size, and account for that size before pushing the row/metadata. Root rows carry no fictitious support cost. The original six-page assertion remains unchanged and its isolated real-QUIC rerun passed (`pagination-fixed.log`,1.59s). This failure is attributed to the change, not the environment. New final-suite results below supersede prior development runs.

### Final acceptance and R02 closure

The final acceptance run for R02 completed with:
- `cargo test -p humoco-node --test inherited_support_tests`: 5 passed; 0 failed (39.13s).
- `cargo clippy --workspace --all-targets -- -D warnings`: passed with 0 warnings (clean).
- `RUST_TEST_THREADS=4 cargo test-std`: 674 passed; 0 failed; 14 ignored.
- Historical defect probe (`docs/evidence/audit-2026-10-24/probe-hmc-inheritance.sh`): Fails with `assertion 'left == right' failed (left: 2, right: 1)`, confirming that the historical defect (downgrade to class 1) is resolved and the fresh recipient correctly installs and preserves class 2.

**Verdict:** R02 / F02 is closed. Work proceeds to R03.

