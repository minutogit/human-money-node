# Parallel follow-up audit: S06, S07 and S08

Date: 2026-11-08. Base revision: `543b1d0dab881052330b23cbb469129096ab482d`.
The reviewed working tree already contained substantial uncommitted changes;
the revision alone does not identify the reviewed source state.

Exactly three agents each executed `prompts/AUDIT_LOOP.md` once, reviewing one
assigned slice. All baseline passes were complete. The coordinator assigned
three distinct ReCheck slices in slice order: S06, S07 and S08. S09 remains for a
later review. The coordinator checked the source traces, independently repeated
the six deterministic findings, updated only these three ledger rows, and
created the combined maintenance prompt. Neither the coordinator nor these
agents edited any file under `crates/`.

## Results

| Slice | New findings | Clean_Streak | Total_Finds | Last_Run | Status |
| --- | ---: | ---: | ---: | --- | --- |
| S06 | 3 | 0 | 10 | 2026-11-08 | `Fix_Open` |
| S07 | 1 | 0 | 12 | 2026-11-08 | `Fix_Open` |
| S08 | 2 | 0 | 14 | 2026-11-08 | `Fix_Open` |

Six new findings: two High and four Medium. Prior findings were not counted
again. In particular, existing S06 admission/ticket/clock regressions, S07
physical-time/network-bound evidence regressions and S08 fractional counter and
neutral-feedback repairs were rechecked. This review does not claim workspace-
wide conformance or implementation of any repair.

| Finding | Priority | Observed behavior | New reproduction |
| --- | --- | --- | --- |
| S06-08 | Medium | Verified relayed endpoint update keeps the old endpoint | Real QUIC |
| S06-09 | High | Unaged admission bitmap counts expired hourly observations | Component with controlled time |
| S06-10 | Medium | Remote qualification survives past 60-day retention | Real QUIC with simulated inactivity |
| S07-12 | High | Lawful composed EMA decay triggers persisted identity bans | Core and real QUIC |
| S08-13 | Medium | Out-of-domain scaled accumulation wraps whole-unit exports | Core boundary probe |
| S08-14 | Medium | Maintenance deletes live fractional quota usage | Core threshold probe; production callers source-traced |

The most consequential reproduced result is S07-12: a current-production
thermometer sequence generates two genuine signed checkpoints that the fraud
verifier accepts as incompatible, and real QUIC processing persists evidence
and bans the author in engine RAM, PeerManager and redb. No voucher monetary loss
or double-spend was alleged or reproduced.

## Coordinator verification and concurrent workspace changes

- The initial `cargo test-std` failed at compilation, exit 101, because
  `status_read_only_tests.rs:529` still passed six arguments to a seven-argument
  `spawn_flush_worker`. Initial Clippy also failed at compilation, exit 101,
  on the equivalent stale call in `own_decision_durability.rs:171`.
- `cargo test-fast` initially reported 211 passed and three failed node tests
  because the sandbox disallowed local socket binding. The completed rerun
  with local socket permission passed: **277 tests, zero failures**, across
  node (214), proto (20), core (43), and a zero-test result group. Log:
  `/tmp/humoco-audit-S06-S07-S08-test-fast-sockets.log`.
- During later checks, files were changed outside this audit:
  `crates/humoco-node/src/storage/engine.rs` and
  `crates/humoco-node/tests/s02_regressions.rs`. The initial source diff was
  saved at `/tmp/humoco-audit-S06-S07-S08-crates-before.diff`; comparison with
  later diffs identified these two changing files. S06/S07/S08 target sources
  and the direct ingress quota predicates cited here remained unchanged in
  that comparison. The audit left all external edits intact.
- The ledger was also edited externally during the run: S02, S04 and S05
  changed from `Fix_Open` to `ReCheck`. This audit preserved those changes;
  its own ledger mutation was restricted to S06, S07 and S08.
- A final full-suite attempt with local socket permission and a final Clippy
  attempt both failed at compilation, **exit 101**, with E0382 at
  `crates/humoco-node/tests/s02_regressions.rs:2016`: `target.identity` had been
  captured by an `async move` block at line 1956 and was borrowed afterward.
  The earlier worker-signature problem had been changed externally. Logs:
  `/tmp/humoco-audit-S06-S07-S08-test-std-final.log` and
  `/tmp/humoco-audit-S06-S07-S08-clippy-final.log`. These results describe the
  exact attempted states; no completed full-workspace or Clippy pass is claimed.
- Compilation failures outside assigned slices are validation prerequisites,
  not additional findings added to the three slice counters. Their latest
  status must be rechecked before implementation. The combined prompt includes
  the concrete last-observed prerequisite without requesting unrelated repairs.
- S06 existing focused regressions passed **9 tests**. S07 focused library and
  fraud regressions passed **70 tests** (20 + 43 + 7). S08 focused core and node
  regressions passed **65 tests** (62 + 3), including existing HTTP and real-QUIC
  fractional-boundary coverage. These counts overlap the library suite and
  must not be added together as a distinct-test total.
- The coordinator independently reran `/tmp/humoco_s06_probe` and confirmed
  the endpoint, stale-window and expired-retention observations. Log:
  `/tmp/humoco-audit-S06-S07-S08-s06-probe.log`. The reviewer also ran the
  positive eighth-current-slot control. Explicit time controls simulate long
  periods; the probes did not wait 24 hours or 61 days in wall-clock time.
- The coordinator independently reran `/tmp/humoco_s07_decay_probe` and the
  compiled real-QUIC test `probe-5bfaafd6598c42a5`. The latter correctly fails
  its expected-safe assertion with `ram_ban=true mesh_ban=true disk_ban=true
  evidence=true`; this is the reproduction of S07-12, not a passing safety
  test. Log: `/tmp/humoco-audit-S06-S07-S08-s07-quic-probe.log`.
- The coordinator reran `/tmp/humoco_s08_ema_boundary_probe`, including its
  50000-credit cleanup control, and confirmed both findings. Its output is
  retained in the S08 evidence below.
- No permanent repository regression test or production fix was added by this
  review. Ignored deep simulations were not run. Manual source inspection and
  focused executions are not formal proofs or exhaustive schedule exploration.

## Mandatory pre-launch cleanup

The unused Mainnet-defaulting transitional
`FraudProofPayload::verify_ingress_counter_conflict` at
`crates/humoco-sim-core/src/fraud.rs:825`–`:827` remains an obsolete wrapper;
`rg` finds no caller under `crates/`. Its removal is in the maintenance prompt,
without recounting the earlier explicit-network requirement as a new finding.
Actively emitted zero-sequence read/status semantics are a separate case and
must not be deleted merely because they resemble older accounting.

The S08 ledger still names removed historical targets (`ceh/`, `p0/`,
`state_machine.rs`, `transport.rs`). All existing targets were reviewed; absent
files are documented as a coverage limitation, not recreated or counted as defects.

## Detailed slice evidence and coverage

The following sections preserve the reviewers' findings, source traces and
coverage. Their validation notes describe earlier stages of this same run;
the coordinator results above record the later full-check attempts.

## S06 audit — 2026-11-08

Exactly one read-only pass of `prompts/AUDIT_LOOP.md`, assigned by the coordinator to S06. No files under `crates/` were edited. Existing workspace changes were left intact. The coordinator owns the ledger mutation.

### Verified new findings

#### S06-08 — Medium — Authenticated relay endpoint updates retain the old endpoint

**Expected specification behavior:** Permanent `NodePubKey` remains stable while endpoints change (`AGENTS.md`, pillar 3). Spec 11 requires verified origin binding before accepting the advertised endpoint. An authentic origin-signed endpoint update through an authorized F2F relay must update that origin's learned endpoint.

**Observed implementation behavior:** `crates/humoco-node/src/network/transport.rs:4339` verifies the relayed origin address binding, but `:4464` calls `learn_node_from_gossip_with_hrw_and_work`. Its wrapper at `crates/humoco-node/src/network/manager.rs:2339` derives `origin_authorized` exclusively from `hops == 0`. Consequently `:2435` rejects every changed address with `hops > 0`, even after the origin signature was verified. New identities can be introduced at an address, but later legitimate relay updates retain the previous address.

**Evidence:** The external probe `/tmp/humoco_s06_probe.rs`, compiled against the current built workspace library, created authenticated sender/receiver QUIC endpoints and a genuinely mined origin ticket. The authorized relay sent a valid signed heartbeat for an already known third party, changing `127.0.0.1:32001` to `127.0.0.1:32002`. Result: `ADDRESS verified_origin=true expected=127.0.0.1:32002 actual=Some(127.0.0.1:32001)`.

**Reliability impact:** Shard-direct routing keeps using an obsolete endpoint despite receiving valid first-party evidence of the new endpoint. No monetary or consensus-safety failure was reproduced. This differs from the earlier unsigned-relay rejection findings: their negative tests remain valid; the missing positive endpoint-update case is new.

#### S06-09 — High — Initial admission can count hourly slots that expired without a new heartbeat

**Expected specification behavior:** Spec 07 `:66` and Spec 11 `:56` require 24-hour observed age and at least eight valid hourly observations in the 24-hour history for initial admission. Time passing must age the observation window even if no new message arrives.

**Observed implementation behavior:** `crates/humoco-node/src/network/manager.rs:364` shifts the 24-bit history only when another heartbeat is recorded. `:427-428` independently returns qualified once observed age reaches 24 hours if the unshifted mask has eight bits, even when `initial_admission_qualified` was never latched. Committee selection at `:3355` and active HRW selection at `:3314` consume this predicate without advancing the history to the current approved network hour.

**Evidence:** A component probe used production 24-hour incubation, explicit first-seen/last-seen test timestamps, and hourly observations at relative slots `[0,1,2,3,4,5,6,21]`. At observed age 21 hours it was unqualified. At age 24 hours, without another heartbeat, slot 0 is outside the current 24-slot history, leaving seven current observations; the current implementation reports qualified and selects the identity. Output: `WINDOW before_24h_qualified=false` and `WINDOW at_24h_current_valid_slots=7 selected=true qualified=true`. Last presence age is three hours, correctly inside the existing 3h15m freshness limit. The probe does not claim that three-hour presence is suspended. Adding a current eighth-slot observation gives the positive control `WINDOW positive_current_eighth_slot_qualified=true`.

**Reliability impact:** An initially unqualified identity can enter HRW committees and qualified-ticket persistence with insufficient current hourly history. This is a new expiration boundary of the repaired S06-01 admission gate; the earlier one-observation and same-hour replay regressions pass. No double spend or actual binding vote release was reproduced. This boundary was validated at the component level, not by QUIC.

#### S06-10 — Medium — Expired remote admission history remains reusable after the 60-day retention period

**Expected specification behavior:** Spec 07 `:81` / INV-0705 explicitly requires returning remote identities to obtain the appropriate newcomer observations after the 60-day metadata retention expires. This finding does not select any disputed short-absence reentry rule, require fresh mining, or alter the separate one-year direct-friend policy.

**Observed implementation behavior:** `crates/humoco-node/src/network/manager.rs:2418` distinguishes only the 3h15m presence timeout; the existing-entry branch retains `initial_admission_qualified`, observation age and ticket state, then `:2450` refreshes presence. There is no 60-day expiry before this refresh. `:428` accepts the old qualification immediately. A search of all known-node removal/mutation sites and daemon maintenance found no remote metadata retention/pruning path. Persistent observations also retain only first-seen time and a permanently OR-latched qualification (`crates/humoco-node/src/storage/db.rs:863`), and boot at `crates/humoco-node/src/daemon.rs:560-570` restores them without an inactivity cutoff. Restart persistence was inspected, not executed in the probe.

**Evidence:** The same real-QUIC probe seeded a legitimately qualified remote ticket, set its last observed presence to 61 days ago, confirmed exclusion while stale, and sent exactly one fresh valid origin-signed heartbeat through the configured relay. Result: `RETENTION before_member=false after_single_heartbeat_member=true qualified=true`. The origin was not a configured direct friend. Production 24-hour incubation remained enabled; only work-floor difficulty was lowered for deterministic test-ticket generation. Explicit timestamps simulated elapsed inactivity; no 61-day wall-clock wait was performed.

**Reliability impact:** Old remote qualification survives past the specified retention boundary and can immediately reenter future committee snapshots. Dormant metadata also lacks the mandated expiry lifecycle. This is separate from ordinary reentry inside the retained-history interval, whose exact predicate remains open in Spec 11 `:60`.

### Coverage and previous-finding recheck

All five S06 target files were read, including their embedded tests:

- `network/clock.rs`: authenticated per-friend median inputs, checked timestamp arithmetic, damping/clamping, monotonic CAS clock, directional jump corroboration, removal/ban revocation. Prior single-friend sample inflation, negative-median corroboration and extreme timestamp cases are repaired; no new verified defect reported here.
- `network/discovery.rs`: bounded signed gateway advertisements, URL validation, network/identity/time binding and expiry; direct manager cache consumers were inspected. No new verified defect.
- `network/peer.rs`: diagnostic debounce, handshake versus actual shard work, neutral idle cleanup, activity diagnostics and hourly malus decay. No new verified defect.
- `network/manager.rs`: every implementation section and embedded tests, including ticket maturity/promotion, hourly admission, local/remote snapshot selection, persistence seeds, authorization, friendship removal, ban enforcement, evidence cache/forwarding, DNS refresh, diagnostics, discovery cache and finality counters. Findings above are limited to concrete behaviors.
- `network/tls.rs`: Ed25519 certificate/key extraction, handshake possession checks, network ALPN and differentiated friend/shard transport settings. Existing compatibility aliases/fallback helpers were identified as cleanup candidates but are not counted as speculative reliability findings.

Direct paths inspected include heartbeat origin signing/address verification in `network/framing.rs`, authenticated heartbeat reception/clock/dedup/ticket learning in `network/transport.rs`, daemon restoration and maintenance, ticket-observation storage methods, existing admission/clock/ticket/gossip integration regressions, and the relevant Spec 03/07/11 sections and invariant registry. Storage internals were consulted only as direct dependencies; this is not an additional S02/S03 slice review.

Prior S06-01..07 regression areas were checked: eight-observation initial admission, friend-removal/ban clock revocation, production rejection of unmined shortcut tickets, qualified persistence, overflow-safe work median, replacement-promotion ordering, and neutral RPC diagnostic suspension for heartbeat gossip. Existing repairs were not recounted as new findings.

### Validation and limits

- Executed `cargo test -p humoco-node --test phase4_net_time_and_quotas --test spec_07_pow_headroom_and_monotonicity_tests --test interview_recovery_membership_tests --test f2f_gossip_and_shard_rpc_tests s06 -- --test-threads=1`: **9 passed, 0 failed**. This includes existing real-QUIC tests.
- Additional `cargo test -p humoco-node --test production_readiness_m2_m3_tests persisted_ticket -- --test-threads=1` and `cargo test -p humoco-node --lib network:: -- --test-threads=1` attempts were blocked by a changed workspace build error: `storage/engine.rs:1030` / `:1210` reference a missing `spawn_flush_worker_internal` (`E0599`). No test from these two additional commands ran. Workspace source outside this agent's read-only S06 scope was changing concurrently; the previously completed nine tests and wire probe refer to the earlier successfully built `libhumoco_node-c288c34cd62417b2.rlib`. S06 production files were not changed by this audit.
- External read-only probe source: `/tmp/humoco_s06_probe.rs`; executable: `/tmp/humoco_s06_probe`. Uses the current workspace rlib and its matching dependencies. Initial sandboxed execution was refused for local UDP socket creation; the authorized local-QUIC execution with sandbox escalation succeeded. Findings S06-08 and S06-10 have wire evidence; S06-09 has a component-level reproduction.
- The coordinator's full `cargo test-std` and Clippy attempts are blocked by preexisting integration-test call-site compile errors after `spawn_flush_worker` gained another parameter. These are workspace validation blockers, not S06 findings. No full-suite-green claim is made.

## Slice S07 audit — 2026-11-08

Exactly one read-only execution of `prompts/AUDIT_LOOP.md`, coordinated assignment S07 from ReCheck priority. No files under `crates/` or the ledger were edited by this reviewer. Existing concurrent work was retained.

### Verified finding

#### S07-12 — High: Lawful composed Q32 decay is classified as first-party fraud and durably bans the author

**Expected specification behavior:** Spec 10 section 5 (`docs/10_p2p_wire_format_und_session_framing.md:214`, `:224`) and INV-0501/1602 require genuinely incompatible signed statements before identity sanctions. Two signed checkpoints generated by the canonical `NetworkThermometer`, with only positive ingress additions and physical-time decay, must not establish fraud, regardless of packet order or unobserved intermediate checkpoints.

**Observed implementation behavior:** `crates/humoco-sim-core/src/fraud.rs:784` subtracts only one integer unit for each possible intermediate sequence from a direct `decay_integer_ema` calculation (`:788`, `:798`). The Q32 table/interpolation multiplication in `crates/humoco-sim-core/src/quota.rs:364`–`:367` is not exactly compositional: two lawful decay segments can produce a lower result than one direct decay by more than that allowance. This is separate from the already repaired S07-10 omission of lawful twelve-hour EMA decay; existing S07-10 coverage uses single-segment vectors and remains green.

**Deterministic current-production vector:**

1. `NetworkThermometer::new()`; `record_write_ingress(100_000, 1_000_000_000_000)`; checkpoint at 100,000 seconds. Sign day 1, sequence 1, timestamp 100,000,000 ms, write EMA 1,000,000,000,000, read EMA 0.
2. `record_write_ingress(101_350, 1)`; checkpoint at 101,350 seconds (the unobserved sequence 2).
3. `record_write_ingress(101_891, 1)`; checkpoint at 101,891 seconds. Sign day 1, sequence 3, timestamp 101,891,000 ms, write EMA **984,957,739,474**, read EMA 0; the two later ingress additions are both positive.
4. Direct `decay_integer_ema(1_000_000_000_000, 1_891)` = **984,957,739,477**; the verifier permits only one intermediate unit, so its minimum is **984,957,739,476**. Both `check_ingress_conflict(Mainnet, &a, &b)` and the reversed argument order return **true**.

**Executed real-QUIC reproduction:** A temporary external test package reuses the current production `NodeIdentity`, `DualTierEngine`, `PeerManager`, `NodeRequestHandler` and `QuicTransport`, with two mutually authorized F2F endpoints on loopback. It constructs the two genuine signed envelopes from the actual current `NetworkThermometer` operations above and sends the resulting `EquivocationProof` over a real QUIC connection. Observed:

```text
actual=984957739474 direct=984957739477 ack=0 ram_ban=true mesh_ban=true disk_ban=true evidence=true
```

The expected-safe assertion at `/tmp/humoco-s07-quic-probe/probe.rs:97` fails. Source: `/tmp/humoco-s07-quic-probe/probe.rs`; complete output: `/tmp/humoco_s07_quic_probe.log`. A first sandboxed attempt was blocked at socket bind (EPERM); the subsequently approved unsandboxed loopback execution reached the incorrect durable sanction above.

**Production trace / reliability impact:** The strict production verifier dispatches ingress evidence to this predicate at `crates/humoco-node/src/network/transport.rs:182`; shared incoming-proof admission invokes that verifier at `:388`. The accepted result causes atomic evidence-plus-ban persistence at `:399`–`:409`, followed by engine RAM ban, peer ban and fraud forwarding at `:424`–`:430`. The ordinary lock path also invokes the same predicate at `:1064`, then persists and bans at `:1073`–`:1084`. Therefore an honest identity can be permanently banned and have its routing/peer eligibility removed because of a deterministic arithmetic approximation discrepancy. The QUIC probe directly verifies persisted evidence and bans; it does not claim loss of voucher funds or a double-spend.

### Coverage and follow-up confirmation

Reviewed all twelve target files in S07, including test sections:

- `crates/humoco-proto/src/{lib,causal,crypto,live,mesh,types,verify}.rs`.
- `crates/humoco-sim-core/src/{crypto,resolver,types,wire,fraud}.rs`.

Reviewed direct callers/callees needed for their boundaries: canonical Q32 decay and `NetworkThermometer` checkpoint/update functions in `quota.rs`; regional/live signing callers in `humoco-node/src/api/live.rs`; original-approval and fraud admission/ban paths in `network/transport.rs`; request signature adapters in `api/hmc.rs`; root sidecar validation in `storage/db/roots.rs`; chain authorization in `storage/engine.rs`; evidence serialization and status/lock envelope generation in framing/routes. Relevant requirements read: AGENTS.md, proto AGENTS.md, ledger, invariant registry, Specs 06 and 10 and associated canonical domain/authority behavior.

Confirmed existing S07-01/S07-02/S07-10/S07-11 regression coverage and did not recount those findings. Proto verification continues to reject empty/ambiguous committees, excess votes, duplicate/nonmember signers and wrong signatures; occupied/unoccupied live purposes remain separated, with exact contextual equality and independent committee input. Resolver confirmation-class/hash/lock-ID ordering, safe fixed-header encoding and canonical length-prefix domains were inspected. No other new verified defect was established.

Mandatory cleanup inspection found the unused Mainnet-defaulting transitional method `FraudProofPayload::verify_ingress_counter_conflict` at `crates/humoco-sim-core/src/fraud.rs:825`–`:827`; `rg` over `crates/` finds only its definition. Remove this obsolete wrapper during maintenance; it is not counted again because explicit-network ingress verification was already S07-11's obligation. Conversely, epoch/sequence zero remains actively emitted by read/status callers (`api/live.rs:196`–`:206`, `api/routes.rs:2152`–`:2162`); do not delete that active semantic branch merely because it resembles older accounting.

### Validation and limits

- `cargo test -p humoco-proto -p humoco-sim-core --lib`: **20 proto + 43 core tests passed**. Log `/tmp/humoco-audit-s07-lib.log`.
- `cargo test -p humoco-sim-core --test spec_10_fraud_proofs`: **7 passed**, including existing S07-10 and S07-11 tests. Log `/tmp/humoco-audit-s07-fraud-tests.log`.
- Fresh `cargo build -p humoco-sim-core`, then standalone current-library Rust probe `/tmp/humoco_s07_decay_probe.rs`: reproduced symmetric false-positive conflict classification.
- `CARGO_TARGET_DIR=/home/basti/Coding/humoco/human-money-node/target cargo test --offline --manifest-path /tmp/humoco-s07-quic-probe/Cargo.toml --test probe -- --nocapture`: **expected-safe regression failed**, with actual real-QUIC durable bans shown above.
- Coordinated `cargo test-std` and `cargo clippy --workspace --all-targets -- -D warnings` did not pass: pre-existing test calls use the earlier `spawn_flush_worker` argument list (E0061/E0308). The coordinator records that separate validation blocker; it is not a S07 finding. No full-workspace green claim from those initial runs. During coordination, an external edit subsequently adjusted the `spawn_flush_worker` public wrapper; the coordinator is rerunning the full checks on that newer workspace state. S07 target sources remained unchanged, and the real-QUIC probe was independently rerun by the coordinator with the same false-sanction result.

## S08 follow-up audit — 2026-11-08

Exactly one coordinated read-only run of `prompts/AUDIT_LOOP.md`, assigned S08 under the ledger's ReCheck priority. Reviewed revision `543b1d0` with preexisting working-tree changes preserved. No file under `crates/` was edited. The coordinator owns the sole ledger edit.

### Findings

Two new verified defects: S08-13 and S08-14. They are distinct boundary defects exposed by the Q96.32 adoption: unbounded accumulation/conversion and cleanup based on lossy whole-unit projection. The previously reported per-update truncation example (S08-11) and obsolete penalty API (S08-12) are not counted again.

#### S08-13 (Priority: Medium) — Scaled thermometer accumulation can wrap its whole-unit exports

- **Expected specification behavior:** Spec 09 section 8 and the engineering checked-arithmetic rule require bounded counters and safe conversions. Recording additional nonnegative usage at one timestamp must not turn a saturated measurement into zero, and raw, projected and checkpointed exports at the same timestamp must agree.
- **Observed implementation behavior:** `crates/humoco-sim-core/src/quota.rs:850` and `:938` add a scaled footprint using `u128::saturating_add` but omit the `MAX_SCALED_USAGE` bound used by `decay_scaled_ema`. The whole-unit casts at `:859`, `:947` and `:908–909` can then truncate more than 64 integer bits. Recording `u64::MAX` then `1` at second 0 yields raw read/write metrics of zero and `checkpoint_emas_at(0) == (0, 0)`, although both corresponding `*_at(0)` projections return `u64::MAX` because that path clamps the input.
- **Reliability impact:** A valid mathematical API boundary sequence produces inconsistent exported measurements/snapshots and a discontinuous next checkpoint. The production allocation adapter exports checkpoint values through `crates/humoco-node/src/ingress/tier.rs:562–579`. This report does not assert realistic traffic can accumulate this amount, a ban, or a transport-side admission bypass.
- **Novelty check:** Before commit `543b1d0`, these accumulators used the `u64` helper `calculate_integer_ema`, whose final addition saturated at `u64::MAX`. This is a newly introduced widening/narrowing regression, distinct from S08-11's repeated rounding loss.

#### S08-14 (Priority: Medium) — Counter cleanup erases live fractional usage

- **Expected specification behavior:** Spec 09 section 3 and INV-0904 require quota usage to decay only with elapsed justified time. Memory maintenance may remove a counter once its scaled usage is zero; it must preserve a positive remainder which still constrains admission.
- **Observed implementation behavior:** `crates/humoco-sim-core/src/quota.rs:699` and `:732` retain counters only when `usage_at(now_sec) > 0`, using the rounded-down whole-unit view rather than `usage_scaled_at`. Once an unknown ID arrives with at least 16,384 tracked counters, any positive usage below one whole unit is removed. The production NodePubKey quota maps repeat the same predicate at `crates/humoco-node/src/ingress/tier.rs:1002` and `:1031`.
- **Concrete trace:** Fill 16,384 read counters at second 0 with one credit each under limit 50,000. At second 1, node 0 still has scaled usage 4,294,933,026 (almost one credit). A new node triggers cleanup and removes node 0; consuming 50,000 credits for node 0 then returns `Ok(50000)`. A control thermometer without cleanup returns `Err(49999)` for the same final request/time.
- **Production reachability:** HTTP status and sync map request values to 16-bit IDs at `crates/humoco-node/src/api/routes.rs:479–501` and `:1990–2005`; `TierController::evaluate_read_quota_with_time` calls the affected core method at `ingress/tier.rs:914`. The full-identity P2P map is also used by receiver read admission at `network/transport.rs:1722`. These are source traces, not a newly executed HTTP/QUIC reproduction of the cleanup boundary.
- **Reliability impact:** Inserting another identity can erase an existing client's or node's remaining accounted usage and change admission without additional elapsed time. The analogous write path has the same verified predicate. No identity or presence penalty is alleged.
- **Novelty check:** S08-11 reported per-event truncation in `RollingQuotaCounter::try_consume` and thermometer checkpoints, which now retain fractions. This separate collection-maintenance transition still discards retained fractions; it requires fixes in the purge predicates rather than the repaired decay/update functions.

### Executed evidence

A standalone Rust probe at `/tmp/humoco_s08_ema_boundary_probe.rs` includes the current, unchanged production `quota.rs` source with the exact `NodeId = u16` alias. It compiled and ran successfully with `rustc --edition=2021`:

```text
after MAX + 1: raw_read=0 projected_read=18446744073709551615 raw_write=0 projected_write=18446744073709551615 checkpoint=(0, 0)
after one-second checkpoint: (18446596885180317695, 18446596885180317695)
fractional retention: before_scaled=4294933026 counter_present_after_new_id=false pruned_result=Ok(50000) unpruned_result=Err(49999)
```

Probe binary: `/tmp/humoco_s08_ema_boundary_probe`. These local reproductions execute actual core methods; no replacement decay algorithm was used.

### Coverage

- All existing S08 target files reviewed completely: `quota.rs` (1,611 lines including unit tests), `storage.rs` (45), `client_flow.rs` (21).
- Historical ledger targets `ceh/*.rs`, `p0/*.rs`, `state_machine.rs` and `transport.rs` do not exist. Their absence is a scope limitation, not a new defect. The ledger row is intentionally preserved except for its audit counters/status/date.
- Direct helpers/callers inspected: core `types.rs` (SimTime, NodeId, normalized HRW score and full-score committee selector); node `ingress/tier.rs` quota maps, thermometer exports and rotation; relevant `api/routes.rs` status/sync/root-window paths; diagnostic HRW caller in `api/dashboard.rs`; storage engine root-window, recovery and TTL-prune callers; daemon thermometer rotation/merge caller; real-QUIC quota receiver admission.
- Specs reviewed: AGENTS.md, translation glossary, relevant Specs 03/06/09/12 and corresponding invariant registry entries. In scope: committee determinism, ingress/root window, expiry+grace, Byte-Years arithmetic, continuous quota decay, ring buffers and neutral feedback.
- Existing regressions reviewed: `audit_s08_regressions.rs`, quota module unit tests, `spec_09_network_thermometer_and_quotas.rs`, relevant quota property tests, `ingress_accounting_regressions.rs` S08-11 tests and `phase4_net_time_and_quotas.rs` feedback cases.
- Earlier report `prompts/reports/2026-11-08_parallel_audit_S02_S04_S08.md` and its maintenance prompt inspected to avoid duplicate findings. Existing S08-03/04/05 regressions pass. `malus_increment`/`malus()` no longer exist in the exported verdict; stale test-name wording is cosmetic and not counted.

### Tests and limits

- `cargo test -p humoco-sim-core --lib --test audit_s08_regressions --test spec_09_network_thermometer_and_quotas`: passed, 62 tests (43 + 6 + 13), zero failures.
- `cargo test -p humoco-node --test ingress_accounting_regressions test_s08_11 -- --nocapture`: passed after local-socket permission, all 3 tests (production tier, HTTP and real QUIC). Initial sandboxed attempt passed the tier and HTTP tests and failed only because QUIC socket binding was disallowed; the completed rerun resolves that environmental limitation.
- Coordinator performs full-workspace verification. At handoff, its `cargo test-std` attempt was blocked by the preexisting `status_read_only_tests.rs:529` stale `spawn_flush_worker` call signature. This is not counted as an S08 finding.
- No new repository regression test or production fix was added; the new boundary probes do not establish end-to-end transport behavior. Real-QUIC verification for S08-14 belongs to the maintenance task.
- This is manual source review plus deterministic targeted execution, not an exhaustive interleaving proof or ignored deep-suite run.

## Handoff

Use [the combined maintenance prompt](2026-11-08_S06_S07_S08_REMEDIATION_PROMPT.md).
It contains all six findings, regression-first changes, the concrete validation
prerequisite, obsolete-wrapper removal and per-slice `Fix_Open` to `ReCheck`
transitions after successful repair and verification. The audit itself is
complete; implementation of these findings remains a separate task.
