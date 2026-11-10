You are a Senior Rust Systems Engineer resolving verified specification and code-quality findings in `human-money-node` (Slices S05, S06 and S08).
Follow all rules in `AGENTS.md`: `#![forbid(unsafe_code)]`, fallible input handling, checked math, German user replies and English code/documentation. The network is pre-launch: delete superseded implementations without compatibility branches or migration shims.

Read `prompts/AUDIT_STATE.md` and `prompts/reports/2026-11-10_parallel_recheck_S05_S06_S08_round2.md`. Exactly three agents each executed the audit loop once at revision `120b9e76552c262e2befb401eae17b1715129574`. Five new findings were verified; no production code was changed. Implement these findings rather than running another slice-selection audit. Recheck current line numbers and preserve unrelated work.

### Verified Findings in Slices S05, S06 and S08

1. **S05-19 (Priority: Medium) — `crates/humoco-node/src/ingress/tier.rs:1415`**
   - **Expected vs. Actual Behavior:** Spec 13 section 3 and AGENTS Rule 5 require canonical length-prefixed domain separation for credential hashes. Friends registration, quota accounting, listing and admission instead use bare `BLAKE3(token)` at lines 1415, 1230, 1486 and 1655.
   - **Reliability Impact:** Credential identifiers omit the required purpose binding. All four paths currently agree; changing only some would disconnect quota/activity lookups. No hash collision or secret disclosure is established.

2. **S06-14 (Priority: High) — `crates/humoco-node/src/network/manager.rs:673`**
   - **Expected vs. Actual Behavior:** INV-1402 requires verified evidence ownership until durable persistence. At capacity, `insert_pending_evidence` unconditionally evicts the oldest pending item, including uncommitted and unforwarded evidence. A capacity-one component probe with two genuine verified proofs reproduced the loss.
   - **Reliability Impact:** Storage faults or forwarding backpressure followed by capacity exhaustion can permanently lose fraud evidence and leave its ban only in volatile RAM.

3. **S06-15 (Priority: High) — `crates/humoco-node/src/network/manager.rs:1708`**
   - **Expected vs. Actual Behavior:** Pending evidence needs retry progress after temporary resource failure without another offender attestation. The sole production flush call is triggered by another original attestation from that same offender; daemon maintenance and forwarding do not retry. Existing tests call flush manually.
   - **Reliability Impact:** Even below capacity, evidence can remain uncommitted or unforwarded indefinitely after resources recover; restarting can lose a ban whose commit was never retried. This is distinct from capacity eviction.

4. **S06-16 (Priority: Medium) — `crates/humoco-node/src/network/manager.rs:4293`**
   - **Expected vs. Actual Behavior:** Spec 07 section 4 / INV-0705 requires operator reactivation after one year of direct-friend inactivity. Pruning removes known-node metadata but retains the friendship and its authorization. A component probe confirmed successful gossip and direct-RPC authorization after more than 365 inactive days.
   - **Reliability Impact:** Expired edges retain trust and reconnect without the required local operator decision. Local deactivation must remain distinct from a cryptographic fraud ban.

5. **S08-16 (Priority: Medium) — `crates/humoco-node/src/daemon.rs:819`**
   - **Expected vs. Actual Behavior:** Spec 09 section 5.4 / INV-0908 requires merge reseeding from the newly learned aggregate median. If load evidence is absent at a size jump, reseeding is skipped but `prev_total` advances at line 849; already initialized histories cannot use the later cold-start path at line 797.
   - **Reliability Impact:** A real daemon/QUIC probe with initialized write/read baselines 960000/50000 and growth 1→21 learned delayed eligible medians 1999999/500000, yet retained old baselines after subsequent maintenance ticks. A signed status query near 1000000 reads/day received `FLAG_QUOTA_EXCEEDED`, although below five times the peer read median. Ticket timing was accelerated in simulation; no finality claim is made.

### Step-by-Step Implementation Plan (Test-First)

1. **Add Specification Conformance Tests First:**
   - **S05:** In `crates/humoco-node/tests/ingress_accounting_regressions.rs`, independently compute a fixed canonical Friends hash vector. Test registration/listing, quota and activity attribution, revocation and private operator HTTP routes. Update the raw-hash expectation in `ingress/tier.rs:1959`; do not merely assert a helper against itself.
   - **S06 evidence:** In `crates/humoco-node/tests/audit08_09_10_regressions.rs`, cover pending saturation with genuine proofs, duplicate insertion, monotonic completion flags and concurrent flushing. Add real-QUIC fault/forwarding-pressure coverage that clears the fault, sends no new offender attestation and lets the actual production lifecycle persist/forward evidence without a manual flush call. Cover cancellation and shutdown ownership.
   - **S06 friendship:** In `crates/humoco-node/tests/production_readiness_m2_m3_tests.rs`, cover just below/above one-year inactivity, restart and explicit operator reactivation. Use real QUIC to verify expired-edge gossip/clock exclusion and restoration after local reactivation; preserve a valid-friend control.
   - **S08:** In `crates/humoco-node/tests/phase4_net_time_and_quotas.rs`, initialize both histories, let the actual daemon detect a merge without load evidence, then deliver valid signed load heartbeats at unchanged network size. Assert eventual one-time reseeding of all 28 slots from eligible medians and corrected QUIC read-quota behavior. Cover missing/invalid evidence, separate write/read arrival, repeated ticks and normal daily rotation. Do not call seed helpers as a substitute for the production ticker.
   - Demonstrate failing regressions before changing production code. Temporary probe paths in the report are evidence references, not test dependencies.

2. **Implement Minimal Production Fix:**
   - **S05:** Define one canonical `HUMOCO_V1_*` Friends credential hashing helper in the shared crypto layer using the one-byte length prefix. Replace all four raw Friends hashes consistently, preserving normalization and opaque operator identifiers. No separate persisted Friends hash table was found; add no migration, raw-hash fallback or alternate identifier.
   - **S06 evidence:** Replace lossy pending eviction with explicit bounded reservation/backpressure that preserves ownership of unsettled proofs. Keep completion flags monotonic. Connect retries to one bounded, tracked daemon/transport lifecycle, with bounded persistence concurrency, observable errors, cancellation and shutdown handling. Keep RAM guards out of persistence waits; use atomic evidence-plus-ban commits.
   - **S06 friendship:** Deactivate expired direct edges consistently across authorization, heartbeat/reconnect targets, clock samples and startup restoration. Persist enough local state to prevent restart from silently restoring an expired configured edge. Reuse explicit local operator administration for reactivation; do not propagate a ban.
   - **S08:** Retain pending merge-reseed work when eligible load evidence is absent and complete it when the evidence arrives, independently of further size growth and cold-start flags. Track write/read completion as needed; preserve ordinary smoothing, daily rotation, usage counters and unrelated merge readiness behavior. Do not continuously overwrite established histories.
   - **Mandatory uncounted cleanup:** Remove identity-as-ticket compatibility wrappers at `network/manager.rs:2678–2700` and update test callers to explicit ticket APIs. Remove the unauthenticated production client-config fallback at `network/tls.rs:350–385` and its exports; negative TLS tests can use a private test-local fixture. No runtime authentication bypass was demonstrated by these unused production APIs.

3. **Verify Full Workspace Suite:**
   - Run the targeted deterministic and real-QUIC regressions, `cargo test-std`, and `cargo clippy --workspace --all-targets -- -D warnings` until green.
   - Audit validation: Clippy passed; the full socket-enabled suite repeat passed (888 passed, 0 failed, 14 ignored). Its first full run failed at `phase3_integration_tests.rs:393` (`test_phase3_multi_shard_and_hmc_sync`); both an isolated repeat and the full repeat passed. Preserve this validation history and investigate if it recurs. Existing passing tests do not cover the five new findings.

4. **Mandatory Ledger Update (`prompts/AUDIT_STATE.md`):**
   - After all fixes and required checks pass, change only S05, S06 and S08 from `🔴 Fix_Open` to `🟡 ReCheck`, keeping `Clean_Streak = 0`. Preserve totals S05=19, S06=16 and S08=16, plus any later additions. Preserve other slices and let a subsequent independent audit establish Clean.
