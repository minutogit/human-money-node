# Maintenance task: S05 and S06 follow-up findings

You are a Senior Rust Systems Engineer resolving verified specification and
code-quality findings in `human-money-node` (Slices S05 and S06).
Follow all rules in `AGENTS.md`: safe Rust, fallible input handling, checked math,
German user replies and English code/documentation. The network is pre-launch;
use one canonical implementation and remove obsolete compatibility wrappers.

Read `prompts/AUDIT_LOOP.md`, `prompts/AUDIT_STATE.md` and
`prompts/reports/2026-11-09_parallel_recheck_S05_S06_S07.md` first.
Exactly three agents each audited one slice once. S07 has no new verified defect;
do not invent a S07 repair or recount previous findings.

### Verified Findings in Slices S05 and S06

1. **S05-17 (Priority: High) — `crates/humoco-node/src/ingress/tier.rs:613` and `crates/humoco-node/src/storage/db.rs:1117`**
   - **Expected vs. Actual Behavior:** An intact restart must preserve signed EMA
     declarations already published to peers. Admission mutates the thermometer,
     but only `record_declared_usage` durably checkpoints it. Successful genesis
     registration returns at `api/routes.rs:2906` before the allocation at
     `:2919`; signature rejection at `:2876` also follows admission without that
     allocation. The daemon publishes raw values at `daemon.rs:931` without a
     durable snapshot acknowledgment. Even explicit accounting drain is discarded
     by the database high-water comparison at `db.rs:1117–1127` when envelope
     metadata is unchanged, despite changed EMA values and time anchors.
   - **Reliability Impact:** Lawful published state can disappear during sender
     controller reconstruction, and the next signed heartbeat establishes an
     apparent counter conflict that bans the honest identity. A drain-only repair
     cannot protect already published declarations across abrupt interruption.
   - **Verified Reproduction:** Use production `TierController` to admit a write
     with TTL `31_536_000` seconds without `record_declared_usage`. Send a genuine
     signed heartbeat over authenticated local QUIC between direct friends, drain
     accounting, reconstruct the controller using the same `RedbStorage`, and
     send the next heartbeat one second later. Observed:
     `before evidence_write=Some(192000000) banned=false`;
     `after_drain disk_write_scaled=0`;
     `after_restart write=0 banned=true`.
     This executes controller reconstruction and actual QUIC, not a complete
     process restart or database reopen. Both reviewer and coordinator reproduced
     it. All seven existing S05-15 filtered regression tests passed; those
     allocation-based cases do not cover this publication path.

2. **S06-11 (Priority: Medium) — `crates/humoco-node/src/daemon.rs:782`**
   - **Expected vs. Actual Behavior:** Spec 07 section 4 / INV-0705 requires
     dormant remote admission metadata to expire after 60 days of actual
     inactivity. `network/manager.rs:1418–1449` includes qualified dormant nodes
     within retention but exports only `(NodePubKey, HrwRoutingId)`.
     The daemon substitutes `now_ms` for both observation timestamps, and
     `storage/db.rs:890` persists `max(old_last_seen, now_ms)`. A maintenance tick
     therefore fabricates a recent observation; startup retention at
     `daemon.rs:573` trusts that refreshed timestamp.
   - **Reliability Impact:** An expired remote identity can recover its old
     qualification after restart and enter a committee after one heartbeat,
     rather than accumulate the required newcomer observations again.
   - **Verified Reproduction:** A mined, qualified remote ticket last seen 59
     days ago is passed through the production snapshot, exact daemon ticker
     mapping and redb writer. Reopen the database, advance controlled network
     time by two days, restore via the boot mapping and deliver one genuine
     origin-signed heartbeat through an authenticated QUIC friend. Observed:
     `actual_absence_days=61 persisted_absence_days=2
     disk_last_seen_artificially_advanced=true no_ticker_control_eligible=false
     after_single_quic_heartbeat_member=true`.
     This uses controlled time and the daemon's source-traced mappings, not a
     continuously running daemon observed for 61 days. Reviewer and coordinator
     independently reproduced it. Existing S06-10 coverage bypasses the faulty
     ticker transformation by supplying observation timestamps directly.

### Step-by-Step Implementation Plan (Test-First)

1. **Add Specification Conformance Tests First:**
   - In `crates/humoco-node/tests/ingress_accounting_regressions.rs`, cover a
     successful authenticated genesis registration followed by heartbeat
     publication with no spend allocation. Assert that every published EMA and
     its fixed-point time anchor is already durable. Also cover admission
     followed by signature rejection or cancellation before allocation.
   - Add an EMA-only snapshot/drain case with unchanged envelope day, sequence,
     cumulative usage and timestamp. Assert exact fractional state survives
     reconstruction and elapsed-time decay. Cover stale concurrent snapshots
     and persistence failure without publishing an unacknowledged declaration.
   - Add real-QUIC direct-friend heartbeat regressions matching S05-17: receive
     the first signed nonzero evidence, interrupt without graceful drain,
     restore from intact storage and receive the next heartbeat without a ban.
     Include database-reopen coverage and a genuine conflicting-evidence
     control. Distinguish controller, database and process lifecycle coverage.
   - In `crates/humoco-node/tests/production_readiness_m2_m3_tests.rs`, extend
     S06-10 with the actual periodic-persistence helper used by the daemon:
     qualified remote last seen 59 days ago, maintenance ticks without new
     heartbeat, redb reopen at actual absence 61 days, one fresh heartbeat.
     Assert original last-seen time is preserved and prior qualification is
     not reused. Include a retained-history control within 60 days and a
     genuine observation that legitimately advances last-seen time.
   - Add real-QUIC delivery to that retention regression, using a properly mined
     remote ticket and controlled time. Keep actual liveness, ticket incubation
     and metadata retention distinct. Demonstrate the regressions fail before
     changing production code.

2. **Implement Minimal Production Fix:**
   - In `ingress/tier.rs`, expose coherent fallible durable EMA snapshots for
     signed producers. Update daemon heartbeat publication and inspect status/
     live producers. Preserve read-service isolation, physical-time decay,
     bounded queues, exact commit acknowledgments and short RAM critical
     sections. Never hold a guard across persistence or perform unmanaged
     synchronous disk I/O on a runtime thread.
   - Update `store_ingress_accounting_state` and its worker to order EMA-only
     snapshots safely even when envelope metadata is unchanged. Distinguish a
     truly identical snapshot from a newer checkpoint; reject stale overwrite.
     Do not order snapshots by raw EMA maxima because lawful decay decreases
     values. Return accounting-drain failures truthfully. Preserve existing
     S05-15 repairs, genesis root-only semantics and fraud-verification rules.
   - Replace the lossy ticket snapshot/ticker mapping with one canonical record
     carrying actual observation anchors. Local maintenance must never refresh
     a remote observation without a genuine accepted heartbeat. Preserve
     real ticket maturation age and initial-admission qualification across
     restart. Use a shared production helper in the retention regression rather
     than merely copying the faulty mapping into a test.
   - Preserve the separate local ticket handling and direct-friend policy;
     do not introduce a new reentry rule or shorten required incubation.

   **Mandatory pre-launch cleanup (not additional counted findings):**
   - Remove these verified unused compatibility wrappers in
     `network/manager.rs`: `handle_node_id_migration` (`:2655`),
     `hrw_for_node` (`:2682`), `effective_hrw_for_scoring` (`:2693`) and
     `get_routing_id` (`:2696`). Retain the canonical implementations.
   - Remove `build_quinn_client_config_with_identity_with_network` in
     `network/tls.rs:350` and its re-export in `network/mod.rs:24`.
     Repository search finds no callers for these five wrappers; the TLS name
     appears only in its definition and re-export. Do not replace them with
     deprecated aliases or migration shims.

3. **Verify Full Workspace Suite:**
   - Run focused regression tests with real QUIC, then `cargo test-std` and
     `cargo clippy --workspace --all-targets -- -D warnings` until green.
   - Audit validation passed Clippy, but the unfiltered default test run failed
     at `node_001_003_integration_tests.rs:520` in
     `test_post_v1_lock_v4_signature_and_clock_drift` with HTTP 503 instead of
     201. An immediate isolated rerun passed. Recheck this default-suite
     stability issue; do not infer a production cause or remove the assertion
     solely from that discrepancy. The remainder run skipping only that test
     passed: 869 passed, 14 ignored, 1 filtered out; this is not an unfiltered
     default-suite pass.
   - Report exact executed checks and any remaining validation limits.

4. **Mandatory Ledger Update (`prompts/AUDIT_STATE.md`):**
   - Once repairs and required checks pass, update only **S05** and **S06**:
     keep `Clean_Streak=0`, retain `Total_Finds=17` / `11` respectively, and
     change `🔴 Fix_Open` to `🟡 ReCheck`. Preserve later independent updates.
   - Keep **S07** at `Clean_Streak=1`, `Total_Finds=12`,
     `Last_Run=2026-11-09`, `🟢 Clean` unless new independently verified work
     requires a separate change. A future confirming audit establishes Clean
     for the repaired slices.
