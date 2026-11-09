# Parallel follow-up audit: S05, S06 and S07

Date: 2026-11-09. Reviewed revision:
`c01b022006b86d0515a5481b4bcaab0922521a83`.
The working tree was clean before the audit.

Exactly three agents each executed `prompts/AUDIT_LOOP.md` once, reviewing one
distinct slice. All initial baseline passes were complete; S05, S06 and S07 were
assigned from Priority 2 ReChecks in slice order. Each agent changed only its own
ledger row. The coordinator checked the new source traces and probe sources,
independently repeated both QUIC reproductions, and prepared the combined prompt.
No file under `crates/` was modified by this audit.

## Results

| Slice | New verified findings | Clean_Streak | Total_Finds | Last_Run | Status |
| --- | --- | ---: | ---: | --- | --- |
| S05 | S05-17, High | 0 | 17 | 2026-11-09 | `Fix_Open` |
| S06 | S06-11, Medium | 0 | 11 | 2026-11-09 | `Fix_Open` |
| S07 | None | 1 | 12 | 2026-11-09 | `Clean` |

Two new findings. Prior repaired findings were rechecked rather than counted
again. Clean is the result of this review, not a formal proof or a claim of
workspace-wide specification conformance.

### S05-17: Heartbeat EMA publication can precede recoverable persistence

Primary references: `ingress/tier.rs:613`, `storage/db.rs:1117` under
`crates/humoco-node/src/`.

Admission changes the thermometer, but successful genesis registration returns
at `api/routes.rs:2906` before `record_declared_usage` at `:2919`. Signature
rejection at `:2876` also occurs after admission. The heartbeat producer at
`daemon.rs:931` publishes raw values independently of an accounting allocation.
An explicit drain exports the changed EMA, but the database treats matching
envelope metadata as identical without considering the EMA fields or anchors.
The recovered controller can therefore publish less than its own previous
signed heartbeat justifies, causing counter-conflict sanctions.

The standalone production-library probe admitted a one-year write without
`record_declared_usage`, delivered a signed heartbeat over authenticated local
QUIC, drained accounting, reconstructed the controller from the same storage
handle and delivered the next heartbeat one second later:

```text
before evidence_write=Some(192000000) banned=false
after_drain disk_write_scaled=0
after_restart write=0 banned=true
```

The reviewer and coordinator both reproduced this result. This is actual QUIC
and controller reconstruction, not a full daemon/process restart or redb reopen.
The genesis path was source-traced, not driven through HTTP in this probe.
The peer-manager ban was observed; no additional claim about disk-ban inspection
is needed for this finding. Read-only zero-sequence evidence alone was not used
to claim a ban. All seven existing filtered S05-15 tests passed; their allocation
path does not cover this missing durable-publication boundary.

Probe source/binary: `/tmp/s05_quic_probe.rs`, `/tmp/s05_quic_probe`.
Independent rerun log: `/tmp/humoco-audit-S05-S06-S07-s05-repro.log`.
The reviewer also executed a separate signature/conflict probe at
`/tmp/s05_probe`, confirming valid signatures and `heartbeat_conflict=true`.

### S06-11: Periodic persistence invents recent remote presence

Primary reference: `crates/humoco-node/src/daemon.rs:782`.

The qualified-ticket snapshot at `network/manager.rs:1418–1449` retains dormant
qualified nodes inside retention but returns only identity/ticket pairs.
The daemon maps each pair to timestamps equal to ticker execution time.
`storage/db.rs:890` retains the maximum last-seen timestamp, so this maintenance
operation refreshes inactivity without a heartbeat. Boot filtering at
`daemon.rs:573` then trusts the artificial timestamp, defeating Spec 07 section 4
/ INV-0705's 60-day remote history retention.

The production snapshot and exact ticker mapping were executed with a qualified,
mined remote ticket last seen 59 days ago. After writing and reopening redb,
advancing controlled network time two days and applying the boot mapping, one
origin-signed heartbeat was delivered through an authorized QUIC relay:

```text
RETENTION actual_absence_days=61 persisted_absence_days=2 disk_last_seen_artificially_advanced=true no_ticker_control_eligible=false after_single_quic_heartbeat_member=true
```

Both reviewer and coordinator reproduced it. The no-ticker control remained
ineligible. This executes real QUIC and redb reopen with simulated inactivity;
it is not a 61-day continuous daemon run. The daemon mapping is source-traced
and copied exactly in the probe rather than executed inside a full daemon.
The follow-up regression must exercise a shared production persistence helper.

Probe source/binary: `/tmp/humoco_s06_20261109_retention_probe.rs`,
`/tmp/humoco_s06_20261109_retention_probe`.
Independent rerun log: `/tmp/humoco-audit-S05-S06-S07-s06-repro.log`.

## Coverage and focused verification

- **S05:** Completely read `ingress/{mod,pow,tier}.rs` and `api/auth.rs`.
  Direct paths included shared proto PoW, core quotas/thermometer, database
  accounting/credentials, control token parsing, daemon heartbeat publication,
  HTTP genesis/admission, live-read declarations and accounting regressions.
  Existing S05-11 through S05-16 repairs were considered. Seven filtered S05-15
  tests passed. One new finding was established by the independent probes.
- **S06:** Completely read `network/{clock,discovery,peer,manager,tls}.rs`,
  6,397 lines including tests. Direct paths included framing/transport, daemon
  boot/ticker and database observation records; Specs 03/07/11 and registry were
  consulted. Network library tests: 56 passed. Focused S06 admission-window
  regressions: 2 passed. Existing S06-08 QUIC and S06-10 QUIC/restart tests:
  1 passed each. The new ticker transformation is outside the old S06-10 test.
  A possible direct-friend deactivation concern was not counted as verified.
- **S07:** Completely read all 12 target files: seven proto modules and core
  `crypto`, `resolver`, `types`, `wire`, `fraud`. Direct paths included quota
  math, live/HMC adapters, root/storage handling, transport and ingress.
  Proto/core library checks: 20 + 43 passed. Fraud integration checks: 17 passed.
  Existing S07 QUIC regression coverage was source-traced; full execution is
  covered by the central suite when reached. S07-12's revised scaled lower
  bound and prior contextual verification repairs were rechecked.

Counts overlap central-suite tests and must not be added as distinct coverage.
No permanent regression or production fix was added. Ignored deep simulations
were not run. Temporary probes are local artifacts, not durable repository tests.

## Central validation

- `cargo clippy --workspace --all-targets -- -D warnings`: passed, exit 0.
  Log: `/tmp/humoco-audit-S05-S06-S07-clippy.log`.
- Initial sandboxed `cargo test-std`: three local QUIC bind failures due to
  `Operation not permitted`; 213 node library tests passed. These environmental
  restrictions are not findings. Log:
  `/tmp/humoco-audit-S05-S06-S07-test-std.log`.
- Socket-enabled `cargo test-std`: failed, exit 101. Completed result groups
  reported 544 passed and 1 failed before the remaining binaries were reached.
  Failure: `test_post_v1_lock_v4_signature_and_clock_drift` at
  `crates/humoco-node/tests/node_001_003_integration_tests.rs:520`, HTTP 503
  instead of 201 for the past-created-at acceptance assertion.
  Log: `/tmp/humoco-audit-S05-S06-S07-test-std-network.log`.
- Immediate isolated exact rerun of that test: passed, exit 0, 1 passed.
  Log: `/tmp/humoco-audit-S05-S06-S07-isolated.log`. This does not establish
  default-suite stability or identify a production cause.
- `cargo test-std -- --skip test_post_v1_lock_v4_signature_and_clock_drift`
  with socket access: passed, exit 0. All 89 result groups completed:
  **869 passed, 0 failed, 14 ignored, 1 filtered out**. This verifies the
  remainder, including the previously unreached binaries; it is not a green
  unfiltered default-suite run. Log:
  `/tmp/humoco-audit-S05-S06-S07-test-std-remainder.log`.
- Both new local-QUIC probe reruns passed their reproduction assertions and
  yielded the defective outcomes above. Passing a reproduction is evidence of
  the reported behavior, not a passing specification regression.

## Cleanup and handoff

Repository search verified five unused compatibility wrappers in S06:
`handle_node_id_migration`, `hrw_for_node`, `effective_hrw_for_scoring`,
`get_routing_id` in `network/manager.rs`, and
`build_quinn_client_config_with_identity_with_network` in `network/tls.rs` with
its `network/mod.rs` re-export. Their deletion belongs in the maintenance work
under the mandatory pre-launch policy; they are not additional counted defects.
Active test callers of other aliases were not described as dead code.

Use the [combined maintenance prompt](2026-11-09_S05_S06_S07_REMEDIATION_PROMPT.md).
It includes the two verified findings, regression-first instructions, cleanup,
validation caveats and the S05/S06 `Fix_Open` to `ReCheck` transitions after
successful repair. This audit did not implement those repairs.
