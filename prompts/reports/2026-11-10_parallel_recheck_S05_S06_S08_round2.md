# Parallel follow-up audit: S05, S06 and S08 — second pass

Date: 2026-11-10. Reviewed revision:
`120b9e76552c262e2befb401eae17b1715129574`. Initial working tree: clean.

Exactly three agents each executed `prompts/AUDIT_LOOP.md` once. Each selected
one distinct Priority 2 ReCheck slice in slice order: S05, S06 and S08. Each
updated only its own ledger row. No file under `crates/` was changed, and no
production fix or permanent regression test was implemented. Previous reports
from the same date are preserved.

## Results

| Slice | New verified findings | Clean_Streak | Total_Finds | Last_Run | Status |
| --- | --- | ---: | ---: | --- | --- |
| S05 | S05-19, Medium | 0 | 19 | 2026-11-10 | `Fix_Open` |
| S06 | S06-14, High; S06-15, High; S06-16, Medium | 0 | 16 | 2026-11-10 | `Fix_Open` |
| S08 | S08-16, Medium | 0 | 16 | 2026-11-10 | `Fix_Open` |

Five new findings. Previously repaired findings were inspected and were not
counted again. All other ledger rows were preserved.

## Verified findings and evidence

### S05-19 — Friends credential hashes omit domain separation

Spec 13 section 3 (`docs/13_client_ingress_und_access_tiering.md:49`) and
AGENTS Rule 5 require canonical length-prefixed credential hashing. Friends
registration, quota accounting, diagnostic lookup and admission metadata use
bare BLAKE3 at `crates/humoco-node/src/ingress/tier.rs:1415`, `:1230`, `:1486`
and `:1655`. The existing removal test at `:1959` also requires that encoding.

All four paths agree today but omit the required purpose binding. Partial
replacement would disconnect accounting or activity from registration. No
collision or disclosure of a secret was demonstrated. This is a source-verified
encoding mismatch, not a new transport reproduction.

### S06-14 — Pending capacity evicts unsettled fraud evidence

At `crates/humoco-node/src/network/manager.rs:673`,
`ObservedVoteCache::insert_pending_evidence` evicts its oldest pending item
without checking durability or forwarding completion. This violates Spec 14 /
INV-1402's evidence ownership requirement during persistence failure.

The temporary component probe `/tmp/humoco_s06_probe.rs` uses a capacity-one
cache and two genuinely signed, first-party-verified fraud proofs. Inserting
the second removes the first uncommitted and unforwarded proof. The coordinator
read the probe and independently repeated it successfully. Production capacity
is 4096; the same unconditional eviction branch applies at that boundary.
This component probe does not establish a new end-to-end QUIC failure.

### S06-15 — Pending fraud evidence has no autonomous retry lifecycle

The only production invocation of `flush_pending_slashing_evidence` is at
`crates/humoco-node/src/network/manager.rs:1708`, after another original
attestation from the same offender. The definition is at `:1828`. Neither
daemon maintenance nor the transport forwarding consumer schedules this retry.
Existing S06-13 regressions manually call the flush API after clearing faults.

Below cache capacity, a temporary failed commit or full forwarding channel can
therefore leave evidence unsettled even after the resource recovers. Evidence
ownership was added by the previous repair; production retry progress without
remote resubmission remains absent. This finding is source/call-graph verified,
distinct from capacity-driven evidence loss in S06-14.

### S06-16 — Annual friendship expiry does not deactivate the edge

Spec 07 section 4 (`docs/07_admission_und_wot_buergschaften.md:83`, INV-0705)
requires explicit operator reactivation after a year of direct-edge inactivity.
`crates/humoco-node/src/network/manager.rs:4293` prunes only known-node metadata;
the friendship map and F2F peer entries remain authorized. Identity-based gossip
and direct RPC checks at `:3414` and `:3436` still succeed.

The same temporary component probe sets a direct friend's last observation to
more than 365 days ago and invokes production pruning. Known-node information
is removed, while `is_f2f_friend`, `can_accept_gossip` and
`can_authorize_direct_rpc` all remain true. The coordinator independently
repeated this result. No new real-QUIC test was added; transport rejection and
operator reactivation coverage are required in the maintenance task.

### S08-16 — Delayed merge evidence cannot reseed initialized histories

Spec 09 section 5.4 / INV-0908 requires merge reseeding from the newly learned
aggregate median. At `crates/humoco-node/src/daemon.rs:819` the actual merge
reseed is skipped when load evidence is unavailable, but `prev_total` advances
at `:849`. Later evidence cannot use cold-start initialization at `:797` if
the histories were already initialized.

The temporary test `/tmp/humoco_s08_delayed_merge_probe.rs` derives from the
existing daemon QUIC regression. It initializes write/read histories to
960000/50000, lets the real daemon detect growth from 1 to 21 without load
evidence, then sends genuine signed heartbeats without further size growth.
Eligible medians become `Some(1999999)` and `Some(500000)`, but after six
seconds of maintenance ticks the histories remain at 960000/50000. A genuine
signed status query near 1000000 reads/day receives `FLAG_QUOTA_EXCEEDED`
(256), below five times the eligible read median (2500000).

The coordinator independently read and repeated this probe. Its log at
`/tmp/humoco-audit-three-s08-merge-coordinator.log` confirms the same medians,
unchanged baselines and quota flag. The expected-success quota assertion fails
(exit 101), which reproduces the defect; this is not a passing regression.
The probe also records orderly daemon shutdown (`DAEMON_RESULT Ok(())`).

The probe accelerates ticket timing in simulation; it does not establish
committee admission or finality. The existing cold-start regression exercises
uninitialized histories and does not cover this merge case. This is a separate
merge transition from the repaired S08-15 cold-start transition.

## Review coverage and cleanup

- S05: all four target files, direct HTTP/operator, credential, quota/EMA,
  persistence and canonical crypto callers; previous S05 fixes considered.
- S06: all five target files, direct transport, daemon, database, clock,
  authorization, ticket/presence and original-approval callers.
- S08: all existing targets (`quota.rs`, `storage.rs`, `client_flow.rs`) and
  direct HRW, root/TTL, tier, daemon and transport dependencies. Historical
  `ceh/`, `p0/`, `state_machine.rs` and `transport.rs` targets remain absent;
  this ledger scope drift is not counted as a code defect.

The pre-launch cleanup work includes the explicit identity-as-ticket legacy
wrappers at `network/manager.rs:2678–2700` and the unauthenticated production
TLS builder at `network/tls.rs:350–385`. Search found test callers rather than
runtime callers. Remove these obsolete production APIs and use explicit
ticket/identity fixtures; negative TLS tests may retain a private test-local
builder. This is an uncounted cleanup obligation, not a demonstrated runtime
authentication bypass. Audit read-only rules defer deletion to maintenance.

## Central validation

- `cargo clippy --workspace --all-targets -- -D warnings`: passed, exit 0.
  Log: `/tmp/humoco-audit-three-clippy.log`.
- Initial sandboxed `cargo test-std`: exit 101; 213 node library tests passed,
  three failed because QUIC socket binding was disallowed (`EPERM`). This is
  an environment restriction, not a code finding. Log:
  `/tmp/humoco-audit-three-test-std.log`.
- First socket-enabled `cargo test-std`: exit 101, with 598 passing tests and
  one failure across 45 completed groups. The failure was
  `test_phase3_multi_shard_and_hmc_sync` at
  `crates/humoco-node/tests/phase3_integration_tests.rs:393`
  (empty `hmc_locks`, expected nonempty). Log:
  `/tmp/humoco-audit-three-test-std-network.log`.
- An isolated rerun of that exact test passed (1 passed, 2 filtered out).
  Log: `/tmp/humoco-audit-three-phase3-isolated.log`. The failure was not
  reproduced in isolation and is not counted as a newly diagnosed defect.
- Full socket-enabled `cargo test-std` repeat: passed, exit 0; all 89 result
  groups completed, **888 passed, 0 failed, 14 ignored, 0 filtered out**.
  The previously failing multi-shard test passed in this full run as well.
  Log: `/tmp/humoco-audit-three-test-std-retry.log`.
- `git diff --check`: passed. `git diff -- crates` is empty. Ledger/report/
  prompt consistency was checked for all five finding IDs and the three totals.

Focused executions overlap the suite. Temporary probes are not permanent
regressions. No ignored deep simulations were run. Existing passing tests do
not invalidate source-verified defects or the new failing S08 boundary probe.

Use the [combined maintenance prompt](2026-11-10_S05_S06_S08_round2_REMEDIATION_PROMPT.md).
