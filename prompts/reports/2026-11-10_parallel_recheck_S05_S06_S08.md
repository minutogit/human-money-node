# Parallel follow-up audit: S05, S06 and S08

Date: 2026-11-10. Reviewed revision:
`1c5cd08e0e0db0d7227a192694c01d3b003e7b22`.
The working tree was clean before the audit.

Exactly three agents each executed `prompts/AUDIT_LOOP.md` once, reviewing one
distinct slice. Initial baseline passes were complete; the coordinator assigned
S05, S06 and S08 from Priority 2 ReChecks in slice order. Each agent updated only
its own ledger row. The coordinator independently inspected the new source
traces and temporary probe sources and repeated all four reproductions.
No file under `crates/` was modified. No production repair was implemented.

## Results

| Slice | New verified findings | Clean_Streak | Total_Finds | Last_Run | Status |
| --- | --- | ---: | ---: | --- | --- |
| S05 | S05-18, Medium | 0 | 18 | 2026-11-10 | `Fix_Open` |
| S06 | S06-12, High; S06-13, High | 0 | 13 | 2026-11-10 | `Fix_Open` |
| S08 | S08-15, Medium | 0 | 15 | 2026-11-10 | `Fix_Open` |

Four new findings. Prior repaired findings were rechecked rather than counted
again. All other ledger rows were preserved.

### S05-18: Chain admission charges one lock's Byte-Years for several new locks

Primary references: `crates/humoco-node/src/api/routes.rs:3465` and
`crates/humoco-node/src/ingress/tier.rs:1496`.

Spec 09 section 1.1 defines storage-time accounting per stored lock. Chain
admission passes a single TTL to the controller, which charges one footprint
to VIP credit, rolling tier quotas and the write thermometer. Its signed
declaration already multiplies the footprint by chain length at
`api/routes.rs:3520` and `:3690`.

The probe separately anchored a root, provisioned 192 Byte-Years of VIP credit,
and submitted two valid new spend locks with approximately one year remaining
through the production HTTP router. Both spends committed:

```text
status=201 Created hops=2 committed_spend_locks=2
balance_before=192 balance_after=Some(0) vip_usage=192
write_ema=191999994 declared_cumulative=383999988
```

Reviewer and coordinator reproduced this result. This uses Axum router
execution and durable storage, not a TCP HTTP client or a new QUIC reproduction.
Root-registration cost is excluded from the two-spend comparison. The A25-R2
archive requirement concerns terminal-parent PoW binding; it does not authorize
flat Byte-Years billing for arbitrary batch lengths. No consensus failure or
identity sanction was demonstrated.

Probe source/binary: `/tmp/s05_chain_accounting_probe.rs`,
`/tmp/s05_chain_accounting_probe`. Reviewer log:
`/tmp/humoco-audit-2026-11-10-s05-chain-accounting.log`.

### S06-12: Equivocation observation blocks a runtime thread under a RAM guard

Primary reference: `crates/humoco-node/src/network/manager.rs:1657`.

The asynchronous `verify_peer_attestation` at `api/routes.rs:950` invokes
`observe_verified_original_attestation` inline. The cache mutex acquired at
`network/manager.rs:1627` remains held across the synchronous redb write
transaction and commit at `storage/db.rs:781` and `:788`. This violates
INV-1503's nonblocking network runtime and guard requirements.

The probe supplied two genuine incompatible approvals to the production async
verifier on a current-thread Tokio runtime while a separate OS thread held
another redb writer for 250 ms. Coordinator reproduction:

```text
conflict_accepted=false verification_elapsed_ms=259
independent_10ms_timer_elapsed_ms=259 durable_ban=true
```

The reviewer observed 260 ms. This establishes runtime starvation and the
source establishes cache-lock retention. It is a component reproduction, not
a real-QUIC test or a measured failure of the complete 800 ms checkout budget.

Probe source/binary: `/tmp/humoco_s06_blocking_probe.rs`,
`/tmp/humoco_s06_blocking_probe`.

### S06-13: Failed persistence and full forwarding queue lose verified evidence

Primary reference: `crates/humoco-node/src/network/manager.rs:1664`.

The same observation path logs a storage error but returns `Some(proof)` and
continues RAM containment and forwarding. The caller at `api/routes.rs:951`
discards the returned proof through `is_some()`. Forwarding ignores a failed
`try_send` at `network/manager.rs:1817`; `ObservedVoteCache` retains only the
first approval at `:634–636`. No retained second approval or pending proof
remains when both persistence and forwarding fail. INV-1402 requires evidence
ownership until durable storage and honest failure reporting.

A temporary redb backend injected a write error while the forwarding channel
was filled with an unrelated sentinel. Reviewer and coordinator reproduced:

```text
injected_write_failure=true proof_returned=true ram_banned=true
proof_queued=false reopened_durable_ban=false
```

The same backend was reopened after clearing the injected fault. The proof's
only surviving local copy in this component probe was the observer's return
value, which the production caller discards. RAM containment is not itself
the defect; losing evidence and suppressing persistence failure are. This is
a component/fault-injection result; no new QUIC execution is claimed.

Probe source/binary: `/tmp/humoco_s06_commit_failure_probe.rs`,
`/tmp/humoco_s06_commit_failure_probe`.

### S08-15: Delayed peer evidence does not complete cold-start initialization

Primary reference: `crates/humoco-node/src/daemon.rs:769`.

INV-0907 requires a joining node to initialize its thermometer history from
eligible peer observations. The only autonomous peer-median sampling is inside
the network-size merge branch at `daemon.rs:769–773`. The cold-start seed
helpers have no production callers. If load evidence arrives after initial
growth, unchanged network size prevents completing peer-based initialization.

The component and real-QUIC probes use twenty known remote identities plus
self. Initial merge reseeding without load evidence produces a read NCB of
192000. A genuine signed status request is accepted and establishes a peer
read median of 500000. A later request with daily rate approximately 1000000
is rejected by the unchanged local baseline, despite being below five times
the observed median. Coordinator's authenticated QUIC reproduction:

```text
seq=1 declared_ema=721348 known_peer_medians=(960000, 500000)
local_read_ncb=192000 quota_rejected=false size=21 unchanged_size_merge=false
seq=2 declared_ema=1442696 known_peer_medians=(960000, 500000)
local_read_ncb=192000 quota_rejected=true size=21 unchanged_size_merge=false
client_192001=Err(ReadQuotaExceeded { available: 192000, required: 192001 })
seeded_control_client_192001=Ok(())
```

The read limits consume the local baseline at `network/transport.rs:1523–1528`
and `ingress/tier.rs:1123–1125`. The manual seed is a comparison control, not
the production fix. The probes execute authenticated QUIC and production
handlers, with simulated ticket timing; the autonomous daemon ticker is
source-verified and not executed by these probes. No committee-admission
property is inferred from the simulated fixture.

Probe sources/binaries: `/tmp/humoco_s08_seed_probe.rs`,
`/tmp/humoco_s08_seed_probe`, `/tmp/humoco_s08_seed_wire_probe.rs`,
`/tmp/humoco_s08_seed_wire_probe`. Coordinator log:
`/tmp/humoco-audit-2026-11-10-s08-wire-coordinator.log`.

## Coverage

- S05: all four target files, including embedded tests; direct proto PoW,
  quota/EMA, fraud, redb accounting/credentials, API chain/single/read,
  operator-token and daemon-heartbeat paths. Existing S05-01 through S05-17
  repairs and related S08 fractional-accounting regressions were considered.
- S06: all five target files, including embedded tests; direct transport,
  API original-vote collection, database and daemon paths. Clock input gating,
  ticket maturity/retention, subjective liveness, TLS identity binding and
  first-party fraud requirements were reviewed against their specifications.
  Existing healthy-commit tests do not cover contention or failed persistence
  combined with a full forwarding queue.
- S08: all existing targets (`quota.rs`, `storage.rs`, `client_flow.rs`) and
  direct TTL/root, HRW, tier, daemon and receiver dependencies. Historical
  targets `ceh/`, `p0/`, `state_machine.rs` and `transport.rs` are absent; this
  ledger scope drift is documented, not counted as a code defect. Existing
  S08-11 through S08-14 repairs were confirmed. Focused existing S08 and Spec 09
  binaries passed 8 and 13 tests respectively.

No additional verified obsolete compatibility structures were identified for
deletion in this pass. Superseded implementations of the reported paths must
be removed during maintenance rather than retained as fallbacks.

## Central validation

- `cargo clippy --workspace --all-targets -- -D warnings`: passed, exit 0.
  Log: `/tmp/humoco-audit-2026-11-10-clippy.log`.
- Initial sandboxed `cargo test-std`: exit 101; 213 node library tests passed,
  three failed because local QUIC binding was disallowed (`EPERM`). This
  environmental restriction is not counted as a defect. Log:
  `/tmp/humoco-audit-2026-11-10-test-std.log`.
- Full `cargo test-std` with local socket access: passed, exit 0; all 89 result
  groups completed, **877 passed, 0 failed, 14 ignored, 0 filtered out**. Log:
  `/tmp/humoco-audit-2026-11-10-test-std-network.log`.
- The coordinator independently repeated S05's router probe, both S06
  component probes and S08's component and authenticated QUIC probes. Their
  successful reproduction of defective outcomes is not a passing new
  specification regression.

Counts from focused checks overlap the full suite. No ignored deep simulations
were run. Temporary probes are not permanent repository tests. Passing existing
tests does not invalidate the newly verified boundary findings.

Use the [combined maintenance prompt](2026-11-10_S05_S06_S08_REMEDIATION_PROMPT.md).
