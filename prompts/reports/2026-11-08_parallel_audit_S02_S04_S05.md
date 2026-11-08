# Parallel follow-up audit: S02, S04 and S05

Date: 2026-11-08. Reviewed revision: `543b1d0dab881052330b23cbb469129096ab482d`.
The working tree was clean before the review.

Exactly three agents each executed one review under `prompts/AUDIT_LOOP.md`.
All slices had completed their initial baseline, so three distinct ReCheck
slices were assigned in slice order: S02, S04 and S05. Each agent updated only
its assigned ledger row. The coordinator checked the source traces, reran all
four production-library reproductions and created this report and the combined
maintenance prompt. No files under `crates/` were modified.

## Results

| Slice | New findings | Clean_Streak | Total_Finds | Last_Run | Status |
| --- | ---: | ---: | ---: | --- | --- |
| S02 | 1 | 0 | 14 | 2026-11-08 | `Fix_Open` |
| S04 | 1 | 0 | 18 | 2026-11-08 | `Fix_Open` |
| S05 | 2 | 0 | 14 | 2026-11-08 | `Fix_Open` |

Earlier findings were not counted again. In particular, the current code
contains the S02-13 persistence service semaphores, S04-17 full-stream framing
validation and S08-11 fractional EMA changes. The new findings concern a
preceding shared pending-operation gate, a distinct roster size mismatch and
two remaining ingress paths. This report does not claim workspace-wide
specification conformance or implementation of any repair.

## Verified findings

### S02-14 — Medium — Shared pending-approval gate defeats internal reservations

Expected: Spec 14 §4.1, lines 145–147, and INV-1307 require separately protected
bounded internal service capacity. Observed: `storage/engine.rs:1136` rejects a
new approval when the shared pending map reaches 256 entries, before selecting
the service semaphore at line 1141. Public HTTP self-votes at
`api/routes.rs:1772` and Internal QUIC approvals at `network/transport.rs:1464`
share this gate. The latter maps failure to `FLAG_NOT_READY` at line 1482.

A controlled unconsumed persistence channel with capacity 1024 and 256 distinct
pending Public approvals produced:

```text
public_pending=256, internal_permits_before=2000, internal_permits_after=2000,
result=Err(DurableCommitFailed("Approval capacity exhausted"))
```

The coordinator reran `/tmp/s02_pending_probe`, linked from
`/tmp/s02_pending_probe.rs` against the reviewed production library. Existing
S02-13 coverage at `tests/s02_regressions.rs:1949` uses only five Public and two
Internal slots and does not reach this gate. This is an availability/isolation
defect, not demonstrated premature signature release or conflicting voting.
No new real-QUIC reproduction of this pending-map boundary was executed.

### S04-18 — Medium — Valid local rosters exceed their payload ceiling

`network/framing.rs:1368` accepts 64 visible neighbors and
`network/f2f_collab.rs:333` builds up to 64. The current serialization needs
`51 + 32*N` bytes, so the 2048-byte ceiling at `framing.rs:1379` permits only
62. `network/transport.rs:3307` silently skips the entire roster on encoding
failure. Consequently, 63 or more visible friends prevent diagnostic neighbor
updates from reaching the direct friend.

Codec reproduction, rerun by the coordinator:

```text
friends=62 visible=62 hidden=0 validate=Ok encode=Ok(2035)
friends=63 visible=63 hidden=0 validate=Ok encode=Err(payload exceeds 2048)
friends=64 visible=64 hidden=0 validate=Ok encode=Err(payload exceeds 2048)
friends=65 visible=64 hidden=1 validate=Ok encode=Err(payload exceeds 2048)
```

A real-QUIC reproduction was executed by the reviewer and independently rerun
by the coordinator with local socket permission:

```text
real QUIC friends=62, received roster=Some(62)
real QUIC friends=63, received roster=None
real QUIC friends=64, received roster=None
```

Sources/binaries: `/tmp/humoco_s04_roster_probe.rs`,
`/tmp/humoco_s04_roster_probe`, `/tmp/humoco_s04_roster_quic_probe.rs` and
`/tmp/humoco_s04_roster_quic_probe`. The combined prompt retains the 2048-byte
ceiling and shares one derived 62-entry bound between builder and validator,
accounting for excess candidates as hidden. No protocol limit expansion or
new gossip stream is required.

### S05-13 — High — VIP ignores authoritative fractional quota rejection

`ingress/tier.rs:1307` uses rounded-down `usage_at()` as its admission check.
After debiting purchased credits, line 1341 discards the fractional
`try_consume()` result. At a fractional boundary, accepted writes therefore
consume credits while their rolling usage is not recorded, contrary to
INV-0904 and the counter contract in `humoco-sim-core/src/quota.rs:549,577`.

The production-tier probe consumed the 4,800,000-unit daily limit at
`1_000_000_000_000 ms`, advanced one second and consumed recovered whole units
until less than one unit remained. Its output, independently rerun:

```text
limit=4800000, usage=4799999
canonical quota result=Err(QuotaExceeded { available: 0, required: 1 })
VIP attempt 0: Ok(Tier1Vip); usage=4799999, balance=Some(9999)
VIP attempt 1: Ok(Tier1Vip); usage=4799999, balance=Some(9998)
VIP attempt 2: Ok(Tier1Vip); usage=4799999, balance=Some(9997)
```

The same probe confirmed correct fractional rejection in Friends/read paths.
Existing fractional tests at `tests/ingress_accounting_regressions.rs:2771`
exercise reads, not this VIP branch. No new HTTP regression for this sequence
was executed; one is required in the maintenance prompt.

### S05-14 — Medium — Sequence leasing releases uncommitted accounting

`ingress/tier.rs:455` promises durable accounting before allocation release.
However, line 550 waits for its acknowledgment only outside the existing
sequence lease. The boot lease at line 317 persists sequence reservation 1024
with cumulative usage zero; it cannot make later consumption durable. Signed
envelope callers consume the returned allocation at `api/routes.rs:2732`.

The current-thread runtime reproduction returned sequence 1/cumulative usage
123 while disk still held cumulative usage 0/timestamp 0. Aborting the queued
worker before it ran and recreating the controller from the intact database
produced sequence 1025/cumulative usage 7 for another 7 units, instead of 130.
The coordinator independently reran this behavior. Sequence reuse remains
prevented. No equivocation, consensus violation or monetary loss is alleged.

Existing S05-11 restart tests explicitly drain accounting before restart
(`tests/ingress_accounting_regressions.rs:2244`), avoiding this interruption
window. This is a remaining lease-window defect, distinct from re-counting
the earlier finding. S05 reproductions share `/tmp/s05_review_probe.rs` and
`/tmp/s05_review_probe`. No new subprocess-crash or real-QUIC reproduction of
this specific window was executed; permanent tests are requested.

## Mandatory pre-launch cleanup

`storage/db/signing.rs:129` retains a `native:` exception from root/choice-TTL
validation. `OriginalApprovalTarget` at `storage/db.rs:172` now has only `Hmc`;
the exception is the sole `native:` occurrence in node source/tests. The
maintenance prompt requires removing this obsolete branch under `AGENTS.md`.
It is recorded separately from the four counted functional findings; no
additional runtime failure is claimed for it.

## Coverage and limitations

- S02: all five listed files (engine, DB, signing, activity and recent), plus
  relevant HTTP/QUIC callers, root/support/recovery helpers, Specs 12/14,
  G1–G5 requirements and S02-05 through S02-13 regressions.
- S04: all three listed transport/framing/pool files, plus relevant TLS,
  authorization, F2F roster, recovery/API connections and existing transport
  regressions including S04-17's trailing-byte/FIN-timeout/permit checks.
- S05: all four ingress/auth files, plus direct quota/thermometer, accounting
  persistence, HTTP/dashboard/daemon callers, Specs 09/10/13, S05-01 through
  S05-12 regressions and the fractional EMA checks.

Each agent completed exactly one slice. This was source review with focused
production-library probes, not a formal proof or exhaustive schedule search.
Two probe compilations initially selected incompatible duplicate Tokio rlibs;
the corrected probes used the Tokio artifact matching the current node rlib.
Those initial probe runtime errors were environment/artifact selection errors,
not repository findings.

## Validation

- `cargo clippy --workspace --all-targets -- -D warnings`: passed, exit 0.
- `cargo test-std` with local socket permission: **failed**, exit 101, after
  44 result groups reporting **552 passed, 1 failed, 0 ignored**. The failure
  was `test_phase11d_shard_digest_isolation_wire` in
  `phase11_wire_level_adversarial_tests`: `Read timeout exceeded on QUIC stream`.
  Subsequent test binaries were not executed by this command. Log:
  `/tmp/humoco-audit-three-test-std.log`.
- Exact isolated rerun of that test with local socket permission: passed,
  **1 passed, 0 failed, 18 filtered out**, in 2.08 seconds, exit 0. Log:
  `/tmp/humoco-audit-three-phase11d.log`. This does not establish that the
  complete suite passes or explain the original timeout; no fifth finding is
  inferred from a single non-reproduced timeout.
- The initial sandboxed full-suite attempt failed on three local socket bind
  restrictions (`Operation not permitted`); the permission-enabled attempt
  resolved that environment restriction and reached the separate timeout above.
- The four focused reproductions were executed and independently rerun.
  No permanent regression test or production fix was added by this audit.
- Ignored deep simulations were not run. Ledger edits are restricted to
  S02/S04/S05; unrelated rows remain unchanged.

## Handoff

Use [the combined maintenance prompt](2026-11-08_S02_S04_S05_REMEDIATION_PROMPT.md).
It contains all four findings, regression-first repairs, mandatory obsolete
branch removal and per-slice `Fix_Open` to `ReCheck` transitions after successful
implementation and validation.
