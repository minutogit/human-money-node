# Parallel follow-up audit: S02, S04 and S08

Date: 2026-11-08. Base revision: `6e77c86844902cf730a39a4780225d3dd91ada5d`.
The reviewed state includes the substantial preexisting uncommitted changes;
the revision alone does not identify the audited source state.

Three agents each performed exactly one review under `prompts/AUDIT_LOOP.md`.
The coordinator selected three distinct ReCheck slices in slice order, verified
the reported source traces, reran the successful local reproductions, and updated
only those three ledger rows. No files under `crates/` were changed by this audit.

## Results

| Slice | New findings | Clean_Streak | Total_Finds | Status |
| --- | ---: | ---: | ---: | --- |
| S02 | 1 | 0 | 13 | `Fix_Open` |
| S04 | 1 | 0 | 17 | `Fix_Open` |
| S08 | 2 | 0 | 12 | `Fix_Open` |

Earlier findings were not counted again. In particular, the five S04 causes in
the 2026-11-01 report are addressed in the current implementation. This audit
does not claim full-workspace conformance or implementation of any new fix.

## Verified findings

### S02-13 — Medium — Shared persistence capacity has no internal reservation

Expected: Spec 14 lines 145–147 and INV-1307 require separately protected bounded
internal shard/sync capacity; one shared exhaustible queue is explicitly
insufficient. Observed: `storage/engine.rs:901` creates a single 10,000-operation
queue. HMC ingress reserves it at `engine.rs:1798`; original approval persistence
uses the same sender at `engine.rs:1034`. Neither reservation distinguishes
public client work from internal shard work.

The public router has no global in-flight admission limit (`api/routes.rs:249`).
Identical authenticated root retries reach durable ingress through
`api/routes.rs:2680–2694` and `commit_root_registration`; VIP/Friend retry branches
return after authentication (`ingress/tier.rs:1183`, `:1272`). These retries avoid
the separate accounting persistence queue but each enqueue another durable root
operation (`engine.rs:1847–1862`). Internal `LockVerifyRequest` handling reaches
the same engine paths (`network/transport.rs:1187`, `:1392`). The separate QUIC
stream permits do not reserve persistence capacity.

When public operations occupy the queue, an internal request is rejected with
`Persistence queue congested (backpressure)`; an original approval can likewise
receive `Persistence queue unavailable`. This is a protected-service capacity
defect, not an observed signature-release bypass. The trace is source-verified.
A temporary standalone queue harness was prepared but could not be linked due
to differing existing Tokio artifacts; it was not executed. No new HTTP/QUIC
reproduction of this scenario was executed in this audit.

### S04-17 — Medium — Dedicated frames are accepted before full stream validation

Expected: Spec 10 lines 287–291 requires rejecting excess bytes before signature
or storage processing. Observed: `network/framing.rs:883` reads through
`reader.take(payload_len as u64)` and returns success without checking stream
completion. Bidirectional dispatch accepts that result at
`network/transport.rs:3987` and invokes the handler at `:4073`; the unidirectional
path accepts the same reader result at `:4151`. Outbound response parsing also
uses this reader.

A standalone parser probe linked the production library and returned:

```text
extra=false result_ok=true total_bytes=33 consumed_bytes=33
extra=true result_ok=true total_bytes=34 consumed_bytes=33
```

The input was a 32-byte header announcing one payload byte, that byte, and,
for the second case, an appended `0x99`. The coordinator reran the probe and
confirmed the result. Handler reachability is source-traced; no new QUIC or
persistence reproduction for excess bytes was executed. Existing framing tests
cover caps, header fields, truncation and deadlines, but no matching exact-frame
plus trailing-byte regression was found.

### S08-11 — High — Repeated integer rounding accelerates EMA quota recovery

Expected: Spec 09 and INV-0904 require decay according to elapsed physical time.
Observed: `humoco-sim-core/src/quota.rs:359` truncates the fractional result;
`RollingQuotaCounter::try_consume` at `:556–562` stores that result and advances
the timestamp on each accepted request. Small frequent operations therefore
discard fractional usage repeatedly.

A probe using production `TierController::evaluate_read_quota_with_time`
(`humoco-node/src/ingress/tier.rs:806`) consumes 50,000 read credits at second 0,
then offers one positive credit per second for 10,000 seconds. All requests are
accepted and cached usage stays 50,000. A physical exponential accumulator for
those accepted inputs would be approximately 55,754.84 credits, so not every
request should have been admitted. The HTTP read path supplies one-credit
requests (`humoco-node/src/api/routes.rs:1998–2004`).

The same cause affects `NetworkThermometer::checkpoint_emas_at` at
`quota.rs:854–869`, called by `ingress/tier.rs:469`: starting at 10,000 read credits,
10,000 one-second checkpoints without new reads reduce usage to zero, whereas
one projection to the same timestamp returns 9,229. Core and production-tier
probes were executed and rerun by the coordinator:

```text
zero-cost updates: usage=0 direct=9229
positive reads: accepted=10000 final_usage=50000
snapshot-only reads: checkpointed=0 direct=9229
production TierController: limit=50000 accepted_one_credit_reads=10000 usage=50000
```

The core probe included the current quota source directly; the tier probe linked
the production library. No new HTTP/QUIC regression for this case was executed.
Existing S05-09 cases cover long decay and midnight boundaries, not repeated
one-second fractional loss. Quota and thermometer effects count as one cause.

### S08-12 — Medium — Exported quota verdict still contains obsolete penalties

Expected: Spec 09 section 5.2 and INV-0909 allow only diagnostic/backoff zones,
without fraud inference or sanctions from differing counters. Observed:
`quota.rs:498` returns `FraudulentRejection { malus_increment: 8 }`, and the public
accessor at `:474` returns that positive malus. Existing core and integration
assertions still require the obsolete result, including
`humoco-sim-core/tests/spec_09_network_thermometer_and_quotas.rs:468`.

The probe confirmed the sanction-bearing exported value. The current production
match in `humoco-node/src/api/routes.rs:1547` correctly ignores the malus and
treats feedback neutrally. No runtime ban, presence penalty or committee change
is alleged. The defect is retained obsolete executable API semantics, which
the pre-launch cleanup rules require removing rather than preserving.

## Coverage and limits

- S02: all five listed files, plus HTTP/QUIC ingress, immutable own-choice and
  root/support persistence, recovery fences and filtering dependencies.
- S04: all three listed files, plus relevant TLS/peer authorization, snapshot
  cuts, RPC callers and existing framing/transport regressions.
- S08: all existing targets (`quota.rs`, `storage.rs`, `client_flow.rs`), plus
  relevant types, routing, tier/HTTP, engine, daemon and dashboard callers.
  Historical targets `ceh/`, `p0/`, `state_machine.rs` and `transport.rs` no longer
  exist. Their absence is recorded as a ledger-scope limitation, not a defect.

This was manual source review with focused local probes, not exhaustive
interleaving exploration or a formal proof. Two agent turns were interrupted by
a service content filter; the same read-only reviews resumed and completed.

## Validation

- `cargo test-std`: passed, exit 0; **811 passed, 0 failed, 14 ignored**, across
  89 result groups. The complete run used local socket permission.
- The initial sandboxed attempt stopped at 207 passed and three failures caused
  by `Operation not permitted` while binding QUIC endpoints. The completed
  rerun resolved that environment limitation.
- `cargo clippy --workspace --all-targets -- -D warnings`: failed, exit 101,
  on two existing blockers: `network/transport.rs:141`
  (`doc_lazy_continuation`) and `storage/db.rs:1063` (`type_complexity`). They
  are verification blockers, not additional functional audit findings.
- The parser, core-EMA and production-tier probes reproduced the stated behavior.
  Probe files were temporary under `/tmp`; no regression test was added to the
  repository. New real-QUIC tests are required by the maintenance prompt.
- Ignored deep tests were not executed.
- `git diff --check -- prompts` passed. The workspace-wide check additionally
  reported a preexisting blank line at EOF in
  `crates/humoco-node/tests/ingress_accounting_regressions.rs:2760`; the audit
  left that unrelated crate change untouched.

## Handoff

Use [the consolidated maintenance prompt](2026-11-08_S02_S04_S08_REMEDIATION_PROMPT.md).
It contains all four findings, a regression-first implementation plan and the
required per-slice `Fix_Open` to `ReCheck` transitions after successful repairs.
