# Isolated resource and real-QUIC evidence

Date: 2026-10-16. This is a measured cost probe, **not an implementation of the
membership/handoff candidate or evidence that the production daemon can issue
safe FINAL payments**. See [research brief](../../prompts/decentralized_robustness_research.md)
and [candidate boundary](../MEMBERSHIP_HANDOFF_RESEARCH.md).

## Reproduction and environment

```bash
CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
  cargo build -p humoco-node --example robustness_probe --release
/usr/bin/time -v target/release/examples/robustness_probe \
  > docs/research/robustness_measurements_baseline.jsonl \
  2> docs/research/robustness_measurements_baseline.time.txt
PROBE_STORAGE_DELAY_MS=25 /usr/bin/time -v target/release/examples/robustness_probe \
  > docs/research/robustness_measurements_slow_storage.jsonl \
  2> docs/research/robustness_measurements_slow_storage.time.txt
```

The normal sandbox forbids even creating an IPv4 UDP socket (`EPERM`). Actual
QUIC runs used the tool's approved local-socket escalation. No external host was
contacted. The executable creates temporary redb files under `/tmp`, removes them
on successful exit, and writes only the named measurement artifacts.

Hardware: AMD Ryzen 7 7730U, 8 physical cores/16 logical CPUs, advertised maximum
4.55 GHz, one laptop host. Linux `7.0.0-38-generic`, x86-64; Rust/Cargo 1.94.1;
`/tmp` is NVMe-backed btrfs, **not tmpfs**. The release build uses opt-level 3,
LTO disabled and 16 codegen units. Tokio has four async worker threads and a
separate blocking writer per replica. Thermal/power state, page cache and host
contention are uncontrolled. This is a short local feasibility measurement, not a
capacity SLA. Three repetitions report variation; no statistical tail confidence
or deployment extrapolation is justified by these samples.

## What executes

[Executable probe](../../crates/humoco-node/examples/robustness_probe.rs):

- A single authorized synthetic owner signs an 88-byte context/sequence/parent/
  value/expiry payload with genuine Ed25519. Total request: 152 application bytes.
- A pinned self-signed TLS certificate secures real Quinn QUIC over loopback.
  The receiver enforces fixed size/context, bounded stream reads, capacity-before-
  signature checks, valid owner signature, exact-intent idempotency and immutable
  per-parent choice. It does **not** implement production NodePubKey mutual TLS,
  F2F learned-peer admission, PoW, quotas, root verification or consensus expiry.
- There are at most 128 concurrent incoming bidirectional streams per connection,
  a 64-job writer queue, maximum batch 32 and a 1 ms group-commit delay. The optional
  storage perturbation adds 25 ms **per batch**, not per request. Choice mutation is
  serialized in redb, with `Durability::Immediate`; successful signed replies are
  released only after commit. There is no RAM choice cache or production hot path.
  Only the configured workload's connections are bounded: the prototype has no
  global connection/handler admission cap and must not be exposed to untrusted
  peers. A bounded writer queue alone is not a global resource-exhaustion defense.
- The owner precomputes workload signatures; preparation duration is recorded
  separately. The measured trip includes QUIC, receiver signature verification,
  writer queue, durable commit, replica signing and client verification. The
  offered scheduler attempts 1k or 10k trips/s for 3 s. At 512 pending client tasks
  it records a capacity drop. Deadline: 800 ms. Catch-up ticks may arrive in bursts.
- `status_counts` indexes: 1 created, 2 exact retry, 3 collision, 4 shape/context,
  5 bad signature, 6 receiver queue full, 7 writer unavailable, 8 transport/deadline
  failure. Useful throughput counts observed 1/2 responses divided by actual
  elapsed time including final drain. A client timeout does not prove absence of a
  durable choice; this is precisely why retries must retain exact intent.
- A separate smoke test creates **20 genuine distinct replica keys, 20 QUIC
  endpoints and 20 redb databases**, still on the same host and in one process.
  It dispatches one owner intent to all 20, verifies returned signatures, exits on
  14, and cancels stragglers. Five requests each use 20/14/13 responding replicas.
  Withholding is injected before RPC dispatch; it models no response rather than
  malicious on-wire traffic. There is no rank replacement or failure scoring.
- Graceful writer drain, database close and reopen verify the first acknowledged
  value remains present; this is **not** a power-cut, forced-process-kill, storage
  rollback or same-key-loss-gate experiment.
  The two-second async join timeout does not cancel a blocked filesystem syscall;
  it is not proof of a hard process shutdown deadline under failed storage.

The 50 ms variant adds an **application sleep before sending**. It measures
increased in-flight residency; it is not a measurement of RTT, packet loss,
jitter, path diversity or bandwidth-limited QUIC recovery.

## Results

Machine-readable [baseline](robustness_measurements_baseline.jsonl) and
[slow-storage](robustness_measurements_slow_storage.jsonl) JSONL plus their
[`time` baseline](robustness_measurements_baseline.time.txt) and
[`time` slow-storage](robustness_measurements_slow_storage.time.txt) records are
authoritative. Each table row pools three 3-second offered workloads. Latency
columns are the range of the three individual reported quantiles, **not pooled
quantiles or confidence intervals**. Only observed useful successes enter latency.

| Storage perturbation | Offered/s to hot replica | Useful/s (range) | Useful/offered | p50 ms | p95 ms | p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| None | 1,000 | 998.7–999.1 | 9,000/9,000 | 2.67–4.31 | 3.23–5.79 | 5.01–6.77 |
| None | 10,000 | 2,908–5,552 | 38,390/90,000 | 12.35–19.89 | 22.45–43.44 | 40.69–118.40 |
| +25 ms/batch | 1,000 | 993.1–995.2 | 8,986/9,000 | 16.22–38.22 | 28.52–65.26 | 30.00–72.49 |
| +25 ms/batch | 10,000 | 949.6–1,116.2 | 9,539/90,000 | 58.05–74.14 | 64.42–99.77 | 84.62–143.61 |

At baseline 10k offered/s, the receiver rejects 50,193 attempts at its full
64-job queue; the client drops 1,321 at its 512-pending limit and observes 96
transport/deadline failures. Slow-storage 10k rejects 80,461 at the receiver,
without client drops or transport/deadline failures. Even slow-storage 1k has
fourteen receiver rejections in one repetition. There is no demonstrated stable
10k hot-replica service envelope. Backpressure prevents unbounded queue growth;
it does not create throughput or guarantee acceptance at the nominal rate.

Ed25519 sign p50/p95/p99: baseline 15.56/18.11/20.90 microseconds; verify
28.04/30.72/33.38 microseconds (5,000 operations each). In the second run sign p50
15.00 and verify p50 29.73 microseconds. Immediate single-record redb transaction
p50/p95/p99: baseline 0.738/0.882/1.245 ms, second run 0.700/0.856/1.014 ms
(200 commits each). The 1 ms group delay and redb batching in the service test are
therefore consequential, and the local 5 ms statement cannot simply substitute
for durable-before-reply latency under load.

One million compact rows occupy exactly 96 MB. Construction takes 132.31/132.53 ms
and a one-shard top20 scan 149.17/148.46 ms across the two runs. A naive full
65,536-shard rescan extrapolates to 9,730–9,776 seconds (about 2.7 hours) on the
measured single-thread path; this is an extrapolation, not a measured full scan.
The probe uses domain-separated synthetic HRW score hashing; the independent
`robustness_envelope` example uses the actual production HRW score function.

Whole-process peak RSS is 109,404/111,328 KiB, including the catalog peak and
subsequent committee phase; this is not the isolated service's memory high-water
mark. Whole runs take 29.02/29.76 s, with 29.72/21.33 CPU seconds (user+system).
`time` reports 2,480,480/496,560 filesystem-output units; those counters are not
wire bytes or database logical size. Raw application sizes are 152 request bytes
and 65 success-response bytes per replica, excluding QUIC/TLS/UDP overhead and
membership/causality evidence. At twenty destinations this is a 4,340-byte/payment
application floor, or 43.4 MB/s at 10k payments/s network-wide before extra rounds.

The application-delay 50 ms/1k case returns all 3,000 successful fresh intents in
both runs, with p99 58.99/87.07 ms. The graceful reopen retains 50,487/21,526 choices
respectively, including the original acknowledged wire-test choice.

Receiver tests run against the actual QUIC receiver, not a direct Rust call:
created -> 1, identical retry -> 2, signed owner conflict -> 3, corrupted payload
with original signature -> 5, valid owner signature in stale context -> 4,
four-byte and 153-byte malformed frames -> 4. A mismatch aborts the program.
The first persisted value is checked again after graceful reopen.

The 14/20 smoke isolates the arithmetic availability boundary: fourteen correct
responders finish 5/5 in each run without six silent members (p50 3.33/2.90 ms);
twenty responders also finish 5/5 (p50 3.56/3.91 ms). Thirteen finish 0/5 in both
runs and expire at about 802.3–802.5 ms, with scheduler overhead beyond the 800 ms
configured timeout. Its roster is a harness fixture, **not cryptographically
justified membership**. Its low-load latency must not be substituted for 1k/10k
full-quorum checkout throughput. The terminal `scope.quorum=false` refers to the
loaded single-replica path; `committee_smoke` rows explicitly record the separate
actual twenty-endpoint collection fixture.

## Scale estimates and measured scan consequence

The catalog benchmark actually allocates one million compact synthetic rows and
scans all tickets to select one shard's top twenty full 256-bit scores. A row is
96 bytes (identity32 + ticket32 + address16 + eligibility8 + epoch8). Therefore
96,000,000 bytes/91.55 MiB is a **lower bound** before maps, allocation, authentic
F2F evidence, duplicate rows, retained tickets or certificates. This is not a
million-node all-pairs simulation and does not validate admission.

Exactly 65,536 shards times twenty memberships gives 1,310,720 assignments. A full
bare routing table of twenty identity keys per shard costs 41,943,040 bytes/40 MiB,
excluding ticket/proof history. At one million identities, a uniformly distributed
node averages 1.31 shard assignments; this says nothing about hot-shard demand or
Byzantine concentration. Naively repeating the measured million-ticket scan for
every shard costs `65,536 * measured_single_shard_ms`. Incremental discovery must
avoid that operation on each heartbeat, and authenticated config history needs a
different indexing design from merely recalculating local HRW.

A minimum 96-byte catalog renewal per identity per hour is 96 MB/hour/node,
26.7 kB/s/node, before signatures, gossip redundancy and paths. A 160-byte signed
presence row instead costs 160 MB/hour or 44.4 kB/s/node. At a million receivers
that is 26.7–44.4 GB/s aggregate useful propagation even before redundancy. These
are arithmetic floors, not measured dissemination performance. A capped local
catalog sacrifices globally complete candidate knowledge unless another explicit
discovery/index proof fills the gap.

If a uniformly sampled 1% of identities changes in an hour, a shard's twenty seats
contain an expected 0.2 changed identities: approximately 13,107 affected seat
assignments/hour across all shards. This assumes uniform independent churn and
does not model a targeted grinder. Closure14 + prepare14 + commit14 + install14
signatures alone cost at least 3,584 bytes per handoff, or about 47 MB/hour across
that expected churn. It excludes manifests, membership proofs, retries, payloads,
duplicate transfer and retained history. State volume dominates this floor.

At aggregate fresh lock rate L, uniform placement creates approximately
`20*L/N` new durable replica choices/s/node. A single hot shard instead delivers
L choices/s to each of its twenty replicas. Thus 10k locks/s **network-wide** does
not mean 10k/s/node at a million nodes; 10k/s **in a hot shard** does. Signing and
verification alone cost roughly `20*(sign+verify)` receiver CPU per payment plus
gateway certificate verification, before disk or transport. Use measured costs,
not the RAM lookup microsecond target, when sizing durable-before-vote service.

For retained byte size S and unexpired duration T, the raw choice floor is
`20*L*S*T` network-wide, `20*L*S*T/N` per uniformly loaded node. At L=10k/s,
S=144 B and T=1 day this is 2.49 TB network-wide; at 30 days 74.65 TB. At a hot
replica it is 124.4 GB/day or 3.73 TB/30 days before evidence and database overhead.
These are engineering sensitivities, not an approved TTL or observed occupancy.

## Exact remaining production evidence

Validation: `cargo test --workspace` passed with local-socket escalation: 504 tests
passed, zero failed, eleven repository-marked tests ignored (65 result groups).
`cargo clippy --workspace --all-targets -- -D warnings` passed. Independent
`cargo test -p humoco-sim-core --example robustness_envelope` passed all three
tests, including the corrected crash/reinstall regression: clearing volatile
staging must also reset its progress cursor and accumulator before any reinstall.
The probe alone passes clippy and rustfmt checking. See
[compact check log](robustness_workspace_checks_summary.txt). Ordinary workspace
tests do not replace explicitly running example tests or the real QUIC probe.

The prototype has no admission, transition, snapshot/delta, closure, BFT view
change, install, stable storage loss detection or epoch expiry protocol. Therefore
it provides no measured handoff pause, catch-up/final-tail bound, inherited-proof
availability, cold same-key restart safety, long-range history protection,
background-recovery contention, or churn/partition convergence. Existing daemon
wire tests cannot fill those candidate implementation gaps.

Before production integration, wire tests must verify real peer authorization,
each canonical field/domain, signer distinctness and certified membership,
snapshot range coverage/delta contiguity, capacity-before-mutation under concurrent
channels, queue and connection-pool fairness, proof-flood limits, durable vote/fence
crash points, install-before-activation, expiry bounds and rollback fail-closed
behavior. A controlled multi-host run must vary RTT/jitter/bandwidth and correlated
outages while 14/20 checkout and actual handoff run concurrently. This report does
not invent a maintainer-approved latency or pause SLA for that future test.
