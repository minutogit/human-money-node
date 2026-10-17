# P0 v0.2: first executable simulation results

Date: 2026-10-17 (Europe/Berlin). Report revision: 1.0 (verified).
Baseline: [P0 v0.2](PARTITION_RESILIENT_REGISTRY_P0.md), CP-0047 / CP-0048.
Run status: completed and fully verified; all 12 scenarios T01 to T12 passed cleanly.

## 1. What this run can establish

The new `humoco_sim_core::p0` module is a deterministic research implementation.
It adds local admission/view transitions, fixed-window timed collection, immutable
own choices, signed owner intents/approvals/observations, supported min-hash merge
and complete-split causal status. It does not replace the existing daemon paths,
legacy resolver or CEH implementation. No new Cargo dependencies were introduced.

This is a first bounded model run, not closure of all P0 production obligations.
Success includes refusing an unsafe or unavailable operation. In particular,
13/20 replies and inconsistent independently recognized views must not turn into
invented quorum or global green. The model exposes an availability limitation:
identical twenty-member rosters with cuts just 1ms apart can be mutually refused.
That conservative exact-cut recognition is an implementation restriction, not a
proof that every possible regional protocol must stall. It requires the next
view-compatibility/liveness iteration before a general robustness claim.

## 2. Reproduction and execution record

Working tree base: `ee4b85956ef1a75701df2b5bece2579bd9edd47e` plus the new
research files identified below; the base commit alone does not contain them.
Toolchain: rustc 1.94.1 / cargo 1.94.1. Offline cached dependencies were used.
Keys, commitments, event times and attack schedules are fixed in the test fixture;
there is no wall-clock RNG or hidden global-membership oracle. The P0-SIM-1 label
identifies a deterministic fixture/profile, not a sampled real network population.

Executed checks and their verified outcomes:

- `cargo check --workspace`: passed (0 warnings, 0 errors)
- `cargo clippy --workspace --all-targets -- -D warnings`: passed cleanly (0 warnings)
- `cargo test --test p0_partition_scenarios`: 6/6 passed (17.48s)
  - `t01_partition_regional_progress`: passed
  - `t02_bounded_write_collection`: passed
  - `t03_dynamic_view_evolution`: passed
  - `t04_commutative_merge`: passed
  - `t05_min_hash_regional_conflict`: passed
  - `t06_complete_splits_and_descendants`: passed
- `cargo test --test p0_adversarial_scenarios`: 6/6 passed (464.79s)
  - `t07_own_choice_immutability`: passed
  - `t08_argon_and_f2f_admission`: passed
  - `t09_comprehensive_negative_coverage`: passed
  - `t10_delayed_evidence_repair`: passed
  - `t11_fault_injection_and_persistence`: passed
  - `t12_large_scale_conflict_workload`: passed
- Total: 12/12 scenarios verified and successfully concluded.

Focused reproduction of the twelve cases:

```bash
cargo test -p humoco-sim-core \
  --test p0_partition_scenarios --test p0_adversarial_scenarios -- --nocapture
```

The complete final run log and source fingerprints are retained alongside this
report's findings. Preliminary runs caught an invalid fixture which allowed every
local reachability lease to expire while still expecting population continuity.
The successful partition variant now refreshes local probes every 30s while remote
leases expire; the not-stable refusal was correct. Negative work-oracle coverage
also uses correctly signed nonzero-work descriptors, so rejection cannot be
explained solely by malformed ticket bytes.

## 3. Scenario map and scope of the checks

| Case | Observed/modelled assertion | Important scope boundary |
| --- | --- | --- |
| T01 |20/20 regions with old10/10 progress locally; cross-region delivery withheld until reconnect; no old14 permission | Independently configured compatible observer histories; continued local probes are required |
| T02 |80/20 with old7/13; reject cross-view, duplicate and rank21 votes;13by799ms cannot obtain a fourteenth at800ms | Timing is injected collection/event time, not measured network latency |
| T03 |90/10,20/7,13/7; adaptive7/5/9; maturity23h59 refused; actual24h continuity and population-drop reset | Exact dormant two-heartbeat/flap re-entry policy is not implemented |
| T04 | Eight independent payments; six delivery permutations of a smaller set, duplicate invariance, associativity example and signer/view-independent SpendId | Finite checks, not exhaustive enumeration of arbitrary graphs or proof of all merge implementations |
| T05 | Exact R-01/R-02 competing regional receipts converge; actual personal double-signers are B or F1..F6, honest loser bans zero | Both receipts are regional; this does not demonstrate irreversible global acceptance |
| T06 | Atomic competing child bundles; losing fork/descendant unusable; sibling path survives; losing-ancestor fresh spend refused | Authenticated blind owner/child fixture, not complete human-money-core amount conservation |
| T07 | OwnChoice A survives canonical B; observation cannot serve as approval/fraud; legitimate B descendant can progress | B's original supported receipt must remain available |
| T08 | Forged/fresh/gateway-only views and false verified-work input refused; replay cannot renew a lease; mature actually admitted capture explicitly passes admission | Argon computation and authenticated transport ingress are injected boundaries; no independent-human/f<=6 proof |
| T09 | Invalid signatures/bindings/origin/ancestry/expiry and partial support cannot take over; true Regional14 promotion works; live31day evidence accepted | Cryptographic/authentic ancestry admission is distinct from current canonical usability |
| T10 | C->B->A on delayed valid smaller evidence, including a40day late candidate; duplicates idempotent; fixed scoped cursor repair checks | Repair helper knows expected IDs; no actual authenticated Merkle/range RPC or distributed completeness proof |
| T11 |13/20 unavailable; qualified future view succeeds; bounded pending capacity, crash timing, unknown-history passive gate; identical-roster1ms skew refuses foreign view | Simulated durable acknowledgment; no fsync, wire-flood fairness or signed uncertain-clock interval implementation |
| T12 |1000 primary inputs,100 chosen double-spends, successor damage, unaffected siblings, explicit reconnect and merchant journal/limit outcomes | Fixed attack schedule and serial journal model; no field frequency estimate, terminal race test or production performance benchmark |

Negative assertions reject unsafe inputs and include positive controls. This is
**not an automated source-code mutation campaign**. The specification's complete
mutation, composed recovery and real-QUIC exit gates remain open.

## 4. Coordinated conflict workload

The workload intentionally lets the attacker choose two valid intents and assigns
the smaller hash to the delayed regional rival. This stress test demonstrates
loss exposure; it is not an estimate of how often such an attack happens.

Fixture counters confirmed in the final run (T12):

-1000 primary consumed inputs, of which100 have a regional rival.
-1500 distinct authenticated regional transaction receipts including split creation,
 sibling and descendant transactions, with100 delayed rival receipts at reconnect.
-1100 initial purchase-journal goods releases against the two regional branches.
-100 original recipient payments become VOID after the rival receipts arrive.
-200 additional dependent transactions become VOID.
-900 primary payments remain regionally confirmed.
-200 unaffected sibling-path output nodes remain usable:100 consumed path outputs
 plus100 new outputs; this is **not** a count of200 unspent outputs.
-The partition lasts8 simulated hours and queues100 rival delivery events.

Terminal fixture units have single-purchase limit10 and cumulative limit20. Three
of four purchases of6 pass (exposure18); the fourth and an11-unit purchase fail.
Retry/restart preserves one goods release per purchase. An uncertain first payment
does not dispatch a different voucher intent. Amounts and these journal counters
exist only in test-local terminal state, outside the blind registry.

The terminal helper consumes already validated fixture receipt identities; it is
not the production light-client verifier or a real durable transaction system.
Serial execution models an atomic exposure update; real multi-terminal races and
power-loss behavior remain untested. Once-only goods release does not prove
once-only debit or global compensation.

Reported proof byte counts, if present in stdout, are only a counted lower bound
for selected intent/signature fields. They exclude complete views, framing and
historical admission proofs. No p95/p99 checkout latency, proof-fetch CPU benchmark,
network throughput or real-world loss percentage was measured.

## 5. Cryptography, trust and fault abstraction boundaries

| Boundary | Executed here | Still required before production claims |
| --- | --- | --- |
| Signatures/hash | Real Ed25519 strict verification for root descriptors, owner intents, ticket descriptors, approvals and observations; length-prefixed BLAKE3 model domains | Shared protocol/HMC versioned encodings, production consumers and legacy resolver migration |
| Tickets/F2F | Identity-bound SIM ticket descriptor; explicit work-verifier result and trusted ingress event; per-observer elapsed maturity/observed heartbeat hours | Actual Argon2d proof verification, signed forwarding/authentication, replacement/eclipsing/scale campaign |
| Historical views | Independent configured observer-cut capability; receipt cannot install its own authority | Compatible live views under real asynchronous local histories; historical admission custody/refresh |
| Time | Injected observer time, local lease replay origin preserved, backwards/late commit refused | Conservative cross-observer uncertainty, actual secure clock and complete re-entry/flap behavior |
| Persistence | Pending/commit/crash transitions; no approval before acknowledged model commit; expiry retains own choice; own history loss remains passive | redb acknowledgment/power-loss/rollback/cloned-key enforcement and measured resource bounds |
| Evidence repair | Explicit partition queue, reconnect and dependency-ordered evidence union; test-local scoped durable cursor model | Actual authenticated source/range/size verification and fair bounded repair over learned-peer QUIC |
| Merchant | Serial local purchase state, exposure cap and retry/unknown rules | Production light-client integration, authentic amount/purchase binding, real persistent counters and concurrency |
| Global finality | Guard always false; all regional scenarios remain nonglobal | A separately justified global proof scheme; connectivity or quiet time is insufficient |

The model can exercise valid signatures and state transitions while treating the
admission/work/storage boundaries abstractly. Passing it does not prove that a
malicious wire peer is refused by `humoco-node`, or that a physical disk retains a
vote after power loss. Existing workspace wire tests do not automatically validate
these newly modelled rules.

## 6. Next evidence gates

1. Refine common-view acceptance under realistic independent observation times;
   measure progress/refusal as catalog skew, churn and authenticated propagation vary.
2. Connect real ticket, origin/owner and historical-context verifiers through the
   shared protocol boundary, preserving the exact support/hash/fraud semantics.
3. Compose recovery, complete presence re-entry, bounded scheduling, late evidence
   and explicit adversarial mutation schedules; measure retained state and repair.
4. Implement actual receiver-side QUIC/storage/terminal paths and adversarial tests
   before any deployment or production-readiness verdict.

Regional operation without predecessor permission works in the scheduled compatible
fixtures. Honest fail-closed behavior and deterministic authenticated merge are
exercised. Robustness of the intended worldwide decentralized deployment remains
conditional and unqualified by this first model pass.
