# Maintenance task: S05, S06 and S08 follow-up findings

You are a Senior Rust Systems Engineer resolving verified specification and
code-quality findings in `human-money-node` (Slices S05, S06 and S08).
Follow all rules in `AGENTS.md`: `#![forbid(unsafe_code)]`, fallible input
handling, zero `.unwrap()`/`.expect()` on external input, checked math, German
user replies and English code/documentation. The network is pre-launch; remove
superseded paths completely without compatibility wrappers or migration shims.

Read `prompts/AUDIT_LOOP.md`, `prompts/AUDIT_STATE.md` and
`prompts/reports/2026-11-10_parallel_recheck_S05_S06_S08.md` first.
Exactly three agents each audited one slice once. Four new findings were
verified and independently reproduced; the audit implemented no production fix.
Recheck current source locations before editing and preserve unrelated work.

### Verified Findings in Slices S05, S06 and S08

1. **S05-18 (Priority: Medium) — `crates/humoco-node/src/api/routes.rs:3465`; `crates/humoco-node/src/ingress/tier.rs:1496`**
   - **Expected vs. Actual Behavior:** Spec 09 section 1.1 defines storage-time
     charges per stored lock and requires aggregating incoming locks. Chain
     admission supplies only one TTL to the tier controller, charging one
     footprint to VIP credit, rolling VIP/Friends/Public quotas and the write
     thermometer, regardless of batch length. The signed footprint already
     multiplies by chain length at `api/routes.rs:3520` and `:3690`.
   - **Reliability Impact:** Several new locks consume one lock's purchased
     credit and admission budget; thermometer usage disagrees with the signed
     aggregate declaration. No consensus failure or identity sanction was
     demonstrated.
   - **Verified Reproduction:** Separately anchor a root with approximately one
     year remaining; provision 192 Byte-Years of VIP credit; submit two valid
     new spends through the production HTTP router. Result: HTTP 201, two
     committed spend locks, VIP debit/rolling usage 192, write EMA 191999994
     micro Byte-Years, declared cumulative usage 383999988. Root-registration
     accounting is excluded from this comparison. A25-R2 requires terminal-
     parent PoW binding, not flat batch billing.

2. **S06-12 (Priority: High) — `crates/humoco-node/src/network/manager.rs:1657`**
   - **Expected vs. Actual Behavior:** AGENTS Rule 1 and INV-1503 require
     nonblocking persistence without retaining RAM guards. Async
     `api/routes.rs::verify_peer_attestation` calls the observer inline at
     `:950`; its cache mutex acquired at `network/manager.rs:1627` remains held
     while the synchronous redb writer and commit execute at
     `storage/db.rs:781` and `:788`.
   - **Reliability Impact:** Storage contention blocks a runtime thread and
     competing observers of the cache. With genuine incompatible approvals
     and another writer held for 250 ms, the production async verifier took
     259–260 ms; an independent 10 ms Tokio timer also completed only after
     259–260 ms. This was a component reproduction, not a new QUIC test or a
     measured violation of the entire 800 ms checkout budget.

3. **S06-13 (Priority: High) — `crates/humoco-node/src/network/manager.rs:1664`**
   - **Expected vs. Actual Behavior:** INV-1402 requires ownership of verified
     evidence until durable persistence and honest error reporting. The
     observer logs a failed commit, continues RAM containment and returns
     `Some(proof)`. Its production caller discards this value via `is_some()`
     at `api/routes.rs:951`; forwarding drops a failed `try_send` at
     `network/manager.rs:1817`, and the cache retains only the first approval
     at `:634–636`.
   - **Reliability Impact:** A storage failure plus forwarding saturation
     loses the second approval/proof without exposing persistence failure.
     A backend-write fault with a full forwarding channel reproduced
     `proof_returned=true ram_banned=true proof_queued=false
     reopened_durable_ban=false`. The same backend was reopened after clearing
     the fault. Justified RAM containment is not itself the defect.

4. **S08-15 (Priority: Medium) — `crates/humoco-node/src/daemon.rs:769`**
   - **Expected vs. Actual Behavior:** Spec 09 section 5.3 / INV-0907 requires
     peer-based initialization of a joining node's thermometer history.
     Production samples peer medians only inside the network-size merge
     branch at `daemon.rs:769–773`; cold-start seed helpers at
     `humoco-sim-core/src/quota.rs:637` and `:827` have no autonomous production
     callers. Evidence arriving after initial growth at unchanged size never
     completes initialization.
   - **Reliability Impact:** Admission uses the fallback-derived local
     baseline even after eligible signed observations become available.
     A fixture with twenty remote identities plus self, using production
     handlers and authenticated QUIC, reproduced local read NCB 192000 after
     a peer read median of 500000 was learned. A later daily rate around
     1000000 was rejected, despite being below five times that median;
     client usage 192001 failed until the manual seed control. Relevant
     consumers are `network/transport.rs:1523–1528` and
     `ingress/tier.rs:1123–1125`. The daemon ticker was source-verified, not
     executed by this probe; simulation accelerated ticket timing only.

### Step-by-Step Implementation Plan (Test-First)

1. **Add Specification Conformance Tests First:**
   - **S05:** Extend `crates/humoco-node/tests/ingress_accounting_regressions.rs`
     with a separately anchored root and two new spends at controlled protocol
     time. One lock's VIP credit must produce HTTP 429 with no new locks or
     usage mutation; sufficient aggregate credit must succeed with matching
     debit, rolling usage, write EMA and declared footprint. Cover Friends and
     Public budget boundaries, exact authenticated retries, single-lock and
     root-registration behavior, bounded chain length and capacity refusal.
     Add real-QUIC gateway-to-receiver aggregate accounting coverage; preserve
     `chain_causality_and_prefix_tests.rs` durable-prefix semantics.
   - **S06:** Extend `crates/humoco-node/tests/audit08_09_10_regressions.rs`.
     Feed two genuine incompatible approvals through the production async
     verifier while another OS thread holds a redb writer. Assert independent
     runtime tasks and unrelated cache observations progress during the wait.
     Inject a storage-write failure with a saturated forwarding queue; require
     retained evidence ownership, observable failure and successful durable
     retry without remote resubmission. Cover closure/cancellation and a
     healthy-commit control. Add real-QUIC collector regressions for these
     original-approval paths; do not substitute incoming fraud-proof dispatch
     tests for coverage of the affected observer.
   - **S08:** Extend `crates/humoco-node/tests/phase4_net_time_and_quotas.rs`
     with a join whose initial observation set lacks load evidence. Deliver
     eligible signed checkpoints later without changing network size. Exercise
     the actual daemon maintenance ticker through real QUIC and assert both
     28-day buffers initialize from their respective write/read medians and
     hard floors. Do not call seed helpers from the regression. Cover absent
     or invalid evidence, one-time initialization and subsequent daily rotation
     without continually replacing the history.
   - Demonstrate each new regression fails before changing production code.
     The report records temporary probe sources for reference; repository tests
     must not depend on `/tmp` files, cached binary names or artifact hashes.

2. **Implement Minimal Production Fix:**
   - **S05:** In `api/routes.rs`, derive an explicit checked aggregate charge
     for the bounded, root-authenticated batch before admission. Make the
     canonical `ingress/tier.rs` admission implementation use that charge for
     VIP credit, all rolling tier quotas and the write thermometer. Reuse the
     accounting basis for signed footprints, with root-registration and retry
     policies applied consistently. Do not multiply the root TTL to represent
     a batch. Preserve terminal-parent stateless PoW and the O(1) Public pool;
     remove the misleading flat-batch comment and superseded paths.
   - **S06:** Limit the cache guard to cache mutation and extract owned proof
     data before persistence. Use a bounded async persistence operation with
     its exact completion result, without guards across the wait or unbounded
     detached blocking tasks. Make observer failures fallible and update the
     async verifier/collectors to preserve that distinction. Keep pending
     verified evidence owned through commit failure and forwarding saturation;
     apply backpressure honestly and retain justified local containment.
     Preserve first-party same-network verification and atomic evidence-plus-
     ban storage; remove the synchronous observer persistence path completely.
   - **S08:** Complete unfinished cold-start initialization when eligible peer
     observations become available, independently of network-size growth.
     Expose the minimal coherent initialization operation for separate write
     and read buffers in `ingress/tier.rs` and core thermometer helpers. Preserve
     usage counters, day rotation, ordinary smoothing and merge behavior. Do
     not replace smoothing with live peer medians on every request or repeatedly
     overwrite established history.
   - Preserve reservation-first mutation, exact durable acknowledgments,
     physical-time EMA decay, fixed checkout committees and neutral peer
     feedback. Add no compatibility or migration branches.

3. **Verify Full Workspace Suite:**
   - Run focused regressions, including the actual QUIC and daemon lifecycle
     cases, then `cargo test-std` and
     `cargo clippy --workspace --all-targets -- -D warnings` until green.
   - Audit baseline was green: 877 passed, 14 ignored, no filtered tests;
     Clippy exit 0. Initial sandbox-only socket failures were resolved by the
     socket-enabled run. Existing suite success does not cover these new cases.
   - Report exact executed checks and any remaining coverage limits. Do not
     claim daemon lifecycle execution from a component-only probe.

4. **Mandatory Ledger Update (`prompts/AUDIT_STATE.md`):**
   - Once repairs and required checks pass, update only **S05**, **S06** and
     **S08**: keep `Clean_Streak=0`; retain `Total_Finds=18`, `13`, `15`
     respectively; change `🔴 Fix_Open` to `🟡 ReCheck`.
   - Preserve the audit date `Last_Run=2026-11-10`, unrelated rows and later
     independent changes. A future audit establishes Clean after the repairs.
     Do not recreate historical absent S08 modules named by the ledger.
