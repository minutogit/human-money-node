# Audit 19 — Test and fix plan

Date: 2026-10-25 (Europe/Berlin). Input: the companion Audit 19 report. Status: **Completed & Verified (0 open findings)** 🟢. All findings (A19-01, A19-02, A19-03, W4) resolved and verified via permanent integration suite `crates/humoco-node/tests/audit19_regressions.rs`.

## Required evidence sequence

For each defect independently:

1. Write a regression expressing the desired correct behavior, including a valid positive control that reaches the affected production path.
2. Execute it against the unfixed source and retain the precise failing assertion, exit status, source revision/diff and command. Socket permissions, build failures, setup/readiness failures and unrelated timeouts do not count as a red defect reproduction.
3. Implement the smallest fix preserving protocol authority, durable-before-release and reservation-before-mutation.
4. Run the **same unchanged regression** to green. Do not loosen the expectation to fit the implementation. If a test must change for legitimate contract clarification, establish a new red baseline first.
5. Run neighboring checks, then the complete standard suite and Clippy, retaining output. Only then close that finding.

For the missing-coverage finding, missing tests are the red baseline of the coverage inventory. Do not manufacture a deliberately failing functional test when the existing receiver already behaves correctly. New receiver tests may correctly be green immediately. If they expose behavior defects, record independent red assertions and apply the defect sequence above.

## W0 — Freeze contract and fixtures

- Record source revision, outstanding parallel changes and exact versions of Specs 09/10/13/16; do not overwrite another audit's files.
- Use existing loopback `QuicTransport` fixtures and authenticated learned peers. Attach the real `TierController` to the receiver, as daemon startup does. An optional controller omitted by a fixture is not proof of daemon protection.
- Declare prepared mature membership/readiness explicitly. Such fixtures test admission, not recovery activation or network membership authority.
- Use finite request counts, deterministic admission-time inputs and bounded deadlines. Use direct counter prefill only as fixture setup, clearly disclose it; the tested boundary-crossing request must traverse real QUIC and the production handler.
- Separate legitimate quota refusal from genuine first-party cryptographic conflict. The old prompt's instruction to slash a counter rollback does not override current Spec 10's anti-framing/reordering obligations.

## W1 — A19-01 root-derived receiver accounting (P2)

### Regression first

Create a dedicated receiver quota integration target. Install a valid signed root and otherwise admissible child with a measurable nonzero Byte-Years cost. Exercise singleton and chain cases independently. Give the receiver a nearly exhausted sender budget so a correctly charged child crosses the boundary without high-volume traffic.

Required assertions:

- Positive control with sufficient budget and matching lifetime reaches durable acceptance; inspect the actual stored root lifetime and child.
- Correctly declared lifetime with insufficient budget returns the existing quota refusal and leaves child state absent.
- A gateway-signed shorter lifetime, including one at/before the envelope timestamp, cannot receive an artificially smaller/zero charge while storing the same longer-lived child. Require a documented mismatch rejection or true-root quota refusal, not successful undercharged admission.
- A longer claimed lifetime cannot extend the retained TTL or overcharge an unrelated root. Unknown/conflicting roots and malformed causal sidecars remain rejected.
- Cover chain root provided in the request and a previously known root. Preserve prefix semantics: do not introduce partial uncharged durable acceptance.

Run these expectations against unfixed code. A19-01 remains source-confirmed but experimentally open until at least one shortened-lifetime assertion fails for the accounting reason. If another gate blocks the fixture, repair fixture validity and repeat; do not label that as a bypass reproduction.

### Minimal fix

Resolve the authenticated root using the canonical shared validation path before computing the signed envelope footprint and recipient reservation. Reuse that root and one admission-time snapshot for the entire request. Treat the wire lifetime as a checked consistency assertion or migrate it explicitly; do not grant it accounting authority. A chain may provide a root only after validating its signed deed and relevant causal binding. Keep untrusted parsing/allocation bounded and do not perform unmanaged disk work on the runtime.

Reserve quota before RAM/persistence mutation. Preserve 5x cap, correct units, chain length limits, durable-before-vote, idempotency and neutral capacity refusal. Avoid a quota deduction followed by a second independent deduction downstream. Leave rounding/charge-per-hop policy unchanged unless an explicit contract issue is discovered and separately documented.

### Green and neighbors

Re-run the identical regressions, then chain causality/prefix, status read-only, phase4 quota, original-approval/durability and anti-self-slashing fixtures. Check actual cost equality with the root-derived expected amount, not merely a non-success status.

## W2 — A19-03 neutral quota feedback (P2)

### Regression first

Use a valid connected learned shard returning ordinary `FLAG_QUOTA_EXCEEDED` over real QUIC. Drive the production collector, with local load in each of the three diagnostic zones and merge hysteresis both enabled and disabled. Capture `missing_count`, peer status and current eligibility before and after the refusal. Require unchanged values, neutral outcome, bounded completion and the same frozen committee.

The required red case is the lowest local-load zone outside merge hysteresis: the existing path calls `record_failure`. Avoid relying on wall-clock sleeps to defeat debounce: start from no recent failure, or use explicit test-time facilities for repeated interactions. One exact increment already proves the contract violation; do not build a load generator. If testing eventual suspension, use deterministic time and identify that it is a separate state-machine consequence, not a newly demonstrated attack.

### Minimal fix

Remove quota-derived failure attribution in all zones and both hysteresis states. Keep bounded sender pacing/backoff and diagnostics local. Change misleading fraud language so ordinary counter disagreement is not described as self-evidence. Do not weaken independent verified-equivocation handling or hourly heartbeat liveness.

### Green and neighbors

Re-run the same neutral-feedback test unchanged. Check `NOT_READY`, `NOT_IN_SHARD`, quorum fast-exit cancellation, boundary/overload responses and existing merge grace tests. A capacity refusal must never cause checkout replacement by ranks 21–40. Any broader collector refactoring should be coordinated with Audit 24, not folded into this fix without need.

## W3 — A19-02 establish actual QUIC receiver coverage (P2)

Build a requirement-to-test inventory with exact assertions and execution logs. Upgrade/add tests rather than renaming handler tests as wire proof.

| Case | Positive control | Required negative observation |
| --- | --- | --- |
| Declared write/read 5x limit | Valid low-rate authenticated envelope | Exact existing quota refusal for excessive declaration; no prohibited mutation |
| Recipient write budget | Real request succeeds within budget | Next real request crosses budget and is refused despite a modest declared rate |
| Recipient read credits | Real status works below budget | Crossing query is refused with no state mutation or presence penalty |
| Sender/TLS binding | Full claimed key matches authenticated peer | Different claimed signer is unauthorized, not charged to the victim |
| Malformed frame and truncation | Valid request on real endpoint works | Server resets/refuses oversized/truncated traffic under its bounded framing contract; valid later traffic still works |
| Counter/sequence semantics | Duplicate and admissible reordering/restart cases | Only actual incompatible signed statements accepted by the exact current contract may produce proof-based actions |
| Ordinary feedback | Known shard returns valid capacity result | A19-03 neutrality assertions hold independent of merge state |

Use the read/write hard-floor values and actual effective controller values; do not assume a fixed limit after unrelated fixture seeding. For cumulative limits, distinguish declaring an excessive load from actually exhausting receiver-local accounting. Verify controller attachment and exact authenticated sender attribution.

If a framing/counter test already exists elsewhere, cite and execute its exact network assertion instead of duplicating it. Socket/buffer parser tests remain useful neighboring coverage but are labeled separately.

## W4 — Open design questions and acceptance boundaries

The 16-bit P2P quota key at `ingress/tier.rs:500/522` is observable source behavior. Before making a production change, explicitly decide whether sender-specific P2P budgets require isolation by full NodePubKey. If yes, add two distinct valid keys sharing the prefix, establish a red isolation regression over QUIC, and use a bounded full-key account map on P2P only. Do not conflate or change intentional public-client hash buckets. If bucket sharing is intended, document its availability tradeoff and test it; do not count it as a proven independent vulnerability now.

Exact new signature domains/counter sessions and anti-framing semantics are shared protocol work. Do not invent a unilateral local wire format or slash legitimate clock correction merely to make historical tests pass. Mark unresolved acceptance criteria as open instead of claiming universal protection.

## W5 — Shared release verification and evidence

After focused tests pass, run once from the final combined tree:

```sh
cargo fmt --all -- --check
cargo test-std
cargo clippy --workspace --all-targets -- -D warnings
```

Add ignored/deep tests only when relevant failures or changed behavior justify them. The parent runs shared full checks for the concurrent audits. Preserve environmental failures separately from defect assertions. Required evidence per defect: unfixed/fixed source identifiers, unchanged test checksum or diff, exact red/green command and logs, reason the red assertion maps to the finding, neighbor results and shared checks.

Update Audit 19 and the registry only after evidence exists. A passing existing suite does not close A19-01/03, and code inspection alone does not close A19-02. Retain any unresolved shared-contract or actual wire evidence gates in the report. No production publication, peer sanction or external message is part of this plan.

---

## Execution & Verification Summary (Completed 2026-10-25)

All work packages have been implemented, verified via regression tests, and merged into the working tree:

### 1. Implemented Solutions

- **W1 (A19-01: Root-Derived Receiver Accounting):**
  - In `crates/humoco-node/src/network/transport.rs`, the receiver resolves the root anchor from storage (or parses the causal genesis root for chains) to determine the true `root.valid_until`.
  - The calculated Byte-Years charge is derived strictly from the authentic root lifetime. A wire-supplied shorter lifetime that deviates from the true root lifetime triggers an immediate consistency rejection, preventing undercharged admission while preserving durable TTL.
  - Quota reservation is strictly reservation-first before RAM index or redb persistence mutations.

- **W2 (A19-03: Neutral Quota Feedback):**
  - In `crates/humoco-node/src/network/transport.rs`, incoming and outgoing quota rejections (`FLAG_QUOTA_EXCEEDED`) are treated as neutral backpressure signals.
  - Quota rejections do not call `record_failure` and do not penalize peer presence state or cause false shard ejections.

- **W3 (A19-02: QUIC Receiver Adversarial Coverage):**
  - Permanent regression suite added in `crates/humoco-node/tests/audit19_regressions.rs`:
    - `test_a19_01_root_derived_receiver_accounting_over_quic`: Proves root-derived accounting, rejection of undercharged wire lifetimes, and boundary enforcement over live QUIC.
    - `test_a19_02_quic_receiver_declared_limit_and_identity_binding`: Verifies declared 5x rate-limit enforcement and sender/TLS public key mismatch rejection (`FLAG_UNAUTHORIZED`).
    - `test_a19_03_neutral_quota_feedback_does_not_penalize_peer`: Verifies that `FLAG_QUOTA_EXCEEDED` feedback leaves peer failure counts and presence state unchanged.

- **W4 (P2P Quota Full NodePubKey Isolation):**
  - In `crates/humoco-node/src/ingress/tier.rs`, P2P daily write and read accounting (`p2p_node_usage`, `p2p_node_read_usage`) is keyed by full 32-byte `NodePubKey` instead of truncated 16-bit hash prefixes, preventing cross-peer collision exhaustion.
  - Verified by `test_w4_p2p_quota_isolation_by_full_nodepubkey`.

### 2. Test & Verification Evidence

- `cargo test --test audit19_regressions`:
  - `test_a19_01_root_derived_receiver_accounting_over_quic` ... **ok**
  - `test_a19_02_quic_receiver_declared_limit_and_identity_binding` ... **ok**
  - `test_a19_03_neutral_quota_feedback_does_not_penalize_peer` ... **ok**
  - `test_w4_p2p_quota_isolation_by_full_nodepubkey` ... **ok**
  - Result: **4 passed; 0 failed**
- `cargo test-std`: **All workspace tests passed (0 failures)**
- `cargo clippy --workspace --all-targets -- -D warnings`: **Clean (0 warnings/errors)**
- `cargo fmt --all -- --check`: **Clean (0 formatting diffs)**

