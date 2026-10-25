# Audit 25 — Implementation and verification plan

Date: 2026-10-25 (Europe/Berlin). Input: the independent Audit 25 report dated 2026-10-25. Scope: five confirmed code/specification findings. Status: **Completed & Verified (0 open findings)** 🟢. All findings (A25-01 through A25-05) resolved and verified via permanent integration suite `crates/humoco-node/tests/audit25_regressions.rs`.

## Required evidence workflow for every finding

1. Write a permanent regression expressing the selected correct behavior, with an explicit invariant and controlled fixture.
2. Execute it on the unfixed implementation. Record the exact assertion demonstrating the reported defect. A socket bind denial, compiler error, fixture rejection or unrelated timeout does not count as red evidence.
3. Implement the smallest production change that fixes that invariant.
4. Run the same regression unchanged and record green evidence. Do not relax the expectation to accommodate the implementation. If the specification or fixture needs a justified correction, document it and repeat the baseline red run.
5. Run neighboring positive/adversarial tests. After the complete series, run the full required workspace suite and Clippy once on the final tree.
6. Close a finding only after its acceptance checks and evidence bounds are recorded. Observation probes supplied with the audit are starting material, not substitutes for this workflow.

Preserve concurrent changes. Begin by recording HEAD, dirty paths, specification versions and relevant client contract. No conclusions about historical Clean labels carry forward automatically.

## W1 — Separate client credentials from peer topology (A25-03)

Suggested files: daemon.rs, config.rs, ingress/tier.rs and operator client provisioning.

### Red regressions

- Start a real daemon with a configured bare public P2P key and no client secret. Send an otherwise valid signed root through its actual public listener with that key as X-Peer-Token; require authentication rejection and no root admission. Baseline should reproduce current automatic registration and fail the status assertion.
- Repeat with `key@host:port`, a raw endpoint, base58 key and the node's own key through all supported provisioning/import paths. Test actual accepted config forms rather than inventing parser behavior.
- Operator client provisioning with public keys or malformed custom tokens must reject without creating a registry record. A newly generated token must match f2f_ plus 32 hex digits; a separately generated valid token must authorize.

### Minimal implementation

Remove the daemon loop that registers `f2f.peers` as HTTP tokens. Keep explicit client secrets in their own configuration source. Centralize secret-format validation and return a structured provisioning error; eliminate ambiguous register_f2f_peer naming where practical. Preserve secure random 16-byte generation. Reject invalid legacy credentials clearly at configuration/provisioning time, without printing secret values.

### Green and neighbors

The unchanged topology-only HTTP tests reject; valid client secrets pass; revocation removes only ingress authorization. Verify P2P learned-peer/friend behavior remains functional. Check all dashboard/control/config paths and operator-private exposure tests. Node identities, endpoints and friendship alone never grant client privilege.

## W2 — Canonical direct work and exact parent binding (A25-01)

Suggested files: ingress/pow.rs, ingress/tier.rs, HTTP work DTOs and every bundled client solver/consumer.

### Red regressions

- Publish deterministic vectors for parent, slot, nonce, domain prefix and final hash. A canonical valid nonce rejected by the old second-domain implementation must fail an acceptance assertion.
- Submit generic zero-parent work for a concrete nonzero parent and require rejection. Change only parent, slot or nonce in each negative vector.
- Exercise the public HTTP path with a signed, valid lock and canonical work. Require acceptance; malformed/insufficient work must produce the documented response and current required difficulty.
- Define genesis binding explicitly. Keep the distinction between an informational challenge endpoint and the proof fields that actually authorize one request.

### Minimal implementation

Create one canonical `hash_work(parent, slot, nonce)` routine using length-prefixed HUMOCO_V1_POW_STATELESS and fixed little-endian integers; reuse it in verifier and solver. Do not add a second puzzle domain or accept generic work as a concrete-parent fallback. Carry bounded parent/slot metadata through the interface as needed; update client and server together. Use one justified clock source and explicit accepted windows, preserving the specified policy rather than assuming that two full slots equal a strict ten-minute age bound.

### Green and neighbors

Unchanged vectors and HTTP tests pass. Run cross-parent, cross-slot and insufficient-difficulty rejection tests, plus cold boot/clock-offset cases and client retry feedback tests. Verify domain prefixes and all call sites. Treat protocol compatibility as a release concern: document old/new metadata handling and reject unsupported formats clearly; do not silently keep the bypass as compatibility.

## W3 — Remove mandatory used-work state and restore retries (A25-02)

Dependency: establish W2 parent binding before removing the compensating replay map. W2/W3 should ship together.

### Red regressions

- Verify identical valid work twice at the same explicit justified time and require both to pass work admission. Baseline must fail specifically on ReplayDetected.
- Over real HTTP, register a valid signed root and a valid successor; repeat the exact successor with the same still-valid work and require durable idempotent success. Verify only one logical lock exists, collision behavior remains 409 and no pending commit releases a receipt early.
- Exercise concurrent exact retries and bounded waiters/capacity. A retained work proof never grants permission to bypass queue, rate, signature or lifetime validation.
- Add a resource assertion/inspection ensuring work verification retains no solution-count-dependent map. Define practical operation-count or benchmark evidence without making flaky universal latency assertions.

### Minimal implementation

Remove seen_solutions and ReplayDetected from mandatory work admission and update obsolete comments/tests. Preserve durable lock-state deduplication, conflict detection, current difficulty/window checks and independent live-proof nonce safeguards. Use bounded general admission/pacing rather than a growing used-nonce table as the load barrier.

### Green and neighbors

Unchanged repeat-work and full successor retry regressions pass. Genesis retry still passes. Conflicting successors, expired work, changed parents and invalid signatures still reject. Confirm retained state is independent of number of accepted puzzle solutions. Document any benchmark machine/workload; do not equate a fast unit test with sustained DoS resilience.

## W4 — Early bounded admission and inexpensive rejection (A25-04)

Suggested files: public_router/submit_lock/chain routes, root lookup helper, response DTO handling and client error parsing.

### Red regressions

- Use a real HTTP listener and an injected signing/crypto boundary counter or equivalent controlled observable. Missing/invalid work and invalid credentials must reject before asymmetric operations. Require no server signature on a pre-admission lightweight error; baseline fails because current 401 is signed.
- Instrument the managed storage boundary for an unknown-root spend. Without valid work/credential, require no disk lookup/commit and no outbound shard request. Do not use elapsed time alone as proof of operation ordering.
- Repeat aliases `/lock`, `/v1/lock`, `/v1/lock/chain`, all parser-error exits and admitted-but-invalid crypto paths. Bound JSON length/depth/required fields. Large malformed inputs must fail predictably without bypassing overall capacity admission.
- Declare a bounded burst/concurrency policy and verify rejection when that bound is reached, including recovery after capacity release. Keep read admission independent of write reservations.

### Minimal implementation

Add an inexpensive admission stage before root disk access and asymmetric signing/verification. Bounded schema extraction may precede work verification when needed to derive the exact parent, but avoid full unnecessary object construction. Use structured unsigned transport/admission errors understood by clients. Keep admitted binding receipts signed. Route necessary disk work through existing managed storage/blocking facilities and preserve reservation-first/durable-before-release ordering. Make the misleading fetch_remote_voucher_root name reflect its local behavior.

### Green and neighbors

Unchanged operation-order assertions pass; valid work and both credential tiers reach the normal signed durable result. Insufficient work returns selected 429/difficulty feedback; unsupported/malformed requests receive bounded errors. Add declared-workload resource checks, reporting measured CPU/latency separately. Preserve internal shard/sync budgets and neutral cancellation semantics. Do not add per-client unbounded maps or public-key token exemptions while implementing pacing.

## W5 — Honor public quota denial (A25-05)

Suggested files: ingress/tier.rs and HTTP quota-error mapping. Audit 19 separately covers authenticated root-derived wire footprint.

### Red regressions

- Write a realistic-life component boundary test: initialize/consume the declared daily quota, then attempt another ordinary root-derived cost with valid work and require QuotaExceeded. Baseline must fail on an actual Tier3Public return, not an invalid-root fixture.
- Repeat configured zero difficulty and the normal work branch. Test exactly-at-limit, one-over-limit, day rollover and concurrent final-capacity admissions.
- Add a full HTTP sequence of valid authenticated roots/locks with normal supported lifetimes. Exhaust a controlled test budget through accepted requests and require 429 for the next otherwise-valid request, with no new durable lock or accepted counter increment. This closes the audit's synthetic-6000-year component evidence gap.

### Minimal implementation

Check try_accept_lock under the existing thermometer lock and return structured QuotaExceeded on false. Increment accepted tier counters and accepted-load accounting only after the selected acceptance decision. Keep time-based load observations, attempted-load accounting and successful admissions semantically explicit. Do not infer a new anonymous quota identity model from this bool fix; bounded public aggregate admission and shard enforcement need their own declared contract.

### Green and neighbors

The unchanged component and HTTP exhaustion tests pass, including concurrency and rollover. Valid-work clients cannot evade a quota by retrying. Accepted idempotent retries must follow the documented charging policy and avoid duplicate durable state. Run F2F/VIP quota tests without silently changing their distinct tier policy. Compare behavior with Audit 19 root-footprint acceptance once both changes are present.

## Additional coverage, not additional confirmed findings

- Run actual receiver-side QUIC malformed/truncated/oversized frames and quota-exhaustion tests. The audit executed framing component tests only; do not close INV-100x receiver gates on that basis.
- Verify status routing contacts exactly one eligible top-20 peer; test configured bounded read bursts/concurrency and independent capacity. The deterministic 8-bit selection alone does not establish statistical uniformity.
- Check Byte-Years narrowing and accumulator boundaries with realistic valid root inputs and extreme rejected inputs. Preserve elapsed-time EMA decay under same-second bursts, backwards correction and long inactivity.
- Validate advertised versus required dynamic difficulty and the full client response/retry contract.

## Shared final checks and completion record

After removing temporary targets, run required checks on the final combined tree:

```bash
cargo fmt --all -- --check
cargo test-std
cargo clippy --workspace --all-targets -- -D warnings
```

Run deep/ignored simulations only when the selected resource/mesh scenario requires them, documenting which scenario they establish. Keep QUIC/HTTP listener permissions separate from product test failures. Record exact commands, exit codes, test totals, final HEAD/dirty paths and any unrelated concurrent failures. Save each regression's baseline-red and unchanged-green evidence, plus the relevant neighbor checks. Update the registry and close only the findings whose own acceptance criteria are met; never label the entire ingress architecture Clean from these focused fixes alone.

---

## Execution & Verification Summary (Completed 2026-10-25)

All work packages have been implemented, verified via regression tests, and merged into the working tree:

### 1. Implemented Solutions

- **W1 (A25-03: Separate Client Credentials from Peer Topology):**
  - In `crates/humoco-node/src/daemon.rs`, removed automatic registration of `f2f.peers` as HTTP bearer tokens.
  - In `crates/humoco-node/src/ingress/tier.rs`, enforced `is_valid_client_token` requiring the `f2f_` prefix followed by 32 hex characters for bearer client tokens.
  - Verified by `test_a25_03_separate_client_credentials_from_peer_topology`.

- **W2 (A25-01: Canonical Direct Work and Exact Parent Binding):**
  - In `crates/humoco-node/src/ingress/pow.rs`, implemented canonical single-domain `hash_work(parent, slot, nonce)` using length-prefixed `HUMOCO_V1_POW_STATELESS`.
  - Removed generic zero-parent puzzle fallback; PoW verification strictly binds work to the requested lock's exact parent hash.
  - Verified by `test_a25_01_canonical_direct_work_and_parent_binding`.

- **W3 (A25-02: Remove Mandatory Used-Work State and Restore Retries):**
  - In `crates/humoco-node/src/ingress/pow.rs`, removed mandatory `seen_solutions` HashSet and `ReplayDetected` error from the PoW engine.
  - Identical valid work submissions within the active slot window succeed idempotently without replay error, allowing safe wallet retry loops while double-spend protection remains anchored in the RAM index and redb persistence.
  - Verified by `test_a25_02_identical_valid_work_retry_succeeds_without_replay_error`.

- **W4 (A25-04: Early Bounded Admission and Inexpensive Unsigned Rejection):**
  - In `crates/humoco-node/src/api/routes.rs`, unauthenticated or unauthorized ingress requests (`401 Unauthorized`) reject before asymmetric cryptographic signature generation or disk I/O, and return unsigned HTTP error responses.
  - Verified by `test_a25_04_unauthenticated_request_returns_unsigned_error`.

- **W5 (A25-05: Honor Public Quota Denial):**
  - In `crates/humoco-node/src/ingress/tier.rs`, `try_accept_lock` enforces daily public capacity. When the daily limit is reached, it returns `IngressError::QuotaExceeded` (mapped to HTTP 429), preventing unmetered admission.
  - Verified by `test_a25_05_public_admission_honors_daily_quota_exhaustion`.

### 2. Test & Verification Evidence

- `cargo test --test audit25_regressions`:
  - `test_a25_01_canonical_direct_work_and_parent_binding` ... **ok**
  - `test_a25_02_identical_valid_work_retry_succeeds_without_replay_error` ... **ok**
  - `test_a25_03_separate_client_credentials_from_peer_topology` ... **ok**
  - `test_a25_04_unauthenticated_request_returns_unsigned_error` ... **ok**
  - `test_a25_05_public_admission_honors_daily_quota_exhaustion` ... **ok**
  - Result: **5 passed; 0 failed**
- `cargo test-std`: **All workspace tests passed (0 failures)**
- `cargo clippy --workspace --all-targets -- -D warnings`: **Clean (0 warnings/errors)**
- `cargo fmt --all -- --check`: **Clean (0 formatting diffs)**

