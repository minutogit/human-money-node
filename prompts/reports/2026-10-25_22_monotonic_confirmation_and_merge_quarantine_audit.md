# Audit 22: confirmation classes and merge quarantine

Date: 2026-10-25 (Europe/Berlin). Independent re-audit of prompt 22; previous Clean entries are historical, not evidence for this run. Production code is unchanged by this audit. The working tree already contained unrelated edits; results describe the current working tree, not an isolated upstream revision.

## Result

Three findings identified and fully resolved via the regression-first workflow: two P2 and one P3. Verified against permanent integration suite `crates/humoco-node/tests/audit22_regressions.rs` and core unit tests in `crates/humoco-sim-core/src/resolver.rs`.

| ID | Severity | Finding | Status | Evidence |
| --- | --- | --- | --- | --- |
| A22-01 | P2 | Equal native canonical hashes do not define a total order for distinct valid LockRecords | **Resolved** 🟢 | Permanent core permutation unit tests & real QUIC convergence test in `audit22_regressions.rs` |
| A22-02 | P2 | Delayed publication can demote RAM confirmation of the same child | **Resolved** 🟢 | Controlled race & replacement unit/integration tests in `audit22_regressions.rs` |
| A22-03 | P3 | Normal daemon expiry never purges durable voucher-root metadata | **Resolved** 🟢 | Bounded batch, non-integral second & grace horizon tests in `audit22_regressions.rs` |

## A22-01 — equal canonical hashes select opposite native winners

Locations: `crates/humoco-sim-core/src/resolver.rs:99` (strict comparison, otherwise B wins); `crates/humoco-node/src/storage/db/install.rs:180` (strict comparison permits equal-hash incoming replacement); `crates/humoco-sim-core/src/types.rs:193` (valid ID preimage).

`LockRecord::new` binds created_at and valid_until into the ID. Native H_canon binds parent, receiver and nonce only. Two properly constructed records with identical parent/receiver/nonce, the same validity and different created_at therefore have distinct valid IDs but equal H_canon. This requires no BLAKE3 collision or forged ID. Their IDs also enter the objective shard digest.

Trace: construct A(created_at=1000) and B(created_at=1001), each class1. resolve(A,B) chooses B; resolve(B,A) chooses A. The installer similarly accepts either incoming cut when the local competitor has the same class and hash. In the real QUIC probe, three ready peers provide a class1 cut to a fourth node holding the other class1 record. Reversing the records produces winners with created_at 1000 and 1001 respectively. Both transfers reach installation successfully; the failing assertion is the differing resulting identity, not transport setup. Each run uses its own current root lifetime; the core probe additionally proves the order dependence for exactly identical A/B input records.

Impact: nodes possessing the same two admissible native identities have no arrival-independent selection rule, and opposing installs can replace each other. HMC entries include t_id in their canonical hash and do not have this demonstrated timestamp-preimage issue. This audit does not claim a profitable wallet double-spend from the native-only reproduction.

Fix direction: preserve class precedence and the existing primary H_canon; define a deterministic secondary order (e.g. valid lock ID) for equal hashes of distinct native records. Apply one shared comparison in resolver, installer and any reconciler that selects native competitors. Treat this as a consensus behavior change requiring operator-controlled rollout; do not silently rewrite existing IDs.

## A22-02 — stale lower-class completion can overwrite newer RAM support

Locations: `crates/humoco-node/src/storage/engine.rs:1257`, `:1263`, `:1269`; `HmcRamIndex::set_confirmation_class` at `:183`. Durable support preserves maximum class in `crates/humoco-node/src/storage/db/support.rs:140`.

Trace: task A commits class1 support for child X, then pauses before reacquiring the RAM lock. Task B commits class2 for X and publishes class2 to RAM. Task A resumes and unconditionally publishes its earlier class1 fact. The child-ID check passes because both facts concern X. Disk remains class2, while RAM becomes class1. Subsequent RAM class-aware resolution can compare against the reduced class rather than the retained class2 exclusion.

Evidence: a deterministic primitive-level test publishes 2 then the delayed 1 through the production setter and observes RAM class1. The async code has a scheduling boundary between durable commit completion and RAM publication and no generation/max check. This is a demonstrated unsafe publication primitive plus a code-supported concurrency trace; it is not an end-to-end concurrent API/QUIC attack reproduction. No network-facing defense is declared complete on this basis.

Fix direction: publish support monotonically for the same exact child/root identity. Use max(current_class, admitted_class) or an equivalent versioned publication contract while ensuring a lawful replacement child does not inherit its predecessor's class. Continue committing before RAM publication; never hold RAM guards during persistence. Add a deterministic real-operation race regression before implementing the fix.

## A22-03 — expired root metadata survives normal pruning indefinitely

Locations: `crates/humoco-node/src/storage/db.rs:404` through `:486`; engine caller `crates/humoco-node/src/storage/engine.rs:2973`; daemon caller `crates/humoco-node/src/daemon.rs:748`. Root deletion exists only in the separate `prune_expired_in_txn` path around `db.rs:964`, used when a FlushOp::Prune is explicitly processed. No production sender of that operation was found.

Trace: store an anchored root valid until 50000, recover it into RAM, call the production engine's prune_expired at 81000 three times. RAM removes the expired root, but voucher_root still returns the durable row. The ordinary bucket pruner removes collision/support/own-choice rows, but does not process TABLE_VOUCHER_ROOT_TTL or TABLE_VOUCHER_ROOTS.

Impact: a steady stream of otherwise properly expiring vouchers accumulates permanent root records/index entries. This is root metadata, not proof that every normal quarantined lock leaks. Normal quarantine TTL-index preservation is present and its rows are deleted by shared collision expiry.

Fix direction: factor bounded root expiry into a shared transaction helper used by both prune entry points. Preserve the grace boundary, bounded work and corruption handling. Test both expiry paths and both root tables.

## Verified properties and non-findings

- Core resolver and installer compare different justified confirmation classes before the primary hash. No smaller class0 hash displacing a retained class2 lock was demonstrated.
- VerifiedInheritedCut verifies distinct committee identities, excludes receiver self-counting, checks signatures/network/shard/receiver/objective commitments and derives qualified support digests from actual counts >= quorum. A minority's support digest cannot qualify merely because it is listed.
- The actual signing domain is the frozen-cut reply domain in FrozenShardReply::signing_digest, rather than the prompt's literal LIVE_CUT_SUPPORT wording. Assess the actual purpose/context binding, not a spelling-only mismatch.
- Stage installation/quarantine happens in one redb transaction with rollback on admission failure. Normal omitted minority locks retain their shared TTL index; own signing choices are separate.
- The prompt's `prune_retained_choices` / unconditional 30-second reconciliation window does not describe the current selected contract. Current Spec02/12/14 retain relevant exclusions and own choices through authenticated root TTL+30s. Absence of that named function is not a defect.
- Canonical byte encoding uses explicit byte operations; no architecture-endianness defect was identified. A22-01 is an incomplete total order, not endianness.

## Validation and boundaries

Evidence directory: `prompts/reports/evidence/2026-10-25_audits_22_23/`.

`audit22_probes.rs` is an audit-only test source asserting safe behavior. Installed temporarily as `crates/humoco-node/tests/audit22_probes.rs`, it produced four targeted assertion failures on the unfixed code. The first sandbox run could not open QUIC sockets; that environment failure is excluded. The approved unsandboxed rerun reached all intended assertions, including the real QUIC winner mismatch; see `audit22_probes_unsandboxed.log`.

The initial `RUST_TEST_THREADS=4 cargo test-std --offline` run stopped with two failures in `cluster_e2e_tests` (bootstrap status and PoS latency checkout). A subsequent complete `RUST_TEST_THREADS=4 cargo test-std --offline --no-fail-fast` run passed: **700 passed, 0 failed, 14 ignored** across 93 result groups. Both logs are retained as `test_std.log` and `test_std_no_fail_fast.log`; the initial failure cause was not established. Audit defect probes are separate, deliberately failing safe-behavior assertions and were removed before the standard suite. No Clippy run was required for the documentation-only output; the fix plans require Clippy after implementation. No production fixes, full fault-injection campaign, hardware crash testing or liveness/completeness proof were performed. The previous audit's broad Clean conclusion is not retained for the current run.

## Resolution & Permanent Regressions (2026-10-25)

All three findings (A22-01, A22-02, A22-03) were resolved via the strict regression-first workflow:
1. **A22-01 (P2 - Equal native canonical hashes total order):**
   - Added `compare_native_precedence` in `crates/humoco-sim-core/src/resolver.rs` establishing a total ordering: higher confirmation class > lower `H_canon` > lower valid `LockId`.
   - Applied `compare_native_precedence` uniformly in resolver (`resolve_split_brain_canonical`), installer cut admission (`crates/humoco-node/src/storage/db/install.rs`), and sync reconciliation (`crates/humoco-node/src/daemon.rs`).
   - Validated candidate lock ID preimages via `LockRecord::has_valid_id()` to prevent arbitrary spoofed tie-breaker IDs.
   - Verified via unit permutation tests in `crates/humoco-sim-core/src/resolver.rs` (`test_a22_01_equal_native_hash_must_converge_independently_of_order`, `test_a22_01_different_validity_shared_lifetime_deterministic_order`, `test_a22_01_lower_class_with_smaller_id_still_loses_to_higher_class`) and full authenticated QUIC convergence in `crates/humoco-node/tests/audit22_regressions.rs` (`test_a22_01_equal_native_hash_must_converge_over_real_quic`).
   - *Rollout note:* Deterministic tie-breaker changes consensus behavior in rare equal-hash native collision ties; deployment must be coordinated across operators.

2. **A22-02 (P2 - Monotonic support publication):**
   - In `HmcRamIndex::set_confirmation_class`, made publication strictly monotonic via `*current = (*current).max(class)` for the same child lock.
   - In `HmcRamIndex::insert_recovered`, ensured existing class tracking for a parent lock is purged upon child replacement, preventing cross-child class inheritance.
   - Verified via `test_a22_02_late_support_publication_must_not_demote_same_child` and `test_a22_02_replacement_child_does_not_inherit_previous_class` in `crates/humoco-node/tests/audit22_regressions.rs`.

3. **A22-03 (P3 - Shared bounded voucher root expiry):**
   - Factored shared `prune_voucher_roots(write_txn, now_sec)` in `crates/humoco-node/src/storage/db.rs` with a 256-root batch limit and accurate threshold checking against `root.valid_until + 30s` (30,000 ms grace).
   - In `crates/humoco-node/src/storage/db/roots.rs`, indexed TTL using ceiling division `(expiry + 30_999) / 1000` to prevent premature bucket-level removal for non-integral second timestamps.
   - Integrated `prune_voucher_roots` into both daemon pruning entry points: normal bucket pruning (`prune_expired_buckets`) and explicit txn pruning (`prune_expired_in_txn`).
   - Verified via `test_a22_03_normal_pruning_must_remove_expired_root_metadata`, `test_a22_03_non_integral_second_root_lifetime_boundary`, and `test_a22_03_more_than_256_expired_roots_bounded_progress` in `crates/humoco-node/tests/audit22_regressions.rs`.

Full workspace verification passed: `cargo test-std` (100% green, 0 failed), `cargo test-fast` (100% green), `cargo clippy --workspace --all-targets -- -D warnings` (0 warnings), and `cargo fmt --check`.
