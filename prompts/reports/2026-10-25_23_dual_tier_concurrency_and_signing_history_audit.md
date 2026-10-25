# Audit 23: dual-tier concurrency and signing history

Date: 2026-10-25 (Europe/Berlin). Independent re-audit of prompt 23 against the current working tree. Production code is unchanged. Existing unrelated work was preserved.

## Result

One open P2 finding, with two reproductions of the same runtime-integrity gap. No normal intact-storage crash-induced double-signing or remote arbitrary-history-deletion attack was demonstrated.

## A23-01 — runtime signing writes do not reconcile the independent history commitment

Severity: P2, under a logical signing-history loss/corruption premise.

Locations: `crates/humoco-node/src/storage/db.rs:268` (missing slot initializes a new choice); `crates/humoco-node/src/storage/db/signing.rs:110`–`:135` (reads metadata and applies deltas without checking current table cardinality/fingerprint); `signing.rs:31`–`:36` (runtime state parse failures return an error without persisting/setting the DB corruption latch). The corresponding HMC original-approval path at `db.rs:202` has the same history behavior.

Execution trace:

1. Commit original approval A for node/parent slot S. The independent SigningState records count=1 and fingerprint(A).
2. Inject loss of that single logical TABLE_OWN_CHOICES row while retaining the independent metadata. This test uses internal redb access; it is not an exposed peer command or an asserted consequence of ordinary ACID crash recovery.
3. Canonical collision state lawfully changes to competitor B. Private original choice A should remain the reason to refuse original B even though a purpose-separated live report may describe B.
4. Attempt original B in S. The missing row is interpreted as a new choice. put_choice increments state.count and XORs B without checking the mismatch against the actual choices table. The durable commit returns approval B successfully; the runtime DB healthy flag remains true.
5. A later startup full scan can detect the mismatch, but that check occurs after the unsafe commit could have released its result.

The first targeted probe expected SigningHistoryCorrupt and obtained Ok("original B"). It uses placeholder approval bytes and validates storage gate behavior, not two real Ed25519 envelopes on the wire. A second probe corrupts TABLE_SIGNING_STATE to invalid JSON: original recording returns an error, but RedbStorage::is_signing_history_healthy remains true. The engine worker separately latches signing_failed after a recording error; this second observation alone is therefore not proof that production handlers continue signing after a parse failure. Both cases expose the mismatch between the runtime integrity contract and the DB-level implementation; they are counted as one finding.

Threat and limits: a coherently missing logical row could result from faulty maintenance/migration or logical corruption. This is not a claim that a peer can alter local redb, that redb ignores torn-page checksums, or that an ordinary SIGKILL deletes an already committed choice. An attacker with arbitrary control of all rows and metadata is outside any guarantee provided by an unkeyed local XOR commitment. The fault model must be stated explicitly; a software fingerprint cannot establish rollback resistance against arbitrary coherent replacement of the entire database.

Proposed fix direction:

- Check the current choices-table cardinality against the independent committed count before mutations, including the exact-retry fast path. This catches the demonstrated missing-row case inside the same serialized write transaction without a whole-history hot-path scan.
- Validate existing row structure, slot/TTL/generation consistency and approved envelope binding to the extent the storage interface can establish it; define what additional commitment check covers same-cardinality corruption.
- Centralize corruption classification and durable/in-memory latching. Do not silently treat a state/row decoding discrepancy as a new healthy row. Reject pending original releases, and preserve the latch on restart/backup.
- Keep integrity rejection distinct from ordinary OwnChoiceConflict and transient I/O failure. Preserve durable-before-release and bounded work.

The exact general row-corruption guarantee remains a design obligation. Do not advertise the cardinality check alone as detecting every same-count row substitution or arbitrary rollback.

## Examined properties and non-findings

- Native and HMC client admissions serialize collision checks under RAM write guards after queue reservation. Conflicting client intent is refused; same pending original approvals have a bounded shared watch operation keyed by identity/slot/child/class.
- Original signing decisions use Immediate redb durability and return retained approval bytes only after commit. Persist worker serialization prevents concurrent conflicting history transactions from both admitting distinct retained children in an intact store.
- Failed or unknown acknowledgment never authorizes an original vote. A timed-out pending intent is deliberately retained; unconditional rollback is unsafe because a late commit may still succeed. The audit prompt's request to always roll RAM back is superseded by current Spec02/14 uncertainty semantics.
- Worker batch commits and retry sleeps execute within spawn_blocking, without holding RAM guards. Ordinary pruning releases RAM guards before disk work. No blocking fsync under a RAM guard was identified in the scoped paths.
- Startup signing validation measures count/XOR/generation/TTL consistency and persists the corruption bit. Verified own-checkpoint contradiction also latches. Existing tests cover intact restart, exact retries, expiry, backups and abrupt process exit after a durable commit.
- The 20ms local durable SLA is a performance requirement, not a theorem established by unit tests. No representative-load percentile benchmark or actual power-loss injection was performed in this audit. No measured guarantee is claimed.

## Evidence and validation

`prompts/reports/evidence/2026-10-25_audits_22_23/audit23_runtime_unit_probes.rs` contains the audit-only internal unit module. It was temporarily appended to signing.rs to reach private tables, then removed. `signing_original.sha256` verifies byte-for-byte restoration. Both tests failed at their intended assertions on unfixed code; see `audit23_runtime_probes.log`.

The first test demonstrates contradictory approval bytes passing the storage gate under the explicit logical-row-loss premise. No real wire double-signature/slashing test was performed for that injected state; the fix plan requires it before claiming network protection. The initial `RUST_TEST_THREADS=4 cargo test-std --offline` run stopped with two failures in `cluster_e2e_tests` (bootstrap status and PoS latency checkout). A subsequent complete `RUST_TEST_THREADS=4 cargo test-std --offline --no-fail-fast` run passed: **700 passed, 0 failed, 14 ignored** across 93 result groups. Both logs are retained as `test_std.log` and `test_std_no_fail_fast.log`; the initial failure cause was not established. Audit defect probes are separate, deliberately failing safe-behavior assertions and were removed before the standard suite. No Clippy run was required for the documentation-only output; the fix plans require Clippy after implementation. No production fixes were implemented.

## Resolution (2026-10-25)

Finding A23-01 resolved via the strict regression-first (TDD) workflow:

1. **Permanent regression suite (`crates/humoco-node/tests/audit23_regressions.rs`)**:
   - `test_a23_01_runtime_missing_choice_must_fail_closed_and_latch`: verifies that injected loss of a logical own-choice row rejects contradictory approvals (`SigningHistoryCorrupt`), latches `is_signing_history_healthy() == false`, and writes no conflicting approval.
   - `test_a23_01_real_quic_signing_release_refuses_double_signature_under_fault`: verifies over live authenticated QUIC that a node suffering logical choice row loss refuses to sign or release a conflicting attestation, closes engine signing readiness, returns local unavailability (`FLAG_NOT_READY`), and does not ban the client.
   - `test_a23_01_runtime_malformed_state_and_row_integrity_latches`: verifies that malformed `TABLE_SIGNING_STATE` JSON, corrupted own-choice rows, and invalid generation relationships fail closed and latch in memory.
   - `test_a23_01_persisted_latch_survives_reopen_and_backup`: verifies that the corruption latch persists durably across reopening and backup restoration.
2. **Red Baseline captured**: All 4 permanent regression tests failed against the unfixed code at their exact intended assertions (`0 passed; 4 failed`).
3. **Implementation**:
   - `validate_and_prepare_own_choice` in `crates/humoco-node/src/storage/db.rs` enforces:
     - `choices.len()? == state.count` table cardinality check inside the serialized write transaction before admitting any new choice or exact-retry return.
     - Strict generation monotonicity (`choice.generation <= state.generation`).
     - Consistent TTL index mapping in `TABLE_OWN_CHOICE_TTL`.
     - Valid JSON decoding of stored choices (failing closed on corrupted entries).
   - `RedbStorage::latch_corruption(&self)` atomically sets the in-memory `signing_corrupt` flag and persists `corrupt = true` into `TABLE_SIGNING_STATE` in an explicit immediate write transaction that survives rollbacks of failed caller transactions.
   - Exact idempotent retries remain byte-identical without creating phantom choices.
   - Ordinary `OwnChoiceConflict` remains distinct from corruption and does not falsely trip the latch.
4. **Green Verification**:
   - `audit23_regressions`: 4 passed, 0 failed.
   - Adjacent suites (`own_decision_durability`, `signing_history_loss_tests`, `anti_self_slashing_wire_tests`, `storage_tests`, `current_proof_boundaries_tests`, `audit22_regressions`): 100% passed.
   - `cargo test-std --no-fail-fast`: 100% passed.
   - `cargo clippy --workspace --all-targets -- -D warnings`: 0 warnings, clean pass.

