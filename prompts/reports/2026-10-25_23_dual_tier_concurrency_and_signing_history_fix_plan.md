# Fix plan for Audit 23

Date: 2026-10-25 (Europe/Berlin).
Source: [audit report](2026-10-25_23_dual_tier_concurrency_and_signing_history_audit.md).
Scope: A23-01 runtime signing-history integrity. No implementation has started.

## Binding regression-first workflow

Apply this gate separately to every finding, even when changes share helpers:

1. Write a permanent regression with the required safe behavior, using production entry points and existing fixtures. Audit reproductions are seeds, not sufficient coverage by themselves.
2. Execute it against the unfixed implementation. Save command, code/tree identity, assertion, exit code and relevant state. It must fail because of the specific defect. Compilation errors, socket-denial, fixture timeouts and unrelated failures are not a red proof.
3. Implement the smallest correction only after the targeted red result is established.
4. Run the **same regression unchanged** to green. Do not weaken its expected behavior, skip it, replace it with an implementation-mirroring assertion or merely adjust a timeout. If the original test was invalid, document why, repair it, and establish a fresh red result before proceeding.
5. Run adjacent regressions, then `cargo test-std` and `cargo clippy --workspace --all-targets -- -D warnings` after integration. Use `cargo fmt --check` for touched files/workspace as applicable. Distinguish unrelated existing failures; do not call a failed suite green or repair unrelated work opportunistically.
6. Save red/green evidence and close the finding only when its acceptance criteria pass. Network protections additionally require real authenticated QUIC tests in `crates/humoco-node/tests/`.

No production fix is authorized by the existence of this plan alone. This document describes future implementation; the present request produced audit and planning artifacts.

## Work package 0 — define the fault boundary and preserve the baseline

Record the current working tree and existing test failures. Preserve foreign changes and immutable own-choice semantics. Read Spec02/12/14, DEC-029 and current signing/checkpoint code before editing.

Document the exact guarantee: detect the demonstrated coherent loss of a logical choice row while independent SigningState remains intact; latch on detected state/row integrity discrepancies. Normal ACID process crashes are a separate existing guarantee. No software-local unkeyed fingerprint can prove integrity against an adversary replacing the entire database and all metadata coherently. Do not promise universal disk-corruption or rollback resistance.

The audit reproduction used placeholder approval bytes to demonstrate the internal storage gate. It did **not** prove real double-signature release or slashing. Permanent tests must add genuine Ed25519 envelopes and the network release path below.

## Work package 1 — establish red regressions for actual signing release

### Local storage fault injection

Move the audit-only tests into an internal unit module/test-only helper, keeping private database mutation unavailable in production APIs. Rename the parse-error test so it describes the runtime latch it actually checks, or extend it to genuinely reopen the store.

Create a real signed original A for node identity K and consumed slot S. Durably commit it through the original-decision gate and save the exact approval envelope. Inject deletion of its TABLE_OWN_CHOICES row without updating independent metadata. Lawfully replace current canonical state with B; retained original choice and canonical state are intentionally separate. Attempt original B and assert integrity rejection, unhealthy signing state and no committed B approval. Compare table cardinality, stored generation and fingerprint before/after, and ensure valid TTL metadata is part of the setup.

Run against the unfixed code and capture the specific wrong success. Do not count an unrelated own-choice conflict, invalid signature, readiness failure or missing root as a reproduction: the test must reach the vulnerable missing-history case.

Add runtime malformed/missing SigningState, malformed existing own-choice row and inconsistent TTL/generation cases. Explicitly distinguish errors actually detected by the design from corruption classes that remain outside the guarantee.

### Real authenticated QUIC release regression

Use anti_self_slashing_wire_tests/own_decision_durability/current-proof fixtures to submit a genuine original A and verify its Ed25519 signature under the correct network/purpose/slot. Inject the logical row loss internally, prepare lawful canonical B and valid readiness context, then request original B over real QUIC. Assert that no second incompatible original signature is released, signing readiness closes, no peer is automatically banned for the local storage fault, and the response expresses local unavailability.

If A's released envelope and any observed B envelope are available, verify both cryptographically rather than comparing opaque byte arrays. A regression that merely sees 503 before reaching the history gate is insufficient. The injected mutation stays test-only; no administrative “delete history” API is added.

### Persisted latch regression

Cause a detected runtime integrity failure, check the in-memory healthy flag, close/reopen, and check the durable latch survives. Create/reopen a backup of the latched store as well. Distinguish failure to persist a latch due to disk failure: in-memory release must still close immediately; durability uncertainty must not restore signing authority.

## Work package 2 — minimal runtime consistency checks and latch

### Transaction checks

Before any history mutation or exact-retry early return, compare the actual own-choice table cardinality with SigningState.count inside the same serialized redb write transaction. For the demonstrated deletion, count mismatch must be detected before treating a missing slot as a new original choice. Keep this check bounded; confirm redb len does not imply a whole-history scan on the hot path.

Check existing row parse, generation and slot/TTL relationships consistently. Preserve the count/XOR update in the same transaction as lock+choice data and Immediate durability. Keep exact retained approvals byte-identical on idempotent retry. Do not reset generation or repair a suspected missing row by synthesizing a new choice.

A cardinality check does not detect every same-count substitution. Before advertising a broader guarantee, select and justify a bounded mechanism for existing-row authenticity/context validation and independent commitment consistency. Prefer validating genuine retained envelope binding where applicable; if extra metadata is needed, document atomic update and migration behavior. Do not add a whole-history scan before every checkout simply to make a test pass.

### Error and latch semantics

Centralize recognized history-corruption errors across original HMC/native approval commits, runtime signing checkpoint reads and pruning history mutations. On recognized corruption:

- Immediately close the in-memory signing gate, including already queued operations and pending release waiters.
- Persist SigningState.corrupt using an explicit transaction path that survives the failed original transaction's rollback. Do not set a bit in a transaction that is then dropped and call it durable.
- Preserve the latch across reopen and backups. Retain relevant data for operator diagnosis; do not erase/rebuild history, invent approvals or auto-clear the latch.
- Keep a normal OwnChoiceConflict distinct from corruption. Keep transient I/O/unknown-commit failure fail-closed without falsely accusing peers.

Review shared-clone AtomicBool ordering and the window between completing persistence and releasing the original approval. A conflicting verified own-checkpoint must still block queued releases. No RAM guard may span disk I/O, and synchronous redb remains on the bounded worker/spawn_blocking path.

## Work package 3 — intact-storage and failure compatibility

Run the new regression unchanged to green, then cover:

- Two simultaneous exact original requests share bounded waiting and return the identical retained approval, with one immutable decision and monotonic generation semantics.
- Conflicting original requests in an intact store never both succeed; ordinary OwnChoiceConflict does not permanently corrupt an otherwise healthy signer.
- A lawful canonical merge A->B may be reported with purpose-separated live signatures, while original B remains prohibited if original A is retained.
- Timeout/cancellation before acknowledgment never releases approval. A late successful commit remains protected and an exact retry is safe.
- Transient and exhausted worker failures release queue permits, preserve uncertainty and gate dependent signing. No unconditional RAM rollback is added.
- Normal root TTL+30s pruning updates count/XOR/generation atomically and does not create an erroneous permanent latch. Test >256 rows across bounded passes.
- Existing startup-corruption and real-QUIC checkpoint-rollback tests remain green.
- Existing abrupt-process-exit test verifies after-commit process death. Add precise controlled before/after commit subprocess cases where meaningful; do not label process exit as hardware power-loss testing.

## Work package 4 — integration and completion

Targeted suites: internal signing tests, own_decision_durability, signing_history_loss_tests, anti_self_slashing_wire_tests, storage_tests, current_proof_boundaries_tests and relevant recovery tests. Then run cargo test-std and Clippy as specified by the common gate, retaining exact existing failures rather than claiming full success.

A performance check should compare representative durable-approval workload before/after and report workload, storage, sample size and tail percentiles. A single fast local test does not prove the 20ms SLA. This plan does not demand unrelated engine redesign or claim guarantees under arbitrary load.

Save both red/green outputs plus real envelope checks, latch/reopen evidence and relevant performance results. Close A23-01 only after the internal gate and genuine network release tests pass. Update the report and Audit23 registry count/history without rewriting historical Clean runs. Any unresolved same-cardinality corruption guarantee or failed required integration check must be stated and tracked explicitly; do not claim universal fail-closed integrity from the cardinality fix alone.
