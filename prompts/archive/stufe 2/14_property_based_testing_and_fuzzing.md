# Audit 14 — Property-based testing and algebraic invariants

Date: 2026-10-25. Scope: existing Core properties and additional temporary generators; audit only.

## Findings

Executed `proptest_invariants` (11), `proptests_humoco_properties` (36), and five newly generated properties in an isolated copy. **52 properties passed**, each configured for 1,024 cases with seed `424242` (53,248 configured cases, excluding shrinking/rejections). No runtime defect was reproduced by these properties. Sampling is evidence, not a formal proof over the entire input domain.

The five additional executable properties checked: arbitrary 32-byte header and LockRecord serialization round trips; valid-window RAM insertion/replay idempotency across generated times; confirmation-class precedence and equal-canonical-hash ID tie-breaking against an independent ordering oracle; per-entry root-TTL retention against a reference model; and ByteYears monotonicity across arbitrary `u64` seconds. They compiled and ran under `crates/humoco-sim-core/tests/stufe2_properties.rs` **only in the temporary copy**.

**A14-01 · P3 · Existing random ordering generators miss intentional canonical-hash ties and mixed confirmation classes.** `proptests_humoco_properties.rs:516–695` generates receiver/nonce values independently and starts with unconfirmed records. `proptest_invariants.rs:87` similarly uses matching status and creation/expiry premises. Distinct LockRecords can share H_canon without a cryptographic collision because creation/expiry are included in the lock ID but not in the canonical hash. The old prompt's “different locks always have different canonical hashes” premise is therefore invalid. Existing Audit-22 example regressions cover ties; the gap concerns randomized combinations. The added equal-preimage property passed the current comparator.

**A14-02 · P3 · Property coverage stops at in-memory Core models.** No `proptest` use was found in `humoco-node`; node integration tests provide examples, not generated operation sequences over the actual DualTierEngine/redb. Core TTL count monotonicity (`proptests_humoco_properties.rs:724`) alone also cannot prove which entries survive. The temporary per-entry model property passed, but does not cover disk recovery, HMC root metadata or RAM/disk publication. This is a test-coverage finding, not proof those production paths are broken.

## Integrated fix plan

1. Port the five temporary properties into the appropriate existing property suites after review. Keep exactly one independent expected ordering: higher justified class, then smaller H_canon, then smaller valid LockId. Generate equal preimages deliberately; do not require impossible random hash collisions.
2. Generate confirmation classes 0/1/2, identical retries, different children, root expiry ±1 ms, saturating boundaries and sequences of insert/prune/recover. Track expected individual records in a reference model, rather than checking only aggregate counts.
3. Add a bounded generated integration test around real DualTierEngine/redb: await durable acknowledgments, reopen storage, compare RAM and disk to the model, and verify idempotency. Keep seed and minimized counterexamples reproducible. Add real QUIC scenarios separately for network claims; Core properties cannot replace Rule 7 evidence.
4. Run deterministic examples plus at least 1,024 cases per property and `cargo test-std`. Treat the existing API failure/signing-history hang as baseline limitations, independently of passing properties.

Reproduction: `PROPTEST_CASES=1024 PROPTEST_RNG_SEED=424242 cargo test --offline -p humoco-sim-core --test proptest_invariants --test proptests_humoco_properties --test stufe2_properties` in the temporary copy. Only this combined finding/plan file was added to the repository for Audit 14.

Final shared validation: the bounded workspace run (`timeout 240s cargo test-std --no-fail-fast -- --skip test_a23_01_runtime_malformed_state_and_row_integrity_latches`) ended with exit 124 while running `status_reconciliation_tests`. Completed targets reported 415 passed, 1 failed and 14 ignored; the unfinished target and the explicitly skipped signing-history test are not included in those totals. The failure was `test_chaos_ingress_quota_exhaustion_under_flood` (503 versus 429). This is an incomplete run, not a clean baseline. The live workspace changed concurrently; the isolated probes/mutations used the earlier copied snapshot.
