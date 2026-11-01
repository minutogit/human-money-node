# Audit 06 — Chaos and wire fuzzing

Date: 2026-10-25. Chosen prompt scenario: malformed wire/HTTP input. Scope: isolated working-tree snapshot plus explicitly identified later workspace checks; audit only.

## Findings

Core chaos scenarios passed **12/12**. The existing node chaos/HTTP suite passed **8/8** in the isolated snapshot. Network exchange passed **4/4** and Phase-4 clock/quota tests **8/8**. Phase-11 adversarial wire tests passed **18/19**; `test_exact_committee_outside_gateway_queries_twenty_wire` returned HTTP 503 instead of 201. It passed in a later workspace run, so the isolated failure remains a timing/load-sensitive observation without an established production root cause.

An additional executable deterministic QUIC sweep was generated and run only in the temporary copy: **64 malformed vectors** (truncated headers, wrong magic, `u32::MAX` lengths and truncated payloads). Every vector was rejected, and a valid query succeeded after each rejection on the same connection. Both endpoints drained cleanly. This proves framing/recovery behavior with the transport's default handler; it does not certify lock semantics or measure peak memory.

A separate mutation replaced production `api/hmc.rs::verify_l2_lock_signature` with `true` in the temporary copy. The existing `test_chaos_hmc_bad_signatures_no_panic` failed, while its unmutated baseline passed. Thus this particular signature test does reach a meaningful rejection boundary; it must not be dismissed merely because its assertion accepts any 4xx.

**A06-01 · P3 · A purported allocation assertion tests its own arithmetic.** `crates/humoco-node/tests/chaos_wire_http_fuzz.rs:188–195` computes `min(len, 64 KiB)`, allocates that size in the test and asserts the same bound. This block never calls the production reader and cannot detect a reader-allocation regression. Other tests do exercise oversized frame rejection; this finding concerns the redundant local oracle, not an observed OOM.

**A06-02 · P3 · The quota flood test serializes away contention.** The same file's `test_chaos_ingress_quota_exhaustion_under_flood` awaits five requests serially and sleeps 150 ms after each (`:432–466`), explicitly to avoid a cache/persistence race. It verifies sequential accounting, not concurrent flood safety. A later live-workspace run failed with HTTP 503 where the test demanded 429; the isolated snapshot passed. Concurrent source changes and system load prevent attributing the difference to one defect.

The prompt's historical unconditional min(H_canon) merge assertion is superseded by confirmation-class precedence. Existing abrupt-exit tests (`own_decision_durability.rs:324`) provide genuine post-commit process evidence; the in-memory 500-lock crash model is not equivalent to a daemon killed under concurrent writes. Neither a 500-request SIGKILL campaign nor 70% real packet loss was executed in this selected fuzzing scenario.

## Integrated fix plan

1. Remove the self-testing allocation block or replace it with a real QUIC boundary test. Cover 0, 65,536, 65,537 and `u32::MAX` lengths, short headers/payloads and an unfinished stream; assert bounded rejection, unchanged durable lock state and a subsequent successful independent request.
2. Keep the sequential quota test as an accounting example. Add a barrier-started concurrent test with fixed inputs, no persistence sleeps, explicit durable acknowledgments and exact conservation of admitted quota. Verify rejected requests do not mutate RAM/disk and healthy peers remain serviceable.
3. Reproduce the observed 503s in bounded isolated runs before changing production logic. Separate expected overload refusal from failed quorum/durable-write deadlines; preserve the evidence rather than weakening assertions to accept arbitrary server errors.
4. Port the temporary 64-vector sweep into an existing permanent real-QUIC test target after review. Extend it with authenticated structured payload mutations; keep the production signature mutation as a meaningful kill check.
5. Run chaos, QUIC quota/framing, cancellation and standard suites under controlled resources. Record any timeout or excluded test explicitly; do not report a green workspace from passing component suites.

No source fixes or permanent test files were created. This file contains both the findings and the implementation/verification plan.

Final shared validation: the bounded workspace run (`timeout 240s cargo test-std --no-fail-fast -- --skip test_a23_01_runtime_malformed_state_and_row_integrity_latches`) ended with exit 124 while running `status_reconciliation_tests`. Completed targets reported 415 passed, 1 failed and 14 ignored; the unfinished target and the explicitly skipped signing-history test are not included in those totals. The failure was `test_chaos_ingress_quota_exhaustion_under_flood` (503 versus 429). This is an incomplete run, not a clean baseline. The live workspace changed concurrently; the isolated probes/mutations used the earlier copied snapshot.
