# Audit 12 — Mutation testing and test blind spots

Date: 2026-10-25. Scope: isolated copy of the current working tree; no production fixes or permanent tests added.

## Findings

Six actual source mutations were applied individually and restored in `/tmp/humoco-stufe2-audit/human-money-node`. The unmutated targeted baseline passed **136 tests**. The command selected `humoco-sim-core` library tests plus `mutant_kills`, `proptests_humoco_properties`, `spec_12_14_ram_index_and_storage_persistence` and `spec_06_order_statistics_quorum`, with `PROPTEST_CASES=256`, `PROPTEST_RNG_SEED=424242`.

| Mutation | Observed result | Existing test that killed it |
| --- | --- | --- |
| M1: ingress `> min_valid` → `>= min_valid` | KILLED | `storage::tests::test_window_and_prune` |
| M2: provisional quorum `2*N/3+1` → `2*N/3` | KILLED | `types::tests::test_quorum_calculations` |
| M3: hard floor `960000` → `959999` | SURVIVED targeted selection; KILLED full Core suite | `test_spec_09_hard_floor_baseline_1000_locks_guarantee` |
| M4: remove simulated WAL enqueue | KILLED | `test_inv1401_dual_tier_safety_wal_and_crash_recovery` |
| M5: deterministic simulation signature verification → `true` | KILLED | `crypto::tests::test_compute_genesis_root_and_sig_helpers` |
| M6: RAM `prune_expired()` → `0` | KILLED | `prop_ttl_prune_never_resurrects` |

**No surviving mutant remains among these six after the expanded M3 run.** M3's full-Core run failed the literal `960000` expectation (actual `959999`); this is not a missing workspace test. These results do not establish coverage of production Ed25519 verification, redb durability, Tokio cancellation or all possible mutations. The six attacks intentionally include simulation paths prescribed by the prompt.

**A12-01 · P3 · A named mutation-kill test retains a tautological legacy section.** `crates/humoco-sim-core/tests/mutant_kills.rs:194–257` claims a statistical `>=` boundary check. Its final loop calls `verify_order_statistics_quorum` 200 times with identical inputs and asserts `found_valid || found_invalid`, which is true after any boolean result. The computed middle threshold is not passed to the verifier. The verifier now checks exact committee membership (`src/types.rs:1037`), so that section cannot prove its stated boundary claim. Other tests do catch the actual quorum-count mutation; this is a misleading local oracle, not evidence that the consensus quorum is untested.

Baseline limitation: the required workspace run failed `api_tests::test_checkout_edge_case_split_dag_change_branch` (HTTP 400 instead of 201). A no-fail-fast run subsequently stalled for several minutes in `test_a23_01_runtime_malformed_state_and_row_integrity_latches` and was interrupted. Existing working-tree changes were present before this audit and additional concurrent changes were observed; neither failure is attributed to an audit mutation.

## Integrated fix plan

1. Replace the obsolete repeated boolean loop with exact current-committee tests, or remove that redundant section if equivalent tests already exist. Assert exact quorum boundaries, outsider exclusion, duplicate exclusion, and fixed 14-of-20 semantics. Do not restore the retired statistical authorization rule.
2. Include `spec_09_network_thermometer_and_quotas` in any targeted hard-floor mutation job. Keep a literal independent oracle; checking against the mutated constant cannot catch M3.
3. Extend the next mutation campaign to production Ed25519 and durable-ack suppression, with real authenticated QUIC assertions. Do not infer those guarantees from M5's simulation signature helper.
4. Diagnose the existing signing-history hang with a bounded subprocess reproduction; add an external watchdog so a synchronous redb deadlock cannot stall the entire suite. Resolve the API failure independently and rerun `cargo test-std` before claiming a clean baseline.

Minimal replacement oracle for A12-01 (use the existing imports):

```rust
#[test]
fn exact_committee_membership_boundary() {
    let members = [1u16, 2, 3, 4, 5];
    assert_eq!(verify_order_statistics_quorum(&[1, 2, 3, 4], &members), (true, false));
    assert_eq!(verify_order_statistics_quorum(&[1, 2, 3], &members), (false, false));
    assert_eq!(verify_order_statistics_quorum(&[1, 2, 3, 99], &members), (false, false));
    assert_eq!(verify_order_statistics_quorum(&[1, 2, 3, 3], &members), (false, false));
}
```

Mutation outcomes and failing test names are embedded above; transient build logs are under `/tmp/humoco-stufe2-*.log`. No repository evidence subfolder or separate fix-plan file was created.

Final shared validation: the bounded workspace run (`timeout 240s cargo test-std --no-fail-fast -- --skip test_a23_01_runtime_malformed_state_and_row_integrity_latches`) ended with exit 124 while running `status_reconciliation_tests`. Completed targets reported 415 passed, 1 failed and 14 ignored; the unfinished target and the explicitly skipped signing-history test are not included in those totals. The failure was `test_chaos_ingress_quota_exhaustion_under_flood` (503 versus 429). This is an incomplete run, not a clean baseline. The live workspace changed concurrently; the isolated probes/mutations used the earlier copied snapshot.
