# Shared validation for Audit 19 and Audit 25

Date: 2026-10-25 (Europe/Berlin).

The two independent agents created reports, plans and audit evidence only. Concurrent
work modified storage/db.rs, storage/db/signing.rs, storage/mod.rs and added
`tests/audit23_regressions.rs`; those changes were preserved. Consequently these
checks describe a changing shared working tree, not a stable release candidate or
an isolated audit patch. See `head.txt` and `working_tree.txt`.

## Results

- `RUST_TEST_THREADS=4 cargo test-std --offline --no-fail-fast`: exit 101;
  **708 passed, 5 failed, 14 ignored**, across 95 result groups.
  Four failures are in the concurrently added `audit23_regressions` target.
  One failure is in `quorum_assembly_tests`:
  `test_gateway_assembles_quorum_from_mixed_200_and_201_responses` expected 200/201,
  received 503. Its cause was not established or fixed by this audit.
- `cargo fmt --all -- --check`: exit 1, formatting differences across existing Rust
  files. The audit agents did not modify those production files to fix formatting.
- `cargo clippy --workspace --all-targets --offline -- -D warnings`: exit 101,
  compiler E0505 at `storage/db/signing.rs:203` in concurrent storage work: moving
  `txn` into commit while a table-open temporary still borrows it. This is not a
  lint-free result and no attribution to Audit 19/25 changes is claimed.

Logs: `test_std.log`, `fmt.log`, `clippy.log`.
These results do not close any audit finding. Both implementation plans retain the
required future targeted red/green tests and final full checks after actual fixes.
The temporary Audit25 observation target was removed before the shared standard run.
