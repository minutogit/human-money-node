# Audit 22/23 evidence (2026-10-25)

The `.rs` sources assert required safe behavior and fail on the audited implementation.
They are audit reproductions, not production fixes. Preserve that distinction when
converting them into permanent regressions.

- `audit22_probes_unsandboxed.log`: four intended assertion failures, including real
  authenticated QUIC recovery. The initial sandbox socket rejection in
  `audit22_probes.log` does not establish the network finding.
- `audit23_runtime_probes.log`: two intended assertion failures for one runtime
  integrity finding; approval values are placeholders, not Ed25519 network proofs.
- `signing_original.sha256`: original signing.rs SHA256, matched after restoring the
  temporary internal unit module. No production signing changes remain.
- `test_std.log`: initial standard suite stopped at two cluster_e2e failures.
- `test_std_no_fail_fast.log`: subsequent complete suite; 700 passed, 0 failed,
  14 ignored across 93 test-result groups. Initial failure cause was not established.

Audit 22 reproduction: temporarily copy `audit22_probes.rs` into
`crates/humoco-node/tests/audit22_probes.rs`, run
`cargo test -p humoco-node --test audit22_probes --offline -- --test-threads=1 --nocapture`
with local QUIC socket access, then remove only that temporary target.

Audit 23 reproduction requires a temporary internal test module because it injects
logical row faults into private tables. Save signing.rs byte-for-byte, append
`audit23_runtime_unit_probes.rs`, run
`cargo test -p humoco-node --lib audit23_runtime_probes --offline -- --test-threads=1 --nocapture`,
then restore the exact saved source even if the test fails. Do not expose the fault
injection through production or administrative APIs. The malformed-state probe's
historical name contains 'across_reopen', but its actual assertion concerns the runtime
latch only; reopen coverage is required by the future fix plan, not demonstrated here.
