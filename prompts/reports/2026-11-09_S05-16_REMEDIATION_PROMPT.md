You are a Senior Rust Systems Engineer resolving verified specification and code-quality findings in `human-money-node` (Slice S05).
Follow all rules in `AGENTS.md` (`#![forbid(unsafe_code)]`, fallible error handling, checked math, German user replies / English code).

Working directory: `/home/basti/Coding/humoco/human-money-node`.
Reviewed revision: `4350b4fdf2ebd98bbdef79acfa180f25d3e0df30`.
Read `AGENTS.md`, `prompts/AUDIT_STATE.md` and `prompts/reports/2026-11-09_recheck_S02_S04_S05.md`.

Exactly three agents each executed `prompts/AUDIT_LOOP.md` once: S02 and S04 had zero new verified findings and became Clean; S05 had one new Medium finding, S05-16, and became Fix_Open. Previous S02-15/S04-19/S05-15 fixes were confirmed and must not be counted again. Implement the finding below; do not replace implementation with another slice-selection run. Preserve unrelated changes and later ledger entries. No files under `crates/` were changed by this audit.

### Verified Findings in Slice S05

1. **S05-16 (Priority: Medium) – `crates/humoco-node/src/api/auth.rs:49`**
   - **Expected vs. Actual Behavior:** The token manager promises strict POSIX 0600 credential-file protection (`auth.rs:28–32`); required permission-enforcement failures must propagate through its existing fallible API. When loading an existing token, `load_or_create` discards `set_permissions` errors at lines 49–50 and then reads and accepts the secret at lines 53–61. With a readable 0644 token file and chmod returning PermissionDenied, it returns a usable manager while the file remains 0644.
   - **Reliability Impact:** Operator authentication can activate with a bearer secret whose required file protection could not be established. This is a local permission/error-propagation defect; no remote authentication bypass is claimed.
   - **Related Code:** Post-creation enforcement at lines 88–89 also discards its error. Treat both sites as one finding; the executed reproduction covers the existing-file path. Existing tests at lines 475–491 cover successful permission correction, not failure.
   - **Verified Reproduction:** A production-library probe and child-only chmod EPERM fault injection against an owned temporary 0644 token file produced `chmod_error=PermissionDenied; manager_returned_ok=true; remaining_mode=644; token_authenticates=true`. The coordinator independently repeated it. Temporary sources: `/tmp/humoco_s05_auth_permissions_probe.rs` and `/tmp/humoco_s05_deny_chmod.py`; command: `python3 /tmp/humoco_s05_deny_chmod.py`. These artifacts may need recreating from the described fixture if unavailable. No system/foreign file was modified.

### Step-by-Step Implementation Plan (Test-First)

1. **Add Specification Conformance Test(s) First:**
   - Add a focused permanent Unix auth regression for an owned, readable 0644 `admin.token` whose permission-setting operation deterministically returns PermissionDenied. Require `AdminTokenManager::load_or_create` to return the error without returning a usable manager.
   - Use a narrow test-only filesystem fault seam or safely isolated subprocess. Keep the regression portable within its declared platform scope, without unsafe Rust or consensus-path test dependencies. Never modify system or foreign-owned files.
   - Retain successful 0644-to-0600 correction, newly created 0600 files, empty-token rejection and valid/invalid authentication cases. Demonstrate the new failure regression detects current behavior before fixing production code.
   - This finding concerns local initialization; no transport rule changes or extra QUIC regression are required.

2. **Implement Minimal Production Fix:**
   - In `crates/humoco-node/src/api/auth.rs`, propagate required permission-enforcement errors at both existing-token and post-creation sites instead of discarding them.
   - Preserve the existing `io::Result` API and valid token behavior. Do not return a manager when required protection fails.
   - Follow pre-launch subtraction rules: add no legacy fallback, alternate permissive path, wire/storage migration or compatibility shim. Remove superseded structures encountered in the repaired path.

3. **Verify Full Workspace Suite:**
   - Run focused auth regressions, then `cargo test-std` and `cargo clippy --workspace --all-targets -- -D warnings` until green.
   - Baseline: Clippy passed. The socket-enabled default suite failed at `test_s02_14_controlled_worker_pending_approvals_isolation` (`tests/s02_regressions.rs:2814`) with a commit-ACK timeout for Public task 128; the same test passed immediately in isolation. Completed groups reported 668 passed, 1 failed, 5 ignored. This full-suite discrepancy was also seen in the previous audit; do not claim a green default baseline or infer an additional production defect without a verified trace.
   - The supplemental `cargo test-std -- --skip test_s02_14_controlled_worker_pending_approvals_isolation` run passed: 866 passed, 0 failed, 14 ignored, 1 filtered out across 89 result groups. Consult the report for exact logs. If the timeout recurs, diagnose its test scheduling/resource conditions without weakening durable-before-release, hiding the failure, removing the test or relabeling a filtered run as full-suite success.
   - Report the repaired ID, executed checks and remaining limits. Do not claim ignored deep tests ran.

4. **Mandatory Ledger Update (`prompts/AUDIT_STATE.md`):**
   - After the repair and required checks pass, update only S05: keep `Clean_Streak=0`, preserve `Total_Finds=16` (and any later additions), and change `🔴 Fix_Open` to `🟡 ReCheck`.
   - Preserve S02/S04 and all unrelated rows. Do not mark the repair Clean; a later independent review must confirm it.
