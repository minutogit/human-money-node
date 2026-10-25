# Fix plan for Audit 22

Date: 2026-10-25 (Europe/Berlin).
Source: [audit report](2026-10-25_22_monotonic_confirmation_and_merge_quarantine_audit.md).
Scope: A22-01, A22-02 and A22-03 only. No implementation has started. Preserve unrelated working-tree changes, original lock IDs, immutable own choices, root validity, class-first resolution and operator sovereignty.

## Binding regression-first workflow

Apply this gate separately to every finding, even when changes share helpers:

1. Write a permanent regression with the required safe behavior, using production entry points and existing fixtures. Audit reproductions are seeds, not sufficient coverage by themselves.
2. Execute it against the unfixed implementation. Save command, code/tree identity, assertion, exit code and relevant state. It must fail because of the specific defect. Compilation errors, socket-denial, fixture timeouts and unrelated failures are not a red proof.
3. Implement the smallest correction only after the targeted red result is established.
4. Run the **same regression unchanged** to green. Do not weaken its expected behavior, skip it, replace it with an implementation-mirroring assertion or merely adjust a timeout. If the original test was invalid, document why, repair it, and establish a fresh red result before proceeding.
5. Run adjacent regressions, then `cargo test-std` and `cargo clippy --workspace --all-targets -- -D warnings` after integration. Use `cargo fmt --check` for touched files/workspace as applicable. Distinguish unrelated existing failures; do not call a failed suite green or repair unrelated work opportunistically.
6. Save red/green evidence and close the finding only when its acceptance criteria pass. Network protections additionally require real authenticated QUIC tests in `crates/humoco-node/tests/`.

No production fix is authorized by the existence of this plan alone. This document describes future implementation; the present request produced audit and planning artifacts.

## Work package 0 — establish reproducible baselines

Record current tree status and the audited files' hashes. Read current Specs02/08/12/14 and DEC-022/064 before changing consensus semantics. The working tree is already modified by other work; do not reset or silently incorporate unrelated diffs. Bring audit-only sources from `evidence/2026-10-25_audits_22_23/` into proper permanent suites with descriptive names and cleanup.

Run `inherited_support_tests`, `final_lock_immunity_tests`, `distributed_recovery_audit_regressions`, `own_decision_durability` and relevant storage tests. Retain the audit's sandbox/real-QUIC distinction. Record the existing standard-suite E2E failures before judging future fixes.

## Work package 1 — A22-01: make native ordering total (P2)

### Desired behavior

For two valid native records consuming the same parent, select the higher justified class; for equal classes retain existing H_canon precedence; for equal primary hashes and distinct IDs use one deterministic, platform-independent secondary ordering. Reversing arrival order must not change the selected valid identity or resulting objective digest.

### Red tests before the fix

- Promote the core reproduction to a permanent resolver test. Construct A/B through LockRecord::new using equal parent/receiver/nonce and validity but distinct created_at. Validate both IDs rather than manually editing them. Require equal H_canon, different IDs and identical selected ID under swapped order.
- Add corresponding different-validity inputs with a shared admissible root lifetime; explicitly preserve the root-validity limits. Do not treat expired data as an admissible competitor.
- Repeat through the real QUIC recovery fixture using **exactly the same valid A/B bytes and root lifetime in both arrival-order cases**. Observe installed lock ID, class, disk/RAM identity and objective digest. Require both directions to implement the same ordering (one may reject an inferior incoming cut until reconciliation supplies the winner; successful installation of both opposite winners is forbidden).
- Keep tests for strictly smaller H_canon and stronger confirmation class. A lower-class record must still lose even when its secondary key is smaller.
- Exercise duplicate/identical records without changing idempotency or generating fraud evidence merely from timestamp differences.

Save the red outputs before editing comparator code. The audit's QUIC probe already demonstrates differing native winners, but its two runs choose current lifetimes independently; the permanent test tightens this premise to identical full records.

### Implementation

Prefer one pure native comparison helper returning a documented ordering from `(confirmation class, H_canon, valid lock ID)` with explicit better/worse semantics. Call it from core resolver and productive native cut ordering, and review native recovery reconciliation for equivalent comparisons. Validate ID preimages before admitting untrusted records; a caller-supplied arbitrary ID is not authority. Avoid changing HMC hashing, primary canonical hashes, network encoding or existing ID preimages to solve this narrow tie.

Update the existing resolver equal-hash test, whose fabricated ID currently codifies “B always wins,” to assert the deterministic valid-record contract. Acknowledge that the tie-case rule changes consensus behavior: document it and require explicit operator-controlled release coordination. Do not introduce automatic node updates.

### Green acceptance

All new permutation tests select one identity; class precedence, ordinary min-hash, idempotency and valid root constraints remain correct. Both native installer and resolver agree. No unintended native/HMC protocol byte changes. Full suite/Clippy and red-green evidence are required before closure.

## Work package 2 — A22-02: monotonic support publication (P2)

### Desired behavior

For the same current child and immutable root, a delayed class1 completion must never overwrite already published class2 support. A new canonical child has its own support and cannot inherit the prior child's stronger class. Durable commit remains before publication; no RAM guard spans disk work.

### Red tests before the fix

- Retain the deterministic setter-level order 2 then stale 1 as a local contract test.
- Add a deterministic **actual operation** race: validate genuine certificates for X, start class1 persistence, hold/resume its publication after class2 has committed and published, then resume class1. Use controlled futures/barriers, not sleep-based probability. Check disk support=2, RAM=2 and child/root unchanged.
- Include reverse completion order and identical-class retries.
- Include canonical replacement X->Y while a completion for X is delayed; X's completion must not modify Y's class. A fresh Y starts with Y's justified support, not X's class.
- Add a real QUIC follow-up in an appropriate fixture that observes the current class-aware state and verifies a lower-class competing cut cannot exploit the delayed publication. The existing primitive probe alone does not prove this network defense.

### Implementation

Either make publication monotonically maximize admitted class for the same entry identity, or carry an explicit publication generation. The minimal max operation is preferable if it fully captures the same-child/root invariant; centralize it rather than fixing only one call site. Review startup recovery and snapshot publication to distinguish reconstruction of a new state from updates to the same state. Keep removal/replacement paths clearing predecessor metadata. Ensure a failed durable update never raises RAM class.

### Green acceptance

The exact deterministic race regression passes unchanged. RAM/disk agree on the maximum admitted support for X; delayed X completions cannot affect Y. Existing inherited-support tests remain green, including single-source forged FINAL, support commitment mutations, wrong receiver/network/shard and native legacy support restrictions. No added synchronous storage lookup on the hot path.

## Work package 3 — A22-03: share bounded root expiry (P3)

### Desired behavior

Both production pruning entry points physically remove expired TABLE_VOUCHER_ROOTS and TABLE_VOUCHER_ROOT_TTL entries after root validity plus the required grace. Normal collision, support, provisional and own-choice expiry remains bounded and consistent.

### Red tests before the fix

- Promote the repeated engine-pruning probe. Insert a root with authenticated expiry, call the same method as the daemon beyond TTL+30s, and check RAM, root row and TTL index. Repeat without relying on any write traffic or manual FlushOp::Prune.
- Test the direct DB bucket-pruner and explicit mixed-batch pruning separately; both must behave identically at the boundary.
- Cover immediately before, exactly at and immediately after the selected grace boundary, including non-integral-second root lifetimes. Root metadata must not disappear early due to bucket rounding.
- Cover more than 256 expired roots and mixed unexpired roots. One pass must obey its budget; repeated passes must make progress to completion. Include a still-relevant quarantined spend and ensure no premature loss.
- Check restart and backup after pruning to ensure deleted metadata is physically absent, with no tombstones.

### Implementation

Extract a shared bounded root-pruning helper from the existing transaction path. Invoke it in both entry points inside their write transactions. Keep iteration budgets and root-index deletion atomic. Resolve any second-rounding mismatch explicitly against the normative TTL+30s boundary; do not simply copy a premature bucket cutoff. Avoid whole-database scans and do not delete unanchored records based on unauthenticated successor TTL hints.

### Green acceptance

Both paths purge expired roots and indexes without needing unrelated ingress, preserve unexpired roots, remain bounded and complete over multiple passes. All existing quarantine/own-choice expiry tests pass. Report scope honestly: this fixes ordinary anchored root metadata; unrelated orphan corruption handling is not silently claimed solved.

## Integration, sequencing and closure

Implement and review W1, W2 and W3 as separate coherent changes with their own red-green evidence. W1 is the consensus-sensitive change; W2/W3 can be independently reviewed. Run targeted checks after each, then the full workspace suite and Clippy once combined. Investigate only failures caused by these changes; preserve baseline failures with exact commands/results and a material validation limitation.

Update the audit report with implementation links and evidence, then reduce only the corresponding open count in AUDIT_REGISTRY.md. Retain original audit findings/history. Do not mark Audit22 Clean until all three acceptance sets and required network checks pass. Provide a rollback/release note for the native tie-rule change; mixed-version behavior must be considered before deployment.
