# Audit 17 — Update verification and Node Sovereignty

Date: 2026-10-25. No version pair was supplied, so the concrete update reviewed is **568dfb8e26c79cb2e9d7f33e90dc511d566bdfbc → 9a28517d0a02e34721c102bccbf786b8443c3664**, plus explicitly separated checkout/provenance observations. Audit only; no update applied.

## Findings

**Verdict: YELLOW — review required, not evidence of a backdoor.** The diff changes expiry boundaries, saturating arithmetic, simulation merge ordering, fraud-constructor error handling and storage API visibility. These are substantive safety changes with tests, rather than a formatting-only update. The strict grace horizon changes from the earlier rounded expression to `(root + 30000)/1000 + 1` with saturation; this deserves the included exact-boundary checks. The review found no new external endpoint, update downloader, shell execution, crypto-domain constant, Argon2 parameter, quorum threshold or financial-deposit mechanism in this diff. `thiserror 1.0.69` becomes a direct Core dependency; its package was already resolved in the lockfile.

**A17-01 · P2 · The reviewed main-repository diff does not pin all protocol source used by the build.** Both workspace crates depend on `humoco-proto = { path = "../../../humoco-proto" }`. Cargo metadata resolves a separate repository, outside this commit. Its observed HEAD was `6877dd91243ac31cc54c8e6384180d01b62ed753`; this is an observation, not an immutable reference in the main manifest/lockfile. A protocol edit there can alter signed-byte verification without appearing in this update diff. `--locked` alone does not pin local path contents. The local `clap_complete` replacement is inside this repository and therefore does have main-commit coverage; it should not be confused with a downloaded upstream package of the same name/version.

**A17-02 · P3 · New public test mutators weaken the stated encapsulation improvement.** `crates/humoco-node/src/storage/engine.rs:131–137` adds ungated `insert_lock_for_test` and `insert_voucher_root_for_test`, while narrowing the underlying fields to `pub(crate)`. These methods remain callable in normal release-library builds and mutate individual maps without coordinated TTL/filter/durable metadata updates. This is an API-boundary/maintenance issue for trusted library consumers, not a demonstrated remote HTTP/QUIC bypass or a new authority granted to network input.

Release verification remains unestablished: the observed commit object has no embedded signature; the checkout contains no SHA256SUMS artifact and its only listed tag is an archive tag. That does not establish anything about unpublished or remote release artifacts. `SECURITY.md` promises signed releases and suggests broad protection even with 30–40% faulty nodes; current specifications correctly make per-committee fault bounds conditional. An AI review or a global node percentage cannot certify release integrity or guarantee an honest shard majority. Current dependency advisories are tracked separately in Audit 16 and were not introduced by this one-line lockfile change.

Pre-existing behavior, not new in this diff: optional configured Telegram/webhook alerts create outbound HTTPS requests; private diagnostics invoke `df -Pk` with argument-vector execution and read `/proc`. No automatic code download/update/install path was found in the searched daemon source. This inspection does not prove absence of every possible side effect.

## Integrated fix plan

1. Record and verify both repository commits and dirty status in every release review. Pin/vendor the protocol source or use a reviewed immutable Git revision; produce a dependency/source manifest that binds the actual protocol bytes. Keep operator-controlled manual deployment.
2. Move test mutation fixtures behind an explicit test-support boundary or into internal tests; expose safe read-only APIs and invariant-preserving production operations. Verify normal release builds do not export raw fixture mutation APIs.
3. Retain the added TTL/overflow/fraud/merge tests and run full validation on the exact two-repository source set. The standard suite currently failed at native linking with `rust-lld` SIGBUS, so this audit cannot issue a green tested-update verdict.
4. Make SECURITY.md distinguish verification instructions from artifacts actually produced, and replace unconditional faulty-node-percentage claims with the per-committee assumption. Bind checksums to authenticated release signatures; a checksum by itself does not authenticate its producer.
5. Apply Audit 16's reviewed dependency remediation separately and regenerate/review Cargo.lock explicitly. No automatic update, remote restart, telemetry sanction or blanket committee reshuffle is part of this plan.

For the operator: the changes address real safety boundaries and introduce no identified covert updater. The build still depends on separately reviewed protocol source, dependency advisories remain open, and full tests were not established. Review those exact inputs before deciding whether to deploy.

## Validation boundary

The required `cargo test-std --no-fail-fast` was attempted from the isolated copy with a 180-second limit and ended with exit 101 before tests executed: several native test links failed with `rust-lld`/`ld` SIGBUS. No cause for those linker crashes was established. A separate `CARGO_BUILD_JOBS=1 cargo test-fast` then completed: **248 passed, 0 failed, 0 ignored** across 3 library targets. Passing libraries do not replace real-QUIC/full-workspace validation. No production refactor, dependency upgrade or permanent regression test was installed by these audits. Exactly one combined finding/plan file was created per audit in `prompts/stufe 6/`; existing deletions and other stage reports were preserved.
