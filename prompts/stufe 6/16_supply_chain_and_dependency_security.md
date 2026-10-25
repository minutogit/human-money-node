# Audit 16 — Supply-chain and dependency security

Date: 2026-10-25. Project snapshot: `9a28517d0a02e34721c102bccbf786b8443c3664`. No dependency update or manifest/lockfile mutation applied.

## Findings

**A16-01 · P2 · The lockfile contains versions covered by current RustSec advisories.** The official database was cloned to `/tmp` at commit `21d909e4c8bd4e14c7aea58bf980c881a0053ab1`. Of 288 locked packages, name filtering found 91 non-withdrawn advisory candidates; Rust `semver 1.0.28` evaluated their patched/unaffected VersionReq ranges in 216 queries. Result: **12 package/advisory matches: 9 vulnerability entries, 2 informational unsoundness entries and 1 unmaintained entry**. These are version-range matches, not twelve demonstrated exploits.

| Locked package | Advisory matches | Minimum remediation / applicability |
| --- | --- | --- |
| `quinn-proto 0.11.17` | [0338](https://rustsec.org/advisories/RUSTSEC-2026-0338.html), [0340](https://rustsec.org/advisories/RUSTSEC-2026-0340.html), [0343](https://rustsec.org/advisories/RUSTSEC-2026-0343.html) (2026) | Resolve >=0.11.18. The reported triggers require unordered reads, opt-in ACK_FREQUENCY, or outgoing datagrams respectively; none of those API uses was found in node source. Do not report a reproduced production panic from the version match alone. |
| `rustls 0.23.43` | [0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html), [0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html), [0348](https://rustsec.org/advisories/RUSTSEC-2026-0348.html), [0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html) (2026) | Resolve >=0.23.46. Findings concern handshake-level validation, custom session-value Debug logging, Brotli certificate allocation and key-share prediction. Brotli is disabled; no custom session-store logging was found; the selected ring provider offers classical groups only, so the described PQC downgrade premise is absent. No authentication bypass is claimed. |
| `rustls-webpki 0.103.15` | [2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html) | Resolve >=0.103.16: rejection of distrusted emSign intermediates. Relevant certificate-chain use is the configured HTTPS client, not an assumption that P2P's custom identity verifier uses CA-chain authorization. |
| `webpki-roots 1.0.9` | [2026-0381](https://rustsec.org/advisories/RUSTSEC-2026-0381.html) | Resolve >=1.0.10 to remove the affected trust anchor. `reqwest` enables this bundled root set. |
| `tokio 1.53.1` | [2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386.html), informational unsound | Resolve >=1.53.3 (or a fully scanned newer release). Unsafe descriptor-lifetime misuse is required; no direct AsyncFd construction was found in node source. Review transitive socket ownership separately. |
| `rand 0.7.3` via `cuckoofilter 0.5.0` | [2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097.html), informational unsound | Old major line has no listed patched 0.7 release. The required `log` feature is absent in the resolved feature set, so this is not a demonstrated reachable issue. Review replacement/update of the parent dependency instead of forcing an incompatible rand version. |
| `bincode 1.3.3` | [2025-0141](https://rustsec.org/advisories/RUSTSEC-2025-0141.html), unmaintained | No patched version is listed; see A16-02. |

**A16-02 · P3 · The shared wire/storage serializer is unmaintained.** Bincode's maintenance notice is not itself an exploitable CVE. Blindly replacing it would change consensus/persistence bytes. Record a bounded maintenance decision and assess a versioned migration with golden-byte fixtures, not an automatic serializer swap.

**A16-03 · P3 · Dependency/license policy is not encoded in a checked gate.** No cargo-deny policy or repository CI workflow was found. Linux metadata resolves 243 packages, including `option-ext 0.2.0` declared **MPL-2.0**; no GPL/AGPL declaration was found in this target's metadata. Therefore “all dependencies are MIT/Apache and copyleft-free” would be inaccurate; MPL presence is not proof the MIT project is incompatible. Keep notices and review policy explicitly. Other-target license metadata was not fully resolved: unrestricted offline metadata failed while unpacking an uncached Windows package into the read-only registry cache.

Duplicate families are cpufeatures (2), getrandom (4), rand (4), rand_chacha (3), rand_core (4), syn (2), thiserror/thiserror-impl (2 each). They arise from incompatible transitive major lines; forced deduplication is unsafe. Direct Tokio/Quinn/Rustls/Reqwest feature selections are already narrow; shared feature unification must be assessed before claiming further savings. No binary-size measurement was performed. External path-source reproducibility is addressed in Audit 17.

## Integrated fix plan

1. In an isolated remediation branch, refresh only the affected compatible lockfile packages: quinn-proto >=0.11.18, rustls >=0.23.46, rustls-webpki >=0.103.16, webpki-roots >=1.0.10 and Tokio >=1.53.3. Raise the direct Tokio/Rustls version floors to the reviewed patched minima while preserving current features. Avoid a blanket major-version update or adding unused direct dependencies solely to constrain transitives.
2. Run official `cargo audit` against a fresh pinned advisory database and `cargo deny` with an explicit target/license policy; neither tool is installed here. The custom scan used official ranges but does not reproduce cargo-audit's full withdrawn/yanked/target/reporting behavior. Record exceptions only with exact feature/reachability evidence and expiry/review ownership.
3. Validate actual TLS/QUIC handshakes, malformed frames, cancellation, quotas and durable-before-release after updates, using real QUIC tests. Recheck custom Ed25519 peer identity verification and external HTTPS trust behavior; do not weaken authentication to make upgrades pass.
4. Review cuckoofilter's older RNG dependency and Bincode's maintenance status separately, preserving false-negative safety and serialization bytes. Capture notices/SPDX inventory for all supported targets and source hashes for local path dependencies.
5. Run the standard suite and Clippy on the exact reviewed dependency set. The attempted current standard baseline failed before test execution with native-linker SIGBUS; no advisory was closed and no clean full-suite result is claimed.

Evidence lives under `/tmp/humoco-stufe6-*`; this report embeds the affected versions, primary-source links, applicability limits and integrated remediation plan. The main Cargo.toml and Cargo.lock remain unchanged.

## Validation boundary

The required `cargo test-std --no-fail-fast` was attempted from the isolated copy with a 180-second limit and ended with exit 101 before tests executed: several native test links failed with `rust-lld`/`ld` SIGBUS. No cause for those linker crashes was established. A separate `CARGO_BUILD_JOBS=1 cargo test-fast` then completed: **248 passed, 0 failed, 0 ignored** across 3 library targets. Passing libraries do not replace real-QUIC/full-workspace validation. No production refactor, dependency upgrade or permanent regression test was installed by these audits. Exactly one combined finding/plan file was created per audit in `prompts/stufe 6/`; existing deletions and other stage reports were preserved.
