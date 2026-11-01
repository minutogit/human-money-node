# Audit 25 — Ingress defense and stateless PoW

Date: 2026-10-25. Scope: ingress pow/tier, public HTTP routes, client provisioning and wire framing. Audit only; no fixes applied.

## Findings

- **A25-R1 — P2: Canonical work helper is not used by verification.** `crates/humoco-node/src/ingress/pow.rs:40` defines the specified direct `hash_work(parent, slot, nonce)`, but `:272` still verifies `compute_solution_hash(challenge, nonce)` using another domain and a nested hash. External deterministic probe: parent `[9;32]`, slot 2, nonce **475**, difficulty 8 satisfies canonical work; verification at 1,200 seconds rejects it with `InsufficientDifficulty { required: 8, provided: 1 }`. The existing “canonical” regression only tests parent mismatch at difficulty zero and cannot detect this.
- **A25-R2 — P2: Chain admission accepts generic zero-parent work.** `api/routes.rs:2703` passes `None` as the PoW parent for all chains, including real terminal spends. Work can therefore be transplanted between unrelated chains in the same slot. Retries for the same operation should remain stateless, but that does not authorize cross-parent reuse. Confirmed by call-chain inspection; no new full HTTP chain-spend reproduction.
- **A25-R3 — P2: Expensive signed rejection remains reachable before admission.** `api/routes.rs:2636` signs an empty-chain error before checking credentials; `:2669` also reads the root before admission. Single-lock handling only checks credential presence at `:1873`, then accesses roots before verifying their validity. External HTTP router probe with an empty chain and no credentials returns **400 with `server_signature`**. Thus anonymous requests can force signing despite the existing unsigned-401 test. No saturation benchmark was performed.
- **A25-R4 — P3: Provisioning accepts weak client credentials.** `ingress/tier.rs:43` permits 8–64 arbitrary alphanumeric suffix characters; `is_valid_client_token("f2f_password")` returns true. The daemon and operator provisioning use that validator, contrary to the required 128-bit random-secret format. The probe establishes format acceptance, not credential compromise. Automatically generated tokens and bare-NodePubKey rejection remain correct.

Verified safeguards: concrete-parent challenge comparison for single spends; stateless exact retries; public quota-denial handling; safe 64 KiB preallocation cap and admitted frame reads; normal status forwards to one committee peer. Dynamic EMA and framing were inspected; no additional confirmed arithmetic or unsafe-decoding defect.

Validation: `cargo test -p humoco-node --test audit25_regressions`: **5 passed**. External probes reproduced R1, R3 and R4. These checks establish no real-QUIC defense by themselves; the final wire audit separately exercises receiver enforcement.

## Integrated fix plan

1. R1: switch verification to `hash_work` with the validated parent and matched current/previous slot. Align client/test solvers; add nonzero-difficulty positive canonical vectors and negative legacy-hash vectors. Keep exact retries valid.
2. R2: derive chain work from the terminal consumed parent (or a specified canonical operation commitment). Use it consistently for challenge generation and verification. Add unrelated-chain transplant rejection plus identical-chain retry tests.
3. R3: perform bounded credential/PoW validation before root I/O, crypto and signed errors on every write route. Charge root-derived quotas only once the authenticated root is resolved. Add empty/malformed chain, bogus bearer, unknown-root and stale-timestamp HTTP cases asserting unsigned early rejection and no pre-admission expensive work.
4. R4: require exactly `f2f_` plus 32 hexadecimal digits at every registration boundary; generate secrets from a CSPRNG and keep labels separate. Test weak strings, malformed lengths and NodePubKey representations in provisioning and admission.
5. Run the ingress, HTTP and adversarial QUIC suites, `cargo test-std` and Clippy. Update stale replay-cache comments and inaccurate regression names alongside the eventual fixes.

Final shared validation: `cargo test-std` — **722 passed, 0 failed, 14 ignored**; `cargo clippy --workspace --all-targets -- -D warnings` passed. These green checks do not invalidate the separate defect probes above.
