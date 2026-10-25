# Audit 01 — Subtraction and simplification

Date: 2026-10-25. Snapshot: `9a28517d0a02e34721c102bccbf786b8443c3664`. Inspection only; no refactoring applied.

## Findings

All five items are **P3 maintainability opportunities**, not demonstrated consensus failures. Approximate net line savings below are planning estimates; an arbitrary 20–30% whole-project reduction is not justified.

| ID | Current location and duplication | Proposed target | Estimated saving |
| --- | --- | --- | --- |
| A01-01 | `crates/humoco-node/src/api/hmc.rs:643–813`: request/entry signature paths repeat current, zero-created-time and legacy hash verification, with additional genesis compatibility in the entry path | One private borrowed payload projection and shared candidate-digest verifier; retain each existing accepted encoding and its context | 40–70 lines |
| A01-02 | `network/transport.rs:403–459,2054–2108`: bidirectional/unidirectional fraud handlers repeat decoding, full-key verification, evidence persistence and ban/forward handling | One internal verified-proof application function; keep stream authorization and response framing in their wrappers | 35–55 lines |
| A01-03 | `api/metrics.rs:324–357`, `api/dashboard.rs:460–500`: both aggregate ingress-source concentration and address-subnet dominance | Share the pure aggregation over a supplied peer snapshot; retain dashboard-specific warnings/diversity masks | 20–30 lines |
| A01-04 | `network/manager.rs:1412–1421`, `identity.rs:250–257`, `storage/engine.rs:100–111`: synonymous HRW and RAM count/empty accessors | One canonical method per meaning, with explicit compatibility migration where externally used | 20–30 lines |
| A01-05 | `humoco-sim-core/src/client_flow.rs:185–191`: `add_to_chain` consumes a record, clones it into the vector and then discards the original | Move the consumed record directly | 0 lines; one record/nonce clone removed per call |

`RequestHandler` is not a useless single-implementation trait: production, default and adversarial test handlers implement it. DTO/wire/domain separation also has a purpose; collapsing these boundaries indiscriminately would weaken reviewability. Epoch, NodePubKey and HrwRoutingId must remain semantically distinct.

## Integrated fix plan

1. Apply the zero-risk ownership cleanup first. Then consolidate private helpers one at a time; measure the actual net diff and stop if new abstraction machinery outweighs the duplication removed.
2. A01-01: build fixtures for every current/legacy/zero-time/genesis signature candidate and exact parent binding before extraction. Never silently broaden accepted preimages or delete compatibility based only on its name.
3. A01-02: retain genuine/forged/cross-network real-QUIC regressions for both stream directions. The shared helper must not bypass the F2F gossip gate, durable evidence policy or full-key identity checks; its result must preserve existing acknowledgment semantics.
4. A01-03: compare exact telemetry outputs from identical snapshots. Keep the result diagnostic under INV-1701; no metric may start affecting bans, quotas or committee eligibility.
5. A01-04: enumerate all workspace and known downstream callers; migrate/deprecate public names before removal. Never confuse public-key identity with replaceable routing tickets. Existing distinct state/index maps must not be merged merely because they share a key type.
6. Run targeted checks and the standard suite after each reviewed refactor. Preserve durable-before-release, original/live signature purposes, TTL boundaries and fixed 14/20 membership. No equivalence proof is claimed for an unapplied refactor.

Concrete target edits (illustrative integrated patch outline, not applied):

```diff
-            .push(record.clone());
+            .push(record);
```

```rust
// Existing wrappers retain their trust/transport boundaries:
verify_signature_candidates(key, signature, canonical_candidates(payload));
apply_verified_fraud(proof, immediate_sender).await?;
let diagnostics = aggregate_peer_sources(snapshot);
// Callers use get_effective_hrw_routing_id(), len(), is_empty().
```

These targets remove duplicate implementation, not checks or consensus state. The proposed hash/handler helpers require the explicit equivalence tests above before removal is safe.

## Validation boundary

The required `cargo test-std --no-fail-fast` was attempted from the isolated copy with a 180-second limit and ended with exit 101 before tests executed: several native test links failed with `rust-lld`/`ld` SIGBUS. No cause for those linker crashes was established. A separate `CARGO_BUILD_JOBS=1 cargo test-fast` then completed: **248 passed, 0 failed, 0 ignored** across 3 library targets. Passing libraries do not replace real-QUIC/full-workspace validation. No production refactor, dependency upgrade or permanent regression test was installed by these audits. Exactly one combined finding/plan file was created per audit in `prompts/stufe 6/`; existing deletions and other stage reports were preserved.
