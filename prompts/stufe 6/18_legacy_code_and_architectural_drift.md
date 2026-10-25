# Audit 18 — Legacy code and architectural drift

Date: 2026-10-25. Snapshot: `9a28517d0a02e34721c102bccbf786b8443c3664`. Findings and removal plan only; no production code or specifications changed.

## Findings

| ID / priority | Location | Confirmed drift and consequence |
| --- | --- | --- |
| A18-01 · P3 | `docs/10_p2p_wire_format_und_session_framing.md:100–120,133–135` versus `crates/humoco-sim-core/src/wire.rs:98–117` and `humoco-node/src/network/framing.rs:80` | The documented enum omits implemented `LiveStateRequest/Response` (0x0040/41) and `ShardBucketRangeRequest/Response` (0x010C/D). It also promises a fixed 64-byte `EpochHeartbeat`, while production uses a variable serialized heartbeat with identity, endpoint, signature, ticket and optional bounded evidence/advertisement fields. These are active protocol paths, not dead types to delete. |
| A18-02 · P3 | `identity.rs:11,229`, `network/manager.rs:74–77` | Comments still describe NodeID as an Argon2 result or BLAKE3 fingerprint. The actual constructor at `identity.rs:115` stores the full Ed25519 verifying-key bytes; the replaceable HRW ticket is separate. The misleading names/comments invite precisely the identity/ticket confusion prohibited by AGENTS.md. |
| A18-03 · P3 | `storage/engine.rs:1151–1174` | Public ingress Rustdoc describes unconditional min-hash replacement, even though the default wrapper is ClientApi, whose collisions must not replace a lock, and sync resolves confirmation classes before hashes. This is comment drift, not a reproduced resolver defect. |
| A18-04 · P2, already tracked | `cli.rs:2025–2133`, `humoco-sim-core/src/fraud.rs:48–63`, `network/transport.rs:148–152` | Production `revoke` still creates simulator heartbeat evidence, which production correctly rejects. This is an active prototype/production boundary crossing, not harmless unused code. The exact disposable-identity and QUIC reproduction is documented in `prompts/stufe 5/09_node_compromise_and_key_revocation.md`; it is the same finding, not an additional independent exploit. |

No unused legacy lock-gossip message type was identified in the current MsgType enum. `IngressLockPayload::{Chain, Single}` at `api/routes.rs:393` represents two current HMC request shapes; neither is the retired generic LockPayload API. QUIC task spawning still serves real transport/sync work; a spawn count alone does not prove a ghost engine. Compatibility signature decoders are reachable and cannot be purged without an explicit migration policy.

## Integrated fix plan

1. Correct the wire table and replace the obsolete fixed-heartbeat description with the actual bounded versioned schema, including compatibility and optional-field rules. Add a specification/source discriminant check; preserve active live-state and paginated-sync functionality. **Delete the stale table text, not the corresponding handlers.**
2. Replace the fingerprint/Argon2 identity comments with “full Ed25519 NodePubKey”; describe Argon2 only for HrwRoutingId. Preserve all key bytes and hash preimages. Deprecate aliases only after the caller review in Audit 01.
3. Replace the ingress Rustdoc with the actual two cases: ClientApi first-seen/idempotency/conflict; qualified PartitionSync class precedence, then canonical/ID tie-breaking. No runtime removal is needed for this item.
4. Follow Audit 09's integrated revocation plan. Remove simulator-proof generation and unsupported success claims from the production command only as part of a truthful local-control/real-revocation implementation; never weaken the first-party verifier or delete the simulation helpers used by specifications.
5. For any subsequent removal, run wire/discovery/live-proof/collision tests and the standard suite. No claim of behavioral equivalence or production security is inferred from documentation cleanup alone.

Illustrative documentation-only target diff:

```diff
- Every active node sends exactly one 64-byte heartbeat payload per hour
+ Hourly presence uses the bounded HeartbeatWirePayload schema and Spec 11 pacing.
- NodeIdentity::node_id() (a BLAKE3 fingerprint)
+ NodeIdentity::node_id() (the full Ed25519 NodePubKey)
- When a colliding lock arrives, min(H_canon) decides.
+ Client ingress preserves the existing lock; qualified sync compares class before hash.
```

## Validation boundary

The required `cargo test-std --no-fail-fast` was attempted from the isolated copy with a 180-second limit and ended with exit 101 before tests executed: several native test links failed with `rust-lld`/`ld` SIGBUS. No cause for those linker crashes was established. A separate `CARGO_BUILD_JOBS=1 cargo test-fast` then completed: **248 passed, 0 failed, 0 ignored** across 3 library targets. Passing libraries do not replace real-QUIC/full-workspace validation. No production refactor, dependency upgrade or permanent regression test was installed by these audits. Exactly one combined finding/plan file was created per audit in `prompts/stufe 6/`; existing deletions and other stage reports were preserved.
