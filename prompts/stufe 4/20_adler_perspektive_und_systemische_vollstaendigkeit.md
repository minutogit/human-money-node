# Audit 20 — System completeness

2026-10-25 · Stage 4 · Commit `9a28517d0a02e34721c102bccbf786b8443c3664` · Source: `/home/basti/Coding/humoco/human-money-node`.
Audit only. Paths below are relative to that root. Current doctrine overrides the prompt's pre-commit signing order, rank-21 replacement and automatic quota-based punishment.

## Findings

- **A20-01 [MEDIUM] — Fraud receipt, live ban and restart state are not one reliable pipeline.** `crates/humoco-node/src/network/transport.rs:435` persists evidence separately, then bans and acknowledges; `storage/engine.rs:1090` changes RAM but drops the ban write if the queue is full/closed. Boot reloads only `db.all_banned_nodes()` (`engine.rs:776`, `daemon.rs:473`), not bans reconstructed from evidence. **Executed real-QUIC fault injection:** abort and await the isolated engine's flush worker, submit genuine Mainnet equivocation from an authorized peer. Result: both verifiers `true`, ACK `262`, engine/PeerManager banned `true`, persisted ban `false`, a newly constructed engine on the same database banned `false`. Durable evidence alone does not restore the punishment. Separately, evidence-write errors are logged and processing continues (`transport.rs:437`, `:2086`), contrary to non-loss requirement INV-1402 (`docs/14_node_persistenz_und_redb_speicher.md:174`). That disk-error branch was inspected, not fault-injected. No consensus double-spend was reproduced.
- **A20-02 [LOW, evidence gap] — “100-node” coverage does not exercise 100 running nodes.** `crates/humoco-node/tests/phase11_wire_level_adversarial_tests.rs:1081` models 100 identities in one PeerManager; `:1126` starts a server/client wire spot-check with manually prepared readiness. It cannot establish automatic 100-daemon bootstrap/recovery, mixed traffic isolation or checkout tail latency. This is a coverage limitation, not a newly demonstrated distributed failure.

## Integrated fix plan

1. **A20-01:** Persist validated evidence and its identity sanction atomically through a bounded protected persistence operation. Await its exact durable result before declaring durable success; keep immediate local containment while pending, with explicit failure reporting. Add restart reconstruction from validated durable evidence where necessary. Do not discard evidence or rely on an unguaranteed future “refresh.” Regress real QUIC with full/closed worker, storage error, crash between evidence/ban and reopen; no forged proof may create a sanction.
2. **A20-02:** Add a separate resource-bounded real-daemon campaign: 100 independent identities/databases, automatic readiness, HTTP writes/live verification, restart/churn, partition/merge and simultaneous gossip/sync/ingress. Record environment, achieved quorum, budgets, resource peaks and failures; retain the existing mathematical test with its narrow interpretation.
3. Close existing G2/G3/G4 proof obligations with explicit source-completeness, authenticated support and clock-composition arguments plus corresponding adversarial scenarios. They are already acknowledged as open in `docs/REGIONAL_AUTHORITY_AND_SIGNING_HISTORY_CONTRACT.md:145`; this audit does not reclassify them as proven exploits or claim to resolve them.

## Seven-pillar implementation check

“Present” means traced implementation, not unconditional production readiness.

| Pillar / specs | sim-core | Node runtime | Result |
| --- | --- | --- | --- |
| Ingress / 09, 13 | Quota/thermometer logic | `ingress/tier.rs`, `api/routes.rs` | Present; A02-02, A05-01 remain open. |
| Wire / 10, 15 | Header/domains | `network/framing.rs`, `transport.rs` | Present; bounded framing and identity checks. |
| HRW/quorum / 01, 03, 06 | Committee/quorum helpers | `network/manager.rs:2078`, `api/routes.rs:1034` | Present; frozen committee, distinct verified signatures. |
| RAM/redb / 12, 14 | Collision/expiry state | `storage/engine.rs:1492`, `:2497`, daemon pruning `:723` | Present; durable release and root-bound pruning. |
| Fraud / 02, 10 | Proof models | `network/transport.rs:403` | Incomplete on A02-01 and A20-01. |
| Gossip/clock / 07, 11 | Time/topology models | `network/clock.rs:87`, `daemon.rs:650` | Present; composition proof remains qualified. |
| Recovery/merge / 03, 08 | Class-aware ordering | `daemon.rs:846`, `:1184`, storage recovery/install | Present; demand sync, staged durable installation, class ordering; open proof gates remain. |

## Validation and limits

Standard workspace suite: **755 passed, 0 failed, 14 ignored**, exit 0. Additional probe reproduced A20-01 over localhost QUIC with temporary redb storage. Reconstructing the engine tests persisted ban loading; a full OS-process crash/restart was not run. Specifications 00–20 were mapped to selected live paths; this is not an exhaustive function-by-function proof. No 100-process deployment, complete wallet purchase/release campaign or deep ignored suite was executed.
