# Parallel baseline audit: S02, S03 and S04

Date: 2026-11-01. Audited revision: `5eaddf15dcaf084c143f89c1b0574beeb39fe206`.

Three subagents each inspected one slice under `prompts/AUDIT_LOOP.md`.
The coordinator checked the reported traces, reran the two temporary storage
reproductions, deduplicated shared causes and updated the ledger centrally.
No files under `crates/` were changed. This is a baseline review of three slices,
not a claim that the full workspace is defect-free.

## Results

| Slice | Scope | New findings | Ledger outcome |
| --- | --- | ---: | --- |
| S02 | Persistence worker, database, signing history, shard activity, recent buffer | 2 | `Fix_Open`, streak 0, total 2 |
| S03 | Recovery, installation, projections, roots, snapshots, confirmation support, filter | 0 independent causes | `Clean`, streak 1, total 0 |
| S04 | QUIC transport, framing, outbound connection pool | 5 | `Fix_Open`, streak 0, total 5 |

S03 shares the effects of S02-02. Its clean result means no additional independent
cause was found in that slice; recovery still needs the S02 fix. The shared defect
is counted once. S01 was not rerun; S05-S09 remain pending.

## Verified findings

| ID | Priority | Primary location | Defect and concrete consequence |
| --- | --- | --- | --- |
| S02-01 | High | `crates/humoco-node/src/storage/db.rs:2119` | Backup to the live source path unlinks that database and creates a snapshot at its name. Later successful writes go to the old unlinked file and disappear on restart. Control and offline CLI both reach this operation. |
| S02-02 | Medium | `crates/humoco-node/src/storage/db.rs:778` | A pass removes only 256 expired HMC spends but removes their root independently. Remaining expired rows lack their root and make sync/snapshot/digest reads fail, including reads for unrelated shards. |
| S04-01 | High | `crates/humoco-node/src/network/transport.rs:2746` | Outbound dialing authorizes an address before TLS but accepts/publishes the presented identity without checking it against the intended known identity. A different key at that address can receive requests. This does not establish forged quorum acceptance. |
| S04-02 | High | `crates/humoco-node/src/network/transport.rs:3780` | The legacy tuple heartbeat branch learns a relayed identity/address without origin signature or ticket validation. A forwarding F2F connection can introduce unauthenticated third-party discovery state. |
| S04-03 | Medium | `crates/humoco-node/src/network/transport.rs:3478` | Bidirectional dispatch applies the direct-RPC allowlist without the F2F-only gossip check used by unidirectional dispatch. A known non-friend can submit an EquivocationProof through this path. Genuine evidence is still required for a ban; the defect is the gossip authorization bypass. |
| S04-04 | High | `crates/humoco-node/src/network/transport.rs:394` | The production fraud handler calls the network-agnostic verifier, despite having a configured network. Two genuine signatures from the other network can trigger a local permanent ban. Mixed-network pairs are already rejected; that existing coverage does not cover an entire foreign-network proof. |
| S04-05 | Medium | `crates/humoco-node/src/network/transport.rs:2144` | Bucket-range requests are decoded with a permissive fallback and their count is not limited by the response frame budget. The handler builds and serializes up to 65,535 bucket rows, repeatedly scanning the shard, before `write_frame` rejects the oversized response. |

### S02 reproduction evidence

Temporary standalone Rust harnesses linked the current production library;
they did not modify crate sources. The backup probe uses a quota value to
demonstrate file divergence, rather than claiming an executed signing-history
loss test. The same replacement file contains the backup of own-choice tables.

```text
self-backup result: Ok(0)
live post-backup quota: 200
reopened quota: 100

pruned: ([], 256)
root present: false
remaining spends: 1
snapshot: Err(DurableCommitFailed("sync HMC lock missing root anchor"))
unrelated shard digest: Err(DurableCommitFailed("committed spend lacks root"))
```

The TTL harness seeded one root with `valid_until = 50_000 ms` and 257 dependent
storage rows, then called `prune_expired_buckets(81)`. It isolates storage
behavior; it is not an end-to-end authenticated client/QUIC reproduction.
The follow-up prompt requires valid protocol fixtures and wire regression tests.

Relevant traces:

- S02-01: `db.rs:2118-2124`; `control/server.rs:494-500`; `cli.rs:2049,2081`.
- S02-02: `db.rs:778-843,1651-1699,1751`; missing-root readers in
  `db.rs:1986-1995`, `db/install.rs:713-723`, `db/snapshot.rs:240-250` and
  `db/projection.rs:27-31`.
- S04-01: address-only precheck at `transport.rs:2708-2717`; handshake and
  publication at `transport.rs:2746-2768`; unchecked sibling at `2793-2841`;
  `network/manager.rs:1102-1138`; `network/tls.rs:113-139`.
- S04-02: structured-heartbeat checks at `transport.rs:3647-3767` versus
  legacy tuple admission at `3780-3794`; `network/manager.rs:1459-1467`.
- S04-03: bidirectional dispatch at `transport.rs:3478-3528`, handler at
  `526-536`, versus unidirectional gossip barrier at `3608-3621`.
- S04-04: `transport.rs:394-430`; network-aware verifier at `139-249`.
- S04-05: `transport.rs:2144-2188`; frame cap applied at
  `network/framing.rs:921-928` only after response construction.

S04 findings were verified by code tracing; no new network reproduction was
executed for those five cases. Existing green wire tests do not prove those
uncovered scenarios. The third agent's initial completion was interrupted by a
service content filter; its defensive static review was resumed and its traces
were independently checked by the coordinator.

## Coverage

All 15 target files were read by their assigned agents:

- S02: `storage/engine.rs`, `storage/db.rs`, `storage/db/signing.rs`,
  `storage/activity.rs`, `storage/recent.rs`.
- S03: `storage/engine/recovery.rs`, `storage/db/install.rs`,
  `storage/db/projection.rs`, `storage/db/roots.rs`, `storage/db/snapshot.rs`,
  `storage/db/support.rs`, `storage/filter.rs`.
- S04: `network/transport.rs`, `network/framing.rs`, `network/pool.rs`.

Paths above are relative to `crates/humoco-node/src/`. Relevant direct callers,
shared storage primitives, TLS and peer-manager code, and existing storage,
recovery, control and wire regressions were also inspected. This was a manual
code review, not exhaustive interleaving exploration or a formal proof.

The suspected signing-latch race was rejected after checking transaction-level
guards. The heartbeat read-evidence candidate was rejected because signature
verification prevents the hypothesized false ban. Neither is counted.

## Validation

- `cargo clippy --workspace --all-targets -- -D warnings`: passed, exit 0.
- `cargo test-std`: passed with local socket permissions, exit 0;
  **881 passed, 0 failed, 14 ignored**, across 113 test/doc-test result groups.
- The first sandboxed run stopped in the node library tests: 173 passed,
  3 failed because local QUIC bind was denied (`Operation not permitted`).
  The complete authorized rerun above resolved that environment limitation.
- Both temporary S02 production-library probes reproduced their intended failures.
- Ignored deep tests were not executed. No production fix has been made, and
  existing suite success does not resolve the seven findings.

## Handoff

Use [the consolidated remediation prompt](2026-11-01_S02_S04_REMEDIATION_PROMPT.md).
It contains the exact traces, regression-first fix plan, full validation commands
and the required `Fix_Open` to `ReCheck` ledger transition.
