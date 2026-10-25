# Audit 05 — Performance and latency

2026-10-25 · Stage 4 · Commit `9a28517d0a02e34721c102bccbf786b8443c3664` · Source: `/home/basti/Coding/humoco/human-money-node`.
Audit only. Paths are relative to that root. Current targets: RAM lookup <1 µs, local durable processing <20 ms, checkout budget 800 ms. The historical 5 ms total-response and unsafe zero-copy-cast assumptions are obsolete.

## Findings

- **A05-01 [MEDIUM, source-confirmed] — Blocking redb access remains on async checkout branches.** `crates/humoco-node/src/api/routes.rs:747` calls synchronous `storage.voucher_root()` inside an async helper; the missing-RAM-root spend branch calls it at `:2030`. `crates/humoco-node/src/ingress/tier.rs:320` also holds the shared quota write lock while a cold cache entry loads from redb at `:323`. Declaring a helper `async` does not offload its body. Cold/fault-delayed reads occupy a runtime worker; the VIP branch additionally blocks other quota accounts. No production p99/SLA violation was measured.
- **A05-02 [LOW, tuning candidate] — Original approvals serialize separate durable transactions.** `crates/humoco-node/src/storage/engine.rs:2764`–`:2838` recursively splits a flush batch at each original approval and invokes `commit_original_approval` / `commit_original_record_approval` separately. A batch with N distinct originals performs N approval commits rather than one group commit, in addition to preceding ordinary writes. This protects signing correctness but limits group-commit throughput. This is a cost model, not evidence that batching currently misses the SLA.
- **A05-03 [LOW, tuning candidate] — Fan-out copies the request body per committee member.** `crates/humoco-node/src/api/routes.rs:1069` uses `query.payload.to_vec()` in every spawned query. For 20 peers and payload length P this creates up to 20 body allocations/copies (20P bytes; at P=64 KiB, 1.25 MiB), excluding serialization and transport buffers. Body size bounds remain effective; this is avoidable copy overhead, not an OOM finding.

## Integrated fix plan

1. **A05-01:** Move root and cold quota reads to bounded blocking workers; hydrate registered VIP balances before enabling service, and never perform storage reads under the shared cache lock. Preserve atomic charging and correct error propagation. Test cold-root/cold-VIP requests alongside an async heartbeat under deliberately delayed storage.
2. **A05-02:** Benchmark present commit count and queue residence under representative concurrent writes first. If significant, group compatible original approvals into one atomic immediate-durability transaction, validate all signing-history constraints, and release acknowledgments only after commit. Preserve exact retries, fail-closed behavior, FIFO fences and history integrity. Do not remove durable-before-vote.
3. **A05-03:** Share one immutable `Bytes`/`Arc<[u8]>` payload across collector tasks; send borrowed slices. Verify byte-identical requests, cancellation and retry behavior. Keep safe `from_le_bytes` header decoding.
4. Measure baseline and changed p50/p95/p99/p99.9 for local durable work and end-to-end checkout with stated hardware, TTLs, body sizes and concurrency. Report actual percentage improvements only after measurement; none is claimed here.

## Validation and limits

`cargo test-std --offline`: **755 passed, 0 failed, 14 ignored**, 99 harness summaries, exit 0. Existing QUIC, collision, quota, signing and cluster tests were included. This suite is not a performance benchmark. Reviewed HTTP → admission → frozen committee → durable local storage → parallel QUIC collection → response, RAM index locks, safe bounded framing and flush sequencing. The RAM implementation uses guarded maps, not a demonstrated hardware CAS; no sub-microsecond or 10,000-concurrent-request performance claim is made.
