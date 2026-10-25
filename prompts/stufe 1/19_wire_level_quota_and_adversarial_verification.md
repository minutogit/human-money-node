# Audit 19 — Wire quotas and adversarial verification

Date: 2026-10-25. Scope: Specs 09/10/12/13, QUIC transport/framing, ingress accounting, fraud verification and integration coverage. Audit only; no fixes applied.

## Findings

**A19-R1 — P1: Ordinary reordered reads can permanently ban an honest peer.** `crates/humoco-sim-core/src/fraud.rs:944` treats a later-arriving packet with an earlier signed timestamp and different operation as fraud before normalizing time order. `crates/humoco-node/src/network/transport.rs:1543` immediately persists evidence, bans the identity and broadcasts the proof. Status envelopes use day/sequence zero, so concurrent independent reads reach this timestamp-order branch. Two genuine signatures demonstrate authorship, not malicious packet order.

New real-QUIC probe: send a correctly signed status read at T, then another for a different lock at T−1 ms, both within normal freshness bounds. First response: flags **0**, not banned. Second: flags **832**, `is_node_banned(sender) == true`. This reproduces an honest-identity sanction without conflicting original spend approvals. Spec 10 lines 199–207 explicitly excludes packet reordering as sufficient fraud evidence.

**A19-R2 — P2: Exact wire retries are charged repeatedly and fail at the daily limit.** `network/transport.rs:1029` reserves Byte-Years for every received write before testing whether the exact operation is already durable. No exact-operation accounting marker or refund exists. Real-QUIC probe: seed sender usage to limit minus one operation; send the same authenticated root-registration payload twice. First flags **0**; identical retry flags **256** (`FLAG_QUOTA_EXCEEDED`), sender remains unbanned. The final permitted operation can thus become unrecoverable to a sender that lost the first response. Spec 10 permits identical forwarding; Spec 12 requires durable idempotency. This reproduction uses a root registration; spend retries reach the same reservation gate by inspection.

**A19-R3 — P2: Receiver quota-boundary coverage is still incomplete.** `tests/audit19_regressions.rs:492` covers excessive *declared* EMA and TLS identity mismatch, while `:609` checks actual cumulative quota and full-key isolation through direct controller calls. `tests/phase4_net_time_and_quotas.rs:227` and `:403` call handlers directly despite their wire-oriented names. No existing checked-in test was found that exhausts receiver-observed write/read budgets over real QUIC and proves the next otherwise-valid request is rejected before mutation. This is an evidence gap, not proof that the quota hook is absent. The temporary retry probe reaches the real write boundary but is not a permanent repository regression.

Verified safeguards: root-derived receiver lifetime checks, authenticated sender binding, sender budgets keyed by all 32 public-key bytes, neutral quota feedback in collection, bounded admitted frame parsing. Public HTTP PoW is not required on the authenticated internal shard tier.

Validation: audit19 regressions **4 passed**; phase4 tests **8 passed**. Two additional temporary QUIC probes reproduced R1/R2. Their successful exit means the defective behavior was observed, not that safety assertions passed.

## Integrated fix plan

1. R1: add a permanent real-QUIC regression requiring no ban for reordered reads, equal-time independent reads, clock correction and retries. Define counter compatibility independently of arrival order; remove timestamp reversal as a sufficient sanction condition. Gate permanent sanctions on genuinely incompatible statements with the same signed context/purpose. Preserve valid original-approval equivocation detection and bounded evidence propagation.
2. R2: deduplicate storage-time charging for exact operations within root TTL, transactionally with durable admission. Reserve/refund safely for concurrent attempts, failed admission and cancellation. Keep separate bounded request/CPU pacing so free exact retries cannot overload crypto. Verify root and spend retries at the quota boundary over QUIC, including lost responses.
3. R3: check in receiver tests for exact limit/limit+1, understated EMA with exhausted observed counters, read exhaustion, full-key prefix collisions, malformed/truncated frames and unchanged state after denial. Exercise actual transport, not only handlers/controllers.
4. Run these tests, the existing QUIC suites, `cargo test-std` and Clippy. Treat signed telemetry anomalies separately from cryptographic equivocation; never add lock gossip or automatic sanctions based on quota disagreements.

Final shared validation: `cargo test-std` — **722 passed, 0 failed, 14 ignored**; `cargo clippy --workspace --all-targets -- -D warnings` passed. These green checks do not invalidate the separate defect probes above.
