# Audit 08 — Sabotage, censorship and eclipse attacks

Date: 2026-10-25. Snapshot: `9a28517d0a02e34721c102bccbf786b8443c3664`, copied to `/tmp/humoco-stufe5-audit/human-money-node`. Audit only; no production fixes or repository tests added.

## Findings

**A08-01 · P2 · An authenticated friend can overwrite another node's routing address without that node's authorization.** `crates/humoco-node/src/network/transport.rs:3391–3548` accepts a zero-signature heartbeat and a legacy `(NodePubKey, SocketAddr)` announcement. Even with a valid origin signature, the verified ingress-envelope digest binds timestamp/load but not `hb.addr` or the complete topology announcement. `network/manager.rs:1278` then unconditionally replaces the known identity's address and refreshes presence.

Two real-QUIC safe-behavior probes failed: an admitted relay changed an already-known victim from `127.0.0.1:31337` to `127.0.0.1:31338`, once with no origin signature and once with a genuine victim signature whose unsigned address field was changed. The sender's TLS identity differed from the advertised victim; the frame correctly claimed one relay hop. This demonstrates routing poisoning and a concrete censorship/availability primitive. It does **not** demonstrate forgery of the victim's TLS key, owner signatures, a live payment quorum or actual loss of funds. The signed case models tampering with a captured authentic heartbeat.

The other requested scenarios have conditional boundaries: a gateway can withhold service, but a fake success flag is not payment evidence; owner causality and fresh context-bound quorum verification are separate obligations. `humoco-proto` supplies verification primitives, while the in-repository `SmartClient` is a simulation; deployed merchant gateway rotation was not audited. Three independent neighbors are recommended by current Spec 07, not a cryptographically proved independence rule or mandatory three-gateway admission threshold. A long-lived trusted friend can introduce valid Sybils; maturation/median rules do not prove an honest majority.

Grey-hole tolerance is bounded by the frozen committee: fourteen timely qualified votes suffice, seven withheld votes prevent FINAL. No rank-21 replacement, neighboring-shard escape, universal 5 ms checkout guarantee or automatic ban for latency is permitted.

## Integrated fix plan

1. Preserve both reproductions as real-QUIC regressions. Assert that unsigned/altered relayed announcements cannot replace an existing identity's endpoint or refresh its presence; retain a positive authenticated address-change case.
2. Define a canonical, network-bound origin signature over the complete immutable announcement, including full identity, advertised endpoint, ticket/work context and timestamp. Forwarding TTL/hops may remain separately mutable. Reject unsigned/legacy announcements as authority for routing/presence changes; compatibility decoding alone must not authorize mutation.
3. Validate origin signature, freshness, work and identity before dedup/learning publication. Accept endpoint changes only from an authenticated origin statement or direct authenticated endpoint proof; prevent a less-direct relay from overwriting stronger information without valid fresh authority.
4. Add adversarial client integration checks for one censoring gateway, stale state and forged conflicts, using independently configured regional sources and bounded exact-intent retries. Do not turn a warning or inconsistent view into a network ban.
5. Run gossip/discovery, current-proof and fixed-committee wire tests plus the standard suite. Keep client deployment and globally independent topology outside any unproved immunity claim.

## Validation boundary

The prescribed standard suite ran in the isolated snapshot with a 240-second external limit: `timeout 240s env CARGO_TARGET_DIR=/home/basti/Coding/humoco/human-money-node/target cargo test-std --no-fail-fast`. It ended with exit 124 while `inherited_support_tests` was unfinished. Completed targets reported **326 passed, 0 failed, 0 ignored** across 27 result summaries; five visible passes in the unfinished target are not included. This is an incomplete baseline, not a clean full-suite result. Existing causality (7/7), current-proof boundaries (3/3), and anti-self-slashing wire coverage (1/1) passed during that run. The separately targeted genuine/forged-proof QUIC test passed 1/1.

Additional safe-behavior probes were written and executed exclusively in `/tmp/humoco-stufe5-audit/human-money-node/crates/humoco-node/tests/stufe5_probes.rs`; their expected assertion failures establish the reported open findings. No additional tests/mutations were installed in the repository. This single file contains the finding and integrated fix plan for its audit; the registry and pre-existing deleted report files were left untouched.
