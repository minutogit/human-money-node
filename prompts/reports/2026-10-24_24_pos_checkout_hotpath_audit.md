# Audit 24: PoS checkout hot path and cancellation safety

Date: 2026-10-24  
Auditor: Codex  
Repository HEAD: `76ef71f530b24daca56a84f02e5461da18837772`  
Result: **4 open findings: 3 HIGH (P2), 1 MEDIUM (P3).** No production code was changed.

## Scope and evidence

Reviewed `api/live.rs`, `api/routes.rs`, `api/hmc.rs`, `network/transport.rs`,
`network/pool.rs`, `network/peer.rs`, committee selection in `network/manager.rs`
and `humoco-sim-core/src/types.rs`, and transport configuration in `network/tls.rs`.
References: audit prompt 24, AGENTS.md, specifications 06 and 15, and the
2026-10-24 architecture implementation audit. The adjacent app's
`src-tauri/src/gateway_resolver.rs` was read to verify the live-proof client deadline.
The adjacent app/core test suites and intra-TTL purchase updates were not rerun.

- Mandatory baseline: `RUST_TEST_THREADS=4 cargo test-std --offline`:
  **681 passed, 0 failed, 14 ignored**, exit 0.
- Three additional audit probes use real loopback QUIC, TLS identities, production
  framing, a 20-member remote committee and the production HTTP router. Request
  handlers are instrumented to delay replies or supply an alternative signed lock.
  **3/3 probes confirmed the reported behavior**, exit 0. Their assertions describe
  current defects; passing these probes does not mean the defects are fixed.
- Initial sandbox execution could not bind local QUIC sockets (`EPERM`). The
  baseline and probes were subsequently executed successfully with approved local
  socket access. This was an environment restriction, not a production finding.
- Raw logs: [baseline](evidence/audit24-2026-10-24/test-std.log),
  [probes](evidence/audit24-2026-10-24/probes.log).
- Reproduce from the repository root:
  `bash prompts/reports/evidence/audit24-2026-10-24/run-probes.sh`.
  The runner extends the existing status reconciliation fixture in a temporary test
  target and removes that target on exit. It does not modify production files.

## A24-01 — HIGH (P2): One fast minority answer prevents a valid live proof

**Location:** `crates/humoco-node/src/api/live.rs:170-181`, `:272-290`.

Discovery returns the first lock with a valid client signature and matching voucher,
then aborts every remaining status query. `verify_current` changes the requested
child and state digest to this single answer and collects votes only for that claim.
A client authorization signature establishes neither current canonical state nor
committee acceptance. A stale/minority peer, or a Byzantine peer holding a valid
alternative signed child, can therefore select a claim the honest quorum cannot sign.
There is no fallback to another discovered candidate.

**Wire trace:** Twenty custodians contain child C. A stateless gateway is asked about
child A. One instrumented authenticated custodian immediately returns a different,
validly client-signed child D; other status responses are delayed by 150 ms. Discovery
chooses D and cancels the other queries. Honest custodians refuse D, and HTTP returns
503. With the alternative response disabled, the same cluster and request return
200 with a verified 14/20 proof for C. The probe does not demonstrate a forged proof
or unauthorized goods release; the impact is loss of availability despite quorum.

**Proposed fix:** Keep bounded candidate discovery alive and group candidates by
complete state digest. Attempt live voting for eligible candidates within one shared
deadline, reusing the frozen committee and recipient nonce. A first answer must not
irrevocably select authority. Only a verified 14/20 live proof can select the result.

## A24-02 — HIGH (P2): Discovery and voting exceed the client's live-proof deadline

**Location:** `crates/humoco-node/src/api/live.rs:170`, `:273`, `:352`.  
**Client boundary:** `../human-money-app/src-tauri/src/gateway_resolver.rs:129-135`.

Remote lock discovery receives a fresh 800 ms timeout. After it finishes, live-vote
collection receives another fresh 800 ms timeout. Setup and local signing are outside
both collection timers. The actual app's `fetch_live_proof` uses one absolute 800 ms
deadline for the request and response body. A server response can thus be valid but
arrive after the client has abandoned the checkout.

**Wire trace:** Delay each StatusQuery response by 450 ms and each LiveStateRequest
response by another 450 ms. The production endpoint returns a valid 14/20 proof after
**984 ms** in the final probe run. Both phases individually fit 800 ms, while the
combined response exceeds the app deadline. The probe measures the server response;
the app timeout consequence follows directly from the inspected absolute deadline.
Spec 06 explicitly distinguishes collection limits from measured end-to-end targets;
this finding concerns the concrete client/server deadline mismatch, not a claim that
all physical checkout latency is universally guaranteed below 800 ms.

**Proposed fix:** Establish one absolute request deadline and pass it through
candidate discovery, connection establishment, local signing and vote collection
using `timeout_at`. Reserve transport/body handling margin or explicitly align the
client and server protocol budgets. Do not add another full budget for each phase.

## A24-03 — HIGH (P2): Remote collisions are overwritten by quorum gating

**Location:** `crates/humoco-node/src/api/routes.rs:2379-2404` and `:2819-2842`.

Both single-lock and chain handlers construct `L2Verdict::Conflict` when remote
collision evidence arrives and the requested lock has no quorum. Immediately afterward,
the generic quorum gate replaces every verdict with `Rejected` and HTTP 503 whenever
the certificate lacks quorum. Therefore the branch specifically intended to expose a
remote collision cannot reach its HTTP 409 response. The client loses the existing
lock evidence and may retry a double spend as if it were a temporary outage.

**Wire trace:** Authenticated remote test handlers return `FLAG_COLLISION_DETECTED`
with a round-trippable lock payload whose client signature is checked by the probe.
The stateless HTTP gateway responds with 503 and
`Rejected { reason: "Quorum not reached: required 14 signatures, collected 0" }`.
The single-lock endpoint was exercised; the identical chain gate was verified by
source inspection. The remote collision replies are controlled test responses,
not a test of the storage engine's conflict detection itself.

**Proposed fix:** Authenticate and validate collision evidence against the exact
request, and return that conflict before applying success quorum gating. Apply the
gate to successful `Verified` outcomes. Add real-wire assertions for both single-lock
and chain endpoints that preserve the existing child and return 409.

## A24-04 — MEDIUM (P3): Successful third write attempt is discarded

**Location:** `crates/humoco-node/src/api/routes.rs:1023-1031`.

If the first two sends fail, the collector awaits a third send. Even if it succeeds,
the response is discarded and the code unconditionally returns
`PeerQueryError::Generic`. This loses a valid attestation or explicit neutral refusal.
The result becomes `PeerQueryResult::Failure`, enters the failure list, and may call
`record_failure` when correlated-failure suppression does not apply. For example,
13 valid votes plus a recovered fourteenth response are incorrectly insufficient.
A third `FLAG_NOT_READY` response can also be misclassified as a failure.

**Evidence level:** Direct control-flow finding; no fault-injected wire reproduction
was executed for the three-send sequence. This is not a claim about QUIC's packet
loss probability. A local failure counter is not a network-wide cryptographic ban.

**Proposed fix:** Return the successful third `(response_header, payload)` into the
same parsing/verification path as the first and second attempts. Preserve neutral
outcomes. Add a wire test that resets two request streams, then returns either a valid
attestation or NOT_READY on the third stream, checking vote count and peer malus.

## Checks without a new confirmed defect

- Full 256-bit HRW ranking, deterministic identity tie-breaking, identity deduplication
  and an immutable at-most-20 write committee are implemented. No rank-21 checkout
  substitution was observed. Existing real-wire committee tests passed.
- NOT_READY refusals and quorum-success cancellations remain neutral on the normal
  collector path. Existing wire tests for seven unavailable peers and fourteen fast
  signers passed. A24-04 describes a separate retry exception.
- The shard pool reserves before dialing, limits outbound shard sessions to 256,
  pins active leases and evicts idle entries. Pool saturation and reverse-RPC lease
  protection passed the existing real-wire lifecycle test.
- Shard transport uses a 15-second idle timeout without keep-alive; friend transport
  enables keep-alive. Cancellation drops owned permits/leases. The local Quinn
  implementation stops unread receive streams and finishes/resets send streams on
  drop; no stream leak was established by this audit.
- LiveStateRequest is handled by local signing and does not recursively invoke the
  HTTP live-verification collector, so no circular RPC cascade was identified.

These checks do not constitute a production-scale 5,000-node load benchmark, a
filesystem latency guarantee, or a proof that every cancellation interleaving is safe.
