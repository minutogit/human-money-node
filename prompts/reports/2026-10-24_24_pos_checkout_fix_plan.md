# Audit 24 remediation plan

Status: completed; all work packages W0-W5 implemented and verified.  
Source: [Audit 24 report](2026-10-24_24_pos_checkout_hotpath_audit.md).  
Scope: A24-01 through A24-04; preserve the fixed committee, durable-before-vote,
cryptographic recipient binding, bounded resource admission and neutral cancellation.

## 1. Target behavior and decisions

1. A live proof succeeds only with 14 distinct, verified current signatures for one
   exact context and the independently justified frozen 20-member committee.
2. One early alternative lock cannot select the claim for every other peer. Client
   signatures authenticate candidate bytes; they do not establish canonical state.
3. All live-verification stages share one monotonic absolute server deadline. The
   client keeps its existing absolute 800 ms deadline, including response-body reads.
4. A request-bound validated collision remains HTTP 409 even without a quorum for
   the attempted new lock. Missing quorum for successful verification remains 503.
5. Every successful retry enters the same response validator. Explicit neutral
   responses stay neutral regardless of the attempt number.
6. No new wire message, consensus threshold, persistent certificate store, or automatic
   ban is needed. Keep the existing request/response DTOs and hash domains.

## 2. Delivery sequence

| Work package | Finding | Dependencies | Intended deliverable |
|---|---|---|---|
| W0 | all | none | Durable adversarial fixtures and explicit expected outcomes |
| W1 | A24-04 | W0 | Correct bounded retries and response handling |
| W2 | A24-03 | W0, shared response validation from W1 | Validated collisions preserved through both HTTP handlers |
| W3 | A24-02 | W0 | Shared live deadline and cancellation ownership |
| W4 | A24-01 | W3 | Per-member live voting/discovery with exact-context aggregation |
| W5 | all | W1–W4 | Full integration validation, evidence and registry closure |

W3 and W4 should ship together: a deadline-only patch would still let the first
minority answer deny service. W1 and W2 are smaller independently reviewable changes.
No deployment or commit is part of this planning task.

## 3. W0 — Turn audit observations into permanent regression tests

Target files: `crates/humoco-node/tests/status_reconciliation_tests.rs`,
`phase11_wire_level_adversarial_tests.rs`, and, if needed for isolation, a focused
checkout retry test target using the existing real-QUIC fixture.

- Reuse the audit's controlled response delays and alternative signed child, but
  invert defect assertions into required production outcomes.
- Keep setup outside timed sections. Install explicit mature tickets and readiness;
  these fixtures do not claim to prove recovery/bootstrap.
- Parameterize handlers with request-kind counters, response controls and stream-reset
  controls. Use Notify/barriers for ordering, rather than depending on arbitrary sleep
  races. Distinguish fixture construction from actual production request handling.
- Add an independent evidence oracle: verify returned live proofs with
  `verify_live_state_proof`; inspect response verdicts, signer identities, request
  counts and peer malus. A status-code assertion alone is insufficient.
- Keep historical audit probes as immutable evidence of the old defects. Document
  that their old assertions should fail after remediation; they are not the new
  acceptance suite.

Acceptance: the new relevant regression fails against the existing implementation
for the intended reason before its associated production change is applied.

## 4. W1 — Preserve the third response and neutral outcomes (A24-04)

Primary file: `crates/humoco-node/src/api/routes.rs`, `collect_peer_attestations`.

1. Replace nested retry branches with a small bounded attempt loop or a narrowly
   scoped helper. Writes retain at most three identical attempts; reads retain
   their existing single-attempt behavior.
2. Keep every attempt inside the existing collector deadline. A retry never starts
   a new global budget, detached task, or connection outside pool admission.
3. On any successful transport response, stop retrying and run the same response
   type, flags, identity, payload and signature validation. Return the third pair
   instead of converting success to Generic.
4. Preserve LocalCapacity and orderly pool rotation as neutral. An explicit
   NOT_READY, NOT_IN_SHARD or PEER_SUSPENDED response is handled once, without
   transport retries or a peer failure penalty. QUIC transport failure is distinct
   from an application-level refusal.
5. Remove inaccurate fire-and-forget and independent UDP probability comments. Quinn
   retransmission does not justify the stated three-attempt packet-loss calculation.
6. Count one peer outcome per request, rather than one failure per failed attempt.
   Keep existing debouncing and correlated-failure suppression.

Real-wire tests:

- Two reset/incomplete request streams, then a valid third attestation supplies the
  fourteenth vote and completes quorum. Check the expected bitmap and signer key.
- Two failed streams, then NOT_READY: no vote, no malus and no fourth attempt.
- First or second successful response: no later attempt is made.
- Three genuine failures: bounded request count, no late success, existing failure
  accounting semantics retained.
- Quorum completes elsewhere while a retry is pending: the task is cancelled,
  leases are released, and the cancelled member receives no penalty.

## 5. W2 — Preserve validated remote conflicts (A24-03)

Primary file: `crates/humoco-node/src/api/routes.rs`.
Related producers: `crates/humoco-node/src/network/transport.rs`.

1. Introduce one narrow collision-validation path before accepting Collision payloads.
   Require the expected response message type and the TLS identity of the queried
   frozen member. Carry enough request context through PeerAttestationQuery to check
   voucher, exact parent lookup tag, attempted child and canonical shard binding.
2. Decode the existing collision representation with bounded framing. Verify the
   client's lock signature against the exact lookup tag, require a different child,
   and check root/voucher consistency using authoritative request/root context.
   Do not treat a well-formed flag or an arbitrary signed lock as sufficient.
3. Inspect optional-field serialization in the current bincode payload. Add round-trip
   coverage for absent and present optional fields. If representation needs repair,
   define and test an explicit compatible decoding policy before changing producers;
   do not silently invent a new wire version or use unbounded format guessing.
4. Mark shard work successful only after the conflict payload passes validation.
   Malformed or unrelated evidence never produces a conflict or earns work credit.
5. Preserve the existing rule that a valid quorum for the attempted lock takes
   precedence over an isolated remote conflict report. A reported conflict is a
   rejection/reconciliation signal, not proof of global canonicality or fraud.
6. Finalize responses by verdict. Apply quorum gating to successful Verified outcomes.
   Validated Conflict returns 409 with existing_lock; Rejected keeps its structured
   error mapping. Apply this consistently to single-lock, chain, stateful and
   stateless paths. Include the early idempotent-return branch in the review.
7. Do not issue a success signature early or add signature/history hoarding. A
   client-signed conflict is not evidence for NodePubKey slashing.

Real-wire acceptance matrix:

| Case | Required result |
|---|---|
| Remote valid conflicting child, no approval quorum | 409 with exact existing child |
| Same case via `/v1/lock/chain` | 409; durable valid prefix remains intact |
| Local durable conflict | Existing 409 behavior retained |
| Same parent and same child | Idempotent path, not a fabricated conflict |
| Invalid signature, wrong tag/voucher/member/message type | Never 409 from this evidence |
| No valid conflict and insufficient approval quorum | 503 |
| Valid approval quorum plus isolated alternative report | Existing qualified success policy retained |

Use both controlled response handlers and a real storage-engine-produced collision;
the latter proves that producer encoding and gateway decoding agree.

## 6. W3 — One deadline for live verification (A24-02)

Primary files: `crates/humoco-node/src/api/live.rs`, route wiring in `api/routes.rs`.
Client contract reference: adjacent app `src-tauri/src/gateway_resolver.rs`.

1. Create a live-request deadline with `tokio::time::Instant`, never consensus wall
   time. Start it in endpoint-scoped middleware before JSON extraction, so bounded
   request-body reading, extraction and validation do not silently reset the budget.
2. Use a named initial server processing budget of 750 ms, leaving a 50 ms nominal
   margin beneath the current client budget. Treat these values as an explicit
   engineering choice to validate with the app; they cannot guarantee Internet RTT.
   If measurements require a different split, change the named values and document
   the evidence without extending the client's 800 ms contract automatically.
3. Pass the same absolute deadline through roster acquisition, local RAM access,
   connection/backoff waits, status discovery, local signing and vote collection.
   Use `timeout_at`; never create another 800 ms window after discovery.
4. Own the JoinSet inside the bounded operation. On timeout, impossible quorum or
   success, cancel remaining work and return a controlled 503 or the completed proof.
   Explicitly distinguish local deadline exhaustion from peer misconduct.
5. Include bounded serialization/final verification in the measured server work.
   Cooperative Tokio deadlines do not preempt CPU work; keep each synchronous section
   bounded by the existing context, frame and roster limits.
6. Keep readiness validation and durable-state checks intact. Do not time out a
   running durable write and then claim it was rolled back; this live route signs
   existing committed state and must not introduce a new storage mutation.
7. Add an app transport regression using controlled HTTP headers/body delays to verify
   that fetch_live_proof continues to enforce one absolute 800 ms budget. If touching
   the adjacent repo is outside the implementation checkout, record this explicitly
   as a required integration validation step rather than claiming it ran.

Tests:

- Discovery and subsequent signing consume the same deadline: 450 ms + 450 ms cannot
  yield a successful late proof. Assert bounded failure with scheduler tolerance.
- A quorum that fits the budget succeeds, including a stateless conflicting-child case.
- Slow body/extraction and local-lock contention consume the existing server budget.
- Slow connection establishment/backoff does not run past a fresh per-stage timeout.
- The client deadline includes body consumption and is not reset across gateway attempts.

A loopback timing assertion should not require an impossible exact wall-clock cutoff
under a loaded debug scheduler. Pair generous timing ceilings with deterministic
barrier/request-count assertions proving that no second budget starts.

## 7. W4 — Per-member claims instead of first-answer authority (A24-01)

Primary file: `crates/humoco-node/src/api/live.rs`.

Preferred design: bounded independent per-member pipelines, aggregated by exact
signed context. Use existing StatusQuery and LiveStateRequest messages.

1. Freeze and validate the committee once at the gateway. Keep the recipient nonce,
   network, voucher, parent/tag, root TTL, shard and ordered roster unchanged for the
   request. A peer still independently validates its local roster before signing.
   Roster disagreement is unavailable authority, not permission to add rank 21.
2. Give each remote member one owned task/connection lease. First ask it to sign the
   original requested context. This retains the normal fast path with one RPC.
3. If that member explicitly refuses the exact claim and discovery is appropriate,
   query that same member for its current lock, validate the candidate, then ask the
   same member to sign that candidate's exact context. Discovery is fallback for
   claim mismatch; do not retry unauthorized, suspended, or local-capacity outcomes
   as if they were alternate-state hints. The current NOT_READY flag also represents
   claim mismatch, so document and test this ambiguity without inventing new flags.
4. Candidate derivation may change child_lock and the complete canonical state digest,
   including when the child matches but the digest differs. It must not substitute
   a new root expiry, voucher, recipient nonce, shard or committee.
5. A member pipeline yields at most one verified vote. The gateway groups results by
   `live_state_digest(context)` and retains the complete matching context. Bind the
   vote signer to that member's TLS key and verify its signature before counting it.
   Never combine votes from different children, state representations or contexts.
6. Handle self as one eligible member using an exact committed local snapshot; an
   alternative local lock is only one candidate/vote and does not dictate remote
   claims. A gateway outside the committee supplies no vote.
7. Exit successfully when any one exact group has 14 distinct verified votes and the
   final shared verifier accepts the proof. Cancel all other tasks neutrally.
8. Track unresolved members. Fail as soon as best_group_votes + unresolved_members
   is below 14 (including the possibility of a previously unseen candidate). Refusal
   of the initial claim is not final failure until that member's bounded fallback
   pipeline finishes or expires.
9. Delete the first-response-wins helper and redundant global context-rewrite path.
   Avoid broadcasting each candidate to all members: this plan uses at most three
   RPCs per remote member, at most 60 for 20 remotes, and at most 20 final vote groups.
   No detached retries, unbounded candidate list or per-candidate fanout is needed.
10. Review admission/accounting against the worst-case 60-RPC live request. Reserve
    bounded work before spawning, respecting existing read quotas, stream limits and
    connection-pool admission. Map actual protocol costs to existing credit units;
    do not simply assume the current literal charge of 20 covers the fallback work.

Real-wire tests:

- One fast alternative signed child, 19 honest matching states: valid 14/20 proof
  for the honest state, regardless of which status reply arrives first.
- Six alternative/unavailable members, fourteen agreeing eligible members: success
  if the complete honest pipelines fit the shared deadline.
- A 13/7 split: no success and no lowered threshold. No aggregation across groups.
- Stateful gateway holding a minority local lock: remote majority can still succeed.
- Stateless gateway asked for the losing child: discovers and proves the winning child.
- Same child with a different state digest: validation never mixes state representations.
- Wrong signer, stale nonce, altered root/shard, bad client signature and invalid vote:
  none contribute to a proof. A remote signature is not membership authorization.
- Committee changes during request: fail closed on mismatches and allow a new request
  to recompute authority; no in-flight committee substitution.
- Assert one vote per identity, at most three RPCs per remote, bounded group storage,
  neutral cancellation, and released pool capacity on every exit.

Liveness premise: at least fourteen eligible members must agree on the exact durable
state, accept the frozen authority and finish within the remaining deadline. This fix
cannot make an inconsistent or unreachable committee available by lowering quorum.

## 8. W5 — Verification and completion criteria

For each work package, execute the focused real-wire regression first. Then run once
against the final combined implementation:

```bash
cargo fmt --all -- --check
RUST_TEST_THREADS=4 cargo test-std --offline
cargo clippy --workspace --all-targets --offline -- -D warnings
```

Also run the affected app gateway deadline tests if that integration changes, and
`scripts/run-architecture-e2e.sh` for the final live-proof/checkout interaction.
Determine its actual build/network prerequisites before execution and report any
unavailable prerequisite precisely. Add an ignored deep/load run only if the changes
create a resource-bound concern the focused wire tests do not settle.

Completion requires:

- A24-01: first-answer attack no longer blocks an otherwise available 14/20 proof.
- A24-02: no independent discovery/voting budget reset; app and server deadline
  assumptions are explicit and tested, with no claim of universal RTT guarantees.
- A24-03: valid conflicts survive all finalization paths; unrelated evidence cannot
  cause a false 409; both single and chain paths are covered over QUIC.
- A24-04: third success and third neutral refusal are processed correctly, and the
  real-wire fault-injection test checks peer counters.
- Existing committee, durability, cancellation, pool lifecycle and causality tests
  continue passing. No threshold or persistent-state format changes are smuggled in.
- Update the audit report with per-finding fix/test references and append remediation
  evidence to the registry. Set open count to zero and status Clean only after every
  acceptance condition passes. Preserve the original audit evidence and all unrelated
  working-tree changes.

## 9. Reviewable change boundaries

Suggested patch boundaries: (1) bounded retry handling plus wire tests; (2) validated
conflict finalization plus both endpoint tests; (3) shared live deadline and per-member
claim aggregation plus client integration validation; (4) final evidence/documentation.
Keep helpers specific to this flow. Avoid a generic RPC framework, new configuration
surface or unrelated pool/storage refactor.
