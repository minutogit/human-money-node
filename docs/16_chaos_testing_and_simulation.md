# 16. Chaos Testing, Deterministic Models and Acceptance Gates

> **Status:** Selected requirements and verification criteria; not a completed security proof or test report.
>
> **Authority:** This English file is canonical for Spec 16. The former German path redirects here.
>
> **Basis:** Architecture interview DEC-053–058, DEC-064–065, DEC-070, DEC-074–088 and the accepted DB5 consolidation package. Newer explicit decisions supersede historical simulation claims.

This specification defines how the Collision Lock Registry's requirements must be challenged at their actual enforcement boundaries. Deterministic models explore schedules and produce reproducible counterexamples. Real QUIC tests must demonstrate receiver-side admission and rejection; relevant HTTP and shared-library/consumer tests must demonstrate payment acceptance behavior; actual daemon-process tests must demonstrate persistence and lifecycle behavior. None of these layers replaces the others.

L1 carries the transaction, voucher and causal history. L2 transfers active `parent_lock -> child_lock` state and supplies a fresh, verified live-state proof from currently justified shard participants. These gates require neither inherited historical quorum-signature archives nor permission from departed committee members. Immutable own signing decisions remain separately protected until the applicable root lifetime plus grace expires.

## 1. Evidence vocabulary and reproducibility

Every rule-to-evidence record must distinguish these independent statuses:

| Status | Required record | What it establishes |
| --- | --- | --- |
| Selected requirement | Decision or authoritative rule and scope | Intended behavior; no claim of proof or delivery. |
| Design/proof | Algorithm, assumptions, failure model and argument or counterexample | Conditional reasoning; a model result is limited to the model. |
| Implemented | Inspected source revision and actual enforcement path | Code exists at that revision; no claim it was executed successfully. |
| Executed and verified | Exact revision, command, environment, scenario, assertions and result artifact | Observed behavior for those executions; not universal correctness. |

A test filename, test count, passing simulation, manually set readiness flag or unexecuted example does not advance another status. Concurrent working-tree edits require their own inspection. This consolidation executes no tests and marks no listed gate as passed.

Use fixed seeds, explicit schedules and controlled clocks in models. Record partition topology, admitted identities, clock assumptions, persistence behavior and adversary capabilities. Retain failing seeds/traces and minimize counterexamples. Do not claim a particular simulator is integrated merely because it could implement this model.

Real-network tests should use explicit synchronization and bounded deadlines, and report timeouts as failures with diagnostics. Test actual authenticated QUIC connections against the receiving shard server, including bypass of the HTTP gateway. Crash tests require a real daemon process and independently observed wire/storage outcomes; dropping a mock handle is insufficient. Performance measurements must state hardware, filesystem/durability settings, workload and load profile.

## 2. Canonical meanings of INV-1601–INV-1605

These identifiers remain stable. This section replaces the stronger legacy descriptions in both former language copies; historical references inherit the qualifications here. No new numbering or independent German definitions are introduced.

### INV-1601 — Conditional regional partition healing

After reconnection, admitted conflicting active state is resolved by the selected confirmation-class hierarchy: higher valid class wins; `min(H_canon)` applies only within the highest valid equal class. Unsupported singleton state does not become confirmed merely through a low hash. Unrelated roots remain unaffected; losing causal branches are handled by the selected minimum sufficient live-exclusion rules.

Exercise multiple regional views, message orderings, delayed competing support and full membership turnover. Establish convergence only under explicitly justified membership, source completeness, time and eventual communication assumptions. Regional FINAL may later be revised by valid competing regional evidence (DEC-053); it is not unconditional global irreversibility. There is no universal O(1) healing deadline. Safe source continuity and activation during turnover remain proof gates, not consequences of deterministic hashing alone.

### INV-1602 — Verified first-party fraud, without framing

Permanent identity/ticket/Web-of-Trust sanctions require two genuine, cryptographically verified conflicting own approvals of the same node for the same defined signing slot/context. A client submitting two conflicting spends is not by itself proof that either node equivocated. A forged proof, wrong key, mismatched context or unverified hearsay cannot authorize a ban.

An honest signer of a losing regional branch may later report the canonical live state without that report becoming a second original write approval. Verify purpose separation and immutable own-choice protection. Locks and receipts are not added to gossip; only the existing F2F presence and verified equivocation-proof streams are used. No probabilistic receipt-cache collision or unsupported three-minute fraud-discovery promise is a success criterion.

### INV-1603 — Admission defenses under explicit adversary assumptions

Exercise isolated Sybil circles, bridge saturation, colluding admitted friends, ticket grinding and topology churn. Ticket work uses Argon2d and its 24-hour maturation rule; passive presence uses the selected three missed hourly heartbeats, not a committee tenure. F2F gossip authorization and learned-peer shard authorization remain separate from permissionless public client ingress. A public node key never becomes an ingress friend bearer secret.

Report which identities can be admitted under the tested assumptions and how limits behave. Neither simulation nor operator belief proves at most six Byzantine members in every subjective committee. Do not assert that all bots always remain immature, that a particular heartbeat-drop percentage is universal, or that circular friendships alone establish a global fault bound. The authority/admission justification remains separately unresolved.

### INV-1604 — Bounded resources and measured service isolation

Under declared public ingress, read and authenticated shard/sync floods, verify bounded buffers, concurrency, batch size/bytes/wait, retries, in-flight coalescing and waiting consumers. Verify cheap admission filters before expensive work and reservation before RAM mutation. Read traffic does not reserve write capacity or commit per query; inbound shard service and recovery have protected bounded budgets.

Measure latency and progress under stated conditions. The 800 ms collection budget is a limit, not a success guarantee; NOT_READY, unavailable and Byzantine members all consume the same six noncontributor slots. Local durable and checkout latency targets require measurements. No finite server promises universal latency under arbitrary load or arbitrary disk stalls. Private bounded diagnostics may explain refusals but never cause bans or authorize committee membership changes.

### INV-1605 — Complete, justified state transfer before readiness

A new or recovering shard remains NOT_READY until its relevant active state is safely validated, durably installed and activated. Check the full authenticated root lifetime through `root.valid_until + 30s`, including locks older than 24 hours, snapshot coverage, bounded concurrent deltas, owner/root/canonical integrity and atomic publication. A matching digest verifies the bytes represented by that digest; it does not establish that the sources contain every required lock.

Include an 8+6+6 distribution of independently confirmed locks across replicas: there may be no 14 identical whole-state digests. Include incomplete or circularly readied new replicas agreeing on an empty/partial digest. The algorithm must justify coverage or remain NOT_READY; it must not wait for nonexistent equality, accept missing records or use new replicas' agreement as proof of source continuity. Honest incomplete replicas may serve bounded retained data without becoming authoritative ready witnesses. Exact source/activation proof remains open; this specification selects no replacement consensus or historical-signature archive.

## 3. Interface and adversarial scenario matrix

All rows below are required acceptance scenarios, not claims that named tests already satisfy them. Positive controls and the stated negative behavior must both be observed. Each row needs its own evidence record from Section 1.

| Gate / relevant rule | Enforcement boundary | Concrete positive and adversarial scenarios | Required observation |
| --- | --- | --- | --- |
| Frozen committee / live proof (DEC-084) | Real QUIC collector, HTTP gateway and actual shared verifier/recipient | Valid 14 distinct current members from one frozen <=20 snapshot; then duplicates, full-key substitution, rank21, different shard/network/lock/state/snapshot or mixed contexts; 13 valid votes plus invalid extras. | Verify every signature and full identity. Only justified current members for one compatible statement count; FINAL needs 14. No threshold lowering, pool expansion or success field accepted without the full verified proof. Membership justification remains an explicit design premise. |
| Purpose, challenge and replay (DEC-083/084) | Real QUIC response and recipient verifier | Fresh receiver challenge succeeds; replay an earlier challenge or transplant a live response as original write approval, or reverse the purposes. | Separate authenticated purposes bind exact target/state/request/context and challenge. Stale/mismatched proofs never release payment or authorize a conflicting write. Normal cheap status stays `read_quorum=1` / INV-0310 and is not promoted to payment proof. |
| Demand readiness (DEC-085/086; INV-1605) | Receiving shard over real QUIC and automatic recovery | First authorized demand for an assigned shard; repeated requests; another ready shard; unauthorized/unassigned triggers; failed transfer and stale completion. | At most one bounded job per shard, bounded overall admission/retries, prompt NOT_READY until safe installation, no node-side payment queue. Unrelated ready shards continue. Readiness is rechecked immediately before every countable signature, including self/live-state paths. |
| Transfer integrity and coverage (INV-1601/1605) | Real peer transfer, persistent installation and signer | Valid full-lifetime snapshot plus deltas; forged/truncated records, missing shard, >24h unexpired lock, root expiry, competing classes, 8+6+6 distribution, incomplete agreeing sources and turnover during installation. | Reject malformed/unjustified imports, preserve required live exclusions and own choices, install durably before activation. Cryptographic byte integrity alone never licenses completeness/readiness. Demonstrate coverage under explicit source assumptions or retain NOT_READY. |
| Durable-before-release (DEC-087) | Actual daemon, worker transaction, receiving peer and restart | Stop/kill before commit, after commit before release and after release; delay/fail commit; duplicate pending/idempotent request; gateway self vote and status path. | No binding signature/vote/envelope escapes before exact atomic durable lock+own-choice acknowledgment. Signature calculation may occur in RAM. Restart with intact committed storage recovers the choice and refuses conflicting approval. No RAM guard is held during await; no synchronous handler disk I/O. |
| Unknown storage loss/rollback | Actual daemon recovery and signing gate | Missing/corrupt storage, stale restored database, failed recovery or unknown commit acknowledgment. | An ordinary crash with intact commits differs from rollback. Unsafe/unknown state cannot authorize new signatures. Do not claim durable ordering alone reconstructs lost storage; rollback recovery remains a separate design/proof gate. |
| Timeout, batching and repeated work (DEC-088; INV-1604) | Real QUIC/HTTP plus worker/storage observation | Single request below batch size; full bytes/count; retry flood; timeout followed by delayed commit; saturated queues and stalled disk. | Bounded time/count/bytes and waiters, coalesced identical work, prompt capacity rejection. No automatic reversal of completed commits, no early RAM-cached signature and no interpretation of timeout as proof of nonpayment. Identical retry discovers committed result safely. |
| Frame and quota defenses (INV-1604) | Real authenticated QUIC at receiving shard, independently of gateway | Oversized/truncated/overflowing lengths, slow partial frames, unsupported flags, malformed proof, replay, over-quota learned peer and flood. | Exact specified wire refusal/drop, bounded incremental allocation, safe checked parsing and cheap checks before costly crypto. HTTP-only rejection or in-memory quota tests do not establish server protection. Assertions include queue/RAM/state side effects, not just an error string. |
| Tier boundaries and admission (INV-1603) | Real QUIC handshake/streams and public HTTP | Friend presence, non-friend gossip, learned shard RPC, unknown peer, public client without P2P friendship and leaked public node key as token. | F2F barrier and learned-peer enforcement hold internally; public client access remains permissionless subject to its own admission rules. No public-key PoW bypass, hearsay sanction or extra gossip stream. |
| Merge and fraud (INV-1601/1602) | Model plus real QUIC receiving merge/fraud paths and verifier | Higher-class vs lower-class, equal-class competing regions, forged double-sign proof, genuine same-slot equivocation, honest postmerge state report. | Class-first then equal-class min-hash; only verified personal fraud sanctions the signer. Branch loss, timeout, NOT_READY or quorum cancellation alone never sanctions identity. Own original choice remains immutable. |
| Operator privacy (DEC-077; INV-1701) | Real HTTP listeners, routing aliases/subroutes and local control boundary | Public requests to every metrics/topology/dashboard alias, alternate listener and nested route; authorized private access. | Private diagnostics remain private at every alias. Public gateway discovery provides its intended HTTP directory only; cached fallback stays in the client. Telemetry cannot ban peers or provide voting authority. |
| Stop and database release (DEC-074–076/088) | Actual CLI/control command, daemon process, OS and database reopen | Clean stop, repeated signals, saturated flush queue, blocked worker and internal deadline with longer supervisor fallback. | Original drain/deadline is preserved, no undurable release, truthful clean/forced result. Default CLI completion establishes actual process exit and released database lock by reopening it from an independent process, not merely receipt of a shutdown request. |

These scenarios do not require recursively collecting retired signers' signatures. They do require full live-proof verification and separate persistence of this node's own decisions. Exact wire schemas, safe current authority, transfer coverage, clock/seal composition and rollback recovery cannot be closed merely by writing this matrix.

## 4. Existing inspection candidates and acceptance records

The following paths existed at consolidation and are **inspection candidates only**. Their names do not prove assertions, automation, coverage, implementation correctness or successful execution:

- `crates/humoco-node/tests/quorum_assembly_tests.rs`, `status_reconciliation_tests.rs`, `anti_self_slashing_wire_tests.rs`: committee, state-evidence and fraud candidates.
- `crates/humoco-node/tests/phase5_pull_sync_and_readiness.rs`, `created_at_bucket_decoupling_tests.rs`, `subquorum_canonical_merge_tests.rs`: recovery, lifetime and merge candidates. A manually toggled readiness flag establishes refusal behavior at most; automatic safe recovery needs its own test.
- `crates/humoco-node/tests/phase11_wire_level_adversarial_tests.rs`, `chaos_wire_http_fuzz.rs`, `phase4_net_time_and_quotas.rs`, `f2f_gossip_and_shard_rpc_tests.rs`: receiver-side parser, quota and authorization candidates.
- `crates/humoco-node/tests/storage_tests.rs`, `control_tests.rs`, `cluster_e2e_tests.rs`, `api_tests.rs`: durability, lifecycle, HTTP and consumer candidates; inspect whether they use actual daemon processes and observe release ordering.

Inspect source and actual assertions before assigning any gate. Shared-library recipient verification and real process-crash coverage may need additional tests; no absence or completion claim is inferred from this list. Preserve useful deterministic/core models as complementary evidence.

For each final rule, record its canonical definition or explicit legacy alias, affected interface and source revision, selected requirement, proof assumptions/open edges, exact test scenario and expected wire/result/state effects, then executed command/result/artifact when available. Associate counterexamples with the rule they refute. A family-level test name or percentage must not replace item-level evidence. Diagnostic artifacts and measurement endpoints obey the private operator boundary.

Acceptance requires the relevant design/proof gates as well as implemented and executed evidence. The architecture interview's selections establish requirements; this consolidation does not declare the entire design verified or production delivered.
