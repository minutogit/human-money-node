# Architecture Interview — Decisions and Open Read-Safety Question

> Live navigation: [ARCHITECTURE_INTERVIEW_STATE.md](ARCHITECTURE_INTERVIEW_STATE.md).
> Workflow: [start/resume prompt](../prompts/architecture_interview.md).
> Earlier handoff/cursor statements below are historical; consult the compact state
> and the current decision register in section 2 when resuming. Checkpoints are in section 9.

Date: 2026-10-13 (Europe/Berlin)
Last updated: 2026-10-19 (Europe/Berlin)

Status: Working interview notes, not a binding specification or an implementation plan.
The interview was saved at the maintainer's request and subsequently resumed.
No protocol changes have been implemented as part of this interview.

## 1. Purpose and interview position

Maintainer clarification at handoff: continue a systematic branching architecture and
security interview, maintaining a decision tree and explicitly closing dependencies,
not simply a sequence of preferences. The compact state now indexes the working root-branch map and active S2–S4
subtree; the prompt defines the recording procedure and separate requirement/design/
implementation/verification gates. Section 2 is the current decision register;
the legacy handoff preserves earlier consolidated context. Its coverage is not yet a complete
specification/invariant inventory; checking that coverage remains mandatory before the
final plan. "Watertight" means justified claims within stated assumptions, not an
unconditional security guarantee.

The interview should uncover architectural blind spots before producing a prioritized
implementation and consolidation plan. Ask one question at a time, give a reasoned
recommendation, and challenge unnecessary complexity. Communicate with the maintainer
in German; write code and documentation in English.

Planned topic order:

1. KISS boundaries and removal of obsolete responsibilities.
2. Checkout path and integration with `human-money-core`.
3. Consensus edge cases, partitions, Sybil grinding, and cryptographic penalties.
4. P2P topology, connection pooling, and local failure handling.
5. Persistence, crash recovery, shutdown, TTL pruning, and deployment.

Historically the discussion reached Phase 5, operations and persistence, after P2P
capacity discussion; it then returned to unresolved S2–S4 consensus dependencies.
Use the compact state for the current cursor. Phase 4 recovery and sizing obligations remain open, as do checkout/read
safety, committee authorization, and safe membership transitions. Do not produce the
final master plan or describe
unresolved proposals below as agreed or proven yet.

## 2. Decisions agreed so far

### 2.1 Current decision register and provenance

Stable IDs were assigned during the CP-0003 documentation review. The register
consolidates existing records; it does not ask or answer new protocol questions.
“Accepted” means accepted **as reported by the existing notes**, not a verified
design, implemented behavior or independently recovered original chat answer.

Provenance **L** means the pre-workflow summary was the only selection record found
for that item. Original question wording, answer and item-specific rationale were
not preserved in the available files. Preserve the recorded selection, flag this
limit and do not invent rejected options or re-ask settled preferences automatically.
Linked evidence is a historical paraphrase in these notes, not a verbatim transcript.
Decision IDs remain stable when wording changes. New facts require a dated update.

Current qualification: DEC-053 explicitly selects regional, potentially revocable
acceptance. Older entries retain their historical wording; any implied globally
irreversible-acceptance or mandatory predecessor-quorum interpretation is qualified
by §7.57. DEC-054 / §7.58 adds the explicit eligibility, honest-merge and merchant
status guardrails. DEC-055 / §7.60 rejects predecessor baton chaining, recursive
L2 receipt chaining and active background presence probes. CP-0050 / §7.61 records
the resulting passive-presence integration gap. DEC-056 / §7.62 subsequently
selects three consecutive missed gossip heartbeats; timing/enforcement remain pending.
DEC-057 / §7.63 requires restart sync-readiness and rejects an empty-state disaster
fallback. DEC-058 / §7.65 selects quorum-backed verified digest-pull as the
mechanism. DEC-059/060 / §7.66 select snapshot+deltas, time buckets and
exact-payload three-send retries. DEC-061 / §7.67 rejects extra correction/version
structures and clarifies wallet-bound T_0 plus distinct live/sync paths. Local
implementation alignment and sealing/source coverage/resource proofs remain open.
DEC-062 / §7.69 subsequently restores RAM-first attestation and ingress-only
freshness, superseding DEC-029 and pre-response commit clauses of DEC-033/034.
Earlier durable-before-response wording below is historical unless requalified.
DEC-063 / §7.71 reaffirms DEC-032 without relaxation. Proposed finite bucket
quarantine still needs a proof against later fresh conflicting spends.
DEC-064 / §7.72 selects class2>class1>class0 with min-hash within the
highest admissible confirmed class; losing a merge alone never proves node fraud.
DEC-065 / §7.73 selects minimum sufficient live exclusion/evidence and own-choice
retention, with excess full losing branches held by clients. TTL+30s purge remains.
DEC-066 / §7.74 selects inline compact authenticated collision evidence in 409;
no extra gateway reference cache or required retrieval round. Numeric checkout
thresholds and first-party evidence rules are retained. DEC-067 / §7.75 rejects
a weaker collision veto against a valid14/20 checkout; collector integration pending.
DEC-068 / §7.76 selects bounded automatic client reconciliation with growing
backoff and read-only status after the30s live window; no guaranteed resolution.
DEC-069 / §7.77 selects exceptional bounded retrieval of original approvals from
the frozen checkout committee, without new votes; exact retention/retrieval audit open.
CP-0067 / §7.78 derives the retrieval skeleton and adds a provisional numbered-spec
coverage map. DEC-070 / §7.79 selects exact-original-approval retention until
root TTL+30s, reusing the own-choice lifecycle; shorter-window B is rejected.
DEC-071 / §7.80 selects durable wallet intent/pending-output storage before
first dispatch, distinct from node RAM-first. Merchant receipt-before-release
ordering is answered with a content correction by DEC-072 / §7.81: durably
store the L1 voucher and purchase journal before release; the checkout quorum
receipt is ephemeral and need not be archived/back-filled after completed checkout.
DEC-069 recovery concerns still-uncertain attempts; DEC-070 node own-approval
retention is not a merchant certificate-archive requirement. Ordinary single-node
read-safety remains a technical proof gap, not established by receipt disposability.
DEC-073 / §7.82 rejects automatic alternate payment strictly in human-money-core/
PoS client policy, including partial multi-voucher purchases; no node purchase logic.
DEC-074 / §7.83 selects idempotent repeated stop signals preserving the original
bounded drain. DEC-075 / §7.84 selects a daemon-internal stop deadline with a
longer outer supervisor margin; example durations are not fixed settings. O4.3
is answered A / DEC-076 (§7.85): stop success requires verified clean completion,
process termination and DB release. O4 user policies are selected; implementation/
validation remains. DEC-077 / §7.86 selects private operator metrics without a
public metrics subset. DEC-078 / §7.87 selects additional dynamic public gateway
discovery using existing passive mesh knowledge and explicitly published HTTP
endpoints. DEC-079 / §7.88 selects bounded cached-address fallback strictly in
the client domain. O5 discovery/cache policies are selected; advertisement and
endpoint verification remain engineering work. DEC-080 / §7.89 selects verified
quorum evidence for payment release; a matching record alone never means paid.
DEC-081 / §7.90 retains cheap ordinary 1-of-20 lookup and explicit quorum-backed
payment verification. WF-005 replaces micro-question sequencing with concise
problem/solution batches for derived details; consequential human tradeoffs retain
A/B. DEC-082 / §7.91 records explicit maintainer acceptance of DETAIL-BATCH-001
as future implementation requirements. DEC-083 / §7.93 rejects the archival
premise of Q-C4-ACTIVE-PROOF-CONTINUITY-01: neither A nor B is selected. Current
qualified shard nodes attest their safely synchronized live lock state; no inherited
original-quorum archive or unconfirmed outcome solely from retired original signers.
LRC-002 replaces LRC-001 where it imposed original-approval prerequisites on live
clearance. Active C4.3b integrates this live-state contract; no human question is
pending. Safe recovery, own-history and actual verifier implementation remain open.
CP-0084 / §7.95 consolidates the LRC-002 request/signature/collector contract and
finds an ungated status-signing path. No new decision is selected; C4.3b remains
active on the authority/readiness premises rather than historical archives.

Unless explicitly evidenced otherwise, design details and implementation/verification
of interview changes remain pending. Constraints in the direction column and the
open-item register below are part of each record, not optional caveats.

| ID | Branch | Topic | Selection status | Current direction and remaining limits | Selection record |
| --- | --- | --- | --- | --- | --- |
| <a id="dec-001"></a>DEC-001 | K1 | Node responsibility | Accepted requirement/direction | Keep a blind Collision Lock Registry plus necessary validation, replication, and abuse defenses. No additional product responsibility in the consensus core. | L (legacy selection summary) |
| <a id="dec-002"></a>DEC-002 | K1/O5 | Existing dashboard | Accepted requirement/direction | Preserve useful existing dashboard work. A bounded diagnostic interface is useful and is not automatically architectural bloat. The exact administrative/security boundary still needs review. | L (legacy selection summary) |
| <a id="dec-003"></a>DEC-003 | O6 | Metric history | Accepted requirement/direction | Retain minute-resolution metrics for 24 hours and hourly summaries for one year. Use bounded storage and background persistence. Aggregation must fit each metric; details remain to be designed. | L (legacy selection summary) |
| <a id="dec-004"></a>DEC-004 | K1/K2 | Compatibility | Accepted requirement/direction | The project is not deployed. Breaking changes are permitted. Remove obsolete or redundant production paths after checking their actual uses. `human-money-core` may also be improved. | L (legacy selection summary); [later consolidation](#evidence-dec-038) |
| <a id="dec-005"></a>DEC-005 | K2/C1 | Genesis versus successor locks | Accepted requirement/direction | Both remain necessary protocol cases. The HMC request model already represents both through `is_genesis`; this distinction does not require two parallel register implementations. | L (legacy selection summary) |
| <a id="dec-006"></a>DEC-006 | K2 | Protocol reference | Accepted requirement/direction | `human-money-core` is the domain reference for formats, signed fields and canonical rules. Consolidation packaging is selected by DEC-038: a small shared Rust protocol library. Its exact crate layout/versioning and signed formats remain open. Do not copy an inadequate core verifier verbatim; §7.3 records concrete gaps. | L (legacy selection summary); [later consolidation](#evidence-dec-038) |
| <a id="dec-007"></a>DEC-007 | K1 | Other applications | Accepted requirement/direction | Any compatible client may use the registry. The node neither needs nor can reliably determine whether the client was built with `human-money-core`. No application-origin whitelist. | L (legacy selection summary) |
| <a id="dec-008"></a>DEC-008 | C2/C3 | Checkout timing | Accepted requirement/direction | The 800 ms limit bounds quorum collection at the gateway, not the entire PoS request. Exit immediately on sufficient quorum or when quorum is no longer attainable. Define a separate measurable end-to-end latency target; successful completion cannot be guaranteed within a deadline over arbitrary Internet connections. | L (legacy selection summary); [durability refinement](#evidence-dec-029) |
| <a id="dec-009"></a>DEC-009 | C3 | Timeout and retry handling | Accepted requirement/direction | Treat a timeout as an uncertain outcome, not proof of a free slot or a conflict. The client stores the signed request and performs bounded automatic retries with delays, preserving the same payload and lock identity. No automatic rollback of accepted locks and no replacement spend for the same predecessor. Do not release goods as finally paid without a verified completion proof. Retry counts, backoff, and overall reconciliation deadlines remain to be specified. | L (legacy selection summary) |
| <a id="dec-010"></a>DEC-010 | C3 | New-payment submission | Accepted requirement/direction | Submit a new signed payment directly through the idempotent write path. Do not perform a separate status preflight merely to check whether the predecessor slot is free; the atomic write collision check remains necessary regardless. Reads for evidence/reconciliation are a separate unresolved topic. This does not remove origin/causality validation or preparation needed for missing proofs. | L (legacy selection summary) |
| <a id="dec-011"></a>DEC-011 | C1 | Reconciliation progress | Accepted requirement/direction | Failure of a later reconciliation request must not roll back locks already accepted by earlier requests. Preserve completed progress and retry idempotently. Within-batch valid-prefix semantics are selected separately in DEC-013; this does not change TTL expiry or settle merge/finality. | L (legacy selection summary) |
| <a id="dec-012"></a>DEC-012 | C1 | Reconciliation request size | Accepted requirement/direction | Submit multiple missing locks together in bounded batches. Determine byte/verification-work limits through measurements. Use DEC-013 for selected within-batch valid-prefix semantics; this is not all-or-nothing acceptance. | L (legacy selection summary) |
| <a id="dec-013"></a>DEC-013 | C1 | Reconciliation batch acceptance | Accepted requirement/direction | For an ordered causal path, accept the valid prefix and stop at the first conflicting/invalid step. Preserve accepted locks; do not accept dependent successors through that step. A batch is a transport optimization, not a distributed all-or-nothing transaction. | L (legacy selection summary) |
| <a id="dec-014"></a>DEC-014 | C1 | Split-voucher reconciliation scope | Accepted requirement/direction | A batch carries only the needed ancestry path to one target lock, including required common ancestors and split/output proofs. Do not include unrelated sibling branches. The registry's overall branching state arises from separate causally valid submissions. | L (legacy selection summary) |
| <a id="dec-015"></a>DEC-015 | C4/N4 | Ingress tiers and evidence | Accepted requirement/direction | Free, Friends, and VIP require the same cryptographic consensus/evidence verification. Payment improves capacity, priority, and service quality; it does not replace or weaken proof requirements. Provider reputation is an additional selection consideration, not a cryptographic guarantee. | [Recorded selection](#evidence-dec-015) |
| <a id="dec-016"></a>DEC-016 | S1 | Coordinated attacker | Accepted requirement/direction | Allow a malicious voucher owner, gateway, and controlled shard nodes to coordinate, pre-share authentic conflicting locks, and selectively withhold replies. Do not multiply independent-fault probabilities for these actors. Bounds on controlled node count, compute budget, and sampling remain to be specified. | [Recorded selection](#evidence-dec-016) |
| <a id="dec-017"></a>DEC-017 | C4 | Recipient-selected verification sources | Accepted requirement/direction | The recipient selects its gateways and verification sources through its own configuration. Sender-provided addresses may help retrieve data but must not replace the recipient's security basis. This reduces sender-controlled witness selection; it does not prove committee correctness or independence of providers. | [Recorded selection](#evidence-dec-017) |
| <a id="dec-018"></a>DEC-018 | S6 | Ticket lifecycle per identity | Accepted requirement/direction | At most one active ticket and one announced successor per `NodePubKey`. Replacing the pending successor restarts its 24-hour incubation. A new ticket must have verified work score W_new > max(W_active, W_pending); preserve this existing monotonicity ratchet. The active ticket remains the basis until an authorized transition. Maturity alone does not prove a safe committee/state transition. | [Recorded selection](#evidence-dec-018) |
| <a id="dec-019"></a>DEC-019 | S6 | Fresh cryptographic identity | Accepted requirement/direction | A new `NodePubKey` starts as a fresh identity. No automatic inheritance of F2F friendship or incubation based on IP address, claimed operator identity, or former node presence. Direct friends must explicitly approve the new identity and its tickets undergo regular incubation. | [Recorded selection](#evidence-dec-019) |
| <a id="dec-020"></a>DEC-020 | C4 | Network-size observations for client statistics | Accepted requirement/direction | Use multiple recipient-selected sources, refreshed in the background and cached, instead of accepting only the currently queried gateway's network-size claim. This reduces single-provider control but does not prove provider independence, globally complete discovery, or authoritative committee membership. Aggregation, disagreement handling, and freshness remain to be designed. | [Recorded selection](#evidence-dec-020) |
| <a id="dec-021"></a>DEC-021 | C4 | Conflicting statistical observations | Accepted requirement/direction | Treat strong source disagreement as an unresolved statistical assessment and obtain/check further information, including freshness and network identity. Do not manufacture a precise confidence value by silently averaging incompatible observations. Payment policy in this situation remains undecided. Disagreement is not fraud evidence or grounds for a node ban. | [Recorded selection](#evidence-dec-021) |
| <a id="dec-022"></a>DEC-022 | S5 | No single-source canonical takeover | Accepted requirement/direction | A conflicting lock supported only by one node must not displace a confirmed branch merely because its H_canon is smaller. Establish sufficient authenticated support in the relevant authorized committee before a state takeover. A peer may transport a valid multi-signer proof; transport-source count is distinct from signer/support count. DEC-064 now selects confirmed class2 priority over class1 and min-hash within class; exact membership/authority and transition proof remain open. Mandatory adversarial QUIC regression coverage is required. | [Recorded selection](#evidence-dec-022) |
| <a id="dec-023"></a>DEC-023 | S5 | Unresolved conflicting slot | Accepted requirement/direction | If sufficient justified support cannot be established, leave the conflicting spend slot and dependent descendants unresolved rather than force a canonical takeover or manufacture quorum. Other unaffected slots/branches continue. The maintainer accepts that a genuine conflict may leave the affected voucher branch unusable; frequency is not measured. Valid late evidence can be re-evaluated, but eventual recovery is not guaranteed. | [Recorded selection](#evidence-dec-023) |
| <a id="dec-024"></a>DEC-024 | N2 | Checkout versus background capacity | Accepted requirement/direction | Reserve capacity for checkout work and give background synchronization a separate bounded budget that still permits progress. Limit locally originated gateway work to protect inbound shard service. Numerical limits and fairness remain to be designed and measured. | [Recorded selection](#evidence-dec-024) |
| <a id="dec-025"></a>DEC-025 | N1/N2 | Full shard-direct pool and work budget | Accepted requirement/direction | Reclaim idle shard-direct sessions first. Do not abort active RPCs merely to make capacity for new requests. If the applicable budget is fully occupied by active work, promptly refuse new work without an additional waiting queue. Count neither ordinary idle closure nor capacity refusal as a peer failure. F2F persistent sessions remain separate. Connection and concurrent-request limits are distinct; exact sizes and wire responses remain to be specified. | [Recorded selection](#evidence-dec-025) |
| <a id="dec-026"></a>DEC-026 | N3/O2 | Recovery signing readiness | Accepted requirement/direction | After state loss or new shard assignment, withhold write votes for the affected shard until justified state recovery is established. Unaffected ready shards continue. The exact recovery evidence remains open. | [Recorded selection](#evidence-dec-026) |
| <a id="dec-027"></a>DEC-027 | C2 | Checkout availability and dispatch | Accepted requirement/direction | NOT_READY supplies no vote, like a timeout; neither proves deceit or authorizes permanent bans. For each admitted checkout request, attempt all remote members of the frozen committee in parallel without an additional checkout-specific offline suppression/backoff mechanism. The original one-application-attempt rule is refined by the explicitly selected conditional three-send heuristic DEC-060 (§7.66); scheduling/resource/cancellation semantics remain to be justified. Preserve resource admission, 800 ms collection deadline, quorum/impossibility exits, and no lower-rank replacements. This supersedes the earlier checkout-backoff proposal. Existing shared transport delays require later review. | [Recorded selection](#evidence-dec-027) |
| <a id="dec-028"></a>DEC-028 | N2 | Possible checkout failure suppression | Deferred optimization; no mechanism selected | Keep a minimal suppression mechanism as an optional later optimization. Compare actual resource costs and effects on protected inbound shard service and bounded background-sync progress before choosing it. No specific algorithm, thresholds, or implementation is approved. | [Recorded selection](#evidence-dec-028) |
| <a id="dec-029"></a>DEC-029 | O1 | Durable signing before response | Superseded response ordering / local SLA by DEC-062 | Historical selection required release only after durable storage of the exact choice, through the bounded asynchronous worker, and removed the rigid <5ms target. DEC-062 now explicitly selects RAM acceptance/attestation before flush and restores the <5ms SLA. Preserve the original rationale and 800ms collection budget; crash/own-choice loss remains a proof obligation, not solved by this reversal. | [Historical selection](#evidence-dec-029); [superseding directive](#769-ram-first-attestation-restored-durability-ordering-superseded) |
| <a id="dec-030"></a>DEC-030 | O1/O2 | Persistent storage failure | Accepted requirement/direction | Keep the process available for diagnosis/local administration, but disable new signing decisions dependent on a store with persistent commit failure. All dependent shards are affected when the store is shared. Do not promote undurable RAM entries through reads. On P2P return existing NOT_READY: no vote and normal attainable-quorum handling, without relying on the claimed cause or treating it as fraud evidence. Preserve the approved all-member checkout dispatch without extra offline suppression. | [Recorded selection](#evidence-dec-030) |
| <a id="dec-031"></a>DEC-031 | O2 | Automatic storage recovery | Accepted requirement/direction | Resume automatically once durable storage and justified recovery of relevant lock/signing state are established, respecting operator stop/veto. The maintainer expects synchronization to restore missing locks before normal work resumes. Exact completeness/readiness evidence remains unresolved; neither a completed download nor a matching digest proves recovery of every prior individual vote. Distinguish a transient write failure with intact durable choices from irrecoverable choice loss or stale-backup rollback. | [Recorded selection](#evidence-dec-031) |
| <a id="dec-032"></a>DEC-032 | O2 | Lost signing choices | Accepted requirement/direction | After loss or rollback of prior signing choices, withhold new binding votes under the existing identity for affected scope until signing safety is justified. Ordinary confirmed-state sync alone is insufficient. The maintainer approves this safety gate even if ordinary sync has completed; exact detection, scope and recovery remain open. | [Recorded selection](#evidence-dec-032) |
| <a id="dec-033"></a>DEC-033 | O1 | Signing protection layout | Immutable-choice table direction retained; pre-response commit order superseded by DEC-062 | Separate immutable own choices in existing redb remains the selected layout direction. Persist related choice/lock atomically through the bounded background worker; DEC-062 removes waiting for its durable success before attestation. Layout is not an implementation or a proof of recovery of volatile issued choices after crash. | [Historical selection](#evidence-dec-033); [ordering change](#769-ram-first-attestation-restored-durability-ordering-superseded) |
| <a id="dec-034"></a>DEC-034 | O4 | Graceful shutdown | Bounded drain selected; acknowledgment qualification updated by DEC-062 | Stop new admission, allow bounded in-flight/persistence drain, then stop within the configured deadline. Preserve durable choices and report incomplete drain honestly. DEC-062 permits earlier RAM-based approvals, so a failed drain may now leave already issued choices undurable; do not retain the superseded assertion that every binding success awaited commit. DEC-074 selects idempotent repeated stop signals; DEC-075 selects internal deadline enforcement plus outer supervisor fallback; DEC-076 selects verified default CLI completion/DB release; deployment sizing, producer ordering and implementation verification remain pending. | [Historical selection](#evidence-dec-034); [RAM-first qualification](#769-ram-first-attestation-restored-durability-ordering-superseded) |
| <a id="dec-035"></a>DEC-035 | O3 | Automatic expiry processing | Accepted requirement/direction | Choose A: remove eligible expired locks and associated justified signing-safety state in bounded background chunks, using short RAM mutation sections and bounded disk work, with enough progress budget to avoid indefinite backlog. Keep verified root TTL plus 30-second grace, no signing of expired roots and no permanent expired-lock tombstones. Expiry rejection does not wait for physical deletion. Exact scheduling, safe time/retention criteria and batch sizes remain to be specified and measured. | [Recorded selection](#evidence-dec-035) |
| <a id="dec-036"></a>DEC-036 | O5 | Deployment default | Accepted requirement/direction | Choose A: native systemd as the primary documented Linux deployment path; retain Docker/Compose as an alternative. Both must obey the same persistence, signing, shutdown and operator-sovereignty rules. Existing template settings are not validated production guarantees. | [Recorded selection](#evidence-dec-036) |
| <a id="dec-037"></a>DEC-037 | O5 | Private operator access | Accepted requirement/direction | Choose A: dedicated local dashboard/admin endpoint, with protected control-socket authority and operator SSH forwarding for remote access. Keep operator routes separate from public client ingress and retain useful local dashboard functions. Exact UI/backend packaging, authentication and permission enforcement remain to be specified and verified. | [Recorded selection](#evidence-dec-037) |
| <a id="dec-038"></a>DEC-038 | K2 | Shared protocol library | Accepted requirement/direction | Choose A: extract a small shared Rust library for canonical L2 types, signed encodings and basic cryptographic verification, used by both core and node without wallet/account/application logic. The maintainer explicitly maintains both projects and authorizes coordinated breaking protocol changes. Retire obsolete paths after checking actual uses. Library layout/versioning and unresolved membership/transition semantics remain to be designed; shared implementation is not itself a safety proof. | [Recorded selection](#evidence-dec-038) |
| <a id="dec-039"></a>DEC-039 | S2/S3 | Committee continuity design direction | Continuity goal accepted; mechanism reopened | Initially selected investigation of fixed committee contexts with justified handoff. The maintainer subsequently reopened this construction to seek a smaller sufficient continuity mechanism (§7.3, §7.8, §7.10). No fixed-context/history scheme, global roster, bootstrap authority or handoff algorithm is finally approved. Preserve safe continuity and full-turnover/progress requirements DEC-045/046; do not turn the earlier sketch into a mandatory implementation. | [Recorded selection](#evidence-dec-039); [reopened](#evidence-reopen-continuity) |
| <a id="dec-040"></a>DEC-040 | O6 | Operator reliability diagnostics | Accepted requirement/direction | Choose A: own direct observations and verified fraud evidence; leave indirect/topological reputation out initially. The maintainer explicitly includes locally observed response reliability. Distinguish valid replies, explicit NOT_READY, and actual request deadline misses. Quorum-completion cancellations and requests never sent due to local admission are not peer misses. Measurements express this observer's service experience, not proof of malicious intent or global badness. No new reputation gossip, automatic bans, committee exclusion or checkout offline suppression is authorized. | [Recorded selection](#evidence-dec-040) |
| <a id="dec-041"></a>DEC-041 | S3 | Handoff interruption preference | Accepted requirement/direction | Choose A: permit a write pause for the affected shard/context to simplify safe handoff. Aim to keep it short; the maintainer suggests a few-second customer wait and explicit temporary-unavailability feedback. No pause-duration guarantee, complete handoff protocol or automatic start after a timer is approved. Other shards continue. | [Recorded selection](#evidence-dec-041) |
| <a id="dec-042"></a>DEC-042 | C3/S3 | Requests during handoff | Accepted requirement/direction | Choose A: the client retains the exact signed intent and performs bounded idempotent retries after temporary unavailability. No additional node-side handoff queue. A pending request/hint is not payment confirmation; normal causality, expiry, quota, collision and durable-vote checks still apply. Exact feedback fields and retry budget remain to specify. | [Recorded selection](#evidence-dec-042) |
| <a id="dec-043"></a>DEC-043 | S3/S4 | Routine handoff cadence | Batching accepted; hourly parameter tentative | Choose A: bundle routine committee-change proposals into spaced per-shard transition attempts to reduce repeated pauses/work. The maintainer tentatively selects approximately hourly candidate checks as the starting parameter; transition only if relevant changes and justified completion. Timing remains unmeasured; elapsed time and ticket maturity never authorize activation by themselves. Verified fraud sanctions are not delayed, and local timeouts/NOT_READY do not trigger committee exclusion. | [Recorded selection](#evidence-dec-043); [tentative hour](#evidence-hourly-cadence) |
| <a id="dec-044"></a>DEC-044 | S1 | Byzantine tolerance target | Accepted requirement/direction | Choose A: seek safety with up to six Byzantine identities in the relevant 20-member committee model, retaining 14 votes. This is a desired conditional design target, not proof that WoT/ticket work enforces the bound. Fault-set scope across views and time, bootstrap, membership eligibility and safe continuity remain unresolved. | [Recorded selection](#evidence-dec-044) |
| <a id="dec-045"></a>DEC-045 | S3 | Complete committee turnover | Accepted requirement/direction | Choose A: valid vouchers must remain serviceable across repeated justified handoffs, including growth from 30 to 1,000 or 10,000 nodes and eventual replacement of every original signer. No founding member must remain online or in the committee. This is a continuity requirement, not proof of a transition algorithm or recovery after sudden old-quorum loss. | [Recorded selection](#evidence-dec-045) |
| <a id="dec-046"></a>DEC-046 | S4 | Handoff progress after contention | Accepted requirement/direction | Choose A: require safe automatic progress once communication stabilizes and the relevant honest quorum is available, including competing proposals. Permit the minimum necessary handoff retry/agreement rules. No specific protocol/library, fixed pause duration, globally common ranking or recovery after permanent old-quorum loss is approved. | [Recorded selection](#evidence-dec-046) |
| <a id="dec-047"></a>DEC-047 | S2/S5 | Intended network topology | Clarified/reaffirmed operating requirement | The maintainer expects one organically connected global network: providers and clients benefit from global connectivity; small startup meshes or deliberate islands are exceptions. Independent permanent trust domains are not the intended product model. This is an operating goal, not a selected common bootstrap anchor, a bound on transient HRW-view differences, or permission to reverse FINAL after partitions. | [Recorded selection](#evidence-dec-047) |
| <a id="dec-048"></a>DEC-048 | C2/S5 | FINAL threshold and organic-network assumption | Clarified/reaffirmed operating requirement | Reaffirmed by the maintainer: retain FINAL from the existing N >= 20 regime with the selected 14/20 checkout policy and existing stability requirements. Organic spread through existing users and preference for globally connected providers make spontaneous independent twenty-node networks an unlikely normal deployment scenario in the maintainer's model; no measured probability is claimed. Do not repeatedly ask whether FINAL should exist at twenty nodes or force a permanent-network/anchor choice. This operating assumption does not establish dynamic committee safety or select FINAL revocation. | [Recorded selection](#evidence-dec-048) |
| <a id="dec-049"></a>DEC-049 | K3 | Client authorization terminology | Accepted naming decision | Q-K3-G021-01 A: “Lock-Signatur” names the individual client authorization signature; “Freigabenachweis” names the combined authorization evidence, including the disclosed key's checked predecessor-output binding and valid signature. Naming only; canonical formats, enforcement and verification remain OPEN-06. | [Answer and scope](#725-client-authorization-names-selected-parent-lock-naming-next) |
| <a id="dec-050"></a>DEC-050 | K3 | Predecessor terminology | Accepted naming decision | Q-K3-G014-01 A: “Eltern-Lock” names the predecessor record; “Vorgängerausgabe” names its particular consumed output. Exact split/output binding remains OPEN-06; no identifier or protocol-format change. | [Answer and next review](#726-parent-terminology-selected-shard-digest-naming-next) |
| <a id="dec-051"></a>DEC-051 | K3 | Shard summary terminology | Accepted naming decision | Q-K3-G049-01 A: “Shard-Zusammenfassung” names the existing “Shard digest” concept. Compact comparison information, not full state or recovery proof. | [Answer and steering](#727-glossary-naming-complete-autonomous-editorial-alignment) |
| <a id="dec-052"></a>DEC-052 | K3 | Autonomous vocabulary maintenance | Accepted workflow/scope direction | Stop glossary preference questions. Maintain and align vocabulary autonomously across current documentation and comments; terms may be refined later. This does not select unresolved protocol behavior. | [Maintainer instruction](#727-glossary-naming-complete-autonomous-editorial-alignment) |
| <a id="dec-053"></a>DEC-053 | K1.1/S2.2/S5 | Partition-resilient regional acceptance | Accepted product direction; simulation verified (S2.2 T01–T12 pass) | Q-K1-FINALITY-01 answered B by explicit maintainer direction: local current-mesh committee constitution without mandatory old14 authorization, regional operation through partitions and deterministic min(H_canon) reconciliation. A regional receipt may lose after discovery of an admissible competing branch; no global irrevocability or99.999% guarantee is inferred. Retain fixed<=20/14 votes per collection, N<20 PROVISIONAL, durable own choices, recipient eligibility checks, support gate and first-party-only fraud penalties. Qualify older strict-CEH/global-FINAL interpretations, not their historical provenance or the original Q-S3.3-01 meanings. | [Decision and limits](#757-partition-resilience-selected-and-p0-reoriented) |
| <a id="dec-054"></a>DEC-054 | S2.1/S2.2/S5/C4 | Regional eligibility, honest merge and merchant risk | Accepted guardrails; simulation verified (S2.2 T01–T12 pass) | Regional voters require valid identity-bound Argon2d tickets, observed24h incubation and independently authenticated F2F admission; no gateway-invented roster. Only two genuine incompatible personal approvals for one slot justify node sanctions; honest single-branch losers are never punished. Distinguish FINAL(Global) from REGIONAL CONFIRMED and keep amount/exposure limits in terminal policy outside blind L2. The formal candidate reserves green behind a separate proof guard; ticket cost does not establish a per-view fault bound. | [P0 elaboration](#758-p0-formal-contract-and-twelve-acceptance-scenarios) |
| <a id="dec-055"></a>DEC-055 | S3/C1/K1 | Rejection of predecessor baton chaining and chained L2 receipts | Accepted negative guardrails / architecture direction | Explicitly rejects mandatory predecessor epoch baton chaining as a permanent dead-end: succession is derived autonomously from the living active mesh via HRW, with min(H_canon) convergence upon merge. Rejects recursive client-side L2 receipt chaining on spend: recipients do not verify historical L2 receipt chains; live collision checking in-RAM suffices, while L1 carries causal ownership. Rejects active 30s background ping storms in favor of passive hourly F2F Dunbar heartbeats. | [Maintainer directive](#760-predecessor-baton-chaining-and-chained-l2-receipts-rejected) |
| <a id="dec-056"></a>DEC-056 | S2.1a/N1 | Passive presence exclusion | Accepted requirement; exact timing/enforcement pending | After three consecutive missed hourly gossip heartbeats, exclude an already admitted peer from future HRW snapshots. This supersedes Q-S2.1-PRESENCE-01's proposed 2h baseline and slow-dormancy alternative. Preserve ticket maturity, historical approvals, frozen in-flight membership and first-party-only sanctions. Exact slot deadlines, safe-time tolerance, restart/re-entry and production/model enforcement still require consolidation. | [Maintainer answer and next question](#762-three-missed-heartbeats-selected-and-total-state-loss-boundary) |
| <a id="dec-057"></a>DEC-057 | S3.4/N3/O2 | Mandatory restart sync-readiness; no empty-state disaster fallback | Accepted requirement / Q-S3-STATELOSS-01 A; recovery proof and implementation pending | After restart or state loss, return FLAG_NOT_READY and withhold lock approvals until justified P2P digest-pull recovery of the affected shard state. No reachable recoverable state means the affected scope remains unrecovered/blocked; L1 evidence alone cannot authorize an empty-state restart. Successful transfer must establish the required scope/coverage, not only matching digests. Preserve the independent lost-own-choice same-key gate; no old-quorum authorization or global completeness claim is inferred. | [Answer, source findings and recovery contract](#763-mandatory-sync-readiness-selected-recovery-completeness-still-open) |
| <a id="dec-058"></a>DEC-058 | S3.4a/N3 | Quorum-backed verified digest-pull | Accepted mechanism / Q-S3-RECOVERY-BASIS-01 A; completeness proof pending | Use Spec03-style agreement among distinct justified shard peers on a state digest (14/20 in regional mode), then fetch the bound snapshot, verify lock signatures, reconstruct the committed state and durably install before readiness. Stay FLAG_NOT_READY until justified complete recovery. Designated-source trust alternative B rejected. Digest agreement and signatures do not by themselves prove preservation of omitted prior locks; source coverage, stable cuts and own-choice recovery remain obligations. | [Selection, proof boundary and live-transfer question](#765-quorum-digest-pull-selected-stable-transfer-under-write-load) |
| <a id="dec-059"></a>DEC-059 | S3.4a.1/N3 | Fixed snapshot with bounded deltas and bucket sealing | Accepted direction / Q-S3-SYNC-WRITES-01 A; sealing semantics pending | Select fixed snapshot plus bounded deltas; use 5-minute timestamp buckets and a 30s grace after bucket end as the selected sealing parameter; immutable-state semantics remain open. Buffer current-window in-flight work without application acceptance/vote before validation/readiness/durable commit; bounds/backpressure required. DEC-061 clarifies direct targeted sync and deterministic recomputation without an extra snapshot-version or correction subsystem. Live-freshness/seal alignment, root expiry and canonical changes still need verification. | [Selection and late-bucket question](#766-fixed-snapshot-deltas-selected-bucket-sealing-and-retry-boundaries) |
| <a id="dec-060"></a>DEC-060 | C3/N4/S3 | Exact-payload retries and three-send heuristic | Accepted maintainer refinement; bounds/integration unverified | Retry the same serialized application payload with unchanged T_0. Adopt the referenced conditional three-send heuristic (initial attempt, error retry, third background attempt) as a refinement of DEC-027's prior one-application-attempt policy. Keep the frozen member set, 800ms checkout, neutral cancellation, deduplication, bounded work and durable vote rules. Sending is neither durable acceptance nor a completeness/delivery guarantee; DEC-061 selects wallet-bound creation-time custody across failover; local schema/signature alignment and resource/cancellation details remain open. | [Maintainer instruction and limits](#766-fixed-snapshot-deltas-selected-bucket-sealing-and-retry-boundaries) |
| <a id="dec-061"></a>DEC-061 | S3.4a.2/K2/C3 | Wallet-bound creation time; fresh live ingress versus historical sync | Accepted maintainer correction; code alignment/proof pending | T_0 is an explicit public wallet-created created_at_ms bound by layer2_signature, distinct from encrypted_timestamp; retain it across retries/failover. Fresh live acceptance must use this same time with the 30s gate; closed 5-minute windows seal after 30s. Recover missing old records via quorum-backed targeted sync and recompute the deterministic bucket projection. Reject Q-S3-LATE-BUCKET-01 A and B as unnecessary additional structures: no separate correction history or snapshot-version subsystem selected. Local code currently gates a gateway-envelope time and projects encrypted_timestamp; alignment, clock/commit/TTL/merge and source coverage remain open. | [Correction, conditional timing argument and code evidence](#767-withdraw-late-bucket-choice-separate-live-freshness-from-sync-repair) |
| <a id="dec-062"></a>DEC-062 | O1/S3.4a.4/C2 | RAM-first attestation; asynchronous persistence; ingress-only freshness | Accepted explicit current direction; crash/seal proofs pending | Wallet T_0 fixes bucket; 30s freshness is entry-only. After reservation-first RAM collision acceptance, sign/respond in <5ms without waiting for redb commit; persistence is bounded asynchronous background work. No post-admission freshness check or variable seal-delay choice selected. Supersedes DEC-029 and pre-response durability portions of DEC-033/034; preserves identity-choice immutability and recovery gates. RAM+disk digest input includes accepted volatile entries, but does not make them durable. Fixed end+30s sealing remains intended; gate-to-insertion timing and clock proof remain open. | [Correction and changed durability contract](#769-ram-first-attestation-restored-durability-ordering-superseded) |
| <a id="dec-063"></a>DEC-063 | O1.1/O2/N3 | Unconditional retention of lost-choice safety gate | Reaffirmed requirement / Q-O1-CRASH-RESUME-01 A; bounded-quarantine construction unproved | DEC-032 stays fully in force; ordinary quorum sync alone is insufficient for same-key signing when own issued choices are missing. B's relaxation categorically rejected. Maintainer proposes finite 5-minute-bucket+30s quarantine; closure of stale live ingress alone does not yet prove immunity to a distinct, fresh-time conflicting spend of the same output. Preserve the bounded-recovery goal and unresolved construction; do not silently auto-open the gate or claim permanent blocking is necessary. | [Answer, counterexample boundary and next merge question](#771-loss-gate-reaffirmed-bucket-quarantine-proof-and-mixed-mode-merge) |
| <a id="dec-064"></a>DEC-064 | S5.1/K1.1 | Strict confirmation-class priority before canonical hash | Accepted policy / Q-S5-MIXED-SUPPORT-01 A | Valid class2 FINAL/Regional14 strictly outranks valid adaptive class1 PROVISIONAL; class0 partials/intents cannot displace a confirmed branch or establish a confirmed winner. Within the highest admitted confirmed class use min(H_canon). Reject mixed-class freezing B; losing causal branch becomes VOID without sanction of honest single-branch signers. Context/signature/causal checks and first-party-only fraud remain. Class priority is not a global irrevocability proof; equal-class regional conflicts still use the selected merge rule. | [Decision and VOID-retention question](#772-class-priority-selected-retention-after-void-remains-open) |
| <a id="dec-065"></a>DEC-065 | S5.2/K1/O3 | Minimal losing-branch retention | Accepted policy / Q-S5-VOID-RETENTION-01 A | Retain the winning lock, minimum sufficient collision/exclusion evidence and immutable own signing choices while the root is usable; clients custody excess complete losing branches. Reject full losing-tree archival B as state bloat. Physically purge root-bound records at root.valid_until+30s; separate identity/fraud rules remain. Exact authenticated compact format, descendant/promotion handling and recovery sufficiency require engineering verification. | [Selection and conflict-response question](#773-minimal-retention-selected-conflict-response-payload-open) |
| <a id="dec-066"></a>DEC-066 | C1.1/K2 | Inline compact conflict evidence | Accepted policy / Q-C1-CONFLICT-RESPONSE-01 A | Include the already available compact signed collision evidence and confirmation status directly in the 409 envelope; no full losing trees, hot-path proof retrieval or required second proof-fetch round. Reject reference-only B to reduce latency and gateway complexity. Exact signer/slot/time binding, encoding, payload limits and verification remain work; a single attestation is not a quorum certificate. | [Selection and checkout conflict-veto question](#774-inline-conflict-evidence-selected-checkout-veto-policy-open) |
| <a id="dec-067"></a>DEC-067 | C2.1/S5 | No minority collision veto at checkout | Accepted policy / Q-C2-CONFLICT-VETO-01 A | A valid14/20 certificate from the frozen committee completes checkout despite weaker authenticated collisions. Reject conservative minority-veto B. A sufficiently supported competitor is evaluated by DEC-064; a peer may carry a full certificate, so transport-source count is not support strength. Partial-only outcomes remain unresolved without payment success or slot rollback. Exact collector/response ordering and wire defenses pending; no global-finality or fault-bound proof inferred. | [Selection, derived response rules and uncertain-payment follow-up question](#775-quorum-checkout-priority-selected-uncertain-payment-follow-up-open) |
| <a id="dec-068"></a>DEC-068 | C3.1/C4 | Bounded automatic client reconciliation | Accepted policy / Q-C3-UNCERTAIN-FOLLOWUP-01 A | Wallet retains the original uncertain intent, performs automatic status reconciliation with growing/exponential backoff and strict attempt/traffic budget, and uses only reads after the original30s freshness window. No historical-order push state at servers; normal status routing remains INV-0310. Reject manual-only B. Example5 attempts and5s/15s/45s schedule are illustrative, not frozen parameters. Budget exhaustion/absence cannot become failure, free slot or14/20 success; sufficient read evidence and exact bounds remain open. | [Selection and proof-retrieval scope question](#776-bounded-client-reconciliation-selected-completion-evidence-retrieval-open) |
| <a id="dec-069"></a>DEC-069 | C4.1/C4.2/K2/O1 | Read-only recovery of original checkout approvals | Accepted policy / Q-C4-COMPLETION-EVIDENCE-01 A | Wallet may recover existing approvals of the original fixed20 within its total retry/read budget, verify14 distinct eligible signatures in one original context for an unresolved checkout; DEC-072 removes mandatory certificate custody/back-fill after completion. No new lock, changed T_0, new write vote, full-tree fetch or replacement committee. Reject status-only B. Missing/insufficient approvals stay unresolved. Original-attestation retention and retrieval are not established in inspected production paths; derive exact format/availability and capacity costs. One-roundtrip cap is an example, not a frozen value or guaranteed single packet. DEC-083 qualifies this as an optional exceptional original-evidence path, not a prerequisite/archive duty for current live-quorum clearance. | [Selection and technical retrieval contract](#777-original-approval-retrieval-selected-technical-contract-and-storage-gap) |
| <a id="dec-070"></a>DEC-070 | C4.2a/O1/O3 | Root-lifetime retention of original own approvals | Accepted policy / Q-C4-APPROVAL-RETENTION-01 A | Keep exact own original approvals and required verification context until root.valid_until+30s, preferably with the already protected own-choice record and common TTL pruning. Reject shorter-window B as a second lifecycle and avoidable offline-wallet recovery loss. No full losing-tree archive or synchronous node commit is added. Actual signature/context storage costs and safe coordinated RAM/disk purge need verification; no guarantee that14 original signers remain reachable. DEC-083 preserves own signing-safety retention, not migration of old quorum bundles or dependence of current clearance on original signers. | [Selection and wallet send-order question](#779-root-lifetime-original-approval-retention-selected-wallet-send-order-open) |
| <a id="dec-071"></a>DEC-071 | C3.2/K2 | Durable wallet intent before network dispatch | Accepted policy / Q-C3-WALLET-SEND-DURABILITY-01 A | Durably commit the exact signed request bytes/T_0 and atomic pending state of the consumed output before the wallet first sends to a gateway. Reject client RAM-first send B: crash must not lose the only original intent while the network may have accepted it. Reuse existing wallet storage; WAL/SQLite are examples, not a selected new dependency. Preserve exact retries, read-only reconciliation after freshness and server RAM-first. Actual client durability/latency and rollback recovery need verification. | [Selection and PoS receipt-order question](#780-wallet-durable-before-send-selected-pos-receipt-order-open) |
| <a id="dec-072"></a>DEC-072 | C2.2/K1/C4 | Durable L1 voucher/purchase, ephemeral completed-checkout certificate | Accepted corrected A / Q-C2-POS-RECEIPT-DURABILITY-01; original A content amended | Before goods release, durably store the received L1 voucher deed and its purchase-journal binding. Verify the live quorum signal during checkout; no mandatory merchant archival/back-fill of its14-signature bundle after completion, no recursive receipt chain and no treating certificates as money/current-unspent proof. Supersede §7.80 certificate-in-durable-purchase requirement, not wallet pre-send durability or node signing-safety retention. Live status is the selected post-restart interface; sufficient read-evidence semantics remain unproved. | [Correction, scope reconciliation and alternate-payment question](#781-merchant-l1-custody-selected-completed-checkout-receipts-ephemeral) |
| <a id="dec-073"></a>DEC-073 | C3.3/K1 | No automatic substitute payment; strict client boundary | Accepted policy / Q-C3-ALTERNATE-PAYMENT-01 A with explicit scope | Wallet/PoS must not automatically issue a second different-voucher payment while the first is uncertain. Multi-voucher purchases retain completed components as partial payment and timed-out components as uncertain; changing tender for the remainder is a conscious cashier/customer decision. Reject automated replacement/refund B. This is exclusively human-money-core/PoS commercial logic: humoco-node knows no carts, purchase IDs, remaining amounts or substitute payments and gains no new API/state for them. | [Client-boundary selection and next node-operation question](#782-client-only-payment-policy-selected-repeated-node-stop-signal-question) |
| <a id="dec-074"></a>DEC-074 | O4.1/O1 | Idempotent repeated termination signals | Accepted policy / Q-O4-SECOND-SIGNAL-01 A | Once bounded graceful shutdown starts, repeated SIGTERM/SIGINT must neither shorten nor restart/extend its original deadline. Continue eligible in-flight work and async persistence within that budget; reject second-signal early-abort B. Operator force-stop remains OS SIGKILL. Bound expiry/incomplete reporting follows DEC-034; readiness and lost-own-choice gates still apply after unclean stop. Reported few-hundred-ms drain is an unmeasured expectation. | [Signal selection, derived stop contract and deadline-enforcement question](#783-idempotent-stop-signals-selected-deadline-enforcement-boundary-open) |
| <a id="dec-075"></a>DEC-075 | O4.2/O5 | Internal shutdown deadline with outer supervisor margin | Accepted policy / Q-O4-DEADLINE-OWNER-01 A | Daemon enforces one finite stop deadline in CLI/service/container operation; supervisor has a longer outer fallback. Reject supervisor-only B.5–10s internal and30s external are examples, not measured/frozen defaults. Use bounded drain and truthful incomplete result; deadline cannot force failed/stuck storage to persist or make a timed-out blocking task vanish. Operator veto, idempotent signals and recovery gates remain. | [Selection, derived lifecycle and stop-CLI semantics question](#784-internal-deadline-selected-stop-cli-completion-contract-open) |
| <a id="dec-076"></a>DEC-076 | O4.3/O5 | Stop CLI waits for verified completion and released DB | Accepted policy / Q-O4-STOP-CLI-01 A | Default humoco stop waits boundedly; exit0 requires confirmed clean shutdown, actual target-daemon termination and released redb handle/lock. Timeout, stuck task, failed/incomplete drain or unverified result is nonzero; request acceptance/socket disappearance is insufficient. Reject immediate-acceptance default B. Existing execute_stop has wait intent but the inspected socket-based check does not prove this full contract. Keep original daemon deadline independent of client wait. | [Selection, shutdown acceptance table and metrics-exposure question](#785-stop-cli-completion-selected-shutdown-acceptance-table-and-metrics-exposure) |

| <a id="dec-077"></a>DEC-077 | O5.1/O6/N1 | Operator-only metrics and diagnostic topology | Accepted policy / Q-O5-METRICS-EXPOSURE-01 A | Expose Prometheus metrics and dashboard only through the private operator boundary; reject a public base-metrics subset. Public clients keep intended payment/status/health interfaces, without private queue, storage, quota or peer diagnostics being re-exported under another route. Enforce listener/route separation and bounded diagnostic cost; current shared router is not proof of private exposure. Public gateway discovery is a separate unselected client policy, never authority for internal P2P admission. | [Selection, endpoint matrix and gateway-discovery question](#786-private-metrics-selected-endpoint-boundary-and-client-gateway-discovery) |

| <a id="dec-078"></a>DEC-078 | O5.2/C3/N1 | Dynamic public gateway discovery | Accepted policy / Q-O5-GATEWAY-DISCOVERY-01 B | Offer clients a simple read endpoint for additional explicitly published HTTP gateways, reusing passive gossip/known-node data; bootstrap/custom lists remain entry points rather than the sole source. Reject A-only discovery. Preserve private internal topology, public free-tier protection, exact-payload failover, recipient source choice and bounded read cost. Existing P2P sockets are not authenticated public HTTP URLs, and hourly presence is not current reachability proof. Route name /v1/gateways is an example; metadata, authentication and delivery remain engineering work. | [Selection, advertisement gap and stale-discovery fallback question](#787-dynamic-gateway-discovery-selected-passive-advertisement-and-stale-cache-policy) |

| <a id="dec-079"></a>DEC-079 | O5.2a/C3/K1 | Bounded last-known gateway fallback belongs to clients | Accepted policy / Q-O5-GATEWAY-STALE-CACHE-01 A with explicit scope | Wallet/app may try locally cached public gateway addresses within its existing attempt/time budget when discovery is stale. Reject current-directory-only automatic fallback B. Cache/connection policy belongs to human-money-core/app, outside node consensus authority; no node cache-control consensus rule or state is added. Preserve endpoint authentication, explicit revocations, provider-scoped credentials and exact original payment retries. Concrete cache parameters and client failure checks remain delivery work. | [Selection, gateway acceptance map and single-status acceptance question](#788-client-cache-fallback-selected-return-to-single-status-acceptance) |

| <a id="dec-080"></a>DEC-080 | C4.3/C2/K2 | Quorum proof required for paid/goods release | Accepted policy / Q-C4-SINGLE-STATUS-ACCEPTANCE-01 A | A matching owner-signed lock or single-source assertion alone never authorizes paid/goods release. FINAL checkout requires mathematically verified14/20 support, with distinct eligible identities and exact context. Reject weaker trusted-single-source B. One transport reply may carry sufficient multi-signer evidence; no mandatory client archive or recursive receipt chain is added. Original-approval recovery and current-state/read semantics remain separate proof obligations; current optional read collector does not establish them. | [Selection, read-path findings and status-verification scope question](#789-quorum-backed-release-selected-status-verification-scope) |

| <a id="dec-081"></a>DEC-081 | C4.3a/C2/N4 | Cheap ordinary lookup, explicit quorum-backed release verification | Accepted policy / Q-C4-STATUS-VERIFICATION-SCOPE-01 A | Keep ordinary status lookup at default read_quorum1 / INV-0310; payment release explicitly requests and verifies the full required quorum (14/20 in FINAL mode). Reject full quorum on every routine read B. Requested read_quorum>=14 is not itself proof: count distinct eligible verified signers/context and support, never lower FINAL to an available minority. Wallet balances remain client-derived, outside the blind node. Routing, current-state evidence and receiver implementation still need proof/testing. | [Selection, batching workflow and derived-detail batch](#790-targeted-quorum-verification-selected-batch-derived-details) |

| <a id="dec-082"></a>DEC-082 | C4/K2/C3/O5 | Confirm derived implementation batch | Explicitly accepted / DETAIL-BATCH-001 DB1-01–06 | Maintainer explicitly confirms all six previously derived directions as requirements for later implementation: distinguish found from confirmed, validate real distinct qualified signatures, preserve uncertainty/original intent, advertise actual public HTTP endpoints, scope provider credentials and isolate every private diagnostic alias. This is requirement acceptance, not source-change authorization, completed design or test evidence. | [Confirmation and conditional live-read verification contract](#791-confirmed-detail-batch-and-live-read-verification-contract) |

| <a id="dec-083"></a>DEC-083 | C4.3b/C4.3c/S3/K1 | Current shard-state quorum, no inherited historical certificate archive | Explicit correction / Q-C4-ACTIVE-PROOF-CONTINUITY-01 withdrawn; neither A nor B | L1 holds the transaction/deed; L2 holds the live parent->child collision barrier. Qualified current shard nodes answer and attest their safely synchronized state, with14/20 live evidence for FINAL release. Do not carry historical signature bundles through successive shard generations or require old signers/certificates for current clearance. Their absence alone cannot make a recovered lock unconfirmed. Keep owner validation, safe state-transfer/readiness, full-key current-quorum verification and separate own-choice/crash safeguards; no claim these are implemented/proved. | [Correction and replacement live-state contract](#793-current-state-authority-selected-historical-proof-archive-premise-withdrawn) |

### 2.2 Alternatives, refinements and superseded proposals

Only attribute rejection/selection where the files document it. A currently
unselected alternative is not necessarily rejected forever. Reasons below summarize
the recorded reasoning; they do not supply missing original user explanations.

| Record | Current result / alternative treatment | Recorded reason and remaining consequence |
| --- | --- | --- |
| DEC-006/038 | Shared protocol library selected over separately maintained adapters/verifiers as the consolidation direction; internal adapters are not forbidden. | §7.3: align canonical types/encodings and real verification across both maintained projects; layout and authority rules remain open. |
| DEC-022/023 | Owner-valid lower-hash singleton takeover withdrawn as sufficient; unqualified conflict remains unresolved. | §7.1: owner authorization is not registry acceptance; raw copy majority can promote unsupported state. Exact provisional/FINAL merge rules remain open. |
| DEC-027/028 | Earlier checkout-specific NOT_READY/timeout backoff and added probing superseded by all-member dispatch. Minimal future suppression remains conditional on measurements. | §7.2.1: simpler dispatch with no extra offline-tracking state; retain admission/receiver defenses and distinguish shared transport behavior. No blanket deletion of P2P failure handling. |
| DEC-029 | Binding vote after durable commit replaces sign-after-enqueue assumption and rigid local 5 ms target in the interview direction. | §7.2.1: crash-before-flush can lose an earlier vote. Keep bounded asynchronous persistence and no RAM lock across I/O; budget/spec consolidation remains pending. |
| DEC-030/031/032 | Remain available for diagnosis, resume automatically only when safe; ordinary sync alone cannot clear lost-choice safety gate. | §7.2.1: registry recovery need not recover non-quorum individual votes. Same-key loss/rollback recovery is unresolved, not replaced by a new-identity shortcut. |
| DEC-033 | Existing redb immutable-choice table A selected; separate durable signing journal B not selected. | §7.2.1 comparative research favors reusing bounded atomic storage; another file adds ordering/recovery work and does not itself survive disk loss. |
| DEC-034 | Bounded shutdown A selected; unbounded wait-until-everything-commits B not selected. | §7.2.1: stop within a configured deadline and report incomplete drain honestly; no measured deadline chosen. |
| DEC-035 | Bounded expiry chunks A selected; one all-expired sweep B not selected. | §7.2.1: avoid concentrated cleanup monopolizing foreground/background resources; safe time/retention criteria and batch sizes open. |
| DEC-036 | systemd-first A selected; container-first documentation B not selected. | §7.2.1: fewer runtime layers for the daemon; preserve useful Docker/Compose support. |
| DEC-037 | Local operator endpoint with SSH forwarding A selected; VPN/private-network default B not selected. | §7.2.1/7.3: private operator boundary, protected control-socket authority and retained useful administration. Exact enforcement open. |
| DEC-039/045 | Full root-lifetime committee pinning B not selected; fixed-context/history construction subsequently reopened. | §7.3/7.4/7.8: long voucher lifetimes and seven departed original members can destroy 14/20 availability. Investigate minimal safe continuity without requiring permanent founders. |
| DEC-040 | Direct diagnostics A selected, including local response reliability; extra topology/reputation advisories B left out initially. | §7.3: bounded useful observations without guilt propagation, hearsay sanctions or a new gossip stream. |
| DEC-041 | Planned affected-shard write pause A selected over investigating concurrent live handoff as the initial direction. | §7.3: simplify cutover; few-second normal-case wait is an aim, not a guarantee or an approved protocol. |
| DEC-042 | Client-retained retry A selected; added newcomer/server pending-intent queue B not selected. | §7.3: avoid another queue while preserving exact-intent retries and uncertain-outcome semantics. |
| DEC-043 | Batch routine changes; hourly candidate checks A only tentative, daily B not selected. | §7.3/7.7/7.8: reduce repeated pauses while allowing workload redistribution. No timer confers authority or shortens incubation. |
| DEC-044 | Six-Byzantine design target A selected instead of weaker three-Byzantine target B. | §7.3: desired safety tolerance; eligibility, actual adversary bound and temporal scope unproved. |
| DEC-046 | Automatic safe progress after stabilization A selected; indefinite write-disable after competing partial endorsements B not selected as intended behavior. | §7.9: immutable one-successor votes alone permit a 13-X/7-Y stall. Concrete safe round/recovery mechanism open. |
| DEC-047/048 | One growing network and existing N >= 20 FINAL policy reaffirmed; repeated S5.1a question withdrawn without an A/B answer. | §7.12/7.13: do not force a permanent-domain product choice or infer FINAL revocation/common-anchor approval. Adversarial partitions and changing views remain in scope. |
| Q-S3.3-01 | Neither one-round/carrying A nor redesigned two-round completion B selected. | §7.5/7.14–7.16: requests to explain existing lock reconciliation are not an answer. §7.16 preserves the exact German presentation; §7.29 adds conditional closure/inclusion findings without changing A/B. No mandatory new reservation object or certificate-return round follows. |
| Q-S2.2-01 | Unanswered; withdrawn as the next decision question because its predecessor-roster prerequisite is unresolved. | §7.36 preserves the exact proposal/question. Maintainer challenges "the previous group"; §7.37 corrects premature decision readiness. Conditional transition research remains, but no shared roster, initial anchor or payment-round choice is selected. |
| Q-K1-FINALITY-01 | Answered B by explicit regional-availability/merge direction; DEC-053. | §7.56 preserves exact A/B. §7.57 records the maintainer's choice to remove mandatory predecessor permission and allow competing regional receipts to converge later. No renewed A/B question; not a choice of payment rounds or proof of the stated success percentages. |

| Q-S3-RECOVERY-BASIS-01 | Answered A / DEC-058; designated recovery-source trust B rejected. | §7.64 preserves exact options; §7.65 selects Spec03 quorum-digest transfer while retaining source-coverage and concurrent-write proof obligations. Selection is not proof of historical completeness. |

| Q-S3-SYNC-WRITES-01 / DEC-059 | Answered A: fixed snapshot plus bounded deltas; repeated full-transfer B rejected for sustained-load recovery. | §7.65 retains exact options. §7.66 records 5-minute/30s sealing directions and late-evidence obligations; no throughput threshold or convergence theorem established. |
| DEC-027 / DEC-060 | One-attempt checkout rule refined by explicitly selected three-send heuristic; all-member dispatch and frozen membership retained. | §7.33's transport/correlated-loss limits remain valid; §7.66 records changed user intent, resource and cancellation obligations. |

| Q-S3-LATE-BUCKET-01 / DEC-061 | Neither A nor B: both additional-structure proposals rejected; question withdrawn. | §7.67 separates stale live ingress from historical sync and accepts direct deterministic bucket recomputation. §7.66 is retained as history, not a mandate for correction logs or versions. Implementation gaps are source observations, not justification to re-ask the withdrawn choice. |

| DEC-029/033/034 → DEC-062 | Durable-before-response / relaxed local SLA superseded; RAM-first attestation and <5ms target restored. | §7.69 records explicit maintainer direction. Async worker+awaited commit was distinct from synchronous fsync in the handler; the changed response order reopens volatile-choice crash composition, not the timestamp/bucket authority. |
| Q-S3-FRESH-COMMIT-01 | Withdrawn after correction; neither A nor B selected. | DEC-062 rejects post-entry freshness recheck and a variable sealing-delay policy. §7.68 remains the original question under the superseded durability premise. |

| Q-O1-CRASH-RESUME-01 / DEC-063 | Answered A; DEC-032 fully retained and B categorically rejected. | §7.71 preserves the finite-quarantine proposal and its remaining proof gap. Do not re-ask whether to accept conflicting own signatures or infer automatic release after bucket seal. |

| Q-S5-MIXED-SUPPORT-01 / DEC-064 | Answered A: strict class2 priority over class1; mixed-class freeze B rejected. | §7.72 records the small-mesh blocking/blackmail concern. Min-hash remains the same-class tie-breaker; class0 is not a payment certificate and honest losing signers are not banned. |

| Q-S5-VOID-RETENTION-01 / DEC-065 | Answered A: minimum sufficient live records; full admitted losing-branch archival B rejected. | §7.73 records client custody, immutable own choices and root TTL+30s physical purge. The exact compact authenticated evidence format remains technical work; no permanent tombstones or recursive L2 receipt chain selected. |

| Q-C1-CONFLICT-RESPONSE-01 / DEC-066 | Answered A: compact signed evidence directly in 409; reference-first B rejected. | §7.74 records one-response clarity, existing RAM data, client custody and stateless gateway intent. Reported 100–300ms savings, a few-hundred-byte size and one-MTU delivery are unverified estimates, not guarantees. |

| Q-C2-CONFLICT-VETO-01 / DEC-067 | Answered A: valid14/20 completes; weaker authenticated collision veto B rejected. | §7.75 records BFT availability and minority-sabotage rationale. Sufficient competing certificates still use DEC-064; partial-only payment uncertainty is derived from existing DEC-009/023 rather than re-asked. |

| Q-C3-UNCERTAIN-FOLLOWUP-01 / DEC-068 | Answered A: automatic bounded client reconciliation; manual-only B rejected. | §7.76 records growing backoff, strict attempt budget and read-only after30s. The selected mechanism may resolve an outcome but bounded single-node reads do not guarantee quorum evidence or deterministic resolution. |

| Q-C4-COMPLETION-EVIDENCE-01 / DEC-069 | Answered A: recover existing original-committee signatures; status-only B rejected. | §7.77 records wallet custody, no new vote and strict total budget. Exact byte/context retention and read-only wire retrieval remain engineering work. No new preference question is needed to choose between original evidence and newly signed status assertions. |

| Q-C4-APPROVAL-RETENTION-01 / DEC-070 | Answered A: original own approvals retained until root TTL+30s; shorter retrieval window B rejected. | §7.79 records one lifecycle, same redb-own-choice record direction, long-offline wallet recovery and physical expiry. Zero additional bytes and instantaneous cross-tier deletion are not established by this selection. |

| Q-C3-WALLET-SEND-DURABILITY-01 / DEC-071 | Answered A: durable original wallet intent/pending-output state before first dispatch; RAM-first client send B rejected. | §7.80 records exact-retry custody and prevention of local phantom unspent state after ordinary crash. WAL/SQLite and sub0.5ms latency are implementation examples/estimates, not measured guarantees or mandatory dependencies. |

| Q-C2-POS-RECEIPT-DURABILITY-01 / DEC-072 | Answered corrected A: durable L1 voucher plus purchase record before release; no permanent checkout-certificate duty. | §7.81 preserves the exact earlier question but supersedes its A requirement to persist the14-signature bundle. Later spending requires current registry checks; historical proof and current status are different claims. Do not infer cancellation of unresolved-attempt recovery or node own-choice rules. |

| Q-C3-ALTERNATE-PAYMENT-01 / DEC-073 | Answered A with explicit client-only scope; automatic substitute/refund B rejected. | §7.82 records partial multi-voucher purchase handling and deliberate tender change. No shopping-cart, purchase-ID, substitute-payment or amount state belongs in humoco-node; return active interview focus to node operations. |

| Q-O4-SECOND-SIGNAL-01 / DEC-074 | Answered A: repeated ordinary stop signals preserve the original bounded drain; early second-signal abort B rejected. | §7.83 records persistence protection and fixed deadline with SIGKILL as explicit OS escape. This does not approve unlimited drain or treat ordinary boot sync as complete lost-own-choice recovery. |

| Q-O4-DEADLINE-OWNER-01 / DEC-075 | Answered A: internal daemon deadline plus longer external supervisor fallback; supervisor-only B rejected. | §7.84 records standalone autonomy and diagnostic opportunity. Example5–10s/30s values are not frozen. Timeout cannot guarantee successful flush; incomplete stop and reboot safety gates remain. |

| Q-O4-STOP-CLI-01 / DEC-076 | Answered A: default CLI waits for verified clean completion/DB release; acceptance-only default B rejected. | §7.85 records exit0/nonzero maintenance scripting contract and checks the claimed existing implementation: wait intent exists, but socket unlink occurs before final flush and does not prove DB release/clean completion. |

| Q-O5-METRICS-EXPOSURE-01 / DEC-077 | Answered A: metrics and dashboard operator-only; public base-metrics subset B rejected. | §7.86 records operator ownership, topology/load privacy and KISS. Existing public status/health remains, but must not serve as an alternative exporter of the same private diagnostic data. This choice does not yet select a public gateway-directory mechanism. |

| Q-O5-GATEWAY-DISCOVERY-01 / DEC-078 | Answered B: additional public gateway discovery selected; bootstrap/custom-only A rejected. | §7.87 records reuse of passive mesh knowledge, automatic Hydra failover and a simple public read interface. B retains explicit public HTTP advertisement and private topology. Claimed minimal effort and practical all-node ingress are design expectations, not measured cost or verified universal reachability. |

| Q-O5-GATEWAY-STALE-CACHE-01 / DEC-079 | Answered A, expressly client-only; fresh-directory-only B rejected. | §7.88 records local cached fallback as app/human-money-core connection policy outside node consensus. Existing security and retry budgets remain; this does not select new node cache management, liveness rules or active background probes. |

| Q-C4-SINGLE-STATUS-ACCEPTANCE-01 / DEC-080 | Answered A: matching record alone never means paid; single-source trust B rejected. | §7.89 records mandatory14/20 proof for FINAL PoS release. This resolves the acceptance policy, not the live-read mechanism, committee authority or receipt/current-state distinction. Ordinary lookup routing versus verification scope is the next explicit question. |

| Q-C4-STATUS-VERIFICATION-SCOPE-01 / DEC-081 | Answered A: cheap default lookup plus explicit quorum-backed payment verification; universal strong-status B rejected. | §7.90 records INV-0310, read_quorum1 and targeted>=14 intent. The request parameter is not evidence; actual verifier/membership/current-state integration remains open. WF-005 bundles routine derived details rather than asking more micro-questions. |

| DETAIL-BATCH-001 / DEC-082 | Maintainer explicitly accepts DB1-01–06 as future implementation requirements. | §7.91 records free-form confirmation of the exact §7.90/chat table. No alternatives were newly posed or rejected; no authorization to change production code or binding specs is inferred. WF-005 remains active. |

| Q-C4-ACTIVE-PROOF-CONTINUITY-01 / DEC-083 | Withdrawn after explicit correction; neither A nor B selected. | §7.93 rejects the assumed need to reconstruct/archive original-quorum signatures for current clearance. Selected contract is a fresh quorum of current qualified shard-state assertions after safe sync, without weakening full-turnover serviceability. Historical §7.92 is retained as rejected reasoning, not an active storage obligation. |

### 2.3 Open design and decision inventory

These are tracked obligations, not a list of questions to ask the maintainer in
sequence. Investigate technical prerequisites autonomously. No glossary naming question is pending: DEC-049–052 settle the names and
authorize autonomous editorial maintenance (§7.27). The scoped editorial pass is complete; naming decisions do not close protocol-design
obligations. Q-S3.3-01 is parked and unanswered with unchanged A/B meanings; §7.16 records its clarified
presentation. Q-K1-FINALITY-01 is answered by DEC-053. S2.2 retains its historical 12/12
P0-SIM-1 result (§7.59); that probe-dependent profile does not verify DEC-055
passive presence. Q-S2.1-PRESENCE-01 is answered by DEC-056: three consecutive
missed gossip heartbeats (§7.62). S2.1a enforcement remains pending; broad recursive-
trust research stays stopped. Q-S3-STATELOSS-01 is answered A by DEC-057 (§7.63).
Q-S3-RECOVERY-BASIS-01 is answered A / DEC-058: quorum-backed verified
digest-pull (§7.65). Q-S3-SYNC-WRITES-01 is answered A / DEC-059 (§7.66).
Source coverage remains open. Q-S3-LATE-BUCKET-01 is withdrawn after the
maintainer rejects both options (DEC-061 / §7.67). S3.4a.3 retains the
wallet-time / live-gate / bucket integration audit. Q-S3-FRESH-COMMIT-01
(§7.68) is withdrawn by DEC-062 / §7.69: no post-gate freshness recheck or
variable seal delay; RAM-first attestation selected. Active O1.1 investigates
issued-but-unflushed own-choice recovery as a prerequisite to signing readiness.
Q-O1-CRASH-RESUME-01 is answered A / DEC-063 (§7.71); relaxation rejected.
O1.1 bounded-quarantine proof remains a technical obligation; user-directed next
decision S5.1 / Q-S5-MIXED-SUPPORT-01 is answered A / DEC-064 (§7.72).
S5.2 / Q-S5-VOID-RETENTION-01 is answered A / DEC-065 (§7.73): minimum
sufficient live evidence and own choices; no full losing-tree archive.
C1.1 / Q-C1-CONFLICT-RESPONSE-01 is answered A / DEC-066 (§7.74): inline
compact signed evidence. C2.1 / Q-C2-CONFLICT-VETO-01 is answered A /
DEC-067 (§7.75): no weaker collision veto against valid14/20. C3.1 /
Q-C3-UNCERTAIN-FOLLOWUP-01 is answered A / DEC-068 (§7.76): automatic bounded
client reconciliation. C4.1 / Q-C4-COMPLETION-EVIDENCE-01 is answered A /
DEC-069 (§7.77): bounded retrieval of original-committee approvals. C4.2a /
Q-C4-APPROVAL-RETENTION-01 is answered A / DEC-070 (§7.79): original own
approvals remain fetchable until root TTL+30s. C4.2 context/storage/wire engineering
remains pending. C3.2 / Q-C3-WALLET-SEND-DURABILITY-01 is answered A /
DEC-071 (§7.80): wallet durable intent/pending-output commit precedes first send.
C2.2 / Q-C2-POS-RECEIPT-DURABILITY-01 is answered with corrected A / DEC-072
(§7.81): durable L1 voucher/purchase before release, ephemeral live certificate
after completion. C3.3 / Q-C3-ALTERNATE-PAYMENT-01 is answered A / DEC-073
(§7.82), strictly client-side, including partial multi-voucher purchases. Active
O4.1 / Q-O4-SECOND-SIGNAL-01 is answered A / DEC-074 (§7.83). Active O4.2 /
Q-O4-DEADLINE-OWNER-01 is answered A / DEC-075 (§7.84): daemon deadline plus
longer supervisor fallback. O4.3 / Q-O4-STOP-CLI-01 is answered A / DEC-076
(§7.85), requiring actual clean completion and DB release. O5.1 /
Q-O5-METRICS-EXPOSURE-01 is answered A / DEC-077 (§7.86): operator-only metrics,
no public basic subset. O5.2 / Q-O5-GATEWAY-DISCOVERY-01 is answered B /
DEC-078 (§7.87): additional public gateway discovery. O5.2a /
Q-O5-GATEWAY-STALE-CACHE-01 is answered A / DEC-079 (§7.88), strictly client-side
bounded cached-address fallback. C4.3 / Q-C4-SINGLE-STATUS-ACCEPTANCE-01 is
answered A / DEC-080 (§7.89): matching record alone never authorizes paid/goods
release, FINAL requires verified14/20. C4.3a /
Q-C4-STATUS-VERIFICATION-SCOPE-01 is answered A / DEC-081 (§7.90): cheap ordinary
lookup and explicit quorum-backed release verification. WF-005 batches derived
details and reserves A/B for consequential choices. Active C4.3b consolidates the
technical read-evidence contract; no human question is pending. DEC-082 confirms
all six DETAIL-BATCH-001 requirements (§7.91). LRC-001 maps separate evidence
roles, shared validation, freshness and bounded collection to source gaps and
planned adversarial checks. Its live-current-state predicate and membership/
recovery premises remain unproved. No completed-receipt archive duty is reopened.
Node RAM-first remains. DEC-083 withdraws C4.3c /
Q-C4-ACTIVE-PROOF-CONTINUITY-01 after correction (§7.93), neither A nor B: current
qualified shards attest synchronized lock state; no inherited historical signature
archive, no unconfirmed outcome solely because old signers left. LRC-002 replaces
original-proof prerequisites in LRC-001. §7.95 consolidates its verifier/collector
contract, records status signing without the write-path readiness gate, and
separates replay resistance from coverage/authority proof. Active C4.3b continues
on those premises; no human question is pending.
DEC-060 refines retry policy.
Loss of the node's own signing history remains a separate gate.
Keep selected requirements separate from unresolved proof/parameter choices.

| Item | Branch | Still unresolved | Detail record |
| --- | --- | --- | --- |
| OPEN-01 | S3.3 | One-round obligations versus redesigned completion; inherited/own records, late certificates, authenticated inclusion and partial conflicts. Conditional witness bound is not an inclusion algorithm. | Q-S3.3-01; §7.5, §7.14–7.17, §7.29 |
| OPEN-02 | S1/S2 | DEC-053 selects qualified current-mesh regional committees. T01–T12 passed under probe-dependent P0-SIM-1; DEC-055 removes those probes, so passive selection needs revised predicates/scenario validation. DEC-056 selects three consecutive missed heartbeats; exact passive timing and enforcement remain pending. Broad recursive-trust research remains stopped. The human fault bound and live Argon/wire integration remain open. Competing regional receipts are allowed, not globally irreversible. | §7.35–7.44, §7.56–7.61; Q-S2.1-PRESENCE-01; DEC-053–055 |
| OPEN-03 | S3/S4 | DEC-057 answers Q-S3-STATELOSS-01 A: mandatory P2P recovery gate after restart/loss; no empty-state fallback. Active S3.4a (§7.63) must establish source continuity, scoped recovery coverage and durable activation; matching empty digests do not prove recovery. Re-scope under DEC-053: regional readiness without mandatory predecessor14, durable own-history preservation, authenticated available-state/client repair and deterministic conflict convergence. Unknown remote competing evidence is an accepted later-revision risk, not proof of global absence. Old fence/inclusion/BFT/install models remain reference evidence; local persistence/install/expiry obligations still require exact predicates and wire verification. | §7.29–7.44, §7.57; DEC-039/041/043/045/046/053 |
| OPEN-04 | C4 | Hidden-query/multiple-witness read proposal, actual evidence, authenticated random sampling, retry/missing-response semantics, accepted residual risk and goods release. DEC-069 selects bounded recovery of original approvals for exceptional uncertain-payment reconciliation (§7.77). C4.2 must establish exact context/read-only wire retrieval. DEC-070 selects original-approval retrieval until root TTL+30s (§7.79); exact storage/context/wire integration remains pending. DEC-072 removes post-completion merchant certificate custody; live-status interface remains selected, while single-node sufficiency is unproved. Ordinary INV-0310 routing stays. DEC-080 resolves release policy: no paid without verified quorum (§7.89). DEC-081 retains cheap default lookup plus targeted payment verification (§7.90). DEC-083 replaces original-proof availability with current qualified shard-state quorum after safe sync; no archival/retired-signer prerequisite (§7.93, LRC-002). Active C4.3b integrates current-state validity, freshness, current authority and purpose-separated signatures. Q-C4-ACTIVE-PROOF-CONTINUITY-01 is withdrawn, neither A/B. | §3–5, §7.1; DEC-015/017/020/021 |
| OPEN-05 | S5/S6 | DEC-053 selects potentially revocable regional acceptance. DEC-064 selects the P0 class ordering. DEC-065 selects minimum sufficient retention rather than full losing-tree archival. Complete bundles, affected descendants, the exact minimal evidence set and separate approval/observation domains still need integration/verification. Losing a regional branch is not node fraud; executable proof/wire validation, historical context and versioned integration remain pending. Green requires a separate justified global proof; baseline schemes are empty. Q-K1-FINALITY-01 is answered. | §5.4, §7.12–7.13, §7.56–7.58; DEC-022/023/048/053/054 |
| OPEN-06 | K2/C1 | Shared crate layout/versioning, signed fields, full identities, parent/output binding, splits, genesis/root TTL, batch behavior and all core consumers. DEC-066 selects inline compact conflict evidence; exact authenticated response envelope and bounds remain pending (§7.74). | §2 closing clarifications, §7.3; DEC-005/006/011–014/038 |
| OPEN-07 | C2/C3 | DEC-067 selects no minority veto; ordered collector/response integration remains pending (§7.75). DEC-068 selects bounded automatic client follow-up; exact budgets/backoff/state transitions remain pending. DEC-071 selects wallet durable intent ordering before first dispatch; DEC-072 selects durable L1 voucher/purchase before release, with no completed-checkout certificate archive. DEC-073 rejects automatic alternate payments at the client only; partial-purchase/tender handling stays outside humoco-node (§7.82). End-to-end targets, bounded retry counts/delays/horizon, handoff/NOT_READY feedback fields and actual shared transport backoff. DEC-060 now selects exact-payload conditional three-send retries; reconcile 800ms cancellation, detached-work bounds, quota/duplicate work, gateway failover and transport retransmissions. This is not a delivery/completeness proof. | §7.2.1/7.3, §7.33; DEC-008/009/027/042 |
| OPEN-08 | N1/N2/N4 | Session/stream/CPU/persistence admission limits, fairness, resource partitioning, exact full-budget refusal, tier lifecycle and receiver-side abuse defenses. | §7.2–7.2.1; DEC-024/025/028; existing project invariants |
| OPEN-09 | N3/O2 | Missing independent locks, divergent partial replicas and recovery without active clients; how readiness is justified beyond complete download/matching digest. Snapshot-bound pagination, no-gap deltas, full commitment coverage and catch-up capacity remain open (§7.31–7.32). Client resubmission is assistance, not a replacement for the DEC-057 restart P2P gate. | §7.2–7.2.1, §7.31–7.32, §7.63; DEC-026/031/032/057 |
| OPEN-10 | O1/O2 | DEC-062 permits RAM-based approval before flush; derive immutable choice/slot/context semantics, issued-but-unflushed loss detection, background durable acknowledgment, duplicate/pending operations and safe same-key resumption under DEC-032. Prior durable-before-vote model is not this crash proof. | §7.2.1/7.3; DEC-029–033 |
| OPEN-11 | O3/O4 | Safe time and choice retention, bounded expiry scheduling, drain/handler ordering and measured deployment stop deadline. DEC-074 selects idempotent repeated stop signals. DEC-075 selects an internal deadline with outer supervisor margin. DEC-076 selects verified stop completion/process exit/DB release for CLI exit0. O4 policies are selected; sizing, producer joins, clean-result transport and teardown remain engineering/validation work (§7.85). | §7.2.1; DEC-034/035 |
| OPEN-12 | O5/O6 | Private admin packaging/auth/socket permissions; operator-only metrics selected by DEC-077, exact public/private endpoint enforcement and bounded diagnostic cost pending. DEC-078 selects additional public HTTP-gateway discovery using passive mesh knowledge; advertisement/authentication/bounds remain pending. DEC-079 selects bounded cached fallback strictly on the client (§7.88). Gateway policies are selected; exact listener/admission/metadata delivery remains pending. Internal topology is not a public directory. Metric aggregation and persistence remain engineering work. | §7.2.1/7.3; DEC-002/003/036/037/040/077 |
| OPEN-13 | C4/S1 | Statistical aggregation/freshness/disagreement payment policy, provider independence, ticket/voucher grinding and quantified adversary assumptions. | §5.5, §7.1/7.3; DEC-016/018/020/021/044 |
| OPEN-14 | F1 | Complete specification/invariant/interface coverage and consolidation of contradictions before final plan. §7.78 adds a provisional map of22 numbered families/24 physical spec files and113 distinct mentioned invariant IDs; this is not item-level semantic or wire-test coverage. Real-wire verification remains a later delivery gate. | §1, §6, §8; CP-0003 below |
| OPEN-15 | K3 | Naming and scoped editorial alignment complete (DEC-049–052); ongoing autonomous maintenance, no preference questions. Protocol conflicts remain OPEN-02/03/05/06/08/09/10/14. | §7.18–7.28; glossary G-001–066 / TERM-01–13; alignment report §8 |

### 2.4 Record gaps and pending specification consolidation

- **GAP-01 — Historical provenance:** L entries retain the earlier accepted-decision
  summary, but lack original Q/A and per-item rationale. Later selections also use
  paraphrased answers. No original-chat comparison was possible from these files;
  this review cannot prove that no earlier decision was ever omitted. Do not invent
  missing alternatives, exact dates or affirmative answers. Ask only if a concrete
  missing detail affects the current design, not to replay every settled choice.
- **GAP-02 — Durability/latency consolidation:** DEC-062 / §7.69 restores RAM-first
  attestation, asynchronous persistence and the <5ms SLA, superseding DEC-029 and
  pre-response commit clauses in DEC-033/034. AGENTS.md Rule1 remains applicable.
  P0 draft0.2 §4.1 and the model still assume durable-before-vote: do not report
  their prior results as verification of the new failure model. Atomic own-choice
  retention, issued-but-unflushed loss, same-key recovery and crash tests remain
  OPEN-10. Earlier durability-selection records stay historical.
- **GAP-03 — Conflict/finality consolidation:** DEC-053 now selects potentially
  revocable regional receipts and removes the mandatory old14 handoff. Retarget
  strict CEH/global-FINAL wording and client statuses accordingly. DEC-022/023 reject unsupported takeover;
  Spec 02 and `AGENTS.md` still describe unconditional deterministic healing, and
  P0 draft0.2 proposes evidence-relative VOID and explicit support-class comparison.
  Preserve the selected safety gate; candidate predicates still need executable
  and wire validation plus deliberate versioned consolidation (§7.58).
- **GAP-04 — Read acceptance:** Spec 06's single-node-match goods-release claim is
  under review, not an accepted solution to OPEN-04. Hidden queries, reputation,
  matching digests and statistical scores alone have not been proved sufficient.
- **GAP-05 — Presence/readiness/membership:** §7.2.1 records Spec 11 versus code/view
  discrepancies, including presence timing and rank-21 promotion language. Existing
  write membership, read routing and candidate proposals must stay distinct. No
  timeout or NOT_READY permits committee replacement; see DEC-027 and OPEN-02/08/09.
- **GAP-06 — Implementation evidence:** Legacy code findings are dated static
  observations, not current executed verification. Interview-selected changes have
  not been implemented/tested here. Do not mark branches delivered or derive a
  completion percentage from the register. Full coverage is still OPEN-14.

### 2.5 Inherited constraints and workflow records

Existing binding rules are not new interview decisions. Preserve `AGENTS.md` and
the applicable specifications, including frozen at-most-20 distinct full-key checkout
membership, 14/20, eligible self vote, adaptive N < 20 quorums, neutral quorum-cancelled
work, F2F-only gossip, learned-peer shard RPC, first-party-only fraud penalties,
reservation-before-RAM, bounded parsing, trusted time, root expiry plus 30 seconds,
no tombstones and real adversarial QUIC verification. Consolidation gaps above do
not silently modify those files or establish a safe membership transition.

- **WF-001 (CP-0001):** durable two-file memory, create only missing files, preserve
  decisions, compact tree/targeted reading, exact pending question and saved next action.
- **WF-002 (CP-0002):** finish one bounded problem, justified A, useful alternatives
  only, explicit uncertainty and one substantive human decision question at a time.
- **WF-003 (CP-0003):** migrate existing records into stable IDs/status/provenance;
  preserve historical derivations and distinguish selected, reopened, tentative and open.
- **WF-004 (CP-0053):** maintainer requests A and B for each interview decision,
  with proposals and a recommendation. Keep factual uncertainty explicit; an option
  selection is not a safety proof. This updates the earlier no-fixed-option-count
  presentation preference, not any accepted protocol requirement.
- **WF-005 (CP-0079):** maintainer requests faster grouped treatment of small details:
  present a short problem/obvious-solution list, derive routine consequences from
  existing decisions autonomously, and keep individual A/B for important choices.
  This refines WF-004; do not invent micro-questions or treat a proposed new policy
  as accepted because it appears in a batch. Unresolved proof obligations stay open.

The maintainer emphasized that locks form a chain, or a branching graph when vouchers
split. Each accepted lock must be causally authorized by the correct predecessor/output;
an arbitrary collection of individually signed entries is insufficient. Exact output
binding and causality verification must be checked against the core reference rules.
Mixed-branch batch processing is outside the selected reconciliation scope.

Metric history is aggregate operational telemetry, not retention of expired transaction
records. Preserve automatic deletion of expired locks. Historical metric retention does
not authorize keeping expired vouchers or permanent lock tombstones.

## 3. Original read-safety problem

An incoming payment refers to a particular predecessor/spend slot and candidate lock A.
A receiver asks the registry whether that lock is secured. A single node returns a lock
whose transaction and owner signature are valid.

Distinguish these claims:

| Evidence | What it can establish | What it does not establish by itself |
| --- | --- | --- |
| Valid owner signature, with verified causality and binding to the queried slot | The authorized owner signed this specific spend. | Acceptance by the required shard quorum, current canonical state, or irreversible finality. |
| A node returns the complete valid lock without receiving the expected transaction in the query | The responder possesses that signed lock. | How it obtained the lock, whether it participated in acceptance, or whether other nodes confirmed it. |
| Authenticated, request-bound node response | That node made that response for this query. | Truthfulness, completeness, or absence of a conflicting confirmed branch. |
| Two valid, divergent owner-signed spends of the same slot | Owner double-spend evidence, provided authorization and exact slot binding are verified. | Which branch obtained a quorum, automatic proof of node equivocation, or compensation for a receiver's loss. |
| Single-node absence response | That node reports no matching local record. | That the slot is globally free or cannot race with another spend. |
| Quorum certificate | Specified members attested the bound statement, if membership and signature checks succeed. | A justified historical membership set or safe future committee transitions unless separately established. |

Finding a valid alternative lock B is therefore significant first-party evidence when
combined with A, but deciding the canonical winner and establishing registry acceptance
are separate questions. Different nodes returning different locks is not automatically
evidence that either node double-signed. Preserve the Anti-Hearsay Principle.

The maintainer highlighted that write requests collect fresh signatures, whereas reads
may not carry the original certificate and shard membership changes over time. A fresh
write certificate also needs a justified committee and state-continuity rules; it does
not independently solve reconfiguration or different local membership views.

## 4. Maintainer's proposed direction — preserve this context

The maintainer wants to investigate a solution without depending on historical per-lock
quorum certificates at read time:

- The receiver knows its own voucher and expected lock, but does not disclose all of that
  information to the node network. It asks the responder to produce the lock itself.
- A malicious node cannot manufacture the authorized owner's signature.
- If a different genuine lock exists, the owner must have authorized a conflicting spend;
  detection and real-world identity/reputation consequences may deter this behavior.
- The receiver chooses and distributes queries over multiple shard nodes. The payer
  should not be able to force the receiver onto the payer's compromised nodes.
- With, for example, three compromised nodes among twenty, random independent selection
  may make successful deception unlikely.
- Generating a voucher for a favorable shard and accumulating compromised shard identities
  may add significant attack cost. This cost is a hypothesis to quantify, not an established
  security bound.
- A previously considered gateway mechanism occasionally cross-checks a response against
  another shard node to discover inconsistencies.

Do not dismiss this direction solely because it does not carry historical certificates.
Analyze exactly what the hidden query and returned lock prove, and whether a useful
probabilistic or deterministic read protocol follows under explicit assumptions.

## 5. Challenges identified, not yet resolved

### 5.1 Colluding payer and nodes

Hiding A from the read request prevents an unrelated responder from inventing it, but
the malicious payer already knows A and can share it with cooperating nodes before the
query. Possession alone is not quorum acceptance. A node can also possess a lock from
earlier traffic without ever having confirmed it.

Audit query fields, locator prefixes, genesis queries, and observable prior traffic to
determine what is actually hidden. Do not assume a formal knowledge proof or privacy
property without defining and verifying it.

### 5.2 Honest nodes can also hold an unconfirmed conflicting lock

Illustrative scenario in one fixed, common committee of twenty, before complete sync:

| Nodes | State/behavior |
| --- | --- |
| 11 honest | Attested B and retain B. |
| 6 honest | Received A first and retain A; do not yet know B. |
| 3 Byzantine | Also attested B, but answer the reader with the valid owner-signed A. |

B has fourteen write signatures. Nine nodes can return A, although A has not obtained
the write quorum. This is a hypothetical placement demonstrating an assumption gap,
not an empirically measured frequency or a completed wire-level exploit.

For k distinct uniformly sampled nodes, an acceptance rule requiring every selected
node to return A can miss B with probability C(9,k) / C(20,k) in this scenario.

| k | Probability all samples come from the three Byzantine nodes only | Probability all samples come from the nine A-returning nodes in the scenario |
| --- | --- | --- |
| 1 | 15% | 45% |
| 2 | 1.578947% | 18.947368% |
| 3 | 0.087719% | 7.368421% |
| 5 | 0% | 0.812693% |

These are conditional calculations with uniform selection without replacement, an
unchanged shared committee, and no retries that discard unfavorable results. They are
not general failure probabilities for HuMoCo. The protocol's maximum allowed Byzantine
count, repeated attack attempts, lagging nodes, and churn must be considered separately.

### 5.3 Selection, authentication, and timeouts

A candidate sampling protocol needs receiver-controlled fresh randomness, distinct
authenticated `NodePubKey` identities, and a justified eligible node set. A malicious
gateway must not choose all witnesses. Deterministic selection by a caller-influenced
tag is not fresh independent sampling.

Request-bound signed responses can prevent response transplantation/replay but do not
make an old lock current. Missing responses, absent records, and disagreement must have
explicit semantics. Retrying until favorable answers appear invalidates a simple sample
bound. Eclipse attacks and local membership views remain relevant.

### 5.4 Committee changes and finality

Current members may lack an old lock unless state transfer guarantees continuity.
Sampling many honest current members does not repair a committee that never received
the relevant prior state.

Potential approaches discussed, none agreed:

- Client-held historical certificates, authenticated historical membership, and safe
  committee transitions.
- Fresh current-state attestations, without retaining each historical certificate on
  every node, still with justified membership and state transfer.
- Receiver-selected probabilistic reads with a quantified residual conflict risk.
- A certified handover binding old/new committees and transferred active state, with
  explicit old/new signing rules and loss of FINAL availability if handover cannot be
  established. This is a candidate design, not a complete safety proof.

The specification currently both promises irreversible FINAL and allows FINAL to become
VOID after partition merge. Deterministic min(H_canon) convergence alone does not prove
that a past accepted payment cannot be reversed.

### 5.5 Economic deterrence and shard targeting

Owner double-spend evidence and real-world consequences can deter fraud, but do not
mathematically prevent a receiver's initial loss. Audit identity linkage, enforcement,
repeatability, and attacker benefit before relying on this economically.

Canonical shard selection uses sixteen bits of the genesis parent anchor. If an attacker
can freely vary valid genesis candidates and each produces a uniformly distributed shard,
targeting a specific shard takes about 65,536 candidates in expectation. Actual candidate
cost depends on `human-money-core` issuance/validation rules, which have not been audited
in this interview. Argon2d node-ticket cost is distinct from voucher-root generation cost.

## 6. Repository observations and specification references

References describe the files inspected on 2026-10-13; re-check them before implementation.

- [Spec 03](03_routing_und_sharding.md), INV-0310: random Top-20 status routing and timeout
  failover. Section 3.1 expressly leaves safe membership transition/state continuity open.
- [Spec 06](06_dumb_server_smart_client_flow.md), sections 3.1 and case 1: a matching,
  owner-signed single-node reply is treated as grounds for immediate green goods release.
  This is the central safety claim to revisit. An optional two-server check is described.
- [Spec 10](10_p2p_wire_format_und_session_framing.md), section 5: prior auditor sampling
  concerned ingress traffic declarations and was removed. Do not confuse this with a
  specified read-response audit protocol.
- [Spec 02](02_lock_zustandsautomat_und_konflikte.md): FINAL irreversibility claims versus
  the FINAL-to-VOID merge transition need reconciliation.
- [`api/hmc.rs`](../crates/humoco-node/src/api/hmc.rs): `L2StatusQuery.read_quorum` defaults
  to one; `L2ResponseEnvelope` has an optional quorum certificate.
- [`api/routes.rs`](../crates/humoco-node/src/api/routes.rs): status fallback chooses one
  candidate deterministically from the tag hash. Additional signatures are collected when
  `read_quorum > 1`. Their existence is not a completed read-safety proof.
- [`storage/engine.rs`](../crates/humoco-node/src/storage/engine.rs): HMC status queries
  return locally held entries as `Verified`. `RamIndex`/`LockRecord` and `HmcRamIndex`/
  `L2LockEntry` coexist. Their production dependencies need consolidation review.
- [`network/transport.rs`](../crates/humoco-node/src/network/transport.rs): the production
  LockVerify path explicitly rejects simulator and legacy raw-tuple write formats.
- [`types.rs`](../crates/humoco-sim-core/src/types.rs): shard derivation and genesis-anchor
  helpers are relevant to voucher grinding and consistent routing.

No complete gateway read-response sampling mechanism was found in the inspected
production paths. `FLAG_HEDGED` exists as a wire constant; that alone does not establish
an implemented or proven two-node verification defense.

## 7. Research consulted

- [Probabilistic Quorum Systems — Malkhi, Reiter, Wool, Wright](https://reitermk.github.io/papers/2001/IC.pdf):
  probabilistic intersection, including Byzantine servers and self-verifying data.
  Useful basis for examining the maintainer's sampling proposal; not proof of this design.
- [Sui Lutris](https://arxiv.org/abs/2310.18042): a fast agreement path with a separately
  analyzed reconfiguration protocol.
- [Sui full-node documentation](https://docs.sui.io/operators/full-node/sui-full-node):
  quorum-signed checkpoints and committee information from the previous epoch.
- [Tendermint light-client documentation](https://docs.tendermint.com/v0.34/tendermint-core/light-client.html):
  verified commits/state proofs, an initial verification anchor, and witness cross-checks.
- [FastPay](https://sonnino.com/papers/fastpay.pdf): clients assemble transfer certificates
  and provide them to recipients. Its funded account model is not HuMoCo's blind registry.

These projects use different membership, identity, economic, and fault assumptions.
Do not import staking, account state, or their guarantees into HuMoCo by analogy.

## 7.1 Committee-view discussion during the resumed interview

The maintainer asked what actually goes wrong when network views differ, whether a
legitimate committee can be proved at all, and whether gateway incentives plus ticket
statistics could provide an adequate practical solution. Preserve these considerations:

- A gateway serving paying customers has incentives to remain reliable and earn future
  revenue. Clients may deliberately choose reputable providers, including Free-tier
  providers. The maintainer does not want unnecessary consensus machinery solely because
  gateways could theoretically misbehave.
- Clients may use HRW ticket/score statistics to assess whether supplied signers plausibly
  belong to the shard. Targeted Argon2d ticket grinding may be costly, especially as the
  network grows. Quantify the assumptions rather than treating that cost as infinite.
- Distinguish valid signatures/tickets and score calculations from completeness of a
  participant set, unique authorized membership, independent operators, and state continuity.
- Different views can cause availability loss or incompatible successful certificates.
  In an extreme disjoint-committee scenario, two partitions can each obtain fourteen
  signatures on different owner-signed spends without any node double-signing. Later
  deterministic convergence does not undo goods released based on the losing branch.
- Spec 03 section 2.1 explicitly treats normalized quantiles and Bloom filters as
  discovery hints, not membership proofs. It leaves globally consistent discovery and
  safe committee transitions as separate obligations. Replacing this with statistical
  acceptance would be an explicit protocol/security-model change, not an implemented
  or already proven defense.
- A gateway's own network-size estimate, roster, and claimed maturity cannot independently
  authenticate their own correctness. Statistical risk bounds need an attacker model,
  independent estimation assumptions, ticket grinding analysis, and voucher-root targeting.
<a id="evidence-dec-015"></a>

- Proposed direction, not agreed: separate cryptographic evidence, probabilistic confidence,
  and provider-selection incentives. The maintainer subsequently agreed that Free/Friends/
  VIP use the same cryptographic verification and payment changes resource priority/SLA,
  not the truth of an attestation. The specific membership/security model remains open.
- A complete global participant list cannot be inferred from isolated local messages.
  Conditional membership proofs may be possible relative to an authenticated protocol
  snapshot and a justified transition/bootstrap rule. The specific mechanism is not chosen.

Additional reference: [Stellar quorum configuration and intersection](https://stellar.org/blog/developers/why-quorums-matter-and-how-stellar-approaches-them).
Its relevance is the explicit dependence of safety on quorum configuration and honest
intersection, not a proposal to replace HuMoCo with Stellar's ledger or trust model.

<a id="evidence-dec-016"></a>
<a id="evidence-dec-017"></a>
<a id="evidence-dec-018"></a>

The maintainer agreed that the attacker model allows a malicious voucher owner, gateway,
and controlled shard nodes to coordinate, and that recipients select their own gateways
and verification sources. Do not treat attacker behavior as independent random faults
or confuse distinct public keys with independent operators. The maintainer also agreed
to one active/one pending ticket per identity with reset incubation on replacement and
emphasized the existing stronger-work requirement for each replacement.

Repository inspection found the strict comparison against both active and pending scores
and pending-time reset in `PeerManager::learn_node_from_gossip_with_hrw_and_work`, and
corresponding direct-manager tests in `spec_07_pow_headroom_and_monotonicity_tests.rs`.
Tests were inspected, not run; complete adversarial QUIC verification is not established.
`compute_work_from_hash` derives W from the Argon2 proof prefix, while the routing ticket
is separately whitened before shard scoring. Do not equate larger W with a guaranteed
larger HRW score for a specific shard, or claim measured physical work from one hash.

<a id="evidence-dec-019"></a>

The ratchet constrains one identity, not unlimited fresh public keys or private candidate
searches. The maintainer agreed that fresh keys cannot inherit friendships or ticket
maturity and emphasized the human effort of obtaining renewed friend approval as a fraud
deterrent. This is not an unconditional proof against Sybils: Spec 07 allows activation
through one F2F friendship, and an attacker-controlled friend can approve multiple keys.
Human approval cannot be inferred from a signature or used to prove independent operators.

<a id="evidence-dec-020"></a>
<a id="evidence-dec-021"></a>

The maintainer selected multiple recipient-chosen, background-refreshed and cached sources
for network-size observations. Even multiple sources do not prove independence or global
completeness. The maintainer agreed to treating strong disagreement as unresolved,
checking freshness/network context, and seeking additional information rather than
silently producing a precise statistic. Payment policy in this case is not decided.
Such telemetry disagreement is not node-equivocation evidence or authority to ban peers.
Ticket authorization, maturity proof, safe committee changes, and statistical bounds
remain open.

The next merge/slashing question concerns an honest node that attested provisional A
and later learns genuine conflicting owner-signed B that wins min(H_canon). May it issue
an explicitly defined provisional revision without being banned, or must its original
vote remain immutable? This question concerns a new attestation, not merely storing the
canonical winner. No revision policy is agreed yet. A proposed legal revision cannot be
created merely by changing a timestamp or declaring a new epoch; FINAL continuity and
forbidden double-commitment rules must remain explicit.

Inspection found that `verify_equivocation_first_party` in the transport checks genuine
signatures on differing locks for the same parent and tries provisional/final as well as
Mainnet/Testnet domains separately. Before enabling any revision policy, audit exact
network, status, slot, and transition scope to avoid penalizing lawful behavior or letting
an offender evade penalties. This is an open review concern, not a tested exploit. Also
keep owner double-spend evidence separate from a shard node's own contradictory votes.

The maintainer considers conflicting village branches rare and economically unattractive,
especially after convergence into one large network. They asked whether to ignore this
case or pragmatically adopt the other lock without a new signature, possibly based on
shard majority. Frequency and attacker benefit have not been measured. Distinct F2F
network views do not necessarily imply geographically inaccessible public client ingress.

Earlier minimal proposal, not agreed and subsequently challenged: do not introduce a
provisional vote-revision protocol yet. On a genuine provisional merge, verify conflicting
owner evidence and use the existing canonical resolver to adopt the winner as registry
state, preserving the node's prior
accepted signing choice for the same spend slot until root expiry. The node must not issue
a new incompatible commitment just because its stored state changed. A status observation
can return the canonical owner's signed lock and an authenticated observation response,
but it must be cryptographically distinct from a write/commitment vote. This may reduce
available confirming votes; it does not prove immediate liveness or solve committee changes.
Bare majority reports are not a replacement for verified evidence, canonical resolution,
or an authorized quorum. No decision about overwriting FINAL is implied.

Implementation concern: the QUIC `StatusQuery` path currently calls the same
`create_attestation_for_network` helper as write votes for matching records. Audit and
separate observation versus commitment semantics before assuming that "read only" cannot
create contradictory node votes. The HTTP response envelope signs its verdict separately,
but that does not establish a complete, request-bound, domain-separated observation protocol.
Retaining old signing choices across asynchronous persistence/crashes needs phase-5 review.

<a id="evidence-dec-022"></a>

Maintainer correction: a node must first establish that the other lock has sufficient
shard support. The majority must not adopt a minority/single-node lock simply because
its hash is smaller. The prior suggestion of canonical state takeover based only on
genuine owner conflict evidence was too broad and is withdrawn as a sufficient admission
rule. Owner authorization proves a candidate is authentic, not that it was accepted by
the registry. Canonical ordering must not create its own endorsement through sync and
subsequent reads/attestations.

Clarify whether "majority" means the existing authorized 14/20 quorum or merely more
than half. Recommend preserving the existing 14/20 threshold for an authoritative
decision at N >= 20; the adaptive provisional and legitimate-partition merge case still
needs a separately justified rule. If neither branch has sufficient support, leave the
decision unresolved rather than manufacturing a majority by overwriting first. Do not
silently overwrite a conflicting existing FINAL proof; conflicting qualified proofs
require analysis of membership/context and the unresolved finality rules.

Required real-QUIC tests for the future selected policy:

- In a fixed twenty-member scenario, a single learned peer supplies a genuine owner-signed
  conflicting B with H(B) < H(A), but no sufficient support. Established A must remain;
  no new incompatible commitment may be generated and B must not become FINAL.
- Repeated delivery or relaying of the same B must not manufacture independent support
  or trigger cascading state replacement.
- Invalid support proofs, duplicate signers, non-members, wrong slots/networks, and
  stale/unauthorized committee contexts must not authorize takeover.
- One peer transporting a genuine sufficient multi-signer proof must not be rejected
  merely because there was only one transport source. Exact authorized takeover behavior
  depends on the selected provisional/finality/transition rule.
- Split support without the required quorum must remain unresolved. Separately cover
  adaptive provisional committees and legitimate merging partitions once their rule is chosen.

Existing inspected tests include direct-engine cases expecting min(H_canon) replacement
under PartitionSync. They are not evidence of this new defense and need reconciliation
with the selected policy. No implementation or new wire test has been written or run
in this interview.

The maintainer reiterated the central requirement: a malicious node must not insert a
new conflicting lock in a way that displaces the established registry state. Distinguish
the unavoidable possibility of arbitrary contents in a Byzantine node's own storage from
acceptance by honest replicas/clients. The defense must prevent unauthorized promotion,
overwrite, and amplification at those honest boundaries.

Proposed conservative decision framework, not agreed yet:

- Distinguish an unconfirmed candidate, a provisional confirmation, and a justified FINAL
  commitment. Keep the evidence supporting that classification, not only a mutable label.
- A conflicting candidate delivered by one node does not authorize state replacement.
- A previously justified FINAL commitment is not overturned by a smaller hash or a later
  raw majority. Two incompatible qualified FINAL proofs are a safety incident, requiring
  membership/transition analysis rather than automatic min(H_canon) resolution.
- Within one justified current committee, use the existing quorum: 14/20 for federated
  operation and floor(2N/3)+1 for N<20. Count authenticated bound commitments, not storage
  copy counts or reports of third parties. The membership and transition obligations
  remain unresolved and cannot be supplied by count arithmetic alone.
- A provisional merge where neither candidate has the required justified support remains
  unresolved; preserve evidence/state and avoid incompatible new commitments. Non-conflicting
  slots continue normally. This trades conflict-specific liveness for safety and does not
  promise eventual convergence without an additional proven recovery rule.

Illustrative small-network values: Q(3)=3, Q(5)=4, Q(8)=6, Q(12)=9. In a justified
eight-member committee, support of five for A and three for B does not reach six for
either. Historical certificates from separate islands cannot simply be added together
as if their contexts were one newly authorized committee. Do not switch the eligible set
mid-request or treat a later count estimate as an authorized membership transition.

<a id="evidence-dec-023"></a>

This framework exposes a real tradeoff: unconditional immediate deterministic healing,
non-displacement of confirmed locks, and a majority prerequisite cannot all be asserted
without defining what happens when conflicting groups have no sufficient common support.
The maintainer agreed to prioritizing safety and leaving the conflicting slot unresolved
instead of forcing a winner, accepting that a voucher may remain unusable in the believed
rare case. Clarify that the block concerns the disputed slot and dependent descendants,
not unrelated split branches or all vouchers. A legitimate, late, sufficiently justified
certificate can be checked and may resolve uncertainty; a permanently split signing
set is not guaranteed to recover. Membership changes alone, resubmission with another
identifier, elapsed time, or min(H_canon) must not bypass evidence requirements.

No simple universally safe recovery mechanism was established in the interview. Safe
committee handover and authenticated historical evidence remain possible research/design
paths, not solved remedies. Client custody can retain evidence without permanent expired
lock tombstones on nodes. Ordinary root expiry still physically removes expired state.
A failed statistical estimate, delayed evidence, and a proven causal double spend need
distinct handling; none authorize an arbitrary new conflicting lock.

The interview can continue to P2P scaling while keeping membership authorization,
statistical bounds, observation/vote separation, and exact merge recovery as explicit
open design/proof obligations. The final master plan must not declare them solved.

## 7.2 P2P scaling and missed-delivery discussion

The maintainer asked whether a node's maximum co-shard neighbor count near N=5,000 can
be estimated and used to size connections, and whether shard replicas need to coordinate
when some never receive a gateway's lock request. They recalled a peak near this network
size. Do not interpret N=5,000 as a maximum supported network population.

Separate possible co-shard neighbors, open QUIC sessions, concurrent RPC streams, incoming
gateways, and outgoing gateway-to-committee requests. One connection can serve multiple
streams and shards. Checkout is gateway-to-shard only, with no blocking shard-to-shard
agreement or lock gossip. Background state reconciliation is separate traffic.

Under independent uniform HRW rankings across S=65,536 shards with R=20 and N=5,000:

- Expected owned shards: S*R/N = 262.144.
- Pairwise co-membership probability per shard: R*(R-1)/(N*(N-1)).
- Expected distinct co-shard peers: (N-1)*(1-(1-R*(R-1)/(N*(N-1)))^S), approximately
  3,153. These are model expectations, not hard adversarial maxima or session-capacity
  guarantees. Possible peers at N=5,000 can reach N-1; gateway routing can additionally
  contact peers without co-shard membership.

Size session/stream budgets using a workload model and load tests, including concurrent
checkouts, reuse, arrivals from other gateways, background sync, idle retention, F2F
sessions, and cold connection bursts. A conservative outgoing bound for K simultaneous
requests to disjoint twenty-member committees is 20K sessions before reuse; it is not
a bound for the whole node. The 128-256 candidate LRU size has not been validated here.

Missed lock delivery is a safety/liveness issue, not merely a connection-sizing detail.
Spec 03 describes digest-first pull with a quorum-supported target digest; the daemon
has a periodic 60-second run and topology-triggered runs with a 5-second debounce.
Digests reveal differences, not which state is authoritative. Fourteen write votes do
not automatically imply fourteen replicas have identical complete shard sets across
multiple partially delivered writes. Verify recovery under differing partial sets,
ongoing writes, quorum fast-exit cancellation, and invalid minority data over real QUIC.
Do not claim the existing motor proves complete convergence without these assumptions.

Implementation observation: the inspected TLS builders configure 15-second idle timeout
and a 5-second keep-alive for the shared configurations. That does not demonstrate the
specified F2F-only keep-alive / ephemeral shard-direct separation. Verify actual tier
selection and enforce a bounded session lifecycle before declaring LRU behavior complete.

The maintainer accepted reserving capacity for checkout work while giving background sync
a separate bounded budget with enough capacity to make progress. This does not approve
particular pool sizes or a pool-full policy. Admission, concurrency limits, active-session
handling, and fairness remain open, including connection/stream/CPU/disk-queue contention.

### 7.2.1 Capacity clarification in the continuation chat

The maintainer requested a distinction between ingress quotas/PoW adaptation and local
resource capacity. They consider brief gateway unavailability acceptable and prefer
protecting shard service; operators selling gateway access must provide sufficient
gateway resources. Their spoken "Chat-Knoten" is interpreted as "shard node" in this
context, not as a new node role.

The preceding overload question concerned simultaneous local work (RPC streams,
connections/handshakes, verification CPU, bounded persistence-queue admission), not an
outgoing traffic allowance. Gateway orchestration, inbound shard verification, and
background synchronization compete for resources when hosted in one process/machine.
Ingress tiers and adaptive PoW regulate admission pressure but do not replace these
hard resource bounds. Inbound shard-server enforcement must also protect against
authorized peers that ignore sender-side limits.

Clarify the intended allocation before selecting a queue policy: gateway-originated
work must not exhaust resources needed for inbound shard requests, while background
sync retains the already agreed bounded progress budget. This allocation is a design
recommendation; exact limits, fairness, and queue behavior are not yet agreed. The
maintainer has not selected the proposed immediate-rejection policy merely by asking
for this clarification. A gateway timeout continues to mean an uncertain payment
outcome and permits only bounded retries of the same signed intent.

<a id="evidence-dec-024"></a>
<a id="evidence-dec-025"></a>

The maintainer then accepted continuing on this clarified basis: limit locally
originated gateway work to protect inbound shard service, with the previously agreed
bounded background-sync progress budget. This agrees the resource-separation direction,
not numerical limits or an exact overload response/queue policy. The next question
addresses shard-direct session eviction: reclaim idle sessions first, preserve active
RPCs, and reject/defer new work if its applicable budget has no reclaimable capacity.
F2F persistent sessions are a separate tier, not ordinary shard-direct LRU entries.
The maintainer explicitly approved this lifecycle/overload policy. Active-request
protection concerns capacity eviction; it does not disable quorum fast-exit cancellation,
request deadlines, protocol/security enforcement, or graceful-shutdown policy. Reuse
an existing connection where its stream/work budget permits. Numerical limits and
resource fairness remain open.

<a id="evidence-dec-026"></a>

Next discuss missed lock delivery and shard signing readiness. A restarted or newly
assigned node must not interpret an empty/incomplete local index as proof of a globally
free slot. Recommend gating write votes per affected shard until justified state recovery
is established, with NOT_READY as a neutral response. The exact recovery/readiness
evidence and safe committee transition are unresolved; merely completing a pull or
receiving matching digests does not establish these guarantees. This recommendation
was approved as a signing gate and must not imply that every routine digest mismatch
disables an otherwise established shard replica. The maintainer expressly challenged
the proposed neutral availability treatment: a peer could lie about NOT_READY, so it
should affect local assessment like a nonresponse. Do not record unqualified agreement
to neutral NOT_READY scoring. Existing repository instructions say NOT_READY is neutral;
any agreed change requires explicit later reconciliation of that rule and tests.

Proposed distinction for the next answer, not yet agreed: NOT_READY supplies no vote
for the current frozen committee and triggers immediate attainable-quorum recalculation.
Repeated inability to serve may justify bounded, local, preferably shard-scoped retry
backoff with recovery probes, without proving deceit or authorizing identity revocation,
WoT severance, or network-wide failure gossip. Backoff must not replace unavailable
committee members with lower-ranked identities or manufacture an eligible committee.
Absence of a readiness vote is not evidence that a slot is free. A timely NOT_READY
reply differs from a timeout in reachability, despite both being unavailable for that
write. Exact scoring/backoff parameters remain open. Direct observed service outcomes
must be distinguished from non-authoritative diagnostic telemetry.

The maintainer approved this NOT_READY/backoff distinction and emphasized that committee
departure after prolonged absence differs from banning a proven fraudster. Clarify that
long absence is locally observed lack of fresh presence, not proof of globally being
offline, and that safe future committee changes remain an open proof obligation.

Targeted follow-up inspection (no tests run) found a consolidation discrepancy:
Spec 11 describes DORMANT after approximately 21-24 hours with at most three presence
bits and physical deletion after 48 hours. `manager.rs` instead defines
`PRESENCE_FRESHNESS_TIMEOUT` as two hours, and `active_known_nodes` filters gossip-learned
entries by that freshness as well as maturity and local suspension. Direct peer entries
follow a different branch. `KnownNodeInfo::is_hrw_eligible` itself checks only maturity.
Do not claim one consistent prolonged-offline membership rule has been verified.
Spec 11 also retains rank-21 promotion language contradictory to the frozen checkout
committee rule in Spec 03/AGENTS.md. Offline thresholds or local suspension do not by
themselves prove state continuity or safe committee transitions.

Next proposed local recovery rule, pending: bounded retry opportunities remain possible;
a genuinely successful shard verification clears its local service backoff, whereas
heartbeats or a timely NOT_READY alone do not demonstrate restored verification service.
Clearing service backoff does not establish readiness evidence, ticket eligibility,
or committee membership. Heartbeat forwarding must retain the F2F/anti-hearsay rules.

The maintainer challenged whether additional checks improve matters when every node
has its own committee view. The proposed successful-service reset rule is not approved.
Clarify that bounded retries can reuse ordinary subsequent RPCs; no new membership
probing or committee-validation subsystem is implied. Recommend keeping local service
backoff separate from the eligible identity roster and using a normal later request
after cooldown, without extra periodic service probes. This simplification is pending.
Neither successful service nor a heartbeat authenticates a shared committee view.

Further inspection qualifies the preceding presence findings: production write collection
in `api/routes.rs` calls `PeerManager::shard_committee`, which selects from mature,
non-banned locally known identities without filtering local suspension or two-hour
presence freshness. Thus the filtered `active_hrw_nodes` view must not be described
as the current write electorate; it is used by reads and other paths. The write helper's
comment explicitly disclaims global agreement. Differences in locally learned identities,
maturity observations, bans, and ticket state still require membership/transition review.
The write collector currently groups NOT_READY with neutral NotInShard handling; the
agreed future backoff policy needs to separate these outcomes. No code changed or tests run.

The maintainer further challenges whether gateway checkout backoff is useful at all:
simply request every authorized committee member for each payment, rather than maintain
extra offline tracking/probes. This is not yet approval to remove all P2P failure handling.
Recommend this simpler default for checkout writes: one application-level attempt per
remote member per admitted request, parallel fanout within reserved budgets, no lower-rank
replacement, and existing quorum/impossibility/deadline exit. Protocol-level QUIC
retransmission is distinct from application retries. Performance comparison is unmeasured;
a failed attempt may involve a cold handshake, retransmissions, and task/connection state,
not literally one packet. Aggregate costs need representative load measurements before
adding a specialized checkout suppression/reconnect policy.

Inspection confirms the current write collector's initial_spawns covers all supplied
committee candidates (`api/routes.rs`); `Transport::connect_peer` nevertheless applies
a reconnect-backoff sleep from shared peer state. Thus all-candidate fanout does not
prove checkout is free of backoff delays. No change is implemented. The newly proposed
simplification would amend the earlier NOT_READY/timeout backoff decision for checkout
dispatch only. Keep resource admission, receiver-side abuse limits, F2F behavior,
background-sync rules, and identity sanctions distinct. The main agent's earlier
recommendation for an additional checkout backoff/probing mechanism is withdrawn as
a necessary default absent measurements; the maintainer's choice remains pending.

<a id="evidence-dec-027"></a>
<a id="evidence-dec-028"></a>

The maintainer explicitly approved the all-member checkout dispatch default and requested
recording the remaining resource tradeoff. This supersedes earlier approval of local
NOT_READY/timeout backoff for checkout dispatch. Keep existing decisions concerning
non-checkout P2P behavior separate; do not remove all peer defenses as a consequence.

Measure failed attempts using representative cold/warm connections, partially offline
committees, concurrent checkouts, and recurring overload: handshake/cryptographic CPU,
packet/byte volume including transport retransmission, task/timer/buffer RAM, session/
stream/socket occupancy, and collection/tail latency. Distinguish those from disk capacity:
an unreachable remote member does not itself cause a local lock persistence write, though
repeated accepted requests and shared resources may still create contention. Quantify
how long resources remain occupied after quorum/deadline cancellation and whether those
costs impair inbound shard verification or the agreed background-sync progress budget.
Compare any future suppression's state/timer/logic overhead, delayed recovery and reduced
quorum availability against the savings. Preserve the option of a simpler KISS suppression
idea discovered later; no new subsystem is required merely to keep that option open.

Next discuss missed-delivery convergence: fourteen votes on each individual lock need
not produce fourteen identical whole-shard digests. The existing matching-digest sync
rule must be checked against divergent partial sets. Keep support authentication and
state readiness as unresolved proof requirements, not solved by digest arithmetic.

The next sync example used independent locks A and B in the same shard: eight nodes
hold both, six only A, six only B. Each lock can have fourteen votes in one common
twenty-member committee, but no complete shard set is held by fourteen nodes. This
is missing delivery, not a double-spend conflict; both entries belong in the converged
state if their supporting evidence is justified. Readiness/sync mechanisms must not
select one independent entry as a winner over the other.

The maintainer related this to the earlier unresolved merge and suggested clients
resubmitting their locks may yield a shard majority. Preserve this as their proposal,
not an agreed new rule. Clarify: the agreed conflicting-slot policy leaves the slot
and its descendants unresolved without sufficient justified authenticated support;
first completion, raw storage-copy majority, and smaller hash do not authorize takeover.
In one justified twenty-member checkout committee, fourteen distinct bound votes are
required, not merely eleven copies; eight plus five votes is thirteen, not fourteen.
Support counts across unrelated historical/partition committees cannot be added without
safe authority/transition rules. No new provisional merge threshold was chosen here.

Client resubmission can aid delivery and preserve accepted valid-prefix progress, but
cannot force an honest node to issue an incompatible vote or manufacture quorum from
unqualified copies. Background sync must still be reviewed when clients are inactive,
and as preparation for safe state recovery and committee changes. The prior recommendation
to require progress across divergent partial sets remains pending; supporting-evidence
representation and safe transitions remain open. No implementation or test run.

The maintainer emphasized the natural wallet incentive to preserve locks/funds and
wants to revisit whether additional healing or majority rules can repair missing
state later. Record client resubmission as useful assistance and the recovery/support
design as open. Their answer does not approve a raw-majority conflict takeover, a
new threshold, or a proof that autonomous sync is unnecessary. Preserve this research
branch for later agreement; do not declare Phase 4 proof obligations complete.

The next operations question concerns crash-safe signing, more specific than recovery
of confirmed registry state. Inspection of `storage/engine.rs` shows accepted HMC entries
queued with `permit.send(FlushOp::PutHmcLock)` and the ingress method returning without
a per-entry durable-commit acknowledgment. The write handler in `network/transport.rs`
then creates an attestation after that return. The background batch interval is 50 ms
with a 100-op batch bound; these are implementation settings, not a guaranteed loss
window. No power-loss/restart test has been run. Do not equate queue reservation with
durability or assume ordinary redb recovery restores uncommitted RAM decisions.

Scenario to discuss: a node signs A, crashes before persistence, restarts with the same
NodePubKey, and could sign conflicting B if its earlier choice is not safely recovered.
A might never have obtained quorum, so recovery of only quorum-confirmed locks cannot
be assumed to restore every prior signing choice. The readiness gate needs more precise
evidence than just a completed sync. Proposed conservative option, not agreed: release
a binding vote only after its exact signing choice is durably recorded through the
asynchronous batch worker. RAM admission may remain quick, but binding response latency
includes durability wait; this exposes a tradeoff with the existing <5 ms attestation
target and the no-I/O checkout axiom. Persisting a mutable current lock alone is not
necessarily a signing journal. Do not silently implement this proposal or claim it
solves disk loss, restored stale backups, or safe committee transitions.

<a id="evidence-dec-029"></a>

The maintainer explicitly approved durable signing-choice storage before releasing the
binding response and removed the rigid five-millisecond requirement: perform local
work as fast as practical and measure it. This intentionally refines the earlier
no-I/O checkout requirement: no synchronous disk operation or RAM lock spanning disk
I/O, but an asynchronous durability acknowledgment may delay the binding response.
It does not approve a specific batch interval or guarantee a new latency target.
The 800 ms gateway signature-collection budget remains in place.

Plan implications, not an implemented change: acknowledge the exact decision's successful
durable commit, not just send/receive on MPSC, serialization success, or an attempted
transaction. Persist immutable signing choices with enough slot/network/context binding
to prevent later mutable registry state from authorizing contradictory votes. Audit every
write/read helper that can emit commitment-domain signatures. Per-request acknowledgments,
idempotent duplicate requests while persistence is pending, batch partial progress, timeout
semantics, storage failure and startup readiness all require design. Shared worker
batching must stay bounded and not block RAM access during commit. Real-QUIC restart/
power-loss-boundary tests and meaningful durability fault injection are future obligations.
Durability-before-vote protects against losing uncommitted RAM choices; it alone does not
protect against disk loss, operator-restored stale snapshots, or unsupported transitions.

Next question: on a persistent write/commit failure, should the process remain available
for local diagnostics and appropriately labeled reads while refusing all new binding
votes dependent on the failed shared store, or terminate? Recommend write-disabled
operation until storage safety is restored; this is pending and does not authorize
serving unproven RAM entries as FINAL or ignoring deadlines on outstanding requests.

<a id="evidence-dec-030"></a>

The maintainer approved write-disabled diagnostic operation for persistent storage
failure and requested peers treat it like other inability to serve, using the existing
NOT_READY message, which a lazy peer could also send dishonestly. Reaffirm current
policy: the gateway counts no vote, exits if quorum is impossible, and applies the
normal deadline otherwise. The next admitted checkout still attempts each authorized
member; do not revive the superseded per-checkout offline backoff. Claimed storage
failure is not cryptographic evidence of honesty or fraud. Local operator diagnostics
can retain precise storage causes without creating a new P2P excuse protocol.

Next question, pending: automatically leave write-disabled mode once the background
worker establishes successful durable commits and safe pending/signing state, or require
operator approval for every recovery. Recommend automatic recovery for transient failures,
with bounded retry work and no reopening merely because a test file/write succeeds.
Account for all pending operations, preserve earlier durable signing choices, and retain
NOT_READY if state completeness/integrity is uncertain. State loss, corrupted storage,
and stale-backup restoration require separate recovery treatment. Operator stop/veto
still takes precedence. No production change or tests run.

<a id="evidence-dec-031"></a>

The maintainer approved automatic resumption, expecting the node to sync and recover
all locks first. Record that operational preference, without claiming a proof of "all
locks" or prior choices exists. A temporarily full disk with intact durable signing
state differs from losing that state altogether. Durability-before-vote prevents an
uncommitted choice from escaping as a binding signature, but cannot prevent later loss
of the committed disk or rollback to a stale snapshot.

Next unresolved data-loss scenario: A had a durable local vote but never reached quorum;
after loss of that node's signing store, peers need not possess or return A. Syncing
only currently qualified/canonical locks cannot restore that individual earlier vote.
Recommend refusing new binding votes under the same NodePubKey for affected scope until
prior signing safety is justified, rather than declaring ordinary sync sufficient.
If justification is impossible, operator recovery/new identity or a provably safe
expiry bound needs a separate rule. Fresh identity does not inherit friendships or
ticket maturity and is not by itself a proof of safe committee transition. This policy
is pending; do not claim irrevocable same-key loss or a new-identity remedy is already
fully decided. No code or tests changed.

<a id="evidence-dec-032"></a>

The maintainer approved the lost-signing-choice safety gate. They also requested that
future interview questions use lettered options: A is the agent's recommended option,
with another viable B when useful. Ask one decision at a time, explain each briefly,
and allow a simple letter response. Do not fabricate alternatives merely to fill a list.

Next storage-layout choice, pending: recommend storing immutable signing choices in
a separate table of the existing redb database, committing the related lock/choice
atomically through the existing bounded batch worker before vote release. Mutable
canonical registry state must not overwrite the earlier choice. Alternative: a dedicated
durable signing journal separated from reconstructible registry storage, with explicit
ordering/recovery requirements and an extra persistence path. Both need true durable
acknowledgments and stale-backup/data-loss safety; a second file on the same disk does
not guarantee survival. Avoid committing to signed field layout or vote-revision scope
before the unresolved protocol rules are defined. Automatic expiry of signing safety
state must follow justified root TTL rules; no permanent expired-lock tombstones.

The maintainer asks whether post-disk-crash observation of gateway signer bitmasks or
identical shard states can suffice to resume signing. They have not chosen storage
option A/B yet; answer the explanatory question before seeking another decision.

Targeted code inspection: `QuorumCertificateDto` (`api/dto.rs`) retains a u32
`signer_bitmap` alongside full signatures. Write assembly computes it from immutable
committee positions (`api/routes.rs`). This is certificate metadata, not independently
verified signer evidence by itself. Spec 03 still describes a four-byte gateway-to-shard
piggyback acknowledgment. No corresponding production send/receive path was found
in the inspected sources: `Transport::send_request` finishes the outgoing request
before reading a single response frame; source searches found bitmap handling in
certificate assembly rather than a post-quorum callback to shard nodes. Do not claim
the callback was historically removed or is implemented merely because documentation
or simulator types mention it. The other heartbeat `piggyback_observations` mechanism
carries ingress evidence, not this signer-bitmask acknowledgment.

`daemon.rs` currently enables readiness after the dominant quorum digest matches or
the divergent paginated pull is treated as completed. This is a registry-state check,
not proven recovery of immutable individual signing choices. Matching authenticated
digests show those responders report the same bounded snapshot; they do not prove
globally identical state, authorized membership, or all prior votes by the crashed
identity. A justified full multi-signature certificate can establish support for one
lock in its authorized context, but still cannot show the recovering identity never
signed a different unconfirmed candidate earlier. A gateway bitmask alone cannot do
either. Current known state and historical signing safety are separate prerequisites.
With lost signing choices, the node may observe/pull/relay evidence while withholding
binding votes. Safe observation-domain/read semantics remain to be specified.
No code changes or tests run; A/B persistence layout remains pending.

The maintainer explicitly requested research into how comparable systems handle the
known problems, to avoid inventing mechanisms unnecessarily. Primary-source research
on 2026-10-14 found:

- [CometBFT FilePV implementation](https://github.com/cometbft/cometbft/blob/main/privval/file.go)
  and [signing specification](https://github.com/cometbft/cometbft/blob/main/spec/consensus/signing.md):
  keep last height/round/step, sign bytes and signature; check regressions/conflicts;
  reuse the prior signature for permitted identical retries; saveSigned invokes state
  Save before assigning the new vote signature and returning. The ordinary loader
  expects both key and signing state; Reset is explicitly marked unsafe. This is
  evidence of save-before-release design, not a full audit of its filesystem durability
  or an instruction to copy panic-based Go error handling into Rust.
- [Ethereum EIP-3076](https://eips.ethereum.org/EIPS/eip-3076): transporting signing keys
  alone omits signing history, so define an interchange format for protection data.
  This supports treating key/anti-equivocation state as one operational safety unit,
  while it does not require one physical file or prove periodic backups are current.
- [Teku slashing protection](https://docs.teku.consensys.io/26.7.0/concepts/slashing-protection):
  use per-validator protection state, including slot/source/target progress values;
  migration stops the old signer and transfers protection data. The documentation
  describes initializing conservative progress values from present chain information
  when migrating from another client. Such floors depend on Ethereum's ordered epoch/
  slot and slashing rules; do not transplant them to arbitrary HuMoCo spend slots.
  The search service supplied this official content, while a subsequent direct open
  returned an access error; no claim of having tested Teku is implied.
- [Lighthouse doppelganger protection](https://lighthouse-book.sigmaprime.io/validator_doppelganger.html?highlight=de):
  observe for 2-3 epochs before signing to detect another live instance, explicitly
  described as imperfect. This is duplicate-live-signer detection, not proof that
  lost historical non-quorum votes never existed; it does not justify HuMoCo's proposed
  same-key recovery from silence alone.
- [Sui checkpoint verification](https://www.docs.sui.io/develop/sui-architecture/checkpoint-verification)
  and [full-node sync](https://docs.sui.io/operators/full-node/sui-full-node): quorum-signed
  checkpoints link history and carry the next committee at epoch end; verification
  starts from an initial genesis committee/checkpoint anchor. These are references
  for authenticated state continuity and committee transitions, not a complete
  HuMoCo membership/merge solution or a proposal for staking or a global ledger.

Transferable mechanism: retain authoritative own signing decisions, check before each
binding vote, persist safely before release, and migrate signer safety state together
with the key. HuMoCo still needs its own exact slot/domain binding, immutable-choice
semantics, expiry rules and total-loss detection/recovery. A single "last counter"
cannot be assumed sufficient for independently revisitable active parent slots without
a new justified ordering/retirement rule. Compact watermark recovery or a bounded
expiry-based pause may be research paths; no such rule is agreed or proven.

Recommendation after research: keep the simple local protection store in existing redb
(storage option A), with an immutable choice table and atomic lock/choice durable
acknowledgment. Option B remains a separate signing journal if operational independence
is worth the extra persistence/recovery path. Whole-disk loss still invokes the approved
safety gate; current or stale backups, mirrored stores, remote signers and safe waiting
bounds have distinct cost/assumption tradeoffs to discuss later. This is a research
recommendation only; A/B selection and new implementation remain pending.

<a id="evidence-dec-033"></a>

The maintainer selected storage option A after the comparative research and asked how
to continue. Record the existing-redb immutable choice table as agreed; do not implement
it before the interview's remaining protocol obligations are resolved. Whole-disk loss
and rollback recovery remain open despite choosing a crash-safe local layout.

Next decision: graceful shutdown. Recommend option A, stop admitting new work, allow
bounded existing work to finish/persist with true durable acknowledgments, then close
within a configured deadline; unresolved requests receive no binding success and retain
unknown/retry semantics. If the deadline/storage failure prevents a clean drain, report
an incomplete shutdown rather than logging clean success. Earlier durable commitments
remain durable and must not be rolled back. Option B is an unbounded drain until every
pending operation is committed, requiring operator intervention if storage never recovers.
Deadline sizing remains to be measured and coordinated with systemd/container stop
behavior. No option has yet been selected.

Inspection: daemon uses a separate flush cancellation token and cancels/awaits the
worker after awaiting listener/background handles; transport.close happens first.
The flush worker caps shutdown-drain batches and warns if the cap is hit; commit_batch
records failures without a per-entry acknowledgment/overall shutdown failure result.
The daemon ignores flush_handle's result and logs stopped. These observations do not
prove all in-flight QUIC handler work is joined or pending operations durably succeed.
The new durable-response architecture needs shutdown ordering and failure reporting
review, including potential callers waiting for worker acknowledgment. No tests run.

<a id="evidence-dec-034"></a>

The maintainer selected shutdown option A. Next discuss bounded automatic expiry
processing, without re-asking agreed root-anchored expiry plus 30-second grace or
allowing permanent expired-lock tombstones. Include the new own-signing-choice table
in justified expiry cleanup, with no new commitment for expired roots and time-safety
gates preserved. Uncertain expiry time must not be resolved by destructive guesswork.

Recommend A: process eligible expiry buckets in bounded background chunks, with short
RAM mutation sections and bounded disk transactions, preserving foreground commit and
background sync progress under mass simultaneous expiry. Alternative B: process all
currently expired entries in one periodic sweep, simpler for tiny volumes but potentially
long disk transactions/RAM work under concentrated expiry. Exact limits/scheduling
remain unmeasured; no new worker architecture is approved by the recommendation.
Expiry eligibility at the agreed time and eventual physical cleanup are distinct:
an expired root is rejected regardless of whether background deletion has finished.
Both options must still physically remove expired data rather than keep tombstones.

Inspection: `DualTierEngine::prune_expired` invokes RAM pruning, releases those guards,
then directly calls synchronous `db.prune_expired_buckets`; daemon schedules it with
clock/boot-safety checks. This shows RAM guards are not held over that call, but not
bounded disk cleanup or runtime isolation under mass expiry. The new signing table
does not exist yet. Preserve relevant time-safety checks and verify cleanup ordering
and starvation after a concrete design is selected. No tests run.

<a id="evidence-dec-035"></a>

The maintainer selected expiry-cleanup option A and requested an overall progress
assessment before the next interview decision. Report progress qualitatively by area:
KISS boundaries mostly agreed; checkout flows agreed with core inspection still missing;
consensus membership/read/finality proofs materially open; P2P capacity/lifecycle directions
agreed with limits/readiness/reconciliation open; phase-5 persistence/shutdown/expiry
directions agreed with deployment/admin and loss recovery still open. A rough interview
progress estimate around two thirds is a subjective topic-coverage estimate only, not
a percentage of fully proven system decisions or production readiness. No fixed exhaustive
weighted decision inventory exists. Remaining proof work can revise earlier choices.
Next finish remaining operations scope, then prioritize unresolved security proofs and
actual core integration rather than expanding peripheral features. No final master plan
is justified yet; no implementation/test evidence has been added during the interview.

The maintainer requested continuing after the progress assessment. Next discuss the
preferred documented Linux deployment route while preserving useful existing templates.
Inspection found both `deploy/systemd/humoco-node.service` and Docker/Compose templates,
each using an unprivileged humoco user and a configured 30-second stop allowance.
Compose declares persistent data/config volumes and includes a Caddy service; the
systemd unit declares a persistent StateDirectory. These settings were read, not built,
deployed or validated. The existing 30 seconds is not an approved measured drain bound.
Verify actual key/config/data paths and persistence, signal ordering, restart readiness,
and operator-controlled updates when implementing the agreed signing store.

Pending deployment-default question: A (recommended) native systemd as the primary
documented Linux route, retaining Docker/Compose as an alternative; B container-first
documentation, retaining native service as an alternative. Prefer A for fewer runtime
layers around the standalone Rust daemon, but do not discard working Docker templates
or invent Kubernetes/HA orchestration. Both must obey identical signing/durability,
operator sovereignty, resource and public-ingress/internal-P2P rules. This decision
is about default documentation/support emphasis, not automatic deployment or a new
permission requirement.

<a id="evidence-dec-036"></a>

The maintainer selected systemd-first deployment option A, retaining Docker. Next clarify
private operator access while preserving useful dashboard features. Inspection found
dashboard diagnostics and admin mutation routes registered in the same API router as
public ingress (`api/routes.rs`). Admin handlers verify an admin bearer token; this is
not evidence of an enforced independent private listener boundary. ControlServer binds
a Unix socket and attempts chmod 0600, but ignores metadata/chmod errors. No complete
auth/proxy/socket-security audit or tests have been performed. Existing dashboard
functions include mesh-friend management, ingress clients and quota, so do not equate
keeping useful dashboard work with mandatory read-only conversion.

Recommend A: keep dashboard and administration on a dedicated local operator endpoint,
with administrative authority through the protected control socket; access remotely via
operator-controlled SSH forwarding. Public wallet ingress must not expose operator
routes. Alternative B: an explicitly configured private VPN/operator-network endpoint,
with appropriate authentication/firewall separation and identical control-socket authority.
Neither proposes a public administrative endpoint, a new VPN implementation in the node,
or deleting useful local UI functions. Both retain local/offline dashboard dependencies,
no automatic peer bans from telemetry, and existing no-browser-backup/manual-prune guards.
Exact UI adapter/listener packaging, token/CSRF policy, proxy handling and fail-closed
socket permissions remain design/audit work. This access-default choice is pending.

### 7.3 Actual core integration located and initial inspection (2026-10-15)

<a id="evidence-dec-037"></a>

The maintainer chose private operator access option A. Rather than add further peripheral
choices, locate and inspect the actual core before returning to security decisions.
Found `/home/basti/Coding/humoco/human-money-core/src/services/l2_gateway.rs` and
`src/models/layer2_api.rs` in the sibling repository; an explicit no-ignore source
search found files omitted by parent-directory ignore rules. Earlier "not found"
statements above are historical. Only targeted read-only inspection was performed;
no core files changed or tests run. Observed HEADs: core b8284e4, node 82f1c42; this
identifies checked repositories, not a guarantee of a pristine core working tree.

Initial concrete findings:

- `verify_quorum_plausibility` deduplicates u16 node_id values and hashes those short
  IDs with the shard for statistical scores. Its body does not verify the attestation
  signature strings, full signer keys/tickets, or authorized membership. At N=20
  its score threshold is zero. `evaluate_quorum_certificate` can return ConfirmFinal
  for a status-1 certificate passing this helper.
- Core `AttestationDto` contains lock_id, parent_lock, u16 node_id, timestamp and
  signature, but no full NodePubKey/shard_id fields present in the node DTO. Shared
  schema/verification consolidation is needed; do not preserve legacy short IDs as
  signer authority. Real production signatures must be verified before counting votes.
- `process_l2_verdict` checks a server signature over SHA256(serialized verdict), not
  the optional certificate. It also verifies the owner's lock proof. These checks
  do not supply the missing individual quorum-vote checks. The inspected unit test
  asserts ConfirmFinal using dummy attestations; it was read, not executed.
- `app_service/conflicts.rs` calls the gateway evaluator through evaluate_l2_action;
  its process_l2_response branch maps ConfirmLocal/ConfirmProvisional/ConfirmFinal
  alike to L2ProcessingOutcome::Confirmed. This needs review before asserting that
  every consumer distinguishes finality; no goods-release UI/HTTP exploit was tested.
- Core request generation includes V3 traps, encrypted timestamp, privacy_guard and
  signed genesis deletable_at. The node has corresponding V3 fields/helpers. This
  shows overlap, not complete wire/digest/causality/split/expiry interoperability.

These are static-code findings, not a completed audit or executed exploit. They confirm
the previously open client validation gap; a statistical score cannot substitute for
signature/membership proof. HMC remains the domain protocol reference, not an instruction
to copy an inadequate implementation verbatim. Membership authentication, hidden-query
read safety, chain/output binding and safe committee transitions remain unresolved.

Next new decision, pending: A (recommended) a small shared Rust protocol library for
canonical L2 types, signed encodings and basic cryptographic verification, usable by
both projects without importing wallet/account/application logic. B: retain separate
thin adapters/verifiers with shared positive and adversarial conformance vectors.
This chooses consolidation packaging, not an unproved membership policy or a new
protocol implementation. Avoid treating "shared code" as a security proof. No need
to re-ask whether actual signatures or full identity verification are required.

<a id="evidence-dec-038"></a>

The maintainer selected shared-library option A and explicitly reiterated ownership
of both core and node, with freedom for coordinated breaking changes. Do not ask again
whether compatibility must be preserved or external core maintainer approval is needed.
This remains an interview/plan decision, not a request to implement the whole protocol now.

Next examine the basis for authorized committee continuity before revisiting read
acceptance. Pending design-direction options: A (recommended for a changing network)
fixed committee contexts with an explicit justified state/authority handoff before a
new committee becomes eligible to issue binding votes for existing roots; B freeze
each root's authorized committee for its full validity, avoiding handoffs for that
root but accepting reduced availability as its members leave. Neither means per-request
replacement or timestamp-only epoch resets. Do not present an epoch mechanism as proven
or adopt a global blockchain/central registry by implication. Define exact handoff and
forbidden cross-context commitments later; the original single-slot safety obligations
cannot be escaped by a new context identifier. Both options still need an authenticated
initial membership basis, fault assumptions, correct ticket eligibility and root binding.
Option B can lose quorum for long-lived roots; A needs an actual safe transition proof.
Ask which direction to develop, not whether completed safety is already established.

<a id="evidence-dec-039"></a>

The maintainer selected committee-continuity direction A but challenged whether an
explicit handoff fits KISS or honest nodes can simply pull from existing peers. They
proposed human/economic friendship maintenance and automated indicators of bad friends
or short gossip-hop paths to bad nodes, with reputational consequences for keeping
poor friends. Preserve the idea as a proposal, not an agreed global reputation system
or relaxation of first-party evidence/telemetry rules.

Distinguish data retrieval, authority/completeness of retrieved state, and operator
incentives. Honest pull is necessary but does not identify missing previously confirmed
locks under partial availability. Successive committees can honestly rely on incompatible
incomplete state without any node double-signing. A local service score cannot recover
absent bytes or authorize a transition. Safety protects honest nodes from incomplete
views; it need not force Byzantine nodes to behave. A handoff can reuse pull transport
plus bound verified evidence, but its evidence/closure/authority rules are unproved;
do not promise a trivial extra acknowledgment or add checkout shard gossip.

Indirect reputation has framing/cascade risks: a friend of an offender is not proven
to have offended, a timeout may reflect a partition, and an attacker can maintain a
reliable-looking cluster. Hop counts at most describe observed propagation paths;
they do not authenticate a shortest path or complete friendship graph. Topology
advisories need authentic edge/path evidence and bounded collection/storage. Automatic
badness inheritance or punitive hearsay gossip contradicts Anti-Hearsay, direct-observation
and non-authoritative-telemetry rules. Operator-chosen friendship changes based on
diagnostics remain permitted. Do not revive checkout offline suppression implicitly.

Primary research on 2026-10-15:
- [Stellar quorum configuration](https://developers.stellar.org/docs/validators/admin-guide/configuring)
  and [Why quorums matter](https://stellar.org/blog/developers/why-quorums-matter-and-how-stellar-approaches-them):
  organization/human-selected trust still requires appropriate quorum intersection.
  This does not prove HuMoCo's different HRW/partition model or propose replacing it.
- [SybilGuard](https://people.cs.uchicago.edu/~ravenben/classes/333/papers/sybilguard.pdf):
  social trust can constrain Sybil influence under structural, attack-edge and mixing
  assumptions; friendship alone is not unconditional proof of honesty/independence.
- [Douceur, The Sybil Attack](https://www.microsoft.com/en-us/research/wp-content/uploads/2002/01/IPTPS2002.pdf):
  multiple cryptographic identities need not be independent entities. Do not read its
  model-specific result as forbidding all conditional resource/social defenses.

Pending scope choice: A (recommended) start with direct local observations and verified
fraud evidence as operator diagnostics; B additionally investigate authenticated topology
advisories with explicit graph-evidence/cost requirements. Both remain operator-only,
without automatic guilt-by-association, hearsay slashing or replacing quorum/transition
evidence with reputation. No reputation algorithm or new gossip stream is approved.

<a id="evidence-dec-040"></a>

The maintainer chose direct-diagnostics scope A, then clarified that locally observed
lower response reliability must be included. Record it explicitly rather than treating
"non-authoritative" as "ignore availability". Use ordinary RPC outcomes without extra
probe traffic, with bounded local storage. Preserve authenticated NodePubKey identity
and distinguish reachability/ready service: NOT_READY is an observed refusal to serve,
not a timeout and not proof of lying. A timeout establishes only that this observer
did not receive the required reply within its budget, not a universal claim that the
peer failed to send. Exclude fulfilled-quorum cancellations and unsent requests from
miss counts; account for sampling/censoring when interpreting rates. Do not automatically
reset diagnostics based solely on a handshake/heartbeat or claim a derived score is
cryptographic evidence. Exact aggregation and diagnostic presentation remain to design.

Next handoff design preference, pending: A (recommended for simplicity) allow a planned
write pause for the affected shard/context while closing old work and establishing
verified state/authority transfer; B investigate concurrent live handoff with old/new
signers and explicit overlap rules. This is an interruption/complexity preference,
not a completed protocol. Existing/potential old certificates and earlier individual
votes must remain accounted for; stopping new requests alone does not invalidate
already-issued votes held by clients. Bound transition attempts and do not permit a
new committee to start merely because a timer elapsed. If evidence is insufficient,
preserve safety/readiness gates; the exact allowable old-state recovery is still open.
Other shards can continue. No universal short-pause/liveness guarantee or new checkout
gossip is promised, and initial membership authority remains unresolved.

<a id="evidence-dec-041"></a>

The maintainer selected handoff write-pause option A and emphasized short duration,
useful PoS feedback, and exploring established algorithms. Their proposal: agree a
database/state snapshot during the pause, transfer it, and let the newcomer collect
new requests without signing, applying them later. Preserve as an idea, not approval
of an unbounded queue, a simple majority snapshot or a proven transition.

Primary research on 2026-10-15:
- [Sui Lutris](https://docs.sui.io/paper/sui-lutris.pdf), sections 4.2-4.3, uses new
  committee preparation/state catch-up, stopping the old fast path, ensuring processed
  certificates reach the checkpoint/consensus sequence, and quorum End-of-Epoch before
  handover. It relies on a consensus/checkpoint system and specific epoch/finality
  assumptions; it is not directly HuMoCo's single-round 14/20 protocol. Do not import
  its stake model, epoch-specific vote resets, transaction rollback or finality definition
  as HuMoCo decisions. In particular a client-held first-round certificate and a
  quorum-accepted certificate have different roles in that paper.
- [etcd learner design](https://etcd.io/docs/v3.7/learning/design-learner/): newcomers
  catch up as non-voters before promotion; its Raft crash-failure/leader model is not
  Byzantine security. Reuse the learner preparation pattern, not Raft as proof for
  malicious HuMoCo peers. The v3.8 page explicitly marked itself draft, so the cited
  v3.7 page was opened for the reference.
- [BFT-SMaRt state transfer/reconfiguration](https://www.di.fc.ul.pt/~bessani/publications/dsn20-smrtobc.pdf),
  section II: checkpoints/request logs support state transfer; its described reconfiguration
  uses a trusted View Manager and total ordering. Those assumptions are unsuitable as
  an unstated authority for HuMoCo. This confirms why a database snapshot alone is not
  the complete algorithm.
- [Kuznetsov/Tonkikh, Asynchronous Reconfiguration with Byzantine Failures](https://arxiv.org/abs/2005.13499)
  offers a different family using dynamic Byzantine lattice agreement and forward-secure
  signatures. Its abstract/metadata were reviewed, not a complete applicability proof.
- [RFC 9110, 503](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.6.4) and
  [Retry-After](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3) provide existing
  HTTP temporary-unavailability/retry-hint semantics. A hint is not a completion promise.

Recommended handoff design to investigate: pre-copy/verify needed active shard state
while old committee serves; prospective members do not vote. Then bound a transition
attempt, close old admission, account for old issued/pending/late-certificate obligations,
transfer remaining justified state and obtain bound authority/readiness evidence before
activation. The protocol snapshot covers relevant shard state and obligations, not an
arbitrary full local redb/config/secret copy or one replica's raw digest. Initial roster,
snapshot completeness, fault bounds, agreement/closure, old-vote retirement and safe
activation remain unproved. A matching digest does not prove these conditions, and
time expiry cannot activate an unproven committee. Short normal-case pauses are a target
to measure; partitions can prevent completion entirely. Do not guarantee a few seconds.

PoS feedback proposal, pending exact encoding: retain NOT_READY at P2P with a bounded
retry hint/reason if useful; a gateway may report temporary unavailability (e.g. HTTP
503 + Retry-After) when it cannot obtain the required quorum. A single refusing peer
must not impose a shard-wide halt if enough valid votes are available. Do not certify
the alleged cause/transition merely from one peer's claim. The client can display
"not yet confirmed, retrying" without showing paid or globally unspent. Keep the exact
signed intent/lock ID and bounded retry horizon; 800 ms remains per collection attempt,
not an unlimited invisible extension of the request. Earlier accepted locks remain.

Next A/B choice, pending: A (recommended) client retains the signed request and retries
after the pause/hint, without a new node-side reconfiguration queue. B: bounded temporary
server-side pending-intent queue during handoff, with explicit size/time/admission limits
and no binding success until real post-handoff verification/durability/quorum. Queued
intent is not accepted registry state or a payment certificate, and cannot bypass
causality, expiry, collision or quota checks. It still requires client uncertain-outcome
retry behavior after a crash, and would add state/work beyond the earlier no-extra-queue
default. The maintainer has not selected either queue option yet. No code/tests changed.

<a id="evidence-dec-042"></a>

The maintainer selected client-retained retry option A for requests during handoff.
Do not implement the earlier newcomer queue suggestion or silently extend collection
beyond the agreed attempt budget. Keep the pre-copy/short-cutover pattern as proposed
design, with actual state closure and authority proofs still open.

Next choice, pending: cadence of routine committee changes. A (recommended) collect
routine join/ticket-maturity/departure proposals and attempt a combined transition
per affected shard in bounded maintenance windows/minimum intervals; B attempt a
separate transition immediately whenever an eligible routine change affects the shard.
Batching aims to reduce repeated pauses and transfer/control traffic; it adds activation
delay. Exact periods are unmeasured. A schedule is only a proposal/attempt trigger,
never authority to activate a committee. Mature tickets remain subject to the existing
24h minimum and the still-unproved authorized handoff. Concurrent proposals, certified
old/new roster authority, initial membership and failure bounds still need design.
Verified fraud evidence/identity bans are not delayed to a routine maintenance window,
and short RPC failures/NOT_READY must not manufacture membership-change proposals.
Do not interpret scheduled handoff as auto-update or add a third F2F gossip stream.

<a id="evidence-dec-043"></a>

The maintainer approved batching routine changes, then asked the essential authority
question: how can nodes identify the old/new committees and their activation if HRW
ranks shift as the network grows? Answer this directly before another implementation
preference. Their question is not approval of any new transition format.

Reinspection confirms `PeerManager::shard_committee` recomputes from the local known/
mature/non-banned identity view; write collection freezes that result for one attempt.
`QuorumCertificateDto` has no committee-context/history/transition reference. No certified
handoff/committee-context implementation was found in the inspected source searches.
Thus per-request freezing does not already provide old/new authority or global view
agreement. Existing rank changes alone cannot justify the proposed safe handoff.

Proposed conceptual model, not an implemented or proved protocol: keep an explicit
accepted committee context per shard. It identifies the full member keys/tickets,
network/shard and relevant protocol scope. HRW over an explicit eligible view proposes
the next roster; falling to rank 21 in one observer's recomputation does not immediately
remove a current authorized member. A verified transition must bind predecessor context,
successor roster, state/obligation commitment and closure/activation evidence. Old/new
member authorization and readiness are determined by this evidence rather than a
globally simultaneous clock instant. Nodes/gateways may learn it at different times,
fetch it on demand, and must not authorize lower-rank replacements or stale-context
new votes. A valid old-context certificate can remain historical evidence; learning
a valid history prefix does not by itself prove it is the latest context.

A successor proof is only meaningful relative to a justified predecessor context and
fault assumptions; an arbitrary self-declared set with fourteen signatures cannot
authorize itself. Initial/bootstrap authority is still unresolved. Likewise HRW
candidate completeness, authenticated ticket maturity, competing transition proposals,
stale-view recovery, bounded proof retention and late-issued-vote safety remain open.
Do not claim that storing a roster and signing a snapshot solves all those obligations
or guarantees universal discovery. No new A/B selection is required just to explain
the current limitation and proposed context/evidence distinction. No code/tests changed.

<a id="evidence-reopen-continuity"></a>

The maintainer explicitly reopens the complexity tradeoff: could small subjective HRW
view differences work without an elaborate authenticated committee-history/handoff
construction, analogous to removing rank-21 checkout replacements? Treat this as
authorized reconsideration, not a request to silently implement earlier handoff sketches.
Agree that the large mechanism must justify its necessity; retain it as a possible
design direction while analyzing a smaller sufficient safety condition first.

Concrete own derivation for two 20-member views C,D, 14-vote certificates Q,R, and
an identity-stable Byzantine bound f relevant to both certifications:

| Shared committee identities | Union size | Minimum common certificate signers |
| --- | --- | --- |
| 20 | 20 | 8 |
| 19 | 21 | 7 |
| 18 | 22 | 6 |

Reordering the same identities changes no membership overlap. If d identities are
replaced, union size is 20+d, so |Q intersection R| >= 28-(20+d)=8-d.
Under full signature/slot binding, persistent non-conflicting honest votes and at most
f Byzantine identities in the relevant overlap, 8-d>f suffices to exclude two conflicting
certificates for this pair. For f=6 this permits d<=1; for f=3, d<=4. These are conditional
pairwise signature-intersection bounds, not full read/reconfiguration/liveness proofs
or observed attack probabilities. Mobile compromise, state loss, old certificate validity
and unbounded churn require further temporal assumptions/protection.

Verified an explicit counterexample by a temporary set calculation (not a wire or unit
test): Byzantine M1..M6; honest H1..H16. C=M1..M6 + H1..H14;
D=M1..M6 + H3..H16, sharing 18 members. Q=M1..M6 + H1..H8;
R=M1..M6 + H9..H16. Each committee has 20 and each certificate 14; their only
six common voters are Byzantine, while honest voter sets are disjoint. A coordinated
owner can supply divergent authorized spends. All signature checks can succeed without
honest double signing; later fraud bans do not prevent the initial incompatible
confirmations. This establishes a real risk without claiming its prevalence or cost.

Removing rank-21 replacements restricted the possible signer universe and therefore
helped safety as well as simplicity. Differing local top-twenties can expand that
universe again. No requirement for exactly identical rank order is justified by this
argument. Even a per-step one-member turnover bound is insufficient for unlimited
root-lifetime churn: nonadjacent committees may eventually have too little overlap.
A local observer cannot infer an upper bound on unseen identities merely from its
own roster. Do not promise that increasing q or adding a score threshold solves
initial authority, indefinite churn or state continuity.

Primary reference: [Stellar Consensus Protocol, section 4.1](https://stellar.org/papers/stellar-consensus-protocol.pdf)
explains why quorums need honest intersection, not merely arbitrary shared nodes.
The table, inequality and counterexample above are our own elementary set derivations,
not measured HuMoCo results or numbers claimed from Stellar. Also consulted primary
Byzantine-quorum research search results; do not import stronger masking-quorum read
requirements as this simple no-double-vote certificate argument.

<a id="evidence-dec-044"></a>

The maintainer selected A: seek protection with up to six Byzantine identities in the
relevant twenty-member committee model, retaining 14/20. The alternative was a deliberately
weaker target of three. This is a desired design tolerance, not proof that WoT/Argon2
enforces the bound. Fault-set scope over time, eligibility verification and how any
deviation bound can be justified still need work. This does not approve statistical
finality or solve the handoff. No production code or protocol tests changed.

### 7.4 Root-lifetime committee pinning: concrete availability cost

Read-only follow-up checked whether fixing a committee for each voucher root could
remove routine handoff. Core `src/models/voucher.rs:369` selects the requested or
standard-default duration and checks standard minimum/maximum ranges; there is no
universal short lifetime here. Node Spec 12 explicitly anticipates multi-year vouchers,
up to ten years (`docs/12_lock_storage_und_ram_index.md:59`). The node storage constants
allow an eleven-year upper-bound buffer, not an eleven-year universal voucher lifetime.

With one fixed roster of twenty and fourteen required votes, seven permanently departed
members leave only thirteen possible votes even if every remaining member is honest.
This elementary availability limit needs no attack or empirical probability assumption.
Byzantine withholding can exhaust the availability margin sooner. Root-lifetime pinning
would also complicate the intended workload redistribution as the network grows, and
would still need justified initial membership; pinning alone is not a safety proof.

<a id="evidence-dec-045"></a>

The maintainer selects A: require still-valid vouchers to remain serviceable through
gradual original-member replacement, and explicitly through many rounds until none
of the original signers remains. Example: the network grows from thirty to one thousand
or ten thousand nodes. Investigate the smallest sufficient continuity mechanism.
The fixed per-root roster alternative B is not selected. No original signer is required
to stay online or remain in future committees. This does not promise recovery after
an abrupt loss of the old quorum; no automatic timeout-based replacement or full
handoff algorithm is approved.

Clarification: complete eventual turnover does not itself invalidate a sequence of
safe transitions. Each successor must inherit the predecessor's binding obligations
and justified authority; it need not share members with the original committee. A
conceptual candidate is an old-committee quorum certifying one successor roster and
one closed state/obligation commitment, with durable old-vote closure and verified new
state installation before activation. HRW proposes candidates; differing local ranks
cannot independently activate competing successors. This is a candidate structure,
not a complete algorithm: proposal agreement/liveness, precise old-vote closure,
in-flight/late certificates, state completeness, new-committee eligibility/fault bound,
bootstrap and late-joiner/history verification remain to establish. A database copy
or a snapshot hash without these properties is insufficient.

Research reconfirms that this is an established problem family rather than a need for
permanent founders. [Sui's consensus documentation](https://www.docs.sui.io/develop/sui-architecture/consensus)
describes reconfiguration as the prior epoch's final state becoming the next epoch's
genesis with a new validator set. Its [Lutris paper, sections 4.2–4.3](https://docs.sui.io/paper/sui-lutris.pdf)
handles cutover races explicitly, using consensus/checkpoints and different transaction
finality rules. Reuse the continuity principle, not its full machinery or stake model.
[CometBFT light-client verification](https://github.com/cometbft/cometbft/blob/main/spec/light-client/verification/README.md)
also verifies successive validator sets, but its trusted starting header and temporal
honesty assumptions do not automatically solve HuMoCo's bootstrap or long-offline
verification. No transition-proof pruning or permanent full-history requirement is
approved by this comparison. No production code or tests changed.

### 7.5 Next handoff decision: outstanding binding votes

The maintainer requested continuation after accepting complete turnover. Analyze the
existing single-round checkout semantics before adding protocol machinery. Concrete
case: fourteen old members durably sign lock A; the gateway can assemble/hold its
certificate while no individual replica has received the aggregate certificate. If
handoff copies only entries marked globally certified, A may be omitted and a later
committee may certify conflicting B. Delivery delay, gateway silence or an 800 ms
timeout does not cancel an already-issued binding vote or prior successful payment.

Recommended candidate A: carry justified active reservations/binding choices, including
those without a known full certificate, into the handoff obligation state. Preserve
the difference between a reservation and FINAL. An honest old closure signer must
durably stop old-context voting and require inclusion of its own earlier binding
choices plus inherited obligations before endorsing the closed state. Authenticate
records and their relevant identity/context/slot and check owner/causality/expiry;
unverified peer claims must not create arbitrary reservations. Conservatively unresolved
conflicting reservations keep the affected slot/dependents blocked under the already
selected conflict policy, without freezing unrelated slots. Exact admission, evidence,
storage and reconciliation rules still need design.

Useful elementary conditional bound: an old fourteen-vote certificate and fourteen
old closure participants intersect in at least eight identities. With at most six
Byzantine identities, at least two common members are honest. If those honest members
must contribute their previous binding obligations and freeze before endorsing closure,
a previously issued certificate cannot be completely invisible to that closure. This
does NOT establish agreement on a common state, inclusion verification, complete safe
activation or progress under competing handoff proposals. It does explain why requiring
every one of twenty replicas to be reachable is not justified by this particular
certificate-preservation argument.

Pending next A/B choice: A (recommended) investigate this conservative promise-carrying
handoff while preserving current single-round payment confirmation; accept that an
unresolved pre-quorum conflict can block its own slot. B investigate a redesigned
payment protocol with a separate quorum-confirmed completion round and explicit
epoch/abort rules for incomplete preparations. B adds a round and needs a new safety
proof; merely broadcasting a certificate once is insufficient. It does not authorize
discarding today's binding votes, resetting same-slot signing choices or rolling back
previously FINAL payments. These are architecture research choices, not implementation
approval or a finished proof.

Primary comparison reconfirmed: [Sui Lutris, sections 2.4 and 4.2–4.3](https://docs.sui.io/paper/sui-lutris.pdf)
uses certificate redistribution/acceptance for finality and consensus-ordered epoch
closure/checkpoints. Its treatment of incomplete transactions depends on those different
rules. HuMoCo cannot copy its reset behavior into the present one-round semantics.
The quorum-intersection calculation above is our own conditional argument. No code,
protocol tests or performance measurements changed.

### 7.6 Clarification: majority reconciliation versus preserved commitments

The maintainer questions the need for additional promise handling: could a newcomer
simply adopt the majority lock state, and do original signing promises lose their value
after signers leave? They again request established simple handoff algorithms. The
section 7.5 A/B question is not answered; prioritize explaining this distinction and
investigating certified checkpoint/state transfer before asking it again.

Concrete counterexample within one authenticated twenty-member committee with six
Byzantine identities and two conflicting owner-authorized locks for one spend slot:

| Members | Earlier votes | Reconciliation answer |
| --- | --- | --- |
| Eight honest | A | A |
| Six honest | B | B |
| Six Byzantine | A and B | B |

The gateway can have a valid fourteen-vote certificate for A (eight honest plus six
Byzantine). B has only twelve votes. Nevertheless a later query to every committee
member can return eight A and twelve B. Selecting the current raw majority would
replace previously FINAL A with a candidate that never achieved fourteen votes.
All honest members voted only once. The malicious owner may sign both spends under
the already selected coordinated-adversary model. Byzantine double-signing is punishable
when both signatures are available; later sanctions do not make the majority selection
safe at acceptance time. This is our own logical counterexample, not a measured attack.

If "majority" instead means a justified fourteen-member certificate for one closed
handoff state in an authenticated old context, this is a useful candidate primitive.
It still requires honest inclusion/closure rules, installation and activation checks;
collecting fourteen arbitrary replies is not fourteen matching attestations, and a
state hash alone does not prove the right state was selected. Copying live state also
needs a cutoff/delta rule for writes racing the copy. Do not silently require fourteen
initially matching whole-shard digests; independent partial deliveries can prevent that
despite individually valid locks (earlier example remains applicable).

"Binding promise" means the existing durable per-slot lock/signing choice behind a
node attestation, not a new ingress reservation message or a requirement that founding
signers remain online. Leaving a committee ends future authority, but must not undo
previously final payments. Successor state must preserve the corresponding collision
constraint until legitimate expiry. A certified state may summarize preserved effects
without every newcomer having every original individual signature; exact evidence
retention, history verification and pruning of own signing protection are not decided
or authorized here. Ordinary majority reconciliation cannot establish that summary.

Established building blocks checked: [Castro/Liskov PBFT, sections 4.3–4.4](https://pdos.csail.mit.edu/6.824/papers/castro-practicalbft.pdf)
uses certified stable checkpoints, recovery by transferring checkpoint state, and
retains prepared-operation evidence beyond the checkpoint during view change. Its
checkpoint protocol permits certain older protocol-log messages to be discarded only
under its own safety rules. PBFT's fixed-membership view change is not itself HuMoCo
dynamic membership. [BFT-SMaRt's state interface](https://bft-smart.github.io/library/javadoc/bftsmart/statemanagement/ApplicationState.html)
explicitly combines checkpoint state with subsequent batches and exposes certified
decision evidence. Its group-management assumptions are not automatically suitable.
[Sui's original platform paper, section 4.7](https://docs.sui.io/paper/sui.pdf) and the
previously reviewed Lutris sections 4.2–4.3 exemplify certified checkpoint/reconfiguration
under their own agreement/finality/stake model. Do not import those mechanisms whole.

Current recommendation: investigate a bounded per-shard certified checkpoint/closed
handoff plus state transfer and safe activation, retaining the existing payment round
unless a concrete proof obligation requires changing it. This is a research direction,
not a finished HuMoCo algorithm or a maintainer selection of section 7.5 A. No production
code, tests or protocol semantics changed.

### 7.7 Timing and authority when local HRW ranks have already shifted

The maintainer asks how often to check/perform transitions, which node's ranking is
authoritative, and whether shard peers sending a newcomer data/work implies that they
already recognize its eligible rank. Explain authorization before adding mechanics.

In the candidate context/handoff model, distinguish proposed HRW top twenty from the
currently authorized twenty. A member that falls to rank twenty-one in one local view
is still an authorized old member until a justified transition ends its role. Checkout
must use the accepted active roster, rather than silently recomputing authority from
new local ranks. Before cutover it may therefore contact an active member whose proposed
rank is twenty-one; this is not adding a twenty-first signer or fallback candidate.
After cutover use the successor roster. The current implementation recomputes local
rosters per request and does not yet enforce this model; it needs an actual protocol
change if selected and proved. Locating and authenticating the latest roster remains
unresolved; do not pretend a stale valid prefix establishes current authority.

Interpret the maintainer's proposal charitably: if an authenticated quorum of the
accepted old committee signs the SAME concrete successor roster together with the
handoff context/state and closure evidence, that can be a candidate authorization
primitive. Individual data/work delivery alone is not such authorization. Sync may
prepare non-voters, and separate peers may endorse different local candidate lists.
Receiving records/request traffic does not establish who will count the newcomer's
vote. Require explicit, bound evidence rather than an inference from connectivity.
This certifies an authorized roster under agreed rules, not a universally complete
ranking of every node that exists. Membership/ticket validation, initial authority,
new-roster fault assumptions, conflicting proposals, closure, latest-view discovery
and activation evidence are still open; do not treat fourteen signatures alone as
proof of all these properties.

<a id="evidence-hourly-cadence"></a>

Cadence recommendation made concrete, subsequently tentatively selected as A: (starting
parameter) check locally relevant shard candidates approximately hourly, using only
mature eligible tickets. If the candidate roster has not changed, do nothing. Otherwise
coalesce routine changes into one bounded handoff attempt, with rate limits/staggering
to be measured. No forced hourly transition, repeated full-state copy when unchanged,
global synchronized instant or guaranteed completion. B check/attempt daily, trading
slower growth-related workload redistribution for fewer opportunities for transition
work. Neither cadence is measured; the maintainer says A would probably be useful.
Preserve twenty-four-hour incubation;
the hourly check does not shorten it. Timers trigger attempts, not authority. Retain
the accepted roster when proof is insufficient, while affected signing/readiness may
remain paused if closure has already begun; do not promise automatic safe resumption.
Verified fraud handling is immediate, while local timeout/NOT_READY never becomes an
automatic membership exclusion. No new gossip stream or implementation is approved.

Primary comparison: [Sui epochs](https://www.docs.sui.io/develop/sui-architecture/epochs)
keeps membership fixed within an epoch and changes it at a controlled boundary. Its
twenty-four-hour mainnet cadence is not justification for choosing HuMoCo's cadence,
and its global consensus/stake model is not imported. HuMoCo's proposed hourly/daily
options are our design tradeoffs, not source-derived requirements.

### 7.8 Maintainer challenges explicit authorization; possible ranks 21–23

The maintainer tentatively selects hourly checks A, but objects that the word
"authorized" seems to require constructing one uniform view through extra complexity.
Each node naturally treats its own HRW ranks one through twenty as eligible. They
suggest perhaps querying through rank twenty-three when growth means an older member
might still be active before the next hourly transition. This explicitly reopens the
earlier no-lower-rank-replacement design for discussion; it does not yet select expanding
the voting pool, weakening the six-Byzantine target or a new quorum threshold.

Acknowledge that a globally identical discovery/ranking view is not itself the goal,
and that an explicit globally common roster/history construction has not been proved
necessary or selected as a final design. Local node sovereignty remains. The actual
safety requirement is compatibility of certificates and persistence of final collision
constraints across their permitted signer sets and time. Do not treat the earlier
accepted-context sketch as an irrevocable requirement or demand a global ranking oracle.

Distinguish querying extra peers for state/transition evidence from counting their votes
as replacements toward payment finality. The latter changes the earlier 14/20 safety
model. Even with an identical, globally known pool of only twenty-three identities,
two fourteen-vote sets may intersect in only 28-23=5 members. Verified a temporary set
example: M1..M5 Byzantine; H1..H18 honest. QA=M1..M5+H1..H9 and
QB=M1..M5+H10..H18. Both have fourteen signatures, their union has twenty-three
identities, and no honest signer is common. Five Byzantine nodes can sign both owner-
authorized conflicting locks; no honest node double-signs. This already defeats a
claimed safety guarantee tolerating up to six Byzantine nodes. These are elementary
set calculations, not unit/wire tests or a claim about attack prevalence.

For a fixed common candidate universe of size m and a stable relevant Byzantine bound
f, signature intersection requires 2q-m>f for this simple no-conflicting-honest-vote
argument. At m=23,f=6, q=15 satisfies that bound. Do NOT present 15/23 as a full fix:
two different local lists of twenty-three may have a larger union, and cumulative churn,
state loss, authenticity and slot/temporal binding remain open. Nor does restricting
additional queries to one hour establish a bound on identity divergence; the number
of new mature candidates and local discovery differences is not bounded by time alone.

Primary comparison: [Stellar Consensus Protocol, section 4.1](https://stellar.org/papers/stellar-consensus-protocol.pdf)
allows locally chosen trust configurations but still requires honest quorum intersection.
It does not establish that arbitrary local HRW top-twenties intersect safely or provide
a drop-in HuMoCo solution. The numerical bounds and example above are our derivation.

Current recommendation: preserve local views as the starting point and investigate the
minimum certificate-intersection/state-continuity rule before imposing a full committee-
authorization history or expanding the voting pool. Extra state/evidence queries can be
considered separately as bounded recovery work; no new query budget is approved yet.
Keep both the 14/20 and six-Byzantine targets pending an explicit justified revision.
Do not re-ask settled fault-target/complete-turnover choices or pretend that hourly
checks alone solve activation. No production code or protocol tests changed.

### 7.9 Investigating standalone newcomer synchronization

The maintainer requests continuation. Investigated whether a fixed newcomer sync/readiness
step could replace explicit handoff coordination. Important negative result: even a
complete, unanimous and honest snapshot at copy time does not close subsequent writes.

Verified another abstract set/event counterexample in temporary JavaScript, with the
same twenty-member/quorum-fourteen/six-Byzantine target and only two replaced members:
old C=M1..M6+H1..H14; new D=M1..M6+H3..H14+N1+N2. N1/N2 copy the empty
state from every old replica before either request exists. Then QA=M1..M6+H1..H8
sign A in the old view. Later QB=M1..M6+H9..H14+N1+N2 sign conflicting B in the
new view. Both certificates have fourteen votes, both committees twenty, committee
overlap eighteen. Only the six Byzantine members double-sign; no honest node does.
The initial snapshot was genuinely complete, so stronger majority counting or more
snapshot witnesses alone would not prevent this execution. This is an abstract
adversarial schedule, not an executed network/crypto exploit or attack-frequency claim.

Consequent research direction: newcomer copy must be coupled to closure of the relevant
old writing scope and preservation of late/prior obligations. A conceptual three-part
structure is prepare/copy, close-and-transfer, then activate. An illustrative closure
record could bind a justified predecessor context, one successor roster, closed state/
obligations and old-quorum signatures; old honest signers persist their closure and
cannot later issue fresh old-context votes. Initial pre-copy remains useful. A newcomer
must verify/install the resulting state before voting. This is still a candidate, not
a newly approved explicit authorization history or a completed algorithm. Old certificates
issued before closure remain historical evidence; closure does not expire them.

Local views can lag (one node knows an accepted transition, another its predecessor)
without all participants having an identical contemporaneous network map. To preserve
safety they cannot install arbitrary incompatible successors. In the same old authorized
twenty, two fourteen-signature closure records intersect in eight including at least
two honest under f<=6; durable one-successor endorsement is a useful conditional
fork-exclusion argument. It does not show progress: competing partial proposals may
strand endorsers without a complete certificate. No automatic release after a timer,
unproved signing-choice reset, or fixed short-pause guarantee follows. Membership
bootstrap/eligibility, evidence availability, own/inherited obligation inclusion, state
completeness, latest-context discovery, abandoned-transition recovery, temporal corruption
and bounded certificate retention remain explicit design/proof obligations.

Primary research reviewed more deeply than the earlier abstract:
[Kuznetsov/Tonkikh, DISC 2020](https://drops.dagstuhl.de/storage/00lipics/lipics-vol179-disc2020/LIPIcs.DISC.2020.27/LIPIcs.DISC.2020.27.pdf),
introduction, sections 3.4–3.6 and 4.2, Algorithm 1. It permits differing local histories
without consensus on one simultaneously current configuration, but requires comparable
certified histories, dynamic Byzantine lattice agreement and per-configuration quorum
assumptions. State transfer reads relevant predecessor configurations after their keys
advance, and installation requires sufficient new replicas to complete transfer. It
also uses confirming rounds and forward-secure signatures for its stronger temporal-
corruption/slow-client model. This is not a drop-in simple observer-sync algorithm or
proof for arbitrary subjective HRW sets; its permanent-removal example conflicts with
unexamined same-identity re-entry assumptions. Reliable broadcast in this paper must
not be confused with authorizing new F2F gossip streams or lock gossip in HuMoCo.
Do not add these mechanisms wholesale, claim consensus is universally necessary or
claim this paper removes all coordination. Its finite-update and active-configuration
assumptions also need applicability review.

Next substantive unresolved policy to explain if needed: what happens when an actual
transition partially closes the old committee and cannot finish? The previous permission
for a short planned pause is not permission to resume old conflicting endorsements
after a timeout, nor a guarantee of eventual progress. First pursue a safe completion/
retry rule or explicitly scope the unresolved liveness requirement, instead of adding
more preference questions that cannot establish a proof. No production code changed;
no Rust/unit/wire tests or performance measurements were run.

<a id="evidence-dec-046"></a>

The maintainer selected A: require safe automatic progress
for handoffs after communication stabilizes and the relevant honest quorum remains
available, including concurrent competing transition proposals. This permits the
minimum necessary retry/agreement protocol confined to per-shard handoff; it is a
liveness requirement, not approval of a library/algorithm or a pause-duration guarantee.
B explicitly permits a first-version handoff to remain write-disabled indefinitely
when competing partial endorsements cannot safely be completed. Operator intent or a
timer alone cannot justify discarding commitments. B is a deliberate liveness limitation,
not a promise that manual intervention always repairs it. B is not selected.
Concrete motivation: with durable one-successor endorsements and no recovery rule,
thirteen old members may endorse successor X and seven Y; neither reaches fourteen.
Quorum intersection prevents two completed forks but does not resolve this stall even
if all old nodes are honest and communication is later reliable. A fixed proposal leader
alone would likewise need a safe replacement rule if faulty/unavailable. Do not claim
consensus-like global coordination per payment is implied by this local requirement.

### 7.10 Candidate agreement mechanisms after progress requirement A

Investigated how established algorithms recover from competing partial proposals.
[CometBFT's consensus specification](https://github.com/cometbft/cometbft/blob/main/spec/consensus/consensus.md)
describes propose/prevote/precommit rounds, proposer rotation and increasing timeouts.
[Its signing specification](https://github.com/cometbft/cometbft/blob/main/spec/consensus/signing.md)
requires sufficient higher-round justification for changing a consensus lock. A timeout
does not erase prior safety bindings. A preliminary protocol vote is not a completed
handoff. Payment lock/signing choices retain their separate immutable durability rules;
handoff votes need separate domains, instance/round/phase binding and evidence semantics.
This does not authorize new payment rounds, a blockchain runtime or a F2F gossip stream.

Applicability limit: ordinary Tendermint-style consensus assumes one defined authenticated
validator set for an instance. It does not prove agreement for arbitrary independent
local HRW top twenties. A limited compromise is subjective network discovery/proposed
ranks with a common authenticated participant roster for this one shard handoff. The
maintainer has reopened this assumption, so do not silently treat it as selected.
Initial authority, closed-state obligation inclusion, successor installation, latest-
context discovery, temporal/key-retirement assumptions and evidence retention remain
open regardless of the agreement engine. No relative code-size/latency claim is measured.

Alternative: [Kuznetsov/Tonkikh DISC 2020](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.DISC.2020.27)
permits differing current configuration knowledge via comparable certified histories
and dynamic Byzantine lattice agreement. It still needs per-configuration quorum
assumptions, protected state transfer and installation evidence; it does not permit
arbitrary incompatible lists. Its forward-secure keys address its temporal-adversary
model; do not assume the round-based alternative avoids old-key attacks automatically.

Recommended investigation direction: first assess an established round-based agreement
pattern for one handoff instance per shard, preserving subjective discovery/HRW proposals.
Be explicit that it needs an authenticated participant roster for each instance; this
scope condition is not yet a maintainer-approved resolution of the local-view objection.
The more general certified-history/lattice-agreement family is an alternative if its
extra dynamic-configuration machinery proves necessary. Both families need verifiable
quorum membership for configurations and may have temporarily lagging local views;
do not falsely contrast them as requiring versus avoiding all explicit membership.
Use engineering judgment to investigate this first rather than asking the maintainer
to choose algorithm names. Neither is library selection, a complete safety proof or
implementation approval. No production code or Rust/unit/wire tests changed.

### 7.11 S2.1: initial authority and the scope of FINAL (2026-10-15 continuation)

Read-only reinspection confirms that `network/manager.rs::shard_committee` derives
write membership from local known/mature/non-banned identities, includes self and
freezes the selected roster. `NetworkConfig::network_id` currently identifies the
`Mainnet`/`Testnet` enum, not a cryptographic commitment to initial participants or
a trusted checkpoint. Spec 03 section 2.1 explicitly requires independently
authenticated membership but leaves its establishment and safe transitions open.
Discovery addresses, identity signatures and a shared network label do not by
themselves establish this authority. These targeted findings are not a full audit.

Initial-configuration counterexample (own logical derivation, not an executed test):
two disconnected groups of twenty distinct honest nodes each use their local set
as sufficient FINAL authority for the same network/shard/spend slot. A malicious
owner supplies a different validly owner-signed spend to each group. Each can supply
fourteen signatures without any node double-signing. The local Byzantine-node count
is zero in both groups. Therefore a per-local-committee six-Byzantine bound alone
cannot establish common finality across arbitrary independently self-established
groups. This is a counterexample to that bootstrap rule, not to a protocol that
already requires justified common authority or honest quorum intersection. Merely
observing twenty nodes, ticket maturity or later connectivity cannot repair earlier
incompatible final acceptance. It does not reopen the selected fault target.

Primary sources rechecked:
- [CometBFT consensus rounds](https://github.com/cometbft/cometbft/blob/main/spec/consensus/consensus.md):
  rounds and proof-based lock changes address competing proposals within the
  applicable validator model; they do not bootstrap arbitrary local electorates.
- [CometBFT light-client verification](https://github.com/cometbft/cometbft/blob/main/spec/light-client/verification/README.md):
  verification starts from an externally trusted initial header and has explicit
  temporal fault/trusting-period assumptions. This supports separating initial
  authentication from subsequent evidence verification; HuMoCo has not adopted
  its temporal assumptions, blockchain or verification protocol.
- [Stellar Consensus Protocol, section 4.1](https://stellar.org/papers/stellar-consensus-protocol.pdf):
  independent local trust choices still require honest quorum intersection for
  common safety. Local trust is an alternative model, not an exemption from this
  obligation or proof that F2F discovery automatically meets it.

Pending substantive scope question S2.1a (not answered/selected):
A (recommended investigation direction): operators and recipient applications
recognize an explicitly authenticated common starting context for the network in
which they accept FINAL, e.g. a verified fingerprint committing to initial
membership/rules, with later authority derived through justified transitions.
Keep discovery subjective and permit complete founding-member turnover. Selection
would authorize investigating this initial trust basis, not approve a complete
committee history, an algorithm, permanent founders or automatic software updates.
B: retain independently chosen F2F-derived trust domains, with FINAL guarantees
scoped to domains satisfying justified honest intersection/continuity; no automatic
irreversible cross-domain acceptance merely because both sides have twenty nodes.
This is a viable reduced guarantee, not a demonstrated arbitrary-local-HRW design.
Do not present these as the only mathematical constructions or as equivalent
guarantees. Neither option has been selected in this continuation.

Remaining dependencies: exact initial roster derivation (including sub-quorum
islands), authenticated distribution to nodes AND recipients, admission/new-set
fault assumptions, stale-prefix/latest-context discovery, temporal corruption,
closed old writes, late certificates, state/obligation availability and installation,
and round recovery. A common starting fingerprint alone solves none of these.
Verification obligations include rejecting a self-declared foreign initial set,
conflicting initialization under one claimed network label, incompatible successor
proofs and stale-context new signing, while preserving earlier valid certificates.
Later implementation must use shared canonical vectors and adversarial real-QUIC
tests. No production code, Rust tests, commits or PRs changed; S2–S4 remain open.

### 7.12 One intended global network; subsequent question withdrawn in 7.13

<a id="evidence-dec-047"></a>

Maintainer clarification: HuMoCo tends toward one global network. Separate networks
have no intended ordinary-use incentive; single-digit startup groups and deliberate
island operation can be exceptions. A client wants a good provider connected to the
global node network. Do not force a product choice between permanent independent
networks or infer that this answer selects section 7.11 A or B. In particular no
common genesis fingerprint or explicit committee-history scheme was approved.

The previous A/B framing combined two different questions: desired network topology
and the evidence/assumptions needed for common finality. Record the former as clarified;
retain the latter as open. Do not insist that the counterexample's permanently
separate groups are the expected deployment. The smaller existing examples of two
different local top twenties during growth and a write racing newcomer synchronization
(sections 7.3/7.9) remain relevant within one intended connected network. Ordinary
message delay, partitions and selective adversarial delivery do not require a product
incentive to maintain separate networks. An honest globally oriented provider also
cannot infer complete, contemporaneous discovery from its intent or connectivity.
None of this establishes attack frequency or that a global anchor is uniquely necessary.

Primary-source context rechecked: [Stellar, sections 3 and 4.1](https://stellar.org/papers/stellar-consensus-protocol.pdf)
also targets organic worldwide growth while defining safety through honest quorum
intersection and allowing adverse message delivery. The applicability to HuMoCo's
specific HRW/handoff construction remains to prove.

Historical proposed question S5.1a (withdrawn as the next policy question in 7.13):
A (recommended): previously valid FINAL remains irreversible across temporary or
initially unnoticed partitions. Affected new FINAL writes may have to wait if the
required authorized quorum/continuity evidence is unavailable; unrelated shards may
continue. This does not require proving live connectivity to every node or detecting
every partition, and is compatible with progress after stabilization under the already
selected conditions. Exact gates and bootstrap are still design work.
B: permit local FINAL during incompatible views to be revoked/VOID after merge.
This explicitly weakens recipient acceptance: goods may already have been released
for a payment later invalidated. It is a possible changed guarantee, not a mechanism
approved by the network-convergence clarification. Neither option grants authority
to arbitrary twenty-node sets or proves an algorithm. Do not conflate lack of new
FINAL with a conflict response or silently authorize a new PROVISIONAL fallback.

This question makes the outstanding FINAL-versus-VOID tension explicit before
prescribing bootstrap machinery. Existing rules against timeout-driven replacement,
hearsay bans and singleton min-hash takeover remain selected. No protocol code,
test campaign, commit or PR changed; only these working interview documents changed.

### 7.13 Maintainer reaffirms the existing twenty-node FINAL policy

<a id="evidence-dec-048"></a>

The maintainer explicitly says this was already defined: from twenty nodes the
system assumes FINAL. They regard two spontaneously arising independent networks
of twenty nodes as unlikely because adoption spreads through existing users,
independent operation has no intended benefit, and users want worldwide protection.
Retain the established 14/20 certificate and stability requirements; the clarification
does not mean a node count alone confirms an individual payment.

The assistant's repeated bootstrap/domain and partition-finality A/B questions did
not advance the agreed interview. Withdraw S5.1a as the next policy question; do not
record A or B as selected, permission to revoke FINAL, or approval of a genesis
anchor/history mechanism. The requirement/operating-model clarification is settled.
Record spontaneous independent large-network formation as outside the intended normal
deployment model, based on the maintainer's qualitative assumption, without inventing
a probability or claiming cryptographic impossibility. Do not silently extend this
to excluding adversarial partitions, delayed discovery, or growth-driven view changes.

Next perform technical investigation of minimal safe handoff within the intended
single growing network. A useful conditional subproblem starts with an authenticated
existing twenty-member committee and examines closed old writes, preserved outstanding
choices, successor installation and automatic round recovery. Clearly retain initial
roster justification and local-view compatibility as open prerequisites rather than
claiming this conditional starting point is already implemented or generally established.
No globally complete topology, common anchor or full committee history is selected.
Previously established ordinary-growth/write-race counterexamples still constrain
candidate mechanisms, without making two independent networks the primary scenario.

Requirement selected/reaffirmed: N >= 20 FINAL operating policy in one organically
growing network. Handoff design, membership/fault derivation, integration and wire
verification remain open. Only working notes/handoff changed; no production edits,
test campaign, commit or PR occurred.

### 7.14 Resume substantive decisions: outstanding payment votes during handoff

The maintainer requests continued systematic progress with recommended A and viable
alternative B, as in the earlier interview, to reach project completion. Continue one
substantive decision at a time; record answers and follow their technical dependencies.
This authorizes continuation of architecture research/documentation, not production
implementation or finalizing the plan before material design obligations are resolved.

Active leaf S3.3, conditional on a justified existing committee (S2 remains open):
resume the still-unanswered section 7.5 choice. Each old member can know its own
binding vote while an aggregate fourteen-vote certificate is held only by a client
or gateway. Copying only certificates currently visible to servers therefore omits
potentially completed payments. This is within one growing network and does not
depend on spontaneously separate global networks.

Targeted read-only reinspection: `storage/engine.rs` still enqueues `PutHmcLock`
without per-entry commit acknowledgement in the inspected path; `network/transport.rs`
then constructs a local attestation after the ingress result, including chain and
single-lock paths. The already-selected durable-choice change remains necessary;
it has not been implemented merely because it was selected. No tests were run.

Primary comparison rechecked: [Sui Lutris, section 2.4 and 4.2](https://docs.sui.io/paper/sui-lutris.pdf)
defines finality after quorum acceptance of the transaction certificate, with two
network round trips, and uses coordinated epoch closure. Its ability to release
incomplete locks relies on those rules; do not import resets into HuMoCo's existing
one-round FINAL semantics. This is a comparison, not an adopted protocol or proof.

Pending choice, no answer yet:
A (recommended KISS direction): retain payment confirmation from fourteen binding
votes in one collection round. Handoff must preserve the safety-relevant effects
of justified own/inherited choices even when no aggregate certificate is available
to the servers. An incomplete conflicting submission may leave its own slot and
dependent descendants unresolved; unrelated branches continue. A reservation is
not FINAL and unverified claims cannot establish obligations. Exact admission,
aggregation, compatibility, closure and late-certificate rules must still be proved;
do not let a bare Byzantine conflicting vote automatically invalidate a proven FINAL.
B: investigate changing payment completion to a preparation round followed by a
separate quorum-confirmed completion round, with explicit safe handoff cutoff and
incomplete-preparation rules. FINAL is issued only after the completion evidence.
This adds a payment round and changes client/core/wire semantics; it does not alone
solve handoff, erase previously binding votes, or guarantee fewer blocked slots.
Neither option is an approved implementation or a completed safety/liveness proof.

After this answer, investigate exact closure/obligation inclusion and bounded state
installation, then automatic competing-transition recovery, keeping authenticated
participant justification open. Do not repeat the N >= 20 or separate-network choice.

### 7.15 Clarification: existing lock records are the handoff data

The maintainer challenges the wording about a missing returned aggregate certificate:
if a lock was inserted, the other signers inserted it too; the data should simply
be reconciled. This is a clarification request/proposal to reuse existing lock sync,
not an explicit selection of section 7.14 A or B.

Clarify the assistant's example: the lock is present at the signers, and absence of
an aggregate certificate at a server does not make that local record disappear.
The risk described was conditional on a handoff incorrectly filtering out records
without locally known aggregate FINAL evidence. Such filtering is not being attributed
to the inspected implementation. The existing accepted lock record can embody the
relevant per-slot binding decision; no second product-level reservation object or
mandatory certificate-return round follows from this example. Aggregate certificate
distribution to every old server is not a prerequisite of the proposed A direction.

Recommendation remains to reuse bounded lock reconciliation/transfer and establish
its exact correctness conditions: preserve all safety-relevant authenticated own and
inherited collision constraints, including those whose aggregate certificate is held
elsewhere; close old writes and transfer final deltas before new voting. An empty
or incomplete copy is not evidence of a free slot. A pre-copy followed by an old
write and then newcomer activation illustrates why a final cutoff is needed even
with perfectly copied initial data. This does not prove a complete handoff mechanism,
require all twenty members online, or make arbitrary Byzantine records authoritative.
Confirmed-lock preservation must also coexist with unresolved partial conflicts.

Explain these as conditions of reliable data reconciliation before asking another
preference question. Keep the one-round versus redesigned completion choice pending;
do not infer approval of an entire protocol from the clarification. No code/tests changed.

### 7.16 Resumed clarification and pending Q-S3.3-01 presentation

Node: S3.3; prerequisite S2 remains unresolved. Date: 2026-10-15 (Europe/Berlin).
The maintainer invoked the start/resume prompt without a new scope or an answer.
CP-0003 matches both memory files; no intervening completed checkpoint was found.
Read the decision register, active dependency evidence in §7.5–7.10, §7.14–7.15,
and the legacy settled directions/counterexamples. No decision was reopened.

Clarification for the pending explanation: the maintainer's existing-lock transfer
proposal is a suitable data-reuse direction. If fourteen nodes have accepted and
durably signed A, their local records exist even if only a gateway holds the aggregate
certificate. No additional product-level reservation subsystem follows. However,
copying at time t does not include a lock accepted after t. The conceptual ordering
to investigate is pre-copy, justified closure of old writes, transfer of final deltas
and relevant own/inherited binding effects, then verified successor installation
before new voting. This ordering is a proof obligation, not an implemented algorithm.
It does not require all twenty old nodes online. Arbitrary peer claims are not
authoritative; genuine partial conflicts and a proven FINAL must be distinguished.

Recommendation A remains conditional on a safe handoff construction: preserve the
existing one-round payment interface and reuse lock data. B is a meaningful protocol
redesign alternative with an extra payment round, not a demonstrated cure for
blocked slots or incomplete transfer. The old-copy/new-write race remains relevant
to either construction. No new external factual claim or implementation finding is
introduced; the explanation uses the recorded abstract counterexamples.

Exact German presentation of the existing question (translation/clarification only;
same ID and A/B meanings as §7.14, not a new choice):

> **Q-S3.3-01: Welche Richtung sollen wir für die weitere Ausarbeitung wählen?**
>
> **A – Empfehlung:** Zahlungsbestätigung weiterhin mit 14 bindenden Stimmen in
> einer Sammelrunde. Bei der Übergabe bleiben auch sicherheitsrelevante eigene und
> übernommene Bindungen erhalten, deren vollständiges Zertifikat den Servern fehlt.
> Ungeklärte Teilkonflikte können den betroffenen Ausgabeslot samt Nachfolgern
> blockieren; unabhängige Zweige laufen weiter.
>
> **B:** Einen Zahlungsablauf mit Vorbereitung und einer zusätzlichen, durch Quorum
> bestätigten Abschlussrunde untersuchen. FINAL entsteht erst nach diesem Abschluss.
> Das erfordert geänderte Client-/Protokollregeln; sichere Übergabe und der Umgang
> mit unvollständigen Vorgängen müssen auch dafür erst begründet werden.

Question status: awaiting answer; neither option selected. Free-form answers remain
valid. Design open; implementation and verification pending. Next action: await and
record the substantive answer, then investigate closure/inclusion/installation under
the selected direction before S4 recovery. Do not infer an answer from invocation,
silence, ordinary sync or a generic continuation request.

### 7.17 Certificate terminology and reliable successor operation

Node: S3.3 / S3 / N3. Date: 2026-10-15 (Europe/Berlin).
Question status: clarification of Q-S3.3-01, not an A/B selection.

The maintainer asks what “certificate” means in the statement that only a gateway
may hold it, and emphasizes that newly participating shard nodes must reliably take
over the data and continue operating. This reaffirms the continuity/recovery intent
of DEC-026/031/045; no additional payment round or handoff algorithm is selected.

Terminology: in the interview's one-round model, a payment quorum certificate means
the collected valid attestations of fourteen distinct eligible committee identities
for the same lock and bound signing context. An individual attestation is one vote;
the collected evidence shows the threshold was reached. The exact canonical fields,
encoding and membership-verification rules remain unresolved. “Only the gateway”
describes a possible evidence-distribution scenario: the collector can hold all votes
while each signer knows its own vote/local record. It is not an audited claim about
current wire responses, a requirement for exclusive gateway custody, or a separately
selected certificate subsystem. Prefer “collected fourteen node confirmations” in
the explanation to avoid introducing an unexplained object.

Reliable takeover is the selected goal. Acceptance obligations for the candidate
handoff remain: preserve relevant unexpired locks and own/inherited binding effects;
include writes accepted during pre-copy through justified closure/final deltas;
verify and durably install the required state before successor write votes; preserve
collision/idempotency behavior and keep affected unready signers gated while safe
recovery proceeds. Other ready shards continue. An empty/incomplete download does
not establish a free slot. Cryptographic admission, partial conflicts, inclusion,
activation, old-quorum loss and automatic transition recovery still need design.
The list is a requirement decomposition, not a completed mechanism or safety proof.

Next action: explain the term and connect it to the maintainer's takeover goal;
do not force an extra preference question during this clarification. Q-S3.3-01
remains unanswered with the same A/B meanings. After clarification, resume concrete
closure/inclusion/installation analysis and resolve the pending choice only where
the payment-semantics tradeoff is necessary. No production edits or tests.

### 7.18 Maintainer-directed detour: shared dictionary first

Record: GLOSSARY-001. Node: K3 (active); S3.3 is parked at its existing return point.
Date: 2026-10-15 (Europe/Berlin).

The maintainer asks to briefly switch tasks: first create a glossary/dictionary of
basic concepts to avoid recurring misunderstandings, review it together in the next
step, and subsequently check consistent terminology throughout the project.
This authorizes a terminology draft; it is not an answer to Q-S3.3-01 or approval
of any new protocol mechanism. Preserve earlier decisions and the interview cursor.

Observed existing solution: `docs/TRANSLATION_GLOSSARY.md` already supplies canonical
German/English mappings but lacks many basic distinctions involved in the current
confusion. Extend this existing reference rather than creating a competing glossary.
Keep its existing mappings/directives unchanged pending review. Add draft G-001–066
for roles, locks/causality, attestations/quorum/certificates, status/uncertainty,
network boundaries, data takeover, persistence and fraud evidence. English definitions
retain German conversation headwords and existing Rust identifiers.

Evidence: targeted reading of `AGENTS.md`, existing glossary, Specs 00/02/03/06/12,
core `types.rs` / `client_flow.rs`, node `api/dto.rs` / `api/hmc.rs`, and existing
interview decisions. Source pointers identify the basis per group; this is not a
repository-wide terminology/security audit. TERM-01–13 collect review questions,
including overloaded certificate/confirmation/reservation words, FINAL/VOID,
durability/latency, identity/ticket distinctions and the retained High Assurance
specification versus binary-regime/code discrepancy. No substantive contradiction
is silently resolved and no production path is renamed.

Delivery status: draft created; definitions await maintainer review. Step two is
reviewing coherent term groups, beginning with locks, individual node confirmations
and quorum evidence. Step three is checking approved meanings across instructions,
specifications, interview records, source comments, APIs and tests. That later audit
and any consistent renaming are not completed here. Preserve historical records and
record corrections rather than rewriting history as if old proposals were decisions.

Return point after the detour: S3.3, §7.17 and Q-S3.3-01, still unanswered with the
same A/B options; continue concrete closure/inclusion/installation analysis. S2
membership justification remains unresolved. No new question or protocol selection.

### 7.19 German glossary walkthrough requested

Node: K3. Date: 2026-10-15 (Europe/Berlin).
The maintainer requests German explanations of the glossary terms. Provide a
plain-language chat walkthrough in G-001–066 order, followed by existing section-1
terms not already explained. Retain the IDs for precise subsequent corrections.
Explain the distinct scopes of client signatures, individual node votes, quorum
evidence, storage acknowledgements and transfer readiness, with short examples.

This is explanation for review, not approval of all definitions. No user correction
or selection has yet been received, and TERM-01–13 remain review items. Existing
meaning/policy conflicts remain explicit, especially FINAL/VOID and handoff safety.
No automatic transition, complete recovery proof or gateway trust is implied.

Next action after the walkthrough: take maintainer corrections/review of coherent
term groups, update proposed definitions accordingly, then perform the requested
repository-wide alignment as a later step. Keep S3.3 parked and Q-S3.3-01 unanswered.
The glossary file remains an English repository reference with German headwords;
the requested German explanation is delivered in chat.

### 7.20 Parent terminology, client authorization and digest wording

Node: K3. Date: 2026-10-15 (Europe/Berlin).
The maintainer suggests “Eltern-Lock” for the preceding lock, asks whether request
authorization signing happens when a gateway forwards a lock, and requests a clearer
German word for shard digest. These are vocabulary suggestions/clarifications,
not answers to Q-S3.3-01 or approval of the entire glossary.

G-014: add the proposed “Eltern-Lock” wording; distinguish the predecessor lock
from a specific spend slot/output, especially after a split. Preserve the code
identifier `parent_lock`; exact output binding remains open.
G-021: explain client-side spending authorization before gateway forwarding.
Targeted evidence: `api/hmc.rs` `L2LockRequest` carries `layer2_signature` and
`sender_ephemeral_pub`; `verify_l2_lock_signature` verifies the request signature.
Its semantics differ from gateway transport authentication, ingress `auth_signature`
and later shard attestations. This is a targeted static read, not an end-to-end audit.
G-049: recommend “Shard-Zusammenfassung” as a plain German name, pending selection;
retain English “Shard digest.” Avoid narrowing every digest to one checksum or
implying a complete copy of all records. No repository-wide renaming is performed.

Next action: answer these three points briefly in German and continue glossary
review from maintainer feedback. The remaining draft definitions are unapproved.

### 7.21 Naming client authorization: signature versus combined evidence

Node: K3. Date: 2026-10-15 (Europe/Berlin).
The maintainer suggests “Lock-Signatur” instead of “Antragstellersignatur,” points
to revealing the public key matching the preceding hash, and requests several names.
No name is finally selected. Explain the distinction between checking the revealed
key against the predecessor output commitment and verifying authorization with the
corresponding private-key signature. A public-key revelation alone is not control
of the private key; neither component alone is complete lock/quorum validity.

Added a naming-review paragraph near G-021. Candidates: Lock-Signatur and
Freigabesignatur for the signature; Freigabenachweis, Berechtigungsnachweis and
Lock-Autorisierung for the broader authorization evidence. Recommendation for review:
Lock-Signatur for the signature, Freigabenachweis for the combined evidence.
This is an explanatory vocabulary distinction, not selection of another stored
object, wire message or proof format. Exact predecessor/output verification and
signed-field coverage remain design/audit obligations. Targeted reads of HMC fields
and signature verification do not prove those checks across all production paths.

Next action: present the alternatives and their scopes in German, then continue
maintainer review. Other definitions remain draft; Q-S3.3-01 remains parked.

### 7.22 Execution plan for terminology alignment

Record: GLOSSARY-002. Node: K3. Date: 2026-10-15 (Europe/Berlin).
The maintainer requests a plan an AI can use to review and, where justified, adjust
glossary usage in code comments and specifications for consistent language.
This turn creates the plan; it does not execute the repository-wide audit.

Created `prompts/terminology_alignment_plan.md` and linked it from the prompt index.
The plan covers applicable instructions, original mappings and all glossary entries,
current specs/guides, source comments/Rustdoc, relevant code as evidence and maintained
prompts. Historical/interview records retain provenance. Its stages establish scope,
review definitions/status, inventory contextual occurrences, classify drift versus
meaning conflicts, apply editorial fixes, verify and report coverage/remaining work.

The future run maintains `docs/TERMINOLOGY_ALIGNMENT_REPORT.md`; that report is not
created or represented as completed by plan preparation. G-014/021/049 suggestions
and the signature/combined-authorization distinction remain proposals. Clear wording
can be corrected while substantive policy conflicts stay explicit. Runtime behavior,
identifiers, interfaces and wire formats are outside the editing scope. No automatic
promotion of the interview's proposed mechanisms or altered safety claims is allowed.

Plan verification: read back the plan and index link, check relative links, review
scope/acceptance criteria and run whitespace checks. No full terminology review,
production/specification edits, Rust/QUIC tests, commit or PR. Next action: execute
the plan when requested, or continue maintainer glossary review. K3 remains active;
Q-S3.3-01 remains parked without an answer.

### 7.23 Execute and reconcile the terminology audit

Record: GLOSSARY-003. Node: K3. Date: 2026-10-16 (Europe/Berlin).
The maintainer explicitly requests execution of the saved alignment plan in the
new chat. This authorizes investigation and editorial alignment, not selection of
proposed names, a payment protocol, changed interfaces or production behavior.

Starting revision `02983adeda594d7610194cb6a4d0abcb118ef051` already contains an initial
alignment report and TA-001–017. The working tree was clean. The saved CP-0011 state
still described the audit as pending, so this continuation reconciles that cursor
with actual repository contents and preserves the existing work.

The report continuation and file inventory account for current specs, both 15/16
filename variants, root guides/prompts and first-party Rust source/test comments,
while distinguishing screening from contextual evidence review. Editorial fixes
separate simulated deterministic test signatures from production Ed25519 approval,
node attestations from quorum certificates, decoding/counting from verification,
node keys from fingerprints/routing tickets, node ban lists from collision locks,
and client double-spend from node equivocation. Remaining identified German
production comments are translated. Historical audit wording is preserved with
a current-status pointer; remaining legacy guide/test language debt is explicit.

The glossary remains the only dictionary. Established meanings receive factual
qualifications; G-014/021/049 names stay proposed. No complete uniformity or protocol
safety claim follows. FINAL/VOID, High Assurance, durability/SLA, justified membership,
handoff/recovery and canonical-format differences remain substantive work. The
report corrects the old claim that `cargo check --tests` established passing doctests;
that inherited command claim was not rerun or independently verified here.

Verification: report section 7.5 records the actual final static checks and limits.
No executable Rust logic, runtime strings, identifiers, wire/API fields, dependencies,
thresholds or timers changed; no build/test suite, commit or PR in this continuation.
Next action: review remaining K3 names and consolidate recorded conflicts, then return
to S3.3. Q-S3.3-01 remains parked and unanswered; S2 remains unresolved. The audit
execution request is not an A/B answer or wholesale approval of the glossary draft.

### 7.24 Resume the pending client-authorization naming review

Record: GLOSSARY-004. Node: K3, bounded focus G-021.
Question: Q-K3-G021-01. Date: 2026-10-16 (Europe/Berlin).
Status: proposed naming distinction; awaiting maintainer answer. No selection.

The maintainer invokes the architecture-interview procedure without changing scope
or answering a pending question. Both memory files exist and match completed
CP-0012; no missing memory requires creation or legacy migration. Resume the recorded
K3 naming review. G-021 is next because the preceding clarification distinguished
one signature from the wider authorization evidence (§7.21), with no final name.
G-014/049 and the report's substantive conflicts remain queued within K3. The
previous S3.3 question stays parked; this invocation is not an answer to it.

Evidence: glossary §3.3; §7.20–7.23; alignment report §7.3. Targeted read-only
reinspection of `api/hmc.rs::L2LockRequest`, `calculate_l2_payload_hash` and
`verify_l2_lock_signature` confirms separate `sender_ephemeral_pub` and
`layer2_signature` fields and verification of the request signature under that
public key. This function alone does not check the predecessor-output key binding
or prove end-to-end authorization correctness; those remain OPEN-06 obligations.

Recommendation A: use “Lock-Signatur” for the individual spending-client signature
and “Freigabenachweis” for the combined authorization evidence: disclosed public
key matching the predecessor output's commitment, plus its valid request signature.
This retains the maintainer's proposed signature name and distinguishes the whole
authorization relationship. A disclosed public key alone does not establish private
key control. Neither term establishes node-quorum payment confirmation. The names
do not select a new proof object, encoding, stored record or wire message. Genesis
authorization is a distinct case under DEC-005, not an invented predecessor output.

Exact German question (quoted interview wording):

> **Q-K3-G021-01:** Sollen wir für G-021 „Lock-Signatur“ für die einzelne Client-Signatur und „Freigabenachweis“ für den beschriebenen Gesamtnachweis übernehmen?
>
> **A – Empfehlung:** Diese beiden Begriffe mit den beschriebenen Bedeutungen übernehmen.

Free-form naming/correction remains possible; no B/C is defined or implicitly
rejected. Silence or a generic continuation does not select A. Other naming
candidates in §7.21 remain unselected, not rejected. Design/proof packaging and
implementation/verification remain open; no protocol policy is reopened here.

Next action: ask Q-K3-G021-01 and await its answer. On an answer, record the precise
selection/correction, then continue the remaining K3 names. Do not treat approval
of this pair as glossary-wide adoption or an answer to Q-S3.3-01. Keep substantive
conflicts explicit and follow their existing architecture dependencies.

### 7.25 Client authorization names selected; parent-lock naming next

Record: GLOSSARY-005. Node: K3. Date: 2026-10-16 (Europe/Berlin).
Answered question: Q-K3-G021-01. Exact maintainer answer: `a`.
Decision: DEC-049, accepted A with the meanings recorded in §7.24. Replace the
G-021 German signature headword with “Lock-Signatur”; record “Freigabenachweis”
as the combined client authorization evidence. Update the existing glossary,
preserving identifiers and English technical terms. The previously proposed
“Freigabesignatur,” “Berechtigungsnachweis” and “Lock-Autorisierung” are not selected
as preferred names; no separate technical rejection is attributed to the maintainer.
The choice retains the client's signature proposal and distinguishes one signature
from the overall evidence; no new proof structure or payment round is selected.
Naming design: resolved for this pair. Protocol design/verification: OPEN-06;
genesis remains a distinct case. Q-S3.3-01 is unchanged and unanswered.

Next bounded focus: G-014. Existing evidence is glossary §3.2 and §7.20: the
maintainer proposed “Eltern-Lock,” while a split can have several independent
outputs. Recommend that name for the predecessor record and “Vorgängerausgabe”
for its particular consumed output. This preserves the proposed plain-language
name without conflating a record with one spend slot. No split representation,
identifier migration or wire layout is selected; exact output binding is OPEN-06.

Exact German question, Q-K3-G014-01:

> Sollen wir „Eltern-Lock“ für den Vorgänger-Lock übernehmen und dessen konkret verbrauchte Ausgabe bei Bedarf „Vorgängerausgabe“ nennen?
>
> **A – Empfehlung:** Diese Begriffe mit der beschriebenen Unterscheidung übernehmen.

Question status: awaiting answer; free-form corrections allowed, no B/C defined.
Next action: ask Q-K3-G014-01 and record the answer before continuing to G-049.
Keep substantive conflicts on their existing branches; return to S3.3 after K3.

### 7.26 Parent terminology selected; shard-digest naming next

Record: GLOSSARY-006. Node: K3. Date: 2026-10-16 (Europe/Berlin).
Answered question: Q-K3-G014-01. Exact maintainer answer: `a`.
Decision: DEC-050, accepted A as recorded in §7.25: “Eltern-Lock” for the
predecessor record; “Vorgängerausgabe” for its specific consumed output. This
preserves the distinction needed when a lock creates independent split outputs.
Naming design resolved; exact output binding/design and verification remain
OPEN-06. Update G-014 in the existing glossary; retain `parent_lock`, formats
and historical proposals. No new split mechanism or protocol policy is selected.

Next bounded focus: G-049, the remaining specifically proposed name. Basis:
glossary §3.6, §7.20 and alignment report §7.3. Recommend “Shard-Zusammenfassung”
for the existing English concept “Shard digest”: compact comparison information
used to identify state differences before transferring relevant records. It is
not a full state copy, a quorum certificate or sufficient recovery-readiness
evidence. “Prüfsumme” would unnecessarily restrict the possible representation;
no hash/tree/Bloom-filter implementation is selected by this vocabulary choice.

Exact German question, Q-K3-G049-01:

> Sollen wir „Shard-Zusammenfassung“ als deutschen Begriff für „Shard digest“ übernehmen?
>
> **A – Empfehlung:** „Shard-Zusammenfassung“ mit der beschriebenen Bedeutung übernehmen.

Question status: awaiting answer; free-form corrections allowed; no B/C defined.
Next action: ask Q-K3-G049-01 and record the answer. Then reconcile the remaining
K3 review obligations and substantive-conflict routing before returning to S3.3.
Do not infer glossary-wide approval, safe recovery or an answer to Q-S3.3-01.

### 7.27 Glossary naming complete; autonomous editorial alignment

Record: GLOSSARY-007. Node: K3. Date: 2026-10-16 (Europe/Berlin).
Answered question: Q-K3-G049-01. Exact answer: `a`. DEC-051 accepts
“Shard-Zusammenfassung” for “Shard digest,” with §7.26's boundaries.

The maintainer then explicitly instructs the agent to stop asking glossary
questions, unify the terminology independently, and allow later vocabulary
adjustments without requiring feedback. DEC-052 records that scope and workflow
change. Naming approval is complete; do not ask for dictionary-wide ratification.
This supersedes the earlier per-name review workflow and proposed-name gates in
the reusable terminology plan. Prior question records remain historical.

Next action: align the existing glossary, maintained plan, current documentation
and source comments under the updated authorization. Preserve historical records,
identifiers, executable behavior and substantive protocol requirements. Record
actual changes and checks in the existing alignment report. FINAL/VOID, durable
vote release, membership/handoff, formats and network-boundary conflicts remain
architecture obligations, not blockers to independent editorial improvements.
Q-S3.3-01 remains unanswered; return there after the editorial pass, with no
inference from the preceding glossary answers. No new architecture choice.

### 7.28 Complete autonomous editorial alignment and resume architecture work

Record: GLOSSARY-008. Node: K3 completion; return to S3.3.
Date: 2026-10-16 (Europe/Berlin).
Names and editorial maintenance policy are settled (DEC-049–052). Updated the
single glossary, current specification prose/diagrams, source comments, roadmap,
task heading and maintained prompts; changes/checks are in alignment report §8
and the continuation inventory. No further glossary feedback is needed. Explicit
legacy anchors preserve existing glossary links; earlier questions/candidates
remain history, not pending choices.

The current pass distinguishes individual client signatures, combined client
authorization evidence, node attestations, assembled quorum certificates and
compact shard digests. Digest documentation now describes the actual hashed
projection rather than claiming complete-record equality or guaranteed safe
handoff. This is a comment correction, not a runtime or normative protocol change.
The report also retains the Spec 15 automatic-sanction idea and Spec 16
client-conflict/receipt-gossip passages as substantive F1/S6/N4 conflicts.

K3 naming/editorial work is complete for the recorded screening; future refinements
are autonomous. Legacy language translation and substantive consolidation remain
separate work, not reasons to keep requesting vocabulary approval. Return to S3.3
because old-write closure, preserved binding effects and successor installation
must precede any justified consolidated handoff wording. S2 remains unresolved.

Pending question: the unchanged Q-S3.3-01, exact German wording/options in §7.16.
Neither A (one collection round with preserved justified binding effects) nor B
(investigate separate preparation/completion payment rounds) has been selected.
Recommendation A remains conditional on a justified handoff; no new question or
option mapping is created here. Next action: resume bounded closure/inclusion/
installation analysis from §7.15–7.17, then use that pending choice where the
payment-semantics tradeoff is necessary. Do not infer any protocol answer from
the glossary answers or current editorial authorization.

### 7.29 Resume S3.3: closure boundary, minority witnesses and installation

Record: S3.3-INVESTIGATION-001. Date: 2026-10-16 (Europe/Berlin).
Resume checks: both memory files end at CP-0017. Read the current register,
§7.5–7.10, §7.14–7.17, §7.27–7.28, the glossary and alignment report §8.
The maintainer requests technical investigation and one justified decision question
only when needed; glossary work stays complete. No answer to Q-S3.3-01 is inferred.

**Scope and evidence.** Analyze the one-round candidate conditionally, within one
justified old twenty-member committee, with at most six Byzantine identities over
the relevant signing/closure interval and no honest loss/rollback of binding state.
S2 has not established those membership/temporal assumptions. This does not select
a globally uniform roster/history scheme. Targeted static inspection at HEAD
`43139a3` (clean working tree before this update):

- `network/transport.rs` checks the shared readiness flag at entry to
  `LockVerifyRequest`, then reaches awaited ingress and later attestation creation
  (single-lock and chain paths). This entry check alone is not a durable per-shard
  old-write fence covering already admitted handlers.
- `storage/engine.rs::FlushOp::PutHmcLock` carries the entry and lookup tag, with
  no per-entry commit acknowledgement. The inspected ingress enqueues it; the
  flush worker commits separately. DEC-029/033 remains selected but undelivered.
- `daemon.rs::run_shard_digest_pull_sync` sets readiness after its convergence/
  completed-pull logic. Successful page transport and matching summaries do not
  establish old-write closure or durable installation of every binding effect.
  This is a bounded path inspection, not an exhaustive source/security audit.

**Derived closure conditions; not an adopted algorithm.**

1. Pre-copy can run while the old committee operates. Before endorsing a final
   closed handoff state, each honest old endorser must durably fence fresh votes
   in that old writing scope and account for all its relevant own/inherited
   bindings. Already admitted work must either have its potentially released vote
   decision included, or be prevented from issuing an unaccounted binding vote.
   Merely flipping an entry flag, waiting 800 ms, closing sockets or taking a
   second live snapshot does not order this race. Admission, pending commits and
   vote release need a recoverable local ordering; no RAM lock across disk I/O
   or synchronous hot-path disk write follows from this requirement.
2. A candidate fourteen-member old closure quorum contains at least eight honest
   members under the stated bound. If all eight remain fenced, at most twelve
   old identities can still issue fresh votes, fewer than fourteen. This excludes
   a wholly fresh old certificate after closure. It does not erase pre-fence
   votes, including those delayed in the network: an old certificate may first be
   assembled/presented after closure and must retain its justified historical
   effect. Network silence is not a certificate-expiry rule.
3. Payment voters P and final closed-state endorsers C satisfy
   `|P intersection C| >= 14 + 14 - 20 = 8`; at least two are honest. If every
   honest endorser verifies inclusion of its earlier bindings before endorsing
   the SAME closed state, a previously certified payment cannot be wholly omitted.
   A list of fourteen unrelated reports, or fourteen signatures over an arbitrary
   state hash, does not satisfy that premise. Endorsements must bind the relevant
   predecessor scope, concrete successor and installed-state commitment; exact
   fields, compatible obligation representation and inclusion checks remain open.
4. Each honest successor must verify the handoff evidence and durably install the
   collision constraints and signing-safety state before its first successor vote.
   A crash between download, commit and activation must restart behind this gate.
   Enough installed eligible members are needed for progress; this argument does
   not require all twenty old or new members online or select a new readiness
   acknowledgement threshold. Repeated turnover must carry inherited effects
   forward until legitimate expiry, without permanent expired-lock tombstones.

These are logical ordering/proof obligations, not a fixed number of protocol
messages, extra payment rounds, a selected agreement engine or a new reservation
object. Competing partial closures still require DEC-046's safe round/recovery
mechanism; no timeout may simply undo fencing or prior signing choices.

**Why a minority report can matter.** Strengthen §7.5's visibility explanation:
let H1–H8 honestly sign payment A, H9–H14 honestly sign conflicting B, and M1–M6
be Byzantine. The Byzantine members sign A, giving A fourteen votes, but report
only B during handoff (they may also sign B). Choose closure participants
`C = H7–H14 + M1–M6`. Their reports show two A and twelve B; the six honest A
signers outside C are unavailable. B has at most twelve old votes in this schedule.
All honest members signed only once. Two A reports therefore cannot be discarded
as a minority or for lacking a locally assembled certificate. This is a symbolic
counterexample, not a QUIC test or attack-frequency estimate. Preserving A's binding
effect does not declare each individual report FINAL, nor does a bare Byzantine
conflict authorize invalidating a proven FINAL. Authentication alone cannot decide
which uncertified partial candidate can safely complete; exact compatibility,
late-certificate adjudication and slot-local blocking/resource bounds remain OPEN-01.

**Primary comparison rechecked.** [PBFT §4.3–4.4](https://pdos.csail.mit.edu/6.824/papers/castro-practicalbft.pdf)
uses certified checkpoints and retained view-change evidence; its fixed-membership
proof does not establish HuMoCo's turnover. [Sui Lutris §2.4/4.2–4.3](https://docs.sui.io/paper/sui-lutris.pdf)
explicitly addresses the snapshot/late-write race, pauses old locking and sequences
handover through its own checkpoint protocol. Its payment path includes certificate
redistribution and quorum execution; its reset rules cannot be imported into a
HuMoCo payment already FINAL after one collection round. These primary sources
support the comparison, not the HuMoCo set arguments or a completed project proof.

**Question and next action.** Re-present **Q-S3.3-01** with exactly §7.16's German
wording and A/B meanings. Conditional recommendation A: retain one-round payments
and reuse existing lock data while investigating the above preservation conditions.
Its real cost is possible slot-local blocking from unresolved partial conflicts.
B remains investigation of separate preparation and quorum-confirmed payment
completion; it changes client/core/wire semantics and does not itself prove safe
handoff or fewer blocked slots. No new ID, no approval inferred, no algorithm choice.
After an answer, record it and derive the selected direction's exact obligation
admission/compatibility and late-certificate rules before S4 round recovery; keep
S2 and safe retention explicit. Design open; production implementation and real
adversarial QUIC verification pending. No Rust tests, test campaign, commit or PR.

### 7.30 Clarify local signing versus acceptance of conflicting quorums

Record: S3.3-CLARIFICATION-001. Date: 2026-10-16 (Europe/Berlin).
The maintainer challenges the German phrase "Schreibbefugnis": each node can
insert a lock and respond when its own readiness and local shard-membership checks
permit it; requesters contact nodes they themselves rank within the shard's top
twenty. They ask what additional authority problem this description leaves.
This is a request for architectural explanation, not an answer to Q-S3.3-01 or
a new naming question. Preserve local node sovereignty and subjective discovery.

**Correction to the presentation.** The previous reply compressed the conditional
common-committee/handoff model into an apparent existing "writing authority."
That model has not been selected or proved; §7.8 already records the same objection.
No central permission issuer, globally identical current ranking, or accepted
committee-authorization history follows. The actual unresolved property is whether
the node confirmations accepted by different recipients can certify conflicting
uses of the same unexpired spend slot as membership/views change. A node's ability
to sign and a recipient's acceptance of that signature toward FINAL are separate
events. Request selection alone does not establish this cross-request property.

**Explain using the maintainer's local-view model.** Reuse §7.9's abstract race:
two newcomers copy an empty slot before payment A. One requester still sees the
old twenty; another sees twenty with two replacements. Both freeze twenty for
their own request. Let six Byzantine nodes be common to both lists. In the old
list, eight honest A voters comprise two departing members and six retained
members. The new list's eight honest B voters comprise the other six retained
honest members and the two newcomers. Byzantine members sign both A and B.
Each requester can collect fourteen confirmations; no honest identity signs both.
All fourteen honest old members are accounted for (eight A, six B), and all
fourteen honest new members are accounted for (six A, eight B). Newcomers' initial
copy was complete when taken. Local membership assessment, fixed per-request lists
and successful initial sync do not by themselves prevent this schedule. This is
our previously recorded symbolic counterexample, not new external research or an
executed attack. It assumes no additional proven transition/admission restriction.

**Consequence and next action.** Frame the handoff obligation as preventing an
old-view accepted payment from disappearing while newcomers begin confirming a
conflicting payment. Investigate which continuity/acceptance condition is sufficient;
do not present the coordinated closure candidate as the only possible mechanism.
Shared signing constraints among unchanged honest nodes help but the schedule
shows they alone are insufficient for two replacements under the six-Byzantine
target. S2 remains the explicit dependency; S3.3 is the sole active explanatory
focus. Answer this clarification without repeating the payment-round choice.
Q-S3.3-01 retains its original unanswered A/B meanings. No accepted decision,
glossary rule, production behavior or specification changes. Design/proof open;
no tests, commit or PR.

### 7.31 Reconciliation methods, candidate safety contract and model-first validation

Record: S3.3-RESEARCH-002. Date: 2026-10-16 (Europe/Berlin).
Maintainer asks for established efficient reconciliation methods (hashes/Merkle
trees, multiple sources), sufficient safety conditions and whether to simulate
before implementation. This requests technical investigation, not an A/B answer,
tree-library selection or permission for production changes/test campaigns.

**Two complementary tasks.** Reconciliation locates/transfers differing records;
handoff establishes which live effects must survive and when a successor may vote.
Under canonical encoding and collision resistance, equal roots commit to equal
encoded snapshot contents. They do not prove that those contents include every
binding decision made before an appropriate cutoff. Multiple sources improve
retrieval and expose differences; selecting a popular live root does not provide
that cutoff or justify dropping minority obligations (§7.29).

| Transfer option | Appropriate use / cost | Applicability to HuMoCo |
| --- | --- | --- |
| Sorted records, whole-snapshot hash, bounded pages | Simplest reference; transfers the whole differing snapshot, even for a small change. | Starting correctness baseline for measured small per-shard state; no assumption that a shard is always 1–3 KB. |
| Deterministic key-prefix/range buckets with hashes | Locate differing buckets, transfer only those buckets; additional metadata and partition rules. | Intermediate candidate if full snapshot transfer is costly. Fixed key ranges avoid page-shift ambiguity. |
| Canonical Merkle tree over keyed records | Compare roots, descend into differing ranges and verify transferred data against the committed root; tree/proof maintenance costs. | Candidate for larger state with small differences; not a finality or completeness oracle. No particular tree/library selected. |

All options need one named stable snapshot across pages/ranges, bounded byte/work
budgets, canonical fields/order/domain tags, authenticated context and proper
root-origin/expiry validation. A per-record inclusion proof does not establish
that the server supplied every record in a requested range. Reconstruct the whole
committed state or use justified range-coverage proofs. A snapshot identifier/hash
without the closure/inclusion contract still authenticates only that snapshot.
Own durable signing choices remain identity-specific: replicas need compatible
transferable collision obligations, not byte-identical private signer journals.
Trusted-time/expiry policy must be fixed for comparison; differing local expiry
filters must not silently drop still-protected obligations. Preserve root TTL,
grace and no-tombstone rules; retention remains OPEN-10/11.

**Primary sources and their limits, checked this turn.**

- [Apache Cassandra repair](https://cassandra.apache.org/doc/latest/cassandra/managing/operating/repair.html)
  compares Merkle trees and streams differences over shared ranges. This supports
  the transfer technique; its repair/tombstone model is not Byzantine payment safety.
- [PBFT §4.3–4.4](https://pdos.csail.mit.edu/6.824/papers/castro-practicalbft.pdf)
  combines certified checkpoints, state transfer and retained recovery evidence.
  Its fixed participant model does not prove dynamic HuMoCo membership.
- [Sui Lutris §2.4/4.2–4.3](https://docs.sui.io/paper/sui-lutris.pdf)
  separates state preparation, old locking closure and checkpointed takeover.
  Its consensus, stake and extra payment completion phase are not imported.
- [CometBFT consensus specification](https://raw.githubusercontent.com/cometbft/cometbft/main/spec/consensus/consensus.md)
  has proposal rotation and justified locks across rounds. It is a comparison for
  DEC-046 transition recovery within a defined participant instance, not permission
  to reset payment choices, gossip locks or add a chain runtime.
- [Kuznetsov/Tonkikh §3.4–4.2](https://drops.dagstuhl.de/storage/00lipics/lipics-vol179-disc2020/LIPIcs.DISC.2020.27/LIPIcs.DISC.2020.27.pdf)
  permits differing local knowledge via comparable certified histories, protected
  state transfer and temporal key assumptions. This remains a more general
  research alternative, not a solution for arbitrary unrelated local top twenties.
- [Lamport: A High-Level View of TLA+](https://lamport.azurewebsites.net/tla/high-level-view.html)
  describes explicit state/step models and model checking above implementation.
  A bounded model result is not a proof for all sizes or for the Rust/QUIC code.

**Recommended candidate to model, not a selected algorithm.** Reuse the accepted
affected-shard pause direction: pre-copy; gather authenticated own/inherited
obligations and durably close old voting including pending work; agree on one
compatible closed state/successor with justified inclusion; transfer final deltas;
verify/commit locally before successor voting. Initial replicas may hold different
partial states: do not require fourteen identical initial roots. A final common
commitment is the output of validated reconciliation/agreement, not a majority
shortcut for choosing an arbitrary initial state. A quorum signature is meaningful
only with honest inclusion/closure validation (§7.29) and justified participants.
The candidate requires a defined verifiable signer set for its handoff instance;
S2 has not selected how to obtain it from subjective discovery. No globally
simultaneously identical network map is assumed. Concurrent live handoff would
need another safe cross-view rule and more protocol work; do not reopen DEC-041
without evidence. Partial conflicting payments and late certificates remain open
under Q-S3.3-01; the candidate does not silently select A or B.

**Concrete model/validation work package.** Define two conflicting locks for one
unexpired slot and at least three committee generations (test inherited effects).
Track each node's local membership view, durable own choice, transferable bindings,
pending writes, durable closure/transition round and installed/active state; track
in-flight votes and independently held quorum evidence. Model events separately:
admit, commit choice, emit/deliver vote, snapshot/copy page, freeze, endorse a
candidate, install/commit, activate, crash/restart, change view and advance round.
Begin without real hashes/trees; model exact record sets and bounded authenticated
statements so the checker tests protocol logic rather than hash speed.

Required properties and adversarial schedules:

1. No two conflicting accepted FINAL outcomes for the same unexpired slot across
   allowed views/generations; never equate storage acceptance with FINAL.
2. Preserve previously released and inherited effects through repeated handoff;
   delayed collection/presentation of old certificates cannot create a free slot.
3. No unaccounted vote after durable closure; no honest successor vote before
   verified durable installation, including crash/restart between these steps.
4. No indefinite transition deadlock from competing partial proposals once
   communication, candidates and sufficient honest old/new participants stabilize.
   This is transition progress, not guaranteed completion of a malicious owner's
   conflicting payment. Without the stated availability/stability assumptions no
   bounded pause or completion guarantee is claimed.
5. Exercise §7.9/7.30's two-newcomer race, §7.29's minority witnesses, independently
   incomplete replicas, omitted/replayed pages, withheld certificates, 13-X/7-Y
   transition endorsements and crash at every durability boundary. Include a
   faulty variant that reproduces the known double-FINAL counterexample; a model
   that merely disables all votes must fail its progress check.

First write executable transition/admission predicates; do not hide unresolved
inclusion, membership or recovery behind an infallible oracle. Bounded exhaustive
checking (e.g. TLA+/TLC) should cover small instances and explicit 20/14/6 schedules;
small-instance success does not establish the general quorum argument. Then run
deterministic Rust event simulations with recorded seeds and fault schedules,
followed by mandatory real adversarial QUIC tests of the implemented rules.
Benchmark transfer alternatives only against the same validated state contract:
live records/bytes per shard, differing fraction, churn, expiry, RTT, transferred
bytes, CPU/RAM and tail pause/recovery times. No tree break-even point is measured.

**Existing implementation/test evidence, static only.** `crypto.rs::compute_shard_digest_at`
hashes a filtered projection; `daemon.rs::run_shard_digest_pull_sync` clusters digests
and pulls pages; `network/framing.rs::ActiveSyncRequest` has cursor/limit and no
snapshot commitment field. These are reuse points, not the above contract.
The inspected `spec_03_shard_baton_handover_and_growth.rs` initializes identical
old replicas and copies them in scripted generations; its noise test seeds fourteen
equal digests. It does not explore the listed interleavings. Fixture warning:
TARGET_SHARD is 1337 but the first parent starts with 0x4242, which the digest
filters to another shard. At least that first record is excluded; no claim that
all generated records are excluded was verified. Before reusing these tests,
assert intended shard coverage and that a relevant change actually changes the
digest, rather than relying on equality that could compare empty projections.
No tests, model checker, simulation or benchmark were run in this interview turn.

Next action: derive the minimal explicit handoff state machine/admission predicates
and its membership/partial-conflict/recovery prerequisites. Ask only if a resulting
product tradeoff needs the maintainer; do not ask them to choose tree/algorithm
names. Q-S3.3-01 remains unanswered with its original meanings. Design open;
implementation and verification pending. No binding spec/code changes, commit or PR.

### 7.32 Online transfer under write load: snapshots, deltas and protocol boundaries

Record: S3.3-RESEARCH-003. Date: 2026-10-16 (Europe/Berlin).
The maintainer emphasizes thousands of locks per second, continually differing
replicas, passive newcomer catch-up and a possible timestamp-X snapshot. They ask
for established solutions rather than a new invention. This is workload/design
steering and a technical question, not selection of Q-S3.3-01 A/B, a separate
signing journal or a guarantee of zero interruption.

**Established patterns, primary evidence checked.**

- [PostgreSQL exported snapshots / logical decoding](https://www.postgresql.org/docs/current/logicaldecoding-explanation.html#LOGICALDECODING-EXPORTED-SNAPSHOTS):
  initial state is paired with a change-stream position so subsequent replay does
  not miss changes during copying. Its origin log defines order; its documentation
  also requires duplicate-safe consumption after a restart and warns that stalled
  replication slots retain resources. This supports the snapshot-plus-deltas
  technique, not Byzantine completeness or a HuMoCo-wide ordered log.
- [etcd learner design](https://etcd.io/docs/v3.5/learning/design-learner/):
  a non-voting learner catches up with leader logs before validated promotion.
  The documented design also limits learners to avoid replication overload.
  Its described operator promotion/future automation is not HuMoCo's selected
  automatic-progress policy; Raft's crash-fault model is not the six-Byzantine model.
- [Bessani et al., USENIX ATC 2013, §3.3](https://www.usenix.org/system/files/conference/atc13/atc13-bessani.pdf):
  collaborative state transfer combines checkpoints and log segments from replicas
  with validation hashes, distributing transfer load despite differing checkpoint
  positions. It uses an agreement ID assigned by an ordering protocol and is
  implemented for BFT-SMaRt. This addresses the high-load transfer question, but
  cannot be copied as if independent HuMoCo local commit counters had that meaning.
  [BFT-SMaRt's own documentation](https://github.com/bft-smart/library#state-transfer-protocols)
  describes basic/advanced transfer and batching; this Java SMR library is a
  reference implementation, not a selected Rust dependency or a drop-in adapter.
- [Sui reconfiguration documentation](https://www.docs.sui.io/develop/sui-architecture/epochs)
  uses a consensus-derived reconfiguration trigger and finalizes remaining work/
  checkpoints at epoch closure. It does not use a client request timestamp alone
  to prove completion of all earlier writes. The different payment/consensus/stake
  assumptions in §7.31 remain explicit; no global Sui runtime is imported.

**Timestamp clarification.** Even a perfectly synchronized clock does not ensure
that every request labelled before X has arrived or completed before X. A delayed
or adversarially backdated request defeats such a cutoff. Retrying, replaying and
in-flight durable commits add the same issue. Use a justified protocol boundary
and source commit/change positions to describe completed work; network time still
serves the existing root-validity rules, not an invented old-write closure proof.
Local replica positions differ and must be bound to identity, snapshot and signing
context; equal numeric positions on two nodes do not identify equal contents.
HuMoCo has no already-approved global per-lock sequence. A possible collection of
per-source bounded ranges is a candidate transport construction, not a proof of a
consistent global cut, participant compatibility or safe successor activation.

**Candidate adaptation, conditional and unselected.**

1. A learned candidate prepares as a non-voter. Existing shard replicas, rather
   than gateways forwarding every ingress request, serve bounded shard-direct
   snapshot/delta pulls. This is a candidate extension of existing sync RPCs,
   subject to learned-peer authorization and resource budgets; no open gossip,
   automatic ingress bypass or extra checkout voter follows.
2. At a source, create a stable committed snapshot and atomically relate it to
   the beginning of retained changes. While copying its pages, collect/replay
   subsequent relevant changes. Do not start the feed after copying (gap), use
   moving offset pages (skip/duplicate risk), or equate a last received packet
   with completion. Require authenticated positions, range continuity/replay
   checks and explicit handling of truncated history. A hash chain can expose
   changes relative to a trusted endpoint, not omissions relative to reality.
3. Data from one or a few sources may supply bulk bytes; validated obligations
   from enough justified old participants determine what must be present.
   Do not require full copies from fourteen peers or fourteen equal initial
   roots. Different replicas can converge to one verified handoff state after
   reconciling their partial obligations. Source completion alone cannot select it.
4. Continue catch-up until final deltas are small, then use the previously chosen
   affected-shard pause direction to close old voting, account for pending work
   and establish a justified final state/successor. Transfer remaining deltas,
   commit them and only then activate successor votes. The exact inclusion,
   membership and round-recovery rules remain §7.29–7.31 / OPEN-01–03; this pattern
   does not establish a fixed pause duration or select a payment completion round.

A snapshot and bounded change tracking are an engineering candidate, not an
approved second persistent signing journal. DEC-033's existing-redb immutable
choices and DEC-042's client-retained retry stay intact. If export metadata is
needed, investigate atomic reuse of existing persistence; do not assume redb
provides PostgreSQL-style WAL subscriptions. Retained deltas, live snapshots,
learners and retries need byte/time/count limits. If a learner falls outside its
retained window, restart/re-snapshot behind the signing gate instead of skipping
history. This must not pin expired locks or old database versions indefinitely,
retain permanent tombstones, or hold the RAM collision index across storage I/O.

**Existing reusable storage primitive and current gap (static).** Cargo.lock pins
redb 2.6.3. Its locally installed `Database::begin_read` documents a committed
snapshot with concurrent writers (`redb-2.6.3/src/db.rs:1036–1047`);
`ReadTransaction` captures the corresponding tree. This supplies a local stable
read primitive, not a distributed checkpoint or complete RAM/pending-write state.
In `network/transport.rs`'s `ActiveSyncRequest` handler, each page rebuilds the
current combined disk/RAM lists, sorts them, and slices by offset. The inspected
request has no snapshot/revision binding. A key inserted before the cursor can
shift subsequent pages; removing a key can cause a later key to be skipped.
`storage/db.rs::apply_flush_batch_atomic` commits batches, but the inspected API
does not expose the proposed export stream/cursor contract. These are targeted
observations, not a full implementation audit or a code-change authorization.

**Throughput condition and next model work.** Distinguish whole-network rate from
the affected shard's actual unique changes and from duplicate per-source records.
If ongoing required transfer/verification work arrives at rate lambda and the
learner sustainably applies it at rate mu in the same units, reducing backlog
while writes continue requires mu > lambda; idealized net drain is mu-lambda.
This is a capacity argument, not a measurement. If mu <= lambda, catch-up requires
more effective capacity, less admitted work, a longer scoped pause or rescheduling;
Merkle compression cannot eliminate the cost of genuinely new required records.
Model and measure snapshot creation time, commit lag, feed gaps/truncation, source
failure, duplicate work, delta retention and checkout contention under target load.
Use small event models first for correctness; an isolated high-throughput simulation
can then test capacity before real-QUIC validation. No benchmark or model executed.

Next action: specify no-gap snapshot/source-cursor lifecycle and how old-quorum
obligation inclusion/closure justifies its final endpoint, without assuming a
global ordered log or safe membership oracle. Derive unresolved predicates before
building a model that might assume the desired answer. Q-S3.3-01 remains unchanged
and unanswered; no new maintainer decision or production/spec change, commit or PR.

### 7.33 Interjection: packet loss, reliable streams and bounded request retries

Current-policy pointer (CP-0055): DEC-060 / §7.66 subsequently selects the
conditional three-send heuristic. The original record below is historical; its
QUIC/correlated-loss and duplicate-work limits remain applicable.

Record: C3-N4-RESEARCH-001. Date: 2026-10-16 (Europe/Berlin).
The maintainer asks whether repeating an unanswered gateway-to-shard request two
or three times would reduce replica differences, using independent 1% packet loss
as an example. This is a proposal/question, not a selected retry count or an answer
to Q-S3.3-01. Address the bounded interjection, then return to S3.3 / §7.32.

**Transport and arithmetic.** [RFC 9000 §2.2/13.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-13.3)
defines ordered streams and retransmission of lost stream information; it is sent
in new packets as needed, not as whole-packet copies or new application requests.
[RFC 9002 §6](https://www.rfc-editor.org/rfc/rfc9002.html#section-6)
specifies loss detection/probing. Static inspection: `Transport::send_request`
(`network/transport.rs`) opens a Quinn bidirectional stream, writes one frame,
finishes its sending side and reads a response frame. This path is not an
unreliable QUIC DATAGRAM service. QUIC stream retransmission reassembles the same
byte stream instead of dispatching another application-level lock operation.

For n independent transmission losses each with p=0.01, losing all copies has
probability p^n: one 1%, two 0.01%, three 0.0001% (one in a million). This elementary
calculation is correct under independence. Bursts, path outage, peer failure and
overload are correlated. Packet loss probability is not the probability an entire
QUIC request fails within its deadline: a request/reply may span multiple packets,
and the transport already retries. No measured end-to-end residual rate follows.
A missing response also does not prove a missing lock; the server may already have
committed/signed while the response is delayed or the connection subsequently fails.
Transport receipt is likewise not durable application acceptance.

**Recommendation and existing decisions.** Keep DEC-027's one application attempt
per frozen committee member as the current default; it already permits transport
retransmissions. Two/three unconditional full requests add application load, not
merely transport redundancy. `api/routes.rs::collect_peer_attestations` fans out
to the frozen candidates with an 800 ms write budget, exits on quorum/impossibility,
and deduplicates collected node identities. `network/transport.rs` performs
authentication/quota admission before the lock result, so storage idempotency must
not be assumed to make repeated requests CPU/queue/quota-free. Exact duplicate
accounting/durable-response behavior remains an audit obligation.

Retain DEC-009/042's bounded delayed retry of the same signed payment intent after
an uncertain operation outcome; this is distinct from blindly duplicating every
per-peer RPC or replacing a committee member. Preserve the 800 ms collection bound,
same intended lock, full-identity vote deduplication, neutral quorum cancellations,
NOT_READY/backpressure semantics and no failure-triggered retry amplification.
No retry count/delay, automatic post-quorum repair task or server-side intent queue
is selected. Quorum fast-exit intentionally does not promise that every one of the
twenty replicas receives/stores the operation. Lagging replicas still need bounded
shard-direct reconciliation (§7.31–7.32); retries reduce some incidental failures
but cannot replace handoff closure or establish complete state.

If future measurements justify changing DEC-027, model a tightly bounded retry of
eligible uncertain transient failures, with explicit budgets, same-intent semantics,
receiver duplicate handling and no retries against explicit overload/readiness
refusals. Required later real-QUIC checks: independent/burst request and response
loss, response loss after commit, connection reset, overload and quorum cancellation;
measure useful completions, duplicate work, bytes and tail latency under load.
No QUIC test, loss simulation, benchmark or production change was run here.
Question/design status: no new decision requested before this transport clarification;
OPEN-07/08 remain open. S3.3 and the original pending question are unchanged.

### 7.34 Status assessment and separate repair/activation acceptance contracts

Record: S3.3-DESIGN-001. Date: 2026-10-16 (Europe/Berlin).
The maintainer welcomes QUIC's loss handling and asks whether synchronization of
new and existing nodes is now solved, whether it is tractable and what to do next.
This is a status/explanation request, not selection of Q-S3.3-01 or authority to
describe research as a completed design. S3.3 remains active. No new preference
question is needed to establish the following engineering contracts.

**Honest status.** Efficient state comparison/transfer is an established engineering
problem with available primitives. The project already has digest/pull paths and
redb stable reads; §§7.31–7.33 identify missing snapshot, delta and delivery details.
Safe Byzantine turnover with partial local states, durable binding one-round votes
and subjective membership is not solved/proved/implemented by those primitives.
Published BFT transfer/reconfiguration establishes conditional feasibility for its
own models, not simultaneous feasibility of every HuMoCo requirement. No categorical
impossibility claim is made either. Existing tests are not a substitute for this
missing construction, and performance at target rates is unmeasured.

**Contract R — continuing-member reconciliation (candidate).** Sources expose named
stable committed snapshots and bounded subsequent changes as in §7.32. Compare only
the same canonical representation and stated scope/expiry policy; differences
between live views are expected and do not establish peer fraud. A receiver may
retrieve/validate missing evidence through learned-peer shard RPC, idempotently
preserving its immutable own choices and inherited live constraints. A conflicting
record must follow the unresolved conflict/finality rules; simple repair must not
overwrite a prior signing choice or choose a raw-majority/lower-hash FINAL winner.
Byte-identical current RAM contents at every node are not an activation prerequisite
for each ordinary write. Detecting/copying differences and establishing safe new
signer eligibility are distinct obligations. Authentication and a matching hash
still cannot prove that an unknown binding obligation was never omitted.

**Contract A — successor activation (conditional candidate).** Make the local data
contract precise before modeling the distributed endpoint: for source identity i,
`S_i(r)` is a stable committed snapshot at source-local revision r, and
`D_i(r,h]` is the complete replayable relevant change range after r through h.
The pair must reconstruct that source's committed transferable state at h under
the declared retention/expiry rules. Bind identity, shard, predecessor context,
snapshot identifier/commitment and both endpoints; missing/truncated/replayed
ranges cannot count as successful catch-up. Revisions from different sources are
not comparable global ordering positions. This equation is a proposed local
export contract, not existing code or proof of distributed completeness.

For a final handoff candidate M, an honest old endorser must durably close its old
voting and check that M preserves the relevant own/inherited bindings through its
endpoint h, including any admitted work whose vote could escape. A successor must
verify the justified predecessor participants, closure/inclusion evidence and the
specific successor/state binding, durably install M and then activate. In a common
justified 20-member predecessor with the stated temporal six-Byzantine bound,
§7.29's intersection argument explains why inclusion checks by fourteen matching
closure endorsers can cover prior certificates; it does not define those checks.
No rule requires fourteen identical initial source snapshots or all twenty nodes
online. Continuing repair can reuse the transport without running this activation
ceremony on each routine comparison. Timeout or hash equality does not replace M.

**Remaining executable predicates.** Before a useful model can be claimed, define
which predecessor/successor rosters and evidence are admissible (S2), which partial
binding effects M must preserve and how late certificates refine conflicts (OPEN-01),
and how transition rounds replace failed proposals without discarding protected
choices (S4 / DEC-046). These must be actual model rules, not assumptions named
"safe state" or an oracle returning the desired answer. Q-S3.3-01 remains the
unchanged payment-semantics choice; investigate independent predicates first and
ask only where that distinction or another genuine product tradeoff matters.

**Next bounded delivery.** Use R/A as the acceptance checklist for a written
minimal state machine, explicitly mark every unfilled predicate, then use §7.31's
small adversarial model and subsequent load/real-QUIC gates once those predicates
are defined. Under continuing writes, require adequate source/learner capacity;
under partitions/lost quorums permit unavailable affected writes rather than
claiming guaranteed progress. No permanent all-node equality or unconditional
low-latency handoff is promised. This turn adds a contract decomposition, not an
approved protocol, executed model or production implementation.

Sources rechecked for the feasibility boundary:
[Cassandra repair](https://cassandra.apache.org/doc/latest/cassandra/managing/operating/repair.html),
[BFT durable transfer](https://www.usenix.org/system/files/conference/atc13/atc13-bessani.pdf),
[Byzantine reconfiguration](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.DISC.2020.27).
Their respective repair, ordered-replication and certified-configuration assumptions
remain distinct. No new external claim that one of them is a drop-in HuMoCo solution.

### 7.35 Maintainer-directed prerequisite: robustness and compression of local views

Record: S2.2-RESEARCH-001. Date: 2026-10-16 (Europe/Berlin).
The maintainer explores median/majority views from gossip, efficient representation
at a million nodes, and the alternative of each node syncing and voting from its
own view. Latest steering: do not assume a common view fixes safety; investigate
how robust subjective views actually are using existing theory/research and then
targeted simulation as needed. This moves the single active focus to **S2.2**, a
prerequisite of S3.3. Return point: §7.34 repair/activation contract. Q-S3.3-01 is
parked with original unanswered meanings; no payment, global-membership or reduced-
safety decision is inferred. Ticket possession still has the existing maturation,
validation and readiness conditions; no immediate voting on ticket creation.

**Research found; applicability limits.**

| Primary work | Useful result/mechanism | What it does not establish for HuMoCo |
| --- | --- | --- |
| [SWIM](https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf) | Scalable weakly consistent membership and dissemination. | Byzantine-safe voting membership, bounded disagreement on HuMoCo's friend graph or safe finality. Its failure-report mechanics are not permission to gossip hearsay sanctions. |
| [T-Man, Jelasity/Montresor/Babaoglu](https://cs.unibo.it/babaoglu/papers/pdf/tman.pdf), §§2–5 | Ranking-based topology construction using bounded descriptor exchanges; theoretical/empirical convergence analysis. | Explicitly excludes Byzantine faults and assumes a peer-sampling service with random samples. Fixed F2F edges/TTL/RED do not automatically supply these assumptions. |
| [Correctness of a Gossip Based Membership Protocol](https://www.cs.cornell.edu/courses/cs6452/2012sp/papers/gossip-podc05.pdf), §§4–5 | Analysis of partial-view maintenance, partition risk and the need for reinforcement of live identities. | Its randomness, dependence approximations and churn model are not a theorem for this project's topology/filtering or payment certificates. |
| [Practical Rateless Set Reconciliation, SIGCOMM 2024](https://cs.stanford.edu/~keithw/sigcomm2024/sigcomm24-final47-acmpaginated.pdf) | Rateless IBLT communicates differences between large sets without first knowing their difference size. | Global membership completeness, adversarial availability, ticket validity or safe activation. CPU still depends on input size; retain decoding/work bounds and validated full records/fallback. |
| [Stellar Consensus Protocol §4.1](https://stellar.org/papers/stellar-consensus-protocol.pdf) | Local trust choices still need honest quorum intersection. | Arbitrary local HRW top-twenties or an adopted Stellar/ledger trust model. |

**Median proposal.** Sets and identities have no numerical median analogous to
clock readings. One can count support for identities or whole rosters, but then
must justify the reporters/denominator, independence/Sybil resistance, freshness
and comparability of sampled neighborhoods. Different honest friend neighborhoods
can produce different majorities. Forwarded copies of one signed announcement are
not independent witnesses. Such aggregation may help discovery/diagnosis but does
not by itself prove membership or authorize automatic bans. Prefer reconciling
authenticated original node/ticket announcements as an investigation baseline;
no median-voting or network-wide agreement subsystem is selected.

**Own analytical result: measure rank-critical overlap.** Let two frozen twenty-
member candidate committees share k identities. Their union has size 40-k, so any
two fourteen-vote sets have intersection at least `max(0, k-12)`. If at most six
identities in this UNION over the relevant interval are Byzantine, and common
honest signers preserve the same spend-slot exclusion across the compared votes,
then k>=19 guarantees an honest common voter for this pair. At k=18 the lower
bound is six, allowing the common voters to be precisely the six Byzantine nodes.
Executed a bounded set/arithmetic check for k=18/19/20 and rechecked §7.9's concrete
22-identity/two-replacement counterexample: two valid-size committees and two
fourteen-vote sets, with only the six Byzantine identities common to both votes.
This is not a new formal proof tool, simulation or network test.

The UNION/temporal bound is an explicit premise, stronger than merely saying each
unrelated local set has at most six Byzantine identities. k>=19 is a pairwise
certificate exclusion lemma under immutable shared signing constraints, NOT a
complete membership/handoff rule: cumulative turnover, inherited effects, key
corruption and rollback still require §7.29–7.34. A valid attack schedule already
refutes an unconditional guarantee for the unrestricted local-view baseline;
simulation can quantify occurrence under stated workloads or evaluate a restriction
that excludes that schedule, not turn an observed low frequency into impossibility.
Near-equality of million-entry catalogs does not imply adequate top-twenty overlap:
discovering only two additional high-ranking mature candidates can replace two
members while nearly all catalog entries remain identical. Median node count and
overall heartbeat-reach percentages therefore do not establish the needed property.

**Million-node representation and KISS.** Do not exchange every observer's roster
for every shard. Signed identity/ticket announcements are candidate facts; HRW
computes rankings from facts. One twenty-member list needs only 20*32=640 raw bytes
for keys, or 1,280 with 32-byte tickets, before signatures/proofs/endpoints/framing.
One million keys+tickets already require 64,000,000 raw bytes; this is a lower bound,
not an actual wire/storage benchmark. Hashes cheaply compare the same canonical
catalog snapshot; Merkle/range reconciliation or, conditionally, IBLTs retrieve
differences. Small messages do not prove no better unknown ticket exists. When
freshness updates or differences are large, payload/work cannot remain constant.
Keep candidate lists/caches for relevant shards rather than transmitting all
opinions; cache correctness and bounded invalidation need design, and a hidden
candidate cannot be authenticated into nonexistence by a hash. No tree/sketch,
new gossip stream or global catalog protocol is approved.

Existing constraints remain: only presence/heartbeat and equivocation-proof F2F
gossip; no lock gossip, no arbitrary-peer probing, shard RPC only with learned
identities. T-Man's arbitrary/random exchanges cannot be imported verbatim.
Any descriptor reconciliation must fit authorized discovery paths and be treated
as a deliberate protocol change if messages/semantics change. No telemetry/root
disagreement becomes fraud evidence. Preserve twenty-four-hour ticket incubation.

**Current evidence versus assumptions (static inspection).** Spec 11 claims
small-world percolation with TTL=16, hourly heartbeats, edge RED/drop budgets and
24h/heartbeat qualification. Those stated ingredients are not a bound on rank-
critical disagreement: an owner announcement cannot traverse a path longer than
its allowed hop budget; connectivity/average diameter alone does not bound tails
or overcome selective filtering. `KnownNodeInfo` uses local first-seen/pending
`Instant` values, so equal incubation durations can finish at different nodes at
different times. `PeerManager::shard_committee` uses local known/mature/non-banned
records, cloning/scanning maps and then selecting candidates. Million-node request-
time cost is an unmeasured scaling obligation, not a proven performance result.

The existing 10k censorship test's `simulate_gossip` is breadth-first propagation
over all honest adjacent edges after excluding selected Byzantine forwarders; it
does not implement timed hourly fan-out/TTL/RED/maturity/churn or measure committee
overlap and competing certificates. The merge-wave tests include an example
90/95%-of-median-node-count syncing gate; that gate alone cannot distinguish
equal-sized catalogs containing different rank-critical nodes. Existing coverage
can supply topology fixtures, not the requested safety result. No tests were run.

**Next bounded research/model deliverable.** Audit the baseline's exact discovery,
maturity, ticket replacement and rank-selection rules against code/spec conflicts;
define assumptions before importing literature bounds. Measure per-shard committee
overlap LOWER TAILS, duration of incompatible views, discovery-before-maturity lag,
rank-critical missing tickets, accepted conflicting certificates and false-ready
events. Include clustered F2F graphs, sparse/failed bridges, TTL, RED, delayed
discovery, fresh/pending replacement tickets, network growth, stale views and
strategic withholding/grinding under a separately stated adversary model. Trace
signing/transfer events to connect discovery to §7.9's attack; do not simulate only
catalog coverage. Track byte/CPU/cache costs and finality availability as separate
outcomes. Start with known counterexamples and small models, then sampled observers/
relevant ticket candidates and scalable event simulations rather than an N-by-N
matrix of complete million-node views. Count-only/graph-only simulations cannot
close the branch. Literature supplies useful mechanisms and conditional analyses;
no verified bound currently shows the unrestricted HuMoCo baseline safe or gives
its failure probability. No policy choice, production change, benchmark or large
simulation is authorized/inferred by this research record.

### 7.36 Decision-ready recommendation and the role of social trust

Current status: CP-0026 / §7.37 withdraws decision readiness and Q-S2.2-01 as the
next question. The conditional proposal and exact wording below remain history;
the maintainer did not select it. Its predecessor-roster premise must be resolved.

Record: S2.2-RECOMMENDATION-001. Date: 2026-10-16 (Europe/Berlin).
The maintainer asks for a solution/decision rather than further open-ended study,
and whether human intervention/reputation in an F2F network materially changes
the result. This is not an answer to Q-S3.3-01 or permission to lower the accepted
six-Byzantine design target. Active focus remains S2.2; no large test run needed
to decide whether an already exhibited permitted counterexample is safe.

**Engineering finding.** Do not approve unrestricted "local mature rank + copy +
start voting" as satisfying the existing FINAL/six-Byzantine requirements. The
§7.9/7.30/7.35 schedule already uses no more than six Byzantine identities and
only two honest newcomers; it is not an argument that all friends are malicious,
that thousands of Sybils are inevitable or that two independent large networks
form spontaneously. Better average gossip coverage or additional reputation
does not exclude the schedule. Rejecting this baseline as a safety justification
is an analytical finding, not a new maintainer-selected protocol or implementation.
Further simulations remain useful for availability, attack cost and performance,
but observing no failures cannot reverse this worst-case counterexample.

**F2F effect, with primary research.**
[SybilLimit, Yu/Gibbons/Kaminsky/Xiao, §§1–4](https://www.comp.nus.edu.sg/~yuhf/yuh-sybillimit.pdf)
uses social trust edges to limit admitted Sybil identities under explicit graph/
attack-edge/mixing assumptions and its random-route acceptance procedure. It also
notes that historical good behavior does not prevent later coordinated attacks.
The paper's simulations/real-world graph evidence are not proof of HuMoCo's graph,
admission procedure or per-shard fault count. Its quantitative admitted-Sybil bounds
cannot be imported into simple friendship approval plus heartbeat percolation.
[SCP §4.1](https://stellar.org/papers/stellar-consensus-protocol.pdf) separately
requires honest quorum intersection despite local trust choices; reputation does
not replace that condition.

Human friend approval, loss of established identity/relationships after verified
fraud, operator oversight, ticket work and incubation can raise practical attack
costs. This is relevant defense and preserves DEC-018/019/040. It supplies no
currently justified probability or bound on six controlled identities. Compromised
keys of previously legitimate friends need no new social admission. One existing
F2F edge suffices in Spec 07; a malicious sponsor can approve multiple keys, and
clusters/bridges can delay honest discovery. Do not equate a distinct public key
with a distinct independent human. No sponsor liability, financial deposit,
reputation-weighted vote, rumor-based penalty or automatic friend ban is proposed.
Retain first-party proof requirements for protocol sanctions. Social friction
reduces attack feasibility; the protocol must still handle the faults it claims
to tolerate once they occur.

**Concrete recommended direction (not yet selected).** Local signed presence and
HRW remain discovery/candidate selection. For a justified current per-shard roster,
keep counted membership stable until a validated transition binds one concrete
successor roster and the preserved live state/obligations. Investigate old-quorum
fourteen-of-twenty agreement for that transition, including durable old-write
closure and per-successor installation before voting. This is a bounded per-shard
change protocol, not an all-million-node median or new per-payment agreement round.
Bulk sync can run beforehand. Different nodes may learn the completed transition
at different times; they cannot each install unrelated successors. Stale gateways
need evidence/temporary failure handling, not automatic replacement voters.

The tradeoff requiring maintainer intent is concrete: a mature high-ranking and
locally synchronized newcomer may wait before its signatures count. If evidence
is unavailable, an affected shard cannot simply invent a replacement electorate
to continue FINAL writes. Preserve DEC-046's automatic safe progress requirement
once enough honest participants and communication stabilize; no permanent partial-
proposal stall is selected. Proposal rotation/recovery, precise inclusion/partial-
conflict semantics, latest-context discovery and bounded retention remain to prove.
An old-quorum signature alone is not the completed proof. Initial roster authority
and temporal/admission bounds remain OPEN-02; do not re-ask the withdrawn common-
genesis/domain question or silently select a global authorization-history scheme.
The rule under consideration is a new joint-transition constraint, not a repetition
of the already accepted local recovery/readiness gate.

**Exact pending decision question — Q-S2.2-01:**

> Sollen wir als Architekturregel ausarbeiten, dass Gossip und HRW weiterhin
> lokal die Kandidaten bestimmen, ein Wechsel der mitzählenden Shard-Gruppe aber
> einen geprüften Übergabenachweis der bisherigen Gruppe benötigt — mit 14 von
> 20 Bestätigungen für dieselbe Nachfolge und den erhaltenen Zustand — und ein
> neuer Knoten bis dahin trotz reifem Ticket und Datenabgleich noch nicht mitzählt?

Recommended answer/direction: yes, investigate this jointly justified transition
as the architectural constraint, accepting the stated availability/activation
tradeoff. Free-form disagreement/constraints remain valid. Do not manufacture a
second option that silently weakens the existing FINAL/fault requirements. This
selects a direction only, not a finished algorithm, measured pause, dependency or
production change. It does not select Q-S3.3-01 A/B or add a payment completion
round; its original wording/meanings stay parked.

After an answer, record the constraint (or reason for rejecting it), then specify
one transition instance's signed fields, closure/inclusion/installation and safe
round-recovery predicates under explicit participant assumptions. Evaluate known
counterexamples before expanding simulations; no more median/global-view machinery
without demonstrated need. No code/spec changes, model or test execution this turn.

### 7.37 Correct the circular predecessor premise; start with actual network growth

Record: S2.1-CLARIFICATION-002. Date: 2026-10-16 (Europe/Berlin).
The maintainer objects that every node still has only its own view, so "the previous
shard group" has not been defined. They point out the simpler N<=20 growth phase:
every newcomer is added to the all-shard participant set instead of replacing a
top-twenty member. This is a prerequisite challenge, not a yes/no answer to
Q-S2.2-01 and not a request to replay the withdrawn genesis/domain choices.

**Correction.** The assistant prematurely presented a conditional handoff sketch
as decision-ready. Neither naming the old group nor collecting signatures from a
locally selected group proves that the recipient should recognize that group.
Withdraw Q-S2.2-01 as the next question, preserving its wording/history and
unanswered status. The old-quorum transition remains a conditional research option,
not a selected rule. Do not repeat it as a solution to its own missing premise.
Move the sole active leaf to **S2.1**, participant justification at the actual
19->20->21 growth/first-FINAL boundary. Return to S2.2 / §7.35 and conditional
S3.3 / §7.34 after this prerequisite. Preserve the one growing network and existing
N>=20 FINAL requirements; do not demand another threshold/domain preference answer.

**Growth arithmetic, explicitly conditional.** With a fixed eligible universe of
exactly twenty identities, two fourteen-vote sets intersect in at least eight;
with twenty-one, at least seven; with twenty-two, at least six. Under at most six
Byzantine identities across the compared votes and immutable common honest
spend-slot exclusions, the first two cases force an honest common voter. A single
replacement among a genuinely common twenty-one-identity universe is therefore
not automatically unsafe. The prior two-newcomer counterexample uses twenty-two.
Rechecked these bounded cardinality calculations this turn; no simulation/test.

For nested nineteen- and twenty-member rosters, Q(19)=13 and Q(20)=14 give a
minimum intersection of seven in their twenty-identity union. This does not decide
PROVISIONAL revision, promotion of earlier provisional locks, or arbitrary
small-network fault tolerance. N<20 retains PROVISIONAL; the current implementation
also requires N>=20 stability hysteresis before FINAL. It is not correct to
describe the twentieth discovery event as immediate unconditional FINAL.

The real question is whether all simultaneously accepted voting sets remain
within a sufficiently bounded identity universe OVER THE relevant interval, or
whether a justified state/participant transition preserves safety when that
universe changes. Nodes do not know the actual global N merely by counting local
messages; a local twenty/ twenty-one view can coexist with undiscovered mature
candidates. Twenty-four-hour incubation alone bounds neither concurrent admissions
nor discovery delay, and repeated one-at-a-time changes do not establish cumulative
safety. Do not replace the missing guarantee with an assumed global growth clock.

**What would remove the circle (research alternatives, not selected).**
One construction would make membership itself durable protocol state: a justified
first FINAL participant/state checkpoint in the organically grown network, followed
by independently verifiable, compatible membership changes and state continuity.
Then "previous" means the participant list verified from that checkpoint/change
evidence, not today's HRW result. There need be no permanently privileged founders
or globally identical live discovery map. However, establishing that first checkpoint
and distributing its recognition to nodes AND payment verifiers is an explicit
bootstrap obligation, not solved by having a list sign itself. A chain starting
with one self-signed key does not automatically provide six-Byzantine safety; an
early compromised signer can fork such a chain unless further assumptions/rules
exclude it. No genesis anchor/history design is thereby approved.

A different construction could retain independently selected local lists but
prove honest quorum intersection and preserved effects across every set clients
are allowed to accept. §7.35 gives a conditional pairwise criterion, not an
operational enforcement rule. Current gossip/incubation has no demonstrated bound
that supplies it. These are ways to discharge the premise, not a new forced A/B
choice or proof that globally identical membership is mathematically necessary.

[Kuznetsov/Tonkikh §3.3–3.5](https://drops.dagstuhl.de/storage/00lipics/lipics-vol179-disc2020/LIPIcs.DISC.2020.27/LIPIcs.DISC.2020.27.pdf)
separates verifiable/comparable configuration histories from transfer and permits
temporarily differing current knowledge; that result depends on its configuration,
quorum and temporal-key assumptions. [SCP §4.1 and reconfiguration discussion](https://stellar.org/papers/stellar-consensus-protocol.pdf)
retains intersection requirements across local configurations. Neither authenticates
an arbitrary self-declared first group. These comparisons support the prerequisite
decomposition, not a ready HuMoCo construction.

**Observed code and next action.** Rechecked `NetworkId` (Mainnet/Testnet label),
`required_quorum` and the N>=20 stability/readiness gate. The known local roster
selection is not a stored common first participant checkpoint. Next write out the
19->20->21 trace and concurrent 21/22-admission variant: what evidence each signer
and verifier has, how a first common accepted participant state can be justified,
and which concrete bound/transition prevents incompatible descendants. Audit this
against the already accepted PROVISIONAL/FINAL policy and §7.13's scope; do not
smuggle in a trusted membership oracle or reopen glossary/threshold questions.
No new human question during this clarification. Q-S3.3-01 remains parked with
unchanged meanings. Design open; no production/spec change, model or test campaign.

### 7.38 Growth evidence check and unknown-participant consensus applicability

Record: S2.1-RESEARCH-003. Date: 2026-10-16 (Europe/Berlin).
Maintainer: "gut wie weiter?" This authorizes continued investigation, not a choice
of an initial anchor, a membership protocol or either parked question's options.
S2.1 remains active; §7.37's correction and return points remain in force.

**Executed bounded check, not a protocol simulation.** A small Python enumeration
(`/tmp/humoco_growth_evidence_cp0027.py`, temporary research artifact) enumerated
every first q-vote subset in a fixed identity universe. Byzantine IDs 0..5 may vote
for both conflicting values; honest first-voters are excluded from the second
value. For each first subset F, second subsets are counted exactly as
`comb(n - len(F - faulty), q)` when the remaining universe has at least q members.
No probability model, network scheduling engine or implementation is exercised.

| Fixed universe | Votes required | First subsets enumerated | Ordered conflicting vote-set pairs |
| --- | --- | --- | --- |
| 20 | 14 | 38,760 | 0 |
| 21 | 14 | 116,280 | 0 |
| 22 | 14 | 319,770 | 12,870 |
| 19 | 13 | 27,132 | 0 |

The last row assumes one exclusive durable decision in an already justified common
nineteen-member predecessor, not ordinary presence reports. The 22 row ranges over
all fourteen-element sets of that universe; it is not the count for one fixed pair
of HRW committees. These results confirm the cardinality argument, not dynamic
safety, actual membership justification, progress or million-node performance.
The script and its assertions were inspected; the execution result was reviewed.
Its temporary path is not a durable dependency: method and witnesses are recorded here.

**Concrete growth traces and evidence.**

- Nested 19->20: q19=13 and q20=14 intersect in at least seven within a common
  twenty-identity union. With at most six Byzantine identities and the same durable
  exclusion slot, conflicting votes cannot both reach those thresholds. Earlier
  PROVISIONAL revision/promotion and different small-network fault bounds remain
  separate obligations. Twenty-four-hour FINAL stability hysteresis is retained.
- Concurrent additions to a common nineteen P={B1..B6,H1..H13}: local views P+X
  and P+Y each have twenty identities. A fourteen-signature roster report for X
  can use B1..B6,H1..H7,X; one for Y can use B1..B6,H7..H13,Y. H7 can truthfully
  report both discoveries. This is not equivocation unless an actual protocol
  establishes an exclusive successor-decision slot. Conversely, this common
  twenty-one-identity universe still prevents two conflicting fourteen-vote LOCK
  decisions if honest nodes keep the same immutable slot choices. Different roster
  reports alone are therefore neither a double-spend witness nor membership consensus.
- Two replacements: C={B1..B6,H1..H14}; D={B1..B6,H3..H14,X,Y}.
  X,Y first copy an empty slot. A then receives votes B1..B6,H1..H8 in C.
  X,Y activate from their earlier copies; conflicting B receives
  B1..B6,H9..H14,X,Y in D. Both have fourteen votes and only Byzantine double-voters.
  Copy completion and individually valid tickets do not close that old-write race.
- A node's received messages can be identical in a twenty-node execution and in
  a twenty-two-node execution whose other mature tickets are delayed. A signature
  proves who sent a statement; it does not prove absence of undiscovered members.
  Local maturity timers, gossip convergence on typical graphs and social deterrence
  do not by themselves establish the required universe/temporal bound.

**Published route from partial knowledge; no universal founder requirement.**
[On the Minimal Knowledge Required for Solving Stellar Consensus, ICDCS 2023,
§III and §V](https://www.di.fc.ul.pt/~bessani/publications/icdcs23-stellar-cup.pdf)
studies Consensus with Unknown Participants (CUP). Nodes initially know subsets,
not a common full roster. Suitable knowledge-graph conditions permit discovery of
a shared sink component and consensus; SCP alone needs additional knowledge beyond
the minimum CUP conditions. The paper assumes a fixed participant set per consensus
instance, a static adversary, unique Sybil-resistant identities, authenticated
reliable channels and partial synchrony. Its knowledge graph is not the physical
friendship/communication graph. This establishes that a manually agreed founder
roster is not a universal mathematical necessity; it supplies no HuMoCo bootstrap.

[Knowledge Connectivity Requirements for Solving BFT Consensus with Unknown
Participants and Fault Threshold, extended version,
§II–IV](https://arxiv.org/html/2405.06055v2) gives authenticated discovery and
sink-identification protocols and a stronger graph model allowing an unknown fault
threshold. Digital signatures simplify protocols but do not remove the knowledge
requirements. Its known-f construction uses a bound for the participating discovery
instance, not an independent bound in each subsequently selected shard. The
unknown-f construction needs stronger structural assumptions. Neither result allows
arbitrary disconnected local views to produce one guaranteed consensus outcome.

**Applicability gate against HuMoCo — current result: no drop-in proof.**

| Required by the compared construction | HuMoCo evidence / missing obligation |
| --- | --- |
| Suitable knowledge connectivity despite faulty participants | F2F admission and presence rules constrain who communicates; no matching cut/connectivity guarantee is established. A malicious discovery bridge may conceal an honest community. |
| Fault/identity premise for that instance | Six Byzantine identities is a selected shard design target. It is not a global six-identity bound for million-node discovery; replaceable keys/tickets and human reputation do not prove Sybil resistance. |
| Reliable authenticated communication between discovered participants | QUIC/TLS is relevant, but mutual learned-peer authorization can still refuse a peer learned only through protocol-carried lists. A discovery protocol cannot silently bypass the F2F barrier. |
| Fixed participants/initial knowledge for an instance | Continuous discovery, local 24h timers, concurrent arrivals, removal and repeated turnover need an explicit mapping and proof. Freezing one's local list alone does not supply it. |
| External acceptance of the outcome | Payment verifiers need a justified acceptance predicate too; node-to-node agreement alone does not authenticate an arbitrary claimed decision group to them. |

Rechecked `network/manager.rs::shard_committee` (local maps/maturity and identity
selection), `KnownNodeInfo` timers, and transport's learned-peer authorization.
These do not implement the compared discovery/consensus construction. No claim
that all live discovery maps must be identical, that CUP is impossible in every
F2F network, or that six real-world attackers are enforced follows from this gate.

**Technical disposition and next action.** Unrestricted own-view activation plus
a completed copy is not a sufficient safety argument under DEC-044 and the growth
cases above. A compatible-membership mechanism or an established intersection
bound remains necessary for the accepted FINAL contract. A small separate operation
for membership changes is a research recommendation, not a selected extra checkout
round, global lock log, permanent founder role or new gossip stream.

Next construct the first-FINAL admission/recognition contract: list exactly what a
new node AND a payment verifier would verify, where the initial justification comes
from, and how concurrent additions preserve compatibility. Compare partial-knowledge
consensus premises with that contract rather than inserting an unnamed "old group."
If an additional operational/trust/availability assumption is unavoidable for a
concrete candidate, identify its effect and only then ask one genuine tradeoff
question; do not replay §7.11–7.13's withdrawn threshold/domain choices. Simulation
can falsify schedules and measure dissemination/cost after the predicates are
explicit; empirical similarity cannot certify an unspecified safety premise.

No new human question or protocol selection. Q-S2.2-01 stays withdrawn as the next
question and unanswered; Q-S3.3-01 remains parked with its exact §7.16 meanings.
DEC-001–052 unchanged. No production/spec edits, Rust/QUIC tests, benchmark,
large simulation campaign, commit or PR. Design open.

### 7.39 Autonomous design and simulation work authorized

Record: S2-S3-SIMULATION-001. Date: 2026-10-16 (Europe/Berlin).
Maintainer explicitly authorizes autonomous continuation until a solution is found,
then writing its simulation, using subagents to retain the overall view. This
extends the earlier interview-only scope to implementation and execution of an
isolated research simulation. It does not authorize deployment, changing binding
specifications/production protocol behavior, commits, or silently selecting either
meaning of Q-S3.3-01. Conditional candidates may be implemented for evaluation.

Delegated independent membership analysis, simulation inventory/implementation and
adversarial handoff review. Initial findings refine the candidate: epoch-wide
fence/drain; non-exclusive closure-inclusion endorsements; separate BFT agreement
with publicly verifiable validity; durable installation before successor voting.
A private own-inclusion rule inside BFT agreement can stall after a prepared value;
this is an explicit adversarial regression, not a solved implementation claim.

Implementation target: isolated Rust example and support modules under
`crates/humoco-sim-core/examples/membership_handoff*`, no new dependencies or daemon
changes. Include faulty-baseline witnesses, real progress gates, multiple full
turnovers, durable ordering, replay/evidence checks and virtual capacity experiments.
The first-recognition premise stays explicit. A recognized initial configuration
fixture tests conditional handoff only and must not be reported as automatic
first-FINAL discovery. Unknown-participant literature is being checked at executable
predicate level; a paper citation alone supplies no admission oracle.

Work in progress. Preserve DEC-001–052 and exact parked Q-S3.3-01, withdrawn
Q-S2.2-01. Next complete the isolated candidate and independent review, execute
bounded adversarial/seeded checks, record outcomes and any remaining impossibility
or new assumptions rather than claiming an unconditional solution.

### 7.40 Conditional membership/handoff candidate implemented and exercised

Record: S2-S3-SIMULATION-002. Date: 2026-10-16 (Europe/Berlin).
The maintainer repeats autonomous continuation until a solution, explicitly allowing
subagents. No additional policy choice or A/B answer is implied. Produced an
isolated executable candidate, not a production/spec change or unconditional FINAL
proof. Detailed contract, argument, assumptions, source discrepancy and validation:
[Membership/handoff research report](MEMBERSHIP_HANDOFF_RESEARCH.md). Executable:
[`membership_handoff_model.rs`](../crates/humoco-sim-core/examples/membership_handoff_model.rs),
with `bootstrap.rs`, `model.rs`, `lifecycle.rs`, and `capacity.rs` alongside it.
No dependencies or production modules changed.

**Independent work and corrections.** Three subagents investigated membership,
simulator reuse/implementation and adversarial handoff review. The primary agent
integrated and finished the model, including the actual first-FINAL bridge and
additional finite lifecycle/capacity checks. Review uncovered private-inclusion
BFT deadlock, fabricated closure-signature acceptance, mutable numeric value
aliases, vacuous forged-prepare tests, missing prepared-value carryover, successor
installation/context replay gaps and leaked global-monitor knowledge. The final
model uses separate signature-emission provenance, immutable exact value bindings,
explicit historical-proof delivery and monotone closed-epoch watermarks. These
are model fixes, not evidence that equivalent daemon defenses were implemented.

**Initial-admission candidate, explicitly conditional.** Authenticated immutable
participant-detector rows define received issuers R and their named universe U.
Require at least thirteen authenticated issuers, at most six missing rows in U,
and authentic instance-participation evidence for every named identity. Verification
sees only the supplied transcript, never actual global membership/fault sets.
An additional premise is that the fixed correct bootstrap participants' effective
knowledge graph is seven-vertex-connected and the instance contains at most six
Byzantine eligible identities. Then an undiscovered correct participant would
require a separator of at most six missing correct identities, contradicting the
premise. U contains all correct instance participants; adaptive quorums in such
universes have honest intersection and availability when h>=13. The arithmetic
check covers h=13..64 and b=0..6. This stronger construction is our own research
candidate, not a theorem/implementation imported from the CUP paper.

The existing F2F policy DOES NOT establish that global graph/identity/fixed-instance
premise. The model demonstrates different local admissible views outside it; this
cannot be hidden behind matching digests, social deterrence or a successful seed
run. General ongoing bootstrap admissions, heterogeneous live agreement electorates,
late-observer recognition and full provisional merge semantics remain open. No
manual founder privilege, initial trusted roster, changed twenty-node threshold or
reduced guarantee is selected. The earlier circular predecessor question stays
withdrawn. Its premise now has a concrete conditional research construction and
an explicit unfulfilled integration gate.

The model integrates local transcript verification, adaptive initial membership
agreement, conservative provisional-choice import, existing full-score HRW
selection of twenty voters, virtual twenty-four-hour stability, first fresh FINAL,
and a full subsequent turnover for initial populations 20, 21 and 22. It does not
promote old PROVISIONAL certificates into FINAL. Conflicting imported slots stay
blocked; unaffected and consistent slots can complete without Byzantine assistance.
These are bounded fixed-instance fixtures, not general dynamic bootstrap proof.

**Primary-source finding.** The literal P3 in
[Heydari et al. v2, Theorem 3 / Algorithm 2](https://arxiv.org/html/2405.06055v2)
counts sources with exterior outgoing edges. In the complete-twenty/six-silent
fixture every candidate available S1 has more than six such sources, so the printed
predicate never returns a sink despite the fixture's strong correct connectivity.
The model reproduces that narrow liveness discrepancy. No silent correction or
claim that all CUP results are refuted. The report distinguishes this from the
independent stronger candidate and cites the compared sources.

**Handoff candidate and exact preservation claim.** Persist an epoch-wide fence,
drain or cancel unreleased old decisions, obtain complete available state, and
collect fourteen non-exclusive own/inherited-inclusion endorsements for the same
state. This closure certificate is PUBLIC validity for a separate BFT successor
agreement. Actual propose/prepare/commit and highest-prepared view-change messages
select a successor/state; no omniscient winner selector is used. Each successor
commits the verified payload before its vote; installation receipts bind context.
A prospective old fourteen-vote certificate intersects closure endorsers in at
least two honest inclusion witnesses. Eight honest fences leave only twelve old
identities able to issue fresh old votes. Preserve inherited effects in every
later transition; keep each reused identity's private exact choice separately.
This does not recover every unavailable non-endorser's singleton. Competing
partial payment effects may block their slot; unrelated slots continue. A late
valid historical certificate is explicitly presented to selected recipients and
may resolve transferred ambiguity without erasing any private own choice. The
global safety monitor never informs node state. No lock gossip.

The example explores the original one-payment-round A as a conditional candidate;
Q-S3.3-01 is STILL unanswered with §7.16's original meanings. Exact bounded effect
sets stand in for normalized BLOCKED/proven effects; TTL, actual signed encodings,
rollback, dynamic ticket eligibility and temporal-key/late-compromise protection
are not implemented. Fault identities are static in the model; six per configuration
must hold throughout its evidence lifetime, not merely while currently active.
No permanent founders or current-committee-only fault assumption is smuggled in.

**Executed evidence.** Twelve example tests passed. Twelve handoff scenarios over
seeds 1..128 produced 1,536 scenario executions / 4,036,608 abstract model steps.
They include expected unsafe copy/activation, three full turnovers with six static
faulty identities per generation, the two-A/twelve-B report split, withheld/late
certificates, three-way conflicts, split and genuinely prepared-value recovery,
forged/replayed/incomplete evidence, individual durable/install gates, overlapping
membership and stale-epoch requests. Expected unsafe/stall variants must exhibit
their failures for the regression check to pass; these counts do not imply safety
for arbitrary schedules. The finite local lifecycle checker exhausts 34 reachable
states / 56 edges and produces a seven-action counterexample for early snapshot.
Agreement has seeded message scheduling; other distributed durable steps remain
scripted. Exhausting a model bound is inconclusive/error, not progress proof.

Fourteen bootstrap-study checks passed their explicitly stated expectations,
including out-of-assumptions and literal-source counterexamples. Six virtual
capacity/transfer checks use 1k/10k offered records/s, bounded admission, snapshot
plus contiguous source changes and final drain. At configured 10k ingress / 5k
transfer records/s, the remaining 125k records cause roughly 25 seconds of pause.
No node-throughput/crypto/disk/network benchmark or deployment SLA is inferred.
Live-offset pagination mutation reproduces an omitted live record.

`cargo test --workspace` passed after sandbox escalation enabled existing loopback
QUIC tests; the first restricted attempt failed to bind sockets. This run preceded
final isolated-model refinements, covered by final example tests and
`cargo clippy --workspace --all-targets -- -D warnings`, which passed. Existing wire
tests do not verify this new unimplemented protocol. No production/spec edits,
commit or PR. Full validation detail and reproduction commands are in the report.

**Disposition and next work.** There is now a concrete conditional design and
executable adversarial simulation. S2.1 remains the sole active prerequisite:
justify/adopt the initial-admission premise or discharge it with another compatible
mechanism, and complete dynamic bootstrap/late-verifier acceptance. Do not claim
unconditional solvability under arbitrary subjective F2F views. Return to S2.2,
S3.3's original choice and remaining wire/canonical/TTL/recovery design gates before
production implementation. Do not repeat withdrawn threshold/anchor or glossary
questions. DEC-001–052 remain unchanged.

### 7.41 Operational verdict for the planned decentralized deployment

Record: S2-S3-ASSESSMENT-001. Date: 2026-10-16 (Europe/Berlin).
Maintainer asks for a direct answer: does this actually work robustly and stably in
the intended decentralized deployment? This is an assessment request, not a new
protocol selection or an answer to either parked/withdrawn question.

**Verdict:** the currently planned complete system cannot be rated robust enough
for reliable irreversible FINAL payment acceptance. The original unrestricted
local-view activation has a concrete conflicting-certificate counterexample; that
is stronger evidence than merely lacking production benchmarks. The new handoff
is a useful conditional research candidate, not a demonstrated end-to-end remedy.

Separate the conclusions:

- Safety: local ticket maturity plus completed state copy does not prevent the
  modeled twenty-two-identity double-FINAL schedule. Conditional closure/inclusion/
  agreement/installation addresses that race within justified configurations.
- Membership/initial recognition: the first-admission construction needs additional
  fixed-instance, identity/fault and strong knowledge-connectivity premises not
  provided by current F2F rules. Human reputation does not establish them.
  Continuous bootstrap and independently joining late verifiers remain unproved.
- Availability/progress: worst-case six Byzantine members may all withhold. A
  single additional unavailable correct member leaves only thirteen responsive
  correct members in a twenty-node shard, insufficient for fourteen. Thus a
  six-Byzantine safety target does not additionally guarantee progress through
  arbitrary honest churn/partitions. The handoff progress premise requires the
  corresponding correct quorums and state available after stabilization. Genuine
  unresolved payment conflicts may still block their affected slots by DEC-023.
- Capacity: configured virtual 1k/10k arrival rates are not measurements of real
  signature verification, disk commits, network queues or large/churning meshes.
  Passing the finite model and existing workspace tests cannot establish a
  deployment throughput, acceptable pause distribution or real robustness rate.

No production/payment-system readiness recommendation follows. Preserve the
potential of the candidate without presenting model success as demonstrated
robustness of the actual planned network. The decision-relevant next gate is an
implementable, justified membership/late-verifier contract under explicit viable
assumptions, followed by end-to-end adversarial implementation and measured load/
churn validation. This assessment introduces no new user question, assumption
adoption, changed quorum, FINAL revocation or Q-S3.3-01 selection.

### 7.42 Autonomous robustness research brief prepared

Record: S2-S3-RESEARCH-BRIEF-001. Date: 2026-10-16 (Europe/Berlin).
Maintainer requests a precise executable prompt for an agent to research existing
solutions online, investigate the blockers to a real robustness verdict, develop
solutions, simulate/test them and determine what changes are necessary. This turn
creates the brief; it does not execute the new research assignment.

Created [decentralized robustness research prompt](../prompts/decentralized_robustness_research.md)
and indexed it in `prompts/README.md`. It preserves the current interview evidence,
DEC-001–052 and original Q-S3.3-01 meanings; requires autonomous lead/subagent work,
primary-source verification, exact node/verifier knowledge, explicit enforceable
assumptions, end-to-end candidates, adversarial simulation and measured versus
configured-rate evidence. It prohibits hiding first membership in an oracle,
assuming a stronger graph without realization, confusing convergence with FINAL,
adding nonresponse tolerances independently, and treating green sampled tests as
proof or actual deployment readiness. Necessary changes to accepted requirements
must be concrete proposals with evidence, not silently selected policy.

The brief defines outcomes, evidence/claim tracking, realistic failure and scale
scenarios, reproduction artifacts, independent review, minimal workable alternatives
when requirements conflict, and persistence/restart discipline. It authorizes
research prototypes/harnesses when invoked, without silently deploying or changing
binding specifications/production behavior. Source discrepancies and current model
claims must be independently checked. The actual research cursor stays S2.1;
first-admission and late-verifier acceptance remain unresolved. No new human
question or protocol choice. No simulation or Rust tests were run for this prompt
creation; readback/link/preservation/whitespace checks are appropriate.

### 7.43 Decentralized robustness research execution

Record: S2-S3-RESEARCH-EXECUTION-001. Date: 2026-10-16 (Europe/Berlin).
The maintainer explicitly invoked the research brief, requested the current
interview state and subagents, and authorized autonomous work to a defensible
result. Starting checkpoint CP-0031 was consistent. Existing uncommitted model,
notes, state and prompt work is preserved. Three independent agents investigate
membership/late verification, adversarial safety and measured execution costs.

Active leaf remains S2.1. Initial falsifiable claim: local mature-ticket activation
and an empty pre-copy admit two conflicting fourteen-vote outcomes in the exact
22-identity growing-network schedule. The broader blocker is compatible first and
late verifier recognition. A recipient-configured checkpoint with certified
successors is investigated as an explicit additional premise/proposal, never as
an adopted policy or proof that present F2F establishes membership. The new
[robustness research report](DECENTRALIZED_ROBUSTNESS_RESEARCH.md) holds stable
R-01–R-12 claim IDs, evidence and continuation. No production changes, specification
rewrite, deployment, commit or PR is authorized by this work. DEC-001–052 and exact
unanswered Q-S3.3-01 remain unchanged. Findings and results will be appended here
before the next checkpoint; this entry records execution in progress.

### 7.44 Decentralized robustness result and tested minimum alternative

Record: S2-S3-ROBUSTNESS-RESULT-001. Date: 2026-10-16 (Europe/Berlin).
Research assignment executed with three disjoint agents, primary-source reads,
independent attacks, isolated executable models and measured real QUIC/storage.
The [focused report](DECENTRALIZED_ROBUSTNESS_RESEARCH.md) owns R-01–R-12,
assumption/enforcement and scenario-coverage tables, sources, proposed protocol,
measured costs, reproducible commands and exact integration gaps. Subreports and
machine-readable manifests live under `docs/research/`.

**Decisive result:** automatic first FINAL from an arbitrary subjective mature
local set is incompatible with irreversible globally compatible payment acceptance
on the allowed F2F discovery cuts. The new 39-identity witness uses one organically
grown network and just one Byzantine bridge. Each hidden nineteen-honest-node
community knows itself plus the bridge and can form a genuine fourteen-signer
certificate for a conflicting owner-authorized spend. The bridge alone double-
signs. Its local transcripts match a legitimate twenty-node world until decision;
waiting a fixed 24-hour interval cannot detect the hidden side before stabilization.
The independent exact 22-identity newcomer/copy-before-A race is also reproduced.
This is a counterexample under permitted discovery conditions, not a universal
impossibility theorem for CUP or stronger externally established graph premises.
The printed CUP v2 source-count P3 discrepancy was independently rechecked against
all fifteen relevant available-row subsets; it is a narrow predicate finding.

**Minimum investigated proposal:** operator-authenticated exact checkpoint bytes
from its own authenticated setup/provisioning/in-person established installation,
followed by certified admitted catalogs/configurations, public closure/inclusion,
BFT successor agreement and durable individual installation. F2F presence supplies
candidates, never self-authorizing votes. No permanent founder must remain; every
original member can be replaced. Late recipients start from their own approved
manifest and verify exact descendant/state/closure/commit/install/payment proofs.
The pure recipient predicate receives no harness membership/fault map. This is an
explicit additional onboarding/admission trust rule, not a selected common root,
not a self-signed list disguised as authority, and not an accepted product change.

The executed security envelope requires <=6 adversarial signing identities per
historical configuration throughout retained evidence use, fourteen responsive
correct old/successor members with required state, eventual authorized learned-
peer communication and nonrollback durable own choices. Current tickets/F2F do
not enforce that key/fault bound. Fourteen recovered retired epoch secrets really
forge history; present-time correctness or fresh labels alone does not prevent
it. Forward-secure/erasure retirement remains a separate unimplemented proposal,
with backup/rollback and final-old-signature ordering costs explicit. Checkpoint
refresh is not a substitute for preserving live old exclusion effects.

**Executed evidence:** original handoff campaign rerun on additive model changes:
seeds1..128, 1,536 scenarios / 4,036,608 abstract steps; all original twelve example
tests passed. New composed campaign: 128 seeds, 1,000,960 scheduled events,
3,072 checks, three full replacements and four honest-only payments per seed,
plus44 recognition/unsafe predicates; fourteen tests passed. This composes actual
model closure/BFT/install/payment outputs with genuine Ed25519 verification.
It retains ideal message authentication and scripted atomic durability; no real
membership wire implementation is claimed. Lead review required the pure anchored
recipient entry point and actual negative tests, including a missing individual
installation receipt despite a valid fourteen-receipt aggregate.

Independent attacks enumerate38,760 closure subsets, retain minority/inherited
conflicts, reproduce private-validity prepared deadlock and long-range mutants.
The new source-transfer verifier has eighteen predicate checks and three tests.
Independent review exposed `install -> crash -> complete -> install` reusing an
old cursor with empty volatile staging. Resetting cursor/root with staging fixes
that regression and retains the previous installed exclusion; a second agent
reviewed the fix. A genuinely re-signed omitted source stream still passes source
cryptography, explicitly demonstrating the separate distributed inclusion gate.

Exact production-HRW-score census over all65,536 shards at N100/10 attackers finds
25 shards above the target six; at N1000/100 attackers it finds131, including13
with at least eight. These deterministic research tickets are not Argon2-verified
eligibility or empirical network probabilities. Hypergeometric sensitivity and
ideal usable-ticket grinding show why a low global fraction, incubation and a
single active ticket are not a per-shard fault guarantee. TTL16 connected-ring/
chain and withheld-bridge counterexamples expose discovery limits even under
optimistic perfect all-edge delivery; local observation times differ.

**Measured execution:** isolated real QUIC/Ed25519/redb Immediate prototype,
queue64/batch32, three3-second repeats. Offered1k/s yields998.7–999.1 useful/s and
p99 5.01–6.77ms. Offered10k/s yields2908–5552 useful/s with saturation; no stable
10k hot-replica result. Adding25ms per storage batch lowers10k offered to950–1116
useful/s. Twenty distinct keys/endpoints/databases complete5/5 low-load checkouts
with20 or14 responders;13 gets0/5 by800ms. Six withholding Byzantine plus one
unavailable correct member therefore cannot progress. Arithmetic minimum for
that extra fault margin is21 voters/q14; it violates selected max20 and is only
an unadopted consequence/proposal. Aggregate network throughput and hot-replica
throughput remain distinct. Million compact catalog rows use96MB and a favorable
single-shard scan about149ms; no million-node all-pairs simulation or deployment
SLA. Handoff latency, real loss/bandwidth/jitter, powercuts, rollback and erasure
remain explicitly unmeasured. Real probe receiver tests reject exact malformed/
tampered/context/conflict cases and demonstrate capacity refusals, not absent
candidate membership/fence/quota/F2F defenses.

**Project checks:** workspace504 passed/0 failed/11 existing ignored tests; strict
workspace all-targets clippy passed, with final changed examples separately
retested. Normal sandbox forbids UDP sockets; authorized loopback execution passed.
Whole-workspace formatting has pre-existing differences and was not rewritten;
new examples formatted, whitespace/links/source hashes and preservation read back.
No production/specification/manifest change, commit, PR or deployment.

**Disposition:** the research establishes a specific incompatibility and a tested
conditional alternative with explicit operational costs. It does not approve
payment deployment or close all implementation obligations. S2.1 remains the sole
active leaf, now at the concrete recognition/admission policy gate; no question
is asked or answered by inference. The next decision must address this researched
onboarding/control-plane tradeoff, then return to S2.2, original Q-S3.3-01 and
resource/durability/wire integration. Preserve DEC-001–052, N>=20/14-of20/800ms,
original unanswered Q-S3.3-01 A/B meanings and withdrawn Q-S2.2-01 status. A broader
six-plus-one outage guarantee cannot be promised without changing max20 or another
explicit requirement. No glossary/threshold/network-domain re-interview.

### 7.45 Project implications and alternative registry architectures

Record: S2-S3-PROJECT-IMPLICATIONS-001. Date: 2026-10-16 (Europe/Berlin).
The maintainer asks whether the project works as planned, what must change and
whether a fundamentally different Collision Lock Registry architecture exists.
This requests explanation/comparison; it does not select checkpoint trust,
federated admission, SCP, an external chain or a new payment-round policy.

Answer: the current complete architecture cannot justify irreversible payment
FINAL under the allowed adversarial discovery/growth schedules. The registry
purpose remains implementable. Blind parent-to-child records, client custody,
origin TTL, bounded queues, QUIC and storage can remain useful components without
claiming each is fully audited. The major required change is counted membership
and its safe state/key succession, not a tuning fix or proof that signatures are
mathematically invalid. A genuine signature authenticates a key's statement; it
does not by itself establish the key's authority in a globally compatible voting
configuration. Every spend slot needs compatible exclusion decisions across time;
independent spends do not inherently need one global total transaction order.

Concrete architecture classes and costs:

- Recognized BFT notary/registry: explicitly authenticate initial voting authority,
  use certified admissions, established round recovery and fenced state transfer.
  This is closest to the tested alternative and preserves blind data/no deposits.
  It introduces onboarding trust and an admission control plane; the historical
  fault/key bound remains an external operating assumption. Fast ordinary spends
  can remain separate from membership agreement. Do not claim an implemented
  or proven one-round HuMoCo design merely because a known engine is available.
- Federated Byzantine agreement: personal trust/quorum choices as in SCP. This is
  a real decentralized alternative, but needs honest quorum intersection and
  explicit trust configuration. Arbitrary F2F friends/HRW views do not supply that
  property. It changes counting and likely the fixed 14/20 architecture.
- External consensus service/ledger: delegate the authoritative consumed-output
  decision (or a separately specified sufficient admission/control protocol) to
  a verifiable existing consensus system. A blind registry can expose only the
  necessary opaque identifiers/proofs, but metadata/privacy must be assessed.
  Import that system's actual finality, availability, cost and trust assumptions.
  Recording an arbitrary later hash does not retroactively prevent double FINAL.
- Single authoritative operator is an engineering baseline with explicit operator
  trust, rather than a solution satisfying the decentralized product objective.

Recommendation is a project judgment, not a selected decision: preserve the blind
registry purpose and useful implementation, simplify/replace the membership and
consensus safety design using an established recognized-group model before
expanding organic sharding. If explicit admission trust is unacceptable, compare
FBA and an external consensus security basis as deliberate larger changes; do not
promise that another algorithm removes all trust/adversary assumptions.

Primary sources rechecked on 2026-10-16:
[SCP §3–4](https://stellar.org/papers/stellar-consensus-protocol.pdf),
[Sui Lutris §2.4/4.2–4.3](https://docs.sui.io/paper/sui-lutris.pdf),
[Kuznetsov/Tonkikh §2–3.5 and Appendix C](https://arxiv.org/html/2005.13499v2),
[Bitcoin §2–5/11](https://bitcoin.org/bitcoin.pdf). SCP's honest-intersection
condition, Lutris's recognized committee/epoch handoff and stake assumption,
reconfiguration's given initial authority and Bitcoin's computational/probabilistic
security are distinct premises, not interchangeable HuMoCo guarantees. No stake
is silently imported into blind L2; no public network product is recommended
without a concrete fit analysis. No new tests or production edits are necessary
for this explanation. DEC-001–052 and original questions remain unchanged.
Active leaf remains S2.1; next action is the researched admission/trust tradeoff,
with the concrete alternatives now explained. No new decision question asked.

### 7.46 Maintainer-directed trust-premise and blind-spot audit

Record: S2.1-TRUST-PREMISE-001. Date: 2026-10-16 (Europe/Berlin).
The maintainer suspects a simple omitted premise and emphasizes that the network
is built through human trust, rather than arbitrary growth. They ask how to find
that blind spot. This steers the next prerequisite within S2.1 toward fidelity of
the intended social admission model before selecting an alternative architecture.
No prior counterexample is erased and no stronger trust rule is inferred.

Read Spec07 §2/2.1, Spec01, current F2F key registration and shard_committee paths.
[Trust audit](research/robustness_trust_blind_spot.md),
[executable finite checks](research/robustness_trust_audit.py) and
[results](research/robustness_trust_audit.json) record the comparison.
Concrete finding: the specification requires meaningful personal/reciprocal/
existing-community checks, but also says one friend suffices for worldwide
activation. Configured NodePubKeys already anchor local friend identity. The
examined committee selector counts local learned mature identities; it does not
verify a transferable human-vetting/delegation predicate. The intended scope of
trust across this step is the active unknown. This is not an assertion that all
social admission is useless or that a new externally issued anchor is necessary.

The bridge fixture models no human performing the qualitative diversity check.
It therefore refutes the precise modeled activation assumptions, not every
possible intended social admission procedure. A stricter intended rule must be
identified concretely and replayed, not invented as a reason to dismiss an attack.
Finite audit shows even minimum nineteen reciprocal friends per identity allows
the 39-identity bridge-only intersection; minimum degree is not correct-graph
connectivity. A separate all-honest weak-handoff mutant with eight newcomers
reproduces fourteen A/fourteen B without honest double-signing when empty pre-A
copy is followed by activation without final cutoff. This isolates protocol
ordering from personal honesty. No real-wire defense or full human model claim.

Working method: reconstruct actual named-human startup/admission actions; identify
which exact honest rule each attack would violate and using what received/local
evidence; formalize only the smallest justified predicate; replay safety and
successful growth/turnover; independently attack colluding introducers, distinct
operator versus machine counts, delays and compromise. Existing friend identity,
reliance on a node's statement and authorization to introduce further voters are
different possible semantics. Signed bounded admission endorsements are an
unselected hypothesis; no transitive guilt, hearsay ban, deposit or new gossip
stream is approved. Preserve separate durability/temporal-key obligations.

Clarification **Q-S2.1-TRUST-01**, sent asynchronously during source review;
exact wording preserved here (ID assigned on durable save):

> Welche Zusage bedeutet eine F2F-Freundschaft für dich konkret: „Ich kenne diesen Betreiber“, „ich vertraue seinen Bestätigungen“ oder zusätzlich „ich stehe für die von ihm aufgenommenen weiteren Betreiber ein“? Beschreibe gern mit einem Beispiel, was ein ehrlicher Betreiber vor einer Aufnahme tatsächlich prüfen muss.

Status at save: clarification pending, no answer or policy selection inferred.
This question does not imply financial liability or punishment of an endorser;
its wording asks the scope of social endorsement. Original Q-S3.3-01 meanings and
withdrawn Q-S2.2-01 status remain unchanged. DEC-001–052 unchanged. Active S2.1;
return to recognition/admission architecture choice only after this premise audit.
No production/specification edit or new Rust/workspace test campaign. Python
finite checks, local links/source hash/preservation/readback checked.

### 7.47 Clarified recursive operator trust; investigation stopped

Record: S2.1-TRUST-CLARIFICATION-002. Date: 2026-10-16 (Europe/Berlin).
The maintainer asks to end the investigation and give only a short statement of
promising directions. Their clarification answers Q-S2.1-TRUST-01: an operator
adds nodes whose operators they believe will keep the intended code unchanged,
operate reliably and themselves select similarly trustworthy friends, recursively.
This is a meaningful intended social admission model and operator belief, not
proof of unmodified execution, a guarantee of zero Byzantine faults or an accepted
unlimited delegation rule. It creates no financial liability, transitive guilt,
automatic ban, measured failure probability or selected protocol change.

Stop further investigation now. Suggested future direction, only: make existing
recursive operator trust explicit in a small F2F admission/delegation contract;
examine what an introducer attests, what other nodes can verify, and how the
influence of a mistaken or compromised friend is bounded. Federated trust/quorum
models are a useful comparison, not an adopted SCP replacement. Preserve the
independent requirement for safe durable state/member succession even when
operators are honest. No new experiments, source search or production edits.

Clarification Q-S2.1-TRUST-01 is answered at the intent level; exact executable
endorsement/delegation rules remain unselected. Q-S3.3-01 remains unanswered and
Q-S2.2-01 remains withdrawn as the next question. DEC-001–052 preserved. S2.1
remains the saved focus; resume further work only on a later maintainer request.

### 7.48 Focused trust-network blind-spot research prompt prepared

Record: S2.1-TRUST-RESEARCH-BRIEF-001. Date: 2026-10-16 (Europe/Berlin).
The maintainer requests a prompt for a future AI investigation into the clarified
recursive operator-trust direction and practical whole-system robustness. This
turn prepares the prompt; it does not resume the stopped investigation.

Created [trust_network_blind_spot_research.md](../prompts/trust_network_blind_spot_research.md)
and indexed it in the prompt README. It starts from §7.47's intended-code,
reliability and recursively careful friendship premise. It requires mapping human
intent/spec/operator actions/local evidence/code/model, checking the admissibility
of prior counterexamples under actual human admission, seeking an existing or
minimal missing mechanism first, primary-source research and independent agents.
It preserves calibrated social premises without pretending acquaintance proves
honesty, key independence, runtime integrity, graph connectivity or stable state.

The future assignment authorizes isolated research models/prototypes and real
execution measurements when explicitly invoked, not production deployment or
specification rewriting. It requires successful growth/full-turnover/late-recipient
and recovery paths, negative mutants, bounded resources, practical operator costs,
wire defense tests and measured-versus-assumed evidence. A positive result is not
predetermined; an unresolved in-envelope double FINAL excludes a safety approval.
A field-robustness claim must disclose unmeasured human behavior and its concrete
validation gap. No blanket algorithm/anchor/FBA choice or smaller attacker assumed.

The planned output is `docs/TRUST_NETWORK_BLIND_SPOT_RESEARCH.md`, stable T-claims,
runnable artifacts/results, operating conditions and a clear verdict. Latest
consistent checkpoint and original decisions/questions must be resumed. DEC-001–052,
answered Q-S2.1-TRUST-01 intent, parked Q-S3.3-01 and withdrawn Q-S2.2-01 unchanged.
Validation is document readback, local links/content gates/preservation and
whitespace only; no experiments or source behavior changes performed here.

### 7.49 Bounded review of the Certified Epoch Handoff proposal

Record: S2-S3-CEH-REVIEW-001. Date: 2026-10-16 (Europe/Berlin).
Maintainer supplies [CERTIFIED_EPOCH_HANDOFF_PLAN.md](CERTIFIED_EPOCH_HANDOFF_PLAN.md)
and asks whether it solves the problem. This authorizes review of that proposal;
it does not invoke the future trust-research prompt, resume a broad experiment
campaign, adopt the proposal or select Q-S3.3-01. The proposed plan was not edited.

**Verdict:** a sound architectural direction for recognized authority, but the
current v1.0.0 text is not a complete safe/live handoff specification. Its "Resolved"
labels and liveness theorem overstate what its actual steps establish.

**What it addresses.** §4.1 line135 introduces authenticated out-of-band approval
of an exact genesis/checkpoint anchor. Given that independently established
reference, a verifier can derive the predecessor roster from the validated chain;
today's local gossip view no longer defines voting authority. This removes the
circular predecessor premise WITHIN that recognized network. Fourteen signatures
from the manifest's own claimed roster do not themselves authenticate the initial
reference, select a globally unique genesis, guarantee honest participants or
establish that every operator was provisioned consistently. Recognition must apply
to nodes/gateways as well as payment recipients. No permanent founders are necessary.
This is explicit onboarding trust proposed by the document, not proof that original
unconstrained subjective activation was sufficient and not an adopted user policy.

**P1 — Successor sign-once is not recoverable BFT agreement (§4.3 lines173–189;
§5 Theorem3 lines244–250).** A permitted execution has six Byzantine members withholding endorsements
and fourteen responsive honest members. A Byzantine proposer sends proposal
X to eight honest nodes and Y to six (e.g. different locally matching roots). Those honest nodes fence and durably sign
once for E+1. Neither proposal reaches fourteen; their immutable choices prevent
later convergence even after communication stabilizes. A failed rank-one proposer
has no specified failover either. Safety of two competing certificates within a
fixed roster follows from the intersection arithmetic, but progress does not.
Define rounds, phase/instance-scoped signing rules and safe prepared-evidence
carryover; resetting sign-once or choosing another proposer alone is insufficient.
[PBFT §4.4](https://www.usenix.org/legacy/publications/library/proceedings/osdi99/full_papers/castro/castro_html/node4.html)
is the checked primary reference for known-roster view change; its recovery
machinery does not itself provide closure validity or unknown membership.

**P1 — No construction of the common closed state (§4.3 lines178–206).**
Different honest replicas can have different valid partial lock/own-choice sets.
Literal equality of the proposed root with each local root does not reconcile
these sets. A union root may differ from every initial local root; forcing equality
can stall despite available honest members. Quorum intersection proves preservation
only when the common available payload is actually validated for inclusion of the
signer's own AND inherited exclusions, including released votes without a stored
full payment certificate. "All active locks" must specify those effects. An
individual released binding vote must not be reclassified as nonbinding merely
because a fourteen-vote aggregate is absent (§2 line30).
Use the prior researched separation: durable proposal-independent fence/drain,
non-exclusive closure-inclusion certificate, then publicly valid successor BFT
agreement. Reintroducing private inclusion validity on every later agreement vote
also reproduces §7.40's prepared-value deadlock; equality cannot simply be replaced
with an unqualified per-voter private inclusion veto.

**P1 — Durable fence/drain/install ordering incomplete (lines179,201–210).**
The proposer computes a root before other members finish closing pending writes.
Specify the final source endpoints after all endorsed effects are closed. An
800ms timeout cannot prove disk commits finished: on expiry, preserve or safely
cancel pending operations and withhold the transition endorsement as necessary.
Persist the fence and inherited state/readiness atomically as appropriate; merely
installing into RamIndex (line193) gives no crash/restart safety argument. An old
pre-fence durable vote may arrive after closure and must remain covered. These are
required ordering contracts, not a finding that every possible implementation of
the current underspecified prose necessarily violates safety.

**P1 — Epoch-history pruning/checkpoint authorization is unsound as stated
(§2 line38; §6 lines258–264).** An old certificate is also an authority link for
later configurations and newly created vouchers. Expiry of its former voucher
records does not remove that verification dependency. Deleting intermediate hash
links breaks a genesis-to-current proof. A Merkle branch against a gateway-published
root proves inclusion in that root, not that the root is an authorized checkpoint.
Require a concrete independently trusted refreshed checkpoint/policy, an adequate
certified compaction proof or retained necessary lineage, including cold/offline
recipient behavior. One shared epoch certificate also has no single root TTL;
its retention cannot be inferred from an unspecified voucher maximum.

**P1/P2 — Remaining security/integration premises.** EpochPubKey fields alone do
not specify genesis epoch-key bindings, exact vote verification keys, safe old-key
retirement/erasure, backup/rollback handling or protection against later compromise
of retired signing quorums. Either explicitly maintain the historical lifetime
fault bound or supply the temporal-key design; a current-committee-only bound is
insufficient. Likewise "HRW rank correct" and ticket age need one agreed proposal
input/eligibility contract; differing live discovery/maturity views are not an
objective shared catalog merely because a successor certificate exists. The six-
fault target is still assumed, not established by admission or signature validity.

**Performance/claim corrections.** Durable redb acknowledgment is on the described
payment path; the entire path is not RAM-only and a CAS timing does not imply a
<5ms processing bound. This also conflicts with the interview's selected removal
of that rigid target. A fenced shard pauses writes during transition; doing work
in a background task does not erase that pause. <=6 total faulty/unavailable
members plus communication/round/state prerequisites is different from six
Byzantine members plus another outage. The 14/20 intersection bound, not CAP alone,
explains why thirteen replies cannot satisfy the chosen quorum.

**Next disposition.** Keep the explicit recognized-anchor/certified-succession
architecture as a candidate. Revise the closure/recovery/pruning/key/eligibility
contracts and replay the existing corresponding mutants before marking them
resolved. No automatic anchor acceptance, new payment round, alternate quorum,
production edit or new test execution. The broad recursive-trust investigation
remains stopped; this bounded proposal review is complete. DEC-001–052, original
Q-S3.3-01 wording/options and other pending/withdrawn statuses are preserved.

### 7.50 Review CEH v1.1.0: improvements and remaining prepared-state trap

Record: S2-S3-CEH-REVIEW-002. Date: 2026-10-16 (Europe/Berlin).
Maintainer asks to inspect the updated [CEH plan](CERTIFIED_EPOCH_HANDOFF_PLAN.md),
now version 1.1.0. Bounded proposal review only; no adoption, plan edit, broad trust
research resumption or new test campaign. Preserve all original decisions/questions.

**Progress compared with v1.0.0.** The text now includes PREPARE/COMMIT rounds,
proposer rotation, prepared-proof carryover, missing-obligation reconciliation,
durable fence/installation and explicitly operator-authenticated recent checkpoints
for cold recipients. These directly address the earlier concerns. Recognized
anchor/lineage remains a sound conditional authority architecture. A genuinely
approved recent checkpoint can replace deleted genesis prefixes for newly
provisioned recipients. It does not authenticate itself via a remote boolean.

**P1 — Public prepared validity versus repeated private inclusion remains
underspecified and admits a stalled execution (lines159–194,218–227).**
Eight honest members and six Byzantine members can issue fourteen PREPAREs for P,
while six other honest members have genuine own obligations missing from P and
refuse its phase-one validation. Deliver the prepared proof to the eight honest
supporters; Byzantine members withhold COMMIT. On round change, the highest
prepared rule carries P. If the new round repeats the written phase-one own-
inclusion check, the six omitted honest members still refuse P; extending P
changes its locked value. Only eight honest votes remain despite all fourteen
honest members being connected. The theorem's step2 (split proposals cannot
produce fourteen prepares) is false: eight honest plus six Byzantine suffice.

The diagram's phase-two validation could be intended to accept a valid prepared
certificate publicly without requiring personal phase-one inclusion. If so, that
exception and recovery path must be explicit, especially after a round change:
may a replica that refused PREPARE still commit based on a prior prepared proof,
and how does the new proposer resume without requiring fresh private inclusion?
Do not claim every conceivable completion of this sketch deadlocks; the literal
repeated phase-one path permits it, so "deadlock-free" has not been established.
Minimal requirement: certified inclusion is PUBLIC validity for agreement/recovery;
private own decisions remain locally immutable even if their singleton effects
were not in the selected closure. A separate non-exclusive closure certificate is
one already researched construction. Missing/inherited conflict effects and genuine
late full certificates must keep their §7.40/7.44 semantics.

**P1 — Fixed five-second rounds do not establish partially synchronous progress
(lines192,222–227).** GST means eventual finite delay, not an established five-
second upper bound for message/state/commit processing. Specify adaptive growing
timeouts and round catch-up, or an explicit sufficient measured/assumed bound.
The next proposer must present fourteen authenticated round-change reports and a
checkable highest-prepared selection FROM THOSE reports; an unknowable global
highest proof is not an executable rule. Phase/round/slot signing domains must
also distinguish legitimate PREPARE/COMMIT and independent payment slots.
[PBFT §4.4–4.5.2](https://www.usenix.org/legacy/publications/library/proceedings/osdi99/full_papers/castro/castro_html/node4.html)
was rechecked: explicit new-view evidence validation and increasing timeouts are
part of the compared recovery mechanism, not supplied by a proposer rotation label.

**P1 — Old admitted writes and transferable effects still need exact closure
ordering.** v1.1 persists the admission fence and installation, improving crash
safety, but does not state the final drain/cancel boundary for already admitted
writes before the endorsed snapshot. Prohibit later unrepresented vote release.
Define own/inherited bindings without requiring a stored full payment certificate;
clarify how a union containing conflicting choices becomes a conservative blocked
effect rather than overwriting one entry or making the whole transition invalid.
Atomic install/readiness and restart checks must remain explicit.

**New scope conflict: one-year voucher maximum (§2 line39; §6 line247).**
`humoco-sim-core/src/storage.rs` lines7–18 currently permits eleven years through
`MAX_LOCK_TTL_YEARS=11`, consistently with the previously inspected ingress tests.
Reducing this to one year changes accepted voucher validity/product compatibility;
it is not implied by approval of a bounded certificate cache. No such requirement
change is selected here. Certificate proof retention/checkpoint refresh and live
own/inherited exclusion retention are distinct concerns; the latter must last
until the authentic root expires plus grace. Explicitly cover an existing terminal
returning after its last verified head has fallen outside the available history,
not only a newly installed terminal. A trusted moving window boundary/refresh
policy is needed. The checkpoint trust direction itself is now materially improved.

**P2 — Self-contained candidate proofs do not establish global HRW completeness
(lines182–185).** Twenty valid identity/ticket/endorsement bundles authenticate
those candidates. They do not prove absence of a higher-ranked omitted identity or
which maturity/first-observation statement others should accept. Define ranking
against a certified common proposal catalog/cutoff, or explicitly authorize the
agreed successor set with HRW as proposal generation. There is no need to demand
identical live discovery caches. The permitted introducer, ticket replacement and
maturity attestation predicate remains to specify; a timestamp alone does not
prove twenty-four-hour network observation.

**P2 — Resource arithmetic and latency remain overstated.** With 32-byte Ed25519
identity and epoch keys, the declared two twenty-key arrays use1,280 bytes. Fourteen
(NodePubKey,Signature) tuples use1,344 bytes, and fixed fields use78 bytes:2,702
bytes before vector/framing overhead, about2.7kB rather than1.5kB. At one committed
transition/day this is roughly1MB per shard/year, not550kB total. State/root/proof
payload and failed-round logs are additional. The <5ms SLA still counts batch
enqueue while invariant2.4 requires durable completion before releasing the vote;
those have different latency semantics. Prior measured costs are not a guarantee.
Historical epoch-key binding/retirement, late compromise and rollback remain
unresolved from v1.0.0; merely retaining the epoch-key field does not resolve them.

**Disposition.** v1.1 is a better foundation and resolves some previous omissions,
but the claim that all six ledger items are resolved is premature. Correct the
prepared/private-validity recovery path, adaptive timing and closure contracts;
resolve the unapproved one-year change and specify checkpoint/eligibility/key
semantics before safety/liveness approval. No new A/B choice or experiment result.
The broad investigation remains stopped; this requested version review is complete.

### 7.51 Review CEH v1.2.0: public prepared validity improved, closure and recovery still conditional

Record: S2-S3-CEH-REVIEW-003. Date: 2026-10-16 (Europe/Berlin).
Maintainer requests another bounded assessment of the current
[CEH plan](CERTIFIED_EPOCH_HANDOFF_PLAN.md), version 1.2.0. This is review only;
the plan's new specification/baseline label is not architecture adoption. Broad
recursive-trust research remains stopped. No proposal/production edits or tests.

**Verdict and actual improvements.** Recognized starting authority plus certified
succession remains a viable conditional architecture. The earlier eight-honest/
six-Byzantine prepared/private-veto scenario is now explicitly addressed (§4.3
rule3): honest replicas may accept the prepared value without repeating private
inclusion vetoes, while retaining their own choices. Do not report this particular
omission as unchanged. The eleven-year voucher maximum is restored and the raw
certificate calculation corrected to approximately2.7kB. These are substantive
repairs. They do not establish the document's unconditional "Resolved" or
deadlock-free claims, nor replace the fault/admission and historical-key premises.

**P1 — Capped backoff contradicts the stated liveness proof (§4.3 lines189–193;
§5 lines218–228).** T(r)=min(2*2^r seconds,60seconds) never exceeds60seconds.
Partial synchrony supplies an eventual finite delay, not a bound below30seconds.
For example, with a stabilized one-way delay of40seconds, T(r)>2*Delta is never
reached; a schedule can keep votes arriving after their round has expired. The
proof and diagram silently use an uncapped formula instead. Require an eventually
sufficient timeout/round synchronizer, or explicitly narrow the operational timing
assumption and retain safe stalled behavior beyond it. State-transfer and durable
processing time also belong in the required interval. Reaching an honest proposer
within seven consecutive leaders does not itself synchronize fourteen replicas.

**P1 — A collection deadline is not a write-completion barrier (§4.3 lines171–173).**
Waiting800ms and flushing currently submitted disk work does not establish that
every previously admitted handler/job finished or was irrevocably canceled. A
paused admitted job can resume after the flush/snapshot; gateway timeout does not
cancel a server-side decision. The claimed no-race property needs an explicit
admission fence plus drain/cancel accounting, followed by the final durable state
and snapshot. If a drain budget expires, remain fenced/not-ready rather than
endorse an incomplete closure. Include shard-direct lock RPC admission, not only
the gateway's POST route. This is a missing executable ordering contract; a proper
barrier can satisfy it without relying on every old node being available.

**P1 — Public validity needs safe round-change evidence, not unconditional
acceptance of any prepared proof (§4.3 lines147,157,186,190).** Define authenticated
NEW_VIEW evidence (fourteen reports in this model), the highest permitted prepared
value within that report set, current-round checks and safe lock carryover. A
delayed proof from an older round must not blindly "force Commit" after a later
decision. Specify exact phase/instance/round signing domains; PREPARE and COMMIT
for the same proposal are legitimate distinct signatures. The same-round sign-once
rule and quorum arithmetic alone do not prove unique successors across rounds.
The cited algorithm's concrete recovery machinery matters:
[PBFT §4.4–4.5.2](https://www.usenix.org/legacy/publications/library/proceedings/osdi99/full_papers/castro/castro_html/node4.html),
rechecked for this review. Its proof is not automatically a proof of this sketch.
Theorem2 step2 is still false as written (eight honest plus six Byzantine can
prepare despite a split), although step6 now explicitly handles that case.

**State-transfer semantics (§4.3 rule3b).** The intersection argument can preserve
every possible old fourteen-vote payment certificate if honest preparers verify
inclusion of all safety-relevant own AND inherited effects after the completed
fence, even without holding the payment aggregate. Define that predicate and the
available authenticated payload. It does not imply that every unreachable
singleton choice is globally present. Keeping a private omitted lock only on a
retired node, then forwarding it after successor activation, does not by itself
make the slot globally blocked. Separate immutable local own-choice retention,
certified inherited exclusions, genuine partial-conflict BLOCKED effects and late
full-certificate handling. Do not invent a requirement to contact all twenty old
nodes. "Retain them permanently" contradicts root-valid-until plus30s expiry;
retain necessary effects until justified expiry instead. Original Q-S3.3-01 stays
unanswered; this review selects neither payment-round alternative.

**Remaining bounded integration gaps.** The preceding-epoch catalog reference
improves the HRW basis, but twenty ticket bundles plus rejection on a locally known
omission proof do not establish catalog completeness. Define the committed catalog
root/cutoff/update and verifiable selection, or explicitly make HRW proposal
generation for an agreed eligible set. Identical live discovery caches are not
required. Existing/checkpointed recipients also need a refresh rule before deleting
authority links they still depend on; recent trusted cold checkpoints are a valid
direction. Epoch-key bindings, retirement/rollback and later compromise of historical
quorums remain unspecified. A current-committee fault bound alone does not cover
old signing-key compromise. The enqueue-only <5ms calculation still omits the
mandatory durable acknowledgment before a binding vote is released.

**Resource scope correction (§1.2 line26; §6).** Approximately10.8MB is PER SHARD
at daily transitions over the stated4015-day window. Keeping independent histories
for all65536 shards would be approximately710GB before payloads, indexes and failed
round logs. This matters at N=20 where every node serves all shards, or for a
verifier configured to retain every shard's history; it is not a claim that every
terminal must retain every shard. Shared/batched certificate structures or newer
trusted checkpoints can change costs, but are not described here. Bounded history
can be O(1) in network age without being one small constant-cost verification.

**Disposition and next gate.** Retain CEH as a concrete architecture/prototype
candidate. Repair the timer/drain/view-change predicates and explicit obligation
semantics, then map this exact version into an executable state machine and replay
the existing adversarial cases before calling it verified. Do not start that
implementation or a broad campaign from this review request alone. No new human
decision is needed for these technical corrections. DEC-001–052 and all exact
pending/withdrawn question meanings are preserved.

### 7.52 Review CEH v1.3.0: improved recovery, unsafe abort inference and incomplete client authority proof

Record: S2-S3-CEH-REVIEW-004. Date: 2026-10-16 (Europe/Berlin).
Maintainer asks to assess the current [CEH plan](CERTIFIED_EPOCH_HANDOFF_PLAN.md),
now version 1.3.0. Bounded review, preserving the stopped broad investigation and
all existing policy/question states. No plan or production edits, new simulation,
benchmark or test execution. Findings below are static protocol reasoning.

**Verdict and progress.** The certified-succession architecture remains a viable
conditional prototype basis, not yet a complete verified deployment design.
Uncapped timeout growth repairs the specific sixty-second-cap defect. Fourteen
signed round-change reports, independently checked highest-prepared selection
and a NewViewCertificate materially improve recovery. The write counter is a
useful barrier ingredient; explicit successor UNRESOLVED_CONFLICT representation
and root-expiry retention improve the transfer discussion. On-demand caching can
reduce terminal persistence. Credit these changes; do not repeat the earlier
absence of growing timeouts or new-view evidence as if unchanged. The audit ledger
now distinguishes specification from empirical verification, but assertions called
formalized are still prose, not an executed formal model or established proof.

**P1 — Forced timeout abort does not discharge a binding write (§4.3 lines212–217).**
The new rule forcefully terminates a write after800ms, marks RAM aborted and
decrements the counter. A gateway deadline is not a local transaction deadline:
the durable choice may already exist or its signature may have escaped, and an
ongoing persistence job may still complete after the request task is canceled.
Neither fact may be erased by a RAM abort marker. Require atomic fencing versus
admission/counter acquisition on every shard-write RPC path; count actual owned
work through durable completion or demonstrably irrevocable pre-decision cancel.
Release the counter only once no unrepresented decision/signature can appear.
Already committed/released choices remain in the closure and immutable own-choice
table. If that cannot be established within a drain budget, stay fenced/not-ready.
Merely forcing the counter to zero does not prove a completed drain. The current
POST-only description also misses the separate shard-direct receiving boundary.

**P1 — New on-demand client tier omits the authority dependency (§4.2 lines154–165).**
Checking fourteen receipt signatures against the roster in the attached current
EpochCertificate proves internal consistency, not recognition by the trusted
network. That certificate is signed by its predecessor; its predecessor roster
must itself be authenticated back to the terminal's trusted checkpoint/anchor.
A cold cache therefore needs the missing chain, or a verifiable membership proof
against a sufficiently current authenticated checkpoint root. An LRU cache of
current certificates does not create that proof. An attacker-supplied roster plus
its own genuine signatures is the simple counterexample if the described two
checks are treated as complete. §4.1's track-forward rule is compatible with a
correct on-demand implementation, but §4.2 must explicitly require and cost the
missing proof rather than imply2.7kB alone authenticates any current committee.
Statistical HRW plausibility is diagnostic only; it cannot independently authorize
FINAL. The diagram's Mode A/B wording and separate Tier2 need that restriction.
A deliberately trusted local gateway is an explicit different verification policy,
not zero-trust client verification. No such policy is selected by this review.

**P1/P2 — A node cannot know a lock never reached quorum (§4.3 lines229–231).**
Concrete permitted history: eight honest nodes sign A, the other six honest nodes
sign B, and six Byzantine members additionally send A signatures only to a gateway.
The gateway holds A's authentic fourteen-vote receipt, while the honest source
records visible during transfer show eight A choices and six B choices. No honest
node double-signed. The same visible honest records are possible when those six
Byzantine A votes never existed. Thus the successor cannot infer "neither reached
14" from the observed partial counts. Both effects may conservatively block the
slot pending evidence; a later genuine A receipt must be re-evaluated under the
selected sufficient-support policy, not categorically ignored until expiry.
The new until-expiry blanket statement lacks this late-evidence path. Also define
which verified conflict effects must be in the certified payload BEFORE readiness;
optional reporting after activation is insufficient for obligations promised by
the closure. Preserve expiry relative to the authentic root, including grace.
This does not require collecting all twenty old nodes or settling Q-S3.3-01.

**Remaining proof and integration limits.** NewViewCertificate is progress, but
the executable round synchronizer, stale-message gating, phase/slot/network/shard
signing domains, durable lock rules and safe state availability still need exact
predicates. Increasing local timeout lengths alone does not prove sufficient
overlap in one round. The reviewed primary reference specifies those recovery
mechanisms explicitly:
[PBFT §4.4–4.5.2](https://www.usenix.org/legacy/publications/library/proceedings/osdi99/full_papers/castro/castro_html/node4.html).
Theorem2 step2 remains false (a split can still yield eight honest plus six
Byzantine prepares); the later prepared-case branch must replace that assertion.
The committed candidate catalog/completeness contract, historical epoch-key
bindings/retirement/compromise and checkpoint refresh before history pruning
remain open from §7.51. The <5ms enqueue-only SLA still does not measure durable
vote release. These are carried obligations, not newly discovered impossibility.

**Resource scope.** Terminal LRU caching is a legitimate storage optimization;
it does not eliminate chain retrieval/verification cost. Assigned-shard storage
uses approximately20/N of all shards: at N=20 every member is still assigned all
65536 shards, so the stated daily eleven-year independent histories still total
approximately710GB per such node if retained for that whole interval. The ledger's
claim that a terminal stores only its voucher shard's10.8MB also contradicts the
main text's multi-shard ephemeral cache description. Shared history/checkpoint
compaction would need its own concrete proof and cost contract.

**Next gate.** Correct the forced-abort semantics, require authenticated client
lineage, and define partial/late-certificate transfer behavior. Then validate this
exact state machine with adversarial scheduling/crash/replay cases before claiming
safe and robust operation. Simulation is evidence, not a substitute for proving
the stated safety assumptions. No new preference question or protocol selection
is necessary for these technical findings. DEC-001–052 and the original unanswered
Q-S3.3-01 remain unchanged; broad trust research remains stopped.

### 7.53 Review CEH v1.4.0: prior fixes credited, new retention and unified-mode contracts incomplete

Record: S2-S3-CEH-REVIEW-005. Date: 2026-10-16 (Europe/Berlin).
Maintainer requests assessment of the current [CEH plan](CERTIFIED_EPOCH_HANDOFF_PLAN.md),
version 1.4.0. Bounded review only. The document's proposed Phase8 freeze does not
constitute maintainer approval, architecture adoption or execution authorization.
Broad trust research stays stopped; DEC-001–052 and exact questions are preserved.

**Verdict and credited repairs.** The previous three highlighted defects are now
addressed at architectural intent level: committed/released votes survive gateway
timeouts and the counter tracks real storage work; FINAL requires an authenticated
epoch-to-anchor/checkpoint chain; a valid late predecessor certificate may resolve
a partial conflict. Do not repeat forced abort, standalone roster verification or
unconditional until-expiry conflict retention as if still prescribed. Atomic
admission fencing across shard-direct writes, crash/replay details and exact
closure validity remain implementation/proof obligations. CEH is a plausible
conditional prototype basis; the new storage rules are not yet a complete safe
retention/compression protocol. This review finds specific gaps, not impossibility
of certified succession or of bounded certificate storage.

**P1 — Thirty-day pruning must preserve old-evidence authorization (§2 line43;
§4.3 line233; §6 lines303–305).** The separation of voucher lifetime from certificate
cache lifetime is legitimate in principle. However, checkpoints must explicitly
preserve the dependencies that the new late-certificate rule needs. Example: at
day0 an authorized old committee produces A's fourteen-vote receipt, held by a
client; successors retain a partial conflict. Certificates are pruned after30days.
At day60, a fresh successor or terminal trusted only from a recent checkpoint
receives A's still-live receipt. Its fourteen public-key signatures cannot alone
prove membership in the day0 authorized committee. A root authenticating only
current rosters does not prove historical membership. Define preserved per-slot
authorization context, a client-carried historical authority proof recognized from
the retained trust basis, or adequate authenticated checkpoint commitments/proofs.
Also cover a verifier returning after more than30days. Do not assume a checkpoint
label automatically supplies either proof availability or backward verification.
The existing structures provide no such contract. This is a carried dependency
made concrete by the newly shortened retention window, not a demand to retain
all historical chains everywhere for eleven years.

**P1/P2 — Unified manifests need a defined commitment; N<=40 changes membership
policy (§4.1 lines111–113; §6 lines297–302).** At N=20 the same identities can serve
all shards, so batching is useful. Nevertheless the declared EpochCertificate
contains shard_id and closed_state_root: certificates for different shards are
not identical even when the signer roster matches. A unified certificate needs
an authenticated mapping/commitment (for example a Merkle root over shard-bound
closure and successor data), a canonical signed format, leaf proofs and durable
activation/transfer rules. Reusing the old2.7kB count alone does not specify this.
At N=21..40, per-shard HRW top20 sets generally differ. Assigning all shards one
common pioneer committee changes eligibility/work distribution and the existing
N>=20 sharding policy; it is not merely certificate deduplication and is not
approved by this review. The executive summary says N<=20 while the detailed
rules say N<=40. Prefer investigating proof batching compatible with the existing
membership rule before constructing a second small-network regime. This is a
technical recommendation, not a selected replacement protocol.

**P2 — The under150MB total-node bound is false (§1.2 line27; §6; ledger row4).**
Using the plan's own approximate2700byte certificate and30daily certificates per
shard gives81000bytes/shard. Bounded arithmetic evaluated this review:

| Network size | Mean assigned shards, 20*65536/N | Thirty-day certificate bytes/node |
| --- | ---: | ---: |
| 41 | 31968.78 | 2589471220 (approximately2.59GB) |
| 100 | 13107.20 | 1061683200 (approximately1.06GB) |
| 1000 | 1310.72 | 106168320 (approximately106MB) |

The all-shard figure is5308416000bytes, matching the document's own5.3GB worst
case. HRW's20/N fraction is an average, not a deterministic per-node upper bound.
These numbers cover certificate bodies only: live eleven-year lock state, payloads,
proofs, indexes and recovery logs are additional. One shared daily certificate
uses985500bytes/year for one logical history; twenty replicated copies use
19710000physical bytes/year, so "across the entire network" must not be used for
the single-copy size. Thirty days also does not imply thirty certificates without
an enforced one-transition/day bound. Updated triggers now say ranks-shift routine
windows. Separate actual byte/epoch cadence assumptions from hard bounds.

**Carried proof gates and next action.** Historical key compromise/retirement,
candidate-catalog commitment/completeness, inherited effect inclusion, safe
new-view/current-round gating and round synchronization remain open from §7.52.
Theorem2 step2 still incorrectly says a split cannot produce fourteen PREPAREs;
eight honest plus six Byzantine suffice. The enqueue-only <5ms claim still omits
the mandatory durable vote acknowledgment. Do not confuse these carried gaps with
new experiments or evidence that the three repaired requirements remain absent.
Before freezing this as a complete simulation specification, define checkpoint
history coverage and unified-manifest semantics, preserve existing sharding unless
explicitly changed, and replace the storage cap with scoped measured/derived
figures. Then test the exact state machine, including day60 late receipt and
20->21 / 40->41 transitions. No simulation was run in this review; only the printed
bounded resource arithmetic was evaluated. No new preference question is required.

### 7.54 Cross-interview risk priority: central handoff problem versus other critical gates

Record: ARCH-RISK-ASSESSMENT-001. Date: 2026-10-17 (Europe/Berlin).
Maintainer asks whether the problem just discussed was the most critical and
whether the remaining interview items are less uncertain/critical. Reviewed the
compact state, decision/open/gap registers, §7.3/7.41/7.44 and §7.49–7.53, plus
the robustness report's evidence ledger, operating envelope and delivery gates.
The current proposal has independently advanced to CEH v1.5.0; this is a bounded
cross-interview assessment, not a full new version review or implementation run.

**Direct answer.** Justified membership and safe preservation across committee
turnover were the largest foundational architecture blocker. R-01/R-02 establish
actual conflicting-FINAL executions under the investigated original rules, not
merely untested performance or a missing cache optimization. Authenticated authority
and certified turnover provide a plausible conditional way forward; related
bounded models demonstrate important cases, not a delivered whole-system proof.
The latest certificate-storage debate is a subproblem of historical verification
and live-obligation continuity, not the original entire blocker. Some remaining
items are more conventional engineering, but several remain equally consequential
to security. Probability/effort/completeness cannot be inferred from this ranking.

| Priority/class | Interview/result references | Remaining consequence and evidence limit |
| --- | --- | --- |
| Fundamental safety: recognized membership, correct closure/inclusion, unique successor and individual durable install | OPEN-01/02/03/09; R-01/02/03/04/09/11 | Incompatible FINAL or lost exclusions if wrong. Concrete original attacks; conditional alternative tested; current CEH not proved end-to-end. |
| Critical security premise: per-shard adversary bound and historical key security | OPEN-02/13; S1/S6; R-05/07 | F2F/tickets do not establish <=6 hostile identities in each relevant committee. Later compromise of fourteen retired secrets reproduced authentic forged history. A current-committee-only bound is insufficient. |
| Critical implementation: durable own choices, crash/loss/rollback gate, safe expiry/time | OPEN-09/10/11; O1/O2/O3; R-09/12 | Losing an issued vote or deleting its exclusion early can enable conflicting signing. Requirements selected, exact production integration and abrupt-failure/rollback validation incomplete. |
| Critical acceptance: genuine signatures, recognized roster, exact intent/slot/root and FINAL/PROVISIONAL distinction at every client consumer | OPEN-04/05/06/13; GAP-03/04; §7.3 | A correct shard protocol cannot protect a recipient accepting an invalid or provisional proof. Prior static core findings are dated observations, not a fresh audit proving the same code is unchanged today. CEH describes intent, not completed shared-library rollout. |
| Operationally critical availability/capacity | OPEN-07/08/09; R-06/08/10 | Six withholding plus one additional correct outage leaves thirteen replies, so14/20 stops. Safe refusal avoids false FINAL but can still make payments unusable. Real local probes do not establish multi-host/churn/high-load robustness. |
| Usually downstream tuning/operations | Parts of OPEN-07/08/12; O4/O5/O6 | Exact retry intervals, cache sizes, metrics, packaging and latency targets are generally bounded engineering once safety semantics are fixed. Administration authentication and receiver-side resource limits remain security relevant; the entire operations branch is not low priority. |

**Interpretation of existing results.** The robustness report records positive
recognized-alternative models (128 seeds,3072 composed checks and multiple full
turnovers), deliberate negative mutants and real QUIC/storage measurements. These
establish feasibility evidence for scoped mechanisms and explicit failures of
others. They do not validate the full current CEH plan, actual human/F2F attacker
distribution, repeated old-key compromise or production integration. Workspace
tests passing in the earlier campaign do not implement missing certified-control-
plane protections. No completion percentage or low residual-risk probability is
justified. Full specification/interface/invariant coverage remains OPEN-14.

**New consequential proposal noticed, not adopted.** CEH v1.5.0 §2.5 and §4.3 rule3
limit late receipt redemption to30days and leave unredeemed conflicts blocked
until voucher expiry. In the §7.52 eight-honest-A/six-honest-B plus six hidden
Byzantine-A-votes history, a legitimate old fourteen-vote receipt presented on
day60 would therefore no longer clear the conflict. This can preserve no-double-
spend safety while denying continued use of an already confirmed, still-live
voucher. It is an additional product/security-availability tradeoff against the
chosen continuity direction DEC-045, not merely a shorter certificate cache and
not approval inferred from this question. The executive assertion that certified
payments can "always" be redeemed must be qualified accordingly. Settled-state
carryover can legitimately summarize old evidence once correctly authenticated;
that does not resolve the separate hidden-certificate conflict case. No A/B choice,
new cutoff, FINAL revocation or Q-S3.3-01 answer is selected.

**Recommended priority.** Establish the full membership/closure/retention contract
with explicit fault/key premises; verify exact client acceptance and durable
restart/install behavior against it; then measure availability and catch-up under
adversarial wire/load/churn conditions. Peripheral tuning follows those gates.
This ordering is an assessment recommendation, not authorization to restart the
stopped broad research campaign or make production changes. No new test/model
execution, deployment or new policy question; DEC-001–052 and original question
meanings preserved. S2.1 remains the saved active prerequisite.

### 7.55 Plan the remaining security work from the supplied architectural response

Record: ARCH-CLOSURE-PLAN-001. Date: 2026-10-17 (Europe/Berlin).
Maintainer supplies a proposed response to §7.54 and requests a concrete plan for
clarifying the open items. Created
[CEH_SECURITY_CLOSURE_WORK_PLAN.md](CEH_SECURITY_CLOSURE_WORK_PLAN.md), with ordered
P0–P7 packages, dependencies, subagent boundaries, concrete deliverables and exit
criteria. CEH v1.5 is the working baseline for planning, not a claimed verified
protocol. The supplied continuity correction reaffirms DEC-045: no thirty-day
deadline may silently invalidate use of a genuine, unexpired payment receipt.

The response is useful direction, but several proposed sufficient conditions are
not sufficient. Historical client custody needs an available authenticated path,
not only one2.1kB certificate; fresh clients after pruning and cross-checkpoint
ownership transfer are explicit proof duties. Ephemeral keys need authentic
lineage, safe retirement and copy/backup/restore assumptions; zeroize alone is not
forward security and does not establish the active per-shard fault bound.

Durable-before-wire and passive recovery follow selected requirements, but a
matching digest does not prove recovery of lost own singleton votes. Checked the
pinned redb2.6.3 source: Immediate durability guarantees persistence on successful
commit return; its storage is copy-on-write. An extra bespoke WAL is not required
by that observation. Plan asynchronous batched durable acknowledgments, preserving
no RAM lock across I/O, and explicitly consolidate older latency wording.

QUIC already retransmits stream information. The300ms retry and95% claim remain
measurement candidates; changing DEC-027's application-attempt policy needs
evidence and explicit reconciliation. At N20 correlated committee loss affects
all shards. An uncertain first payment prohibits silently paying the same purchase
again with another voucher. Local Tit-for-Tat does not authorize fraud punishment
or guarantee a quorum remains available for rotation. The nonnegative quorum
intersection bound and FLP's actual termination scope are clarified in the plan.

Two independent subagents reviewed proof/key and recovery/availability contracts,
then the draft. Incorporated explicit cold-client-after-pruning acceptance,
physical-erasure limits, a fourteen-old-secret long-range negative control and
the prohibition on using fresh identity as a shortcut to lost-signer recovery.
Primary zeroize/QUIC/PBFT/FLP references and pinned redb transaction semantics were
checked. Their guarantees are distinguished from the HuMoCo proof obligations.

Execution order: P0 common baseline/fault model, P1 historical proofs with P2 keys
and P3 recovery contracts in parallel; P4 composed model; P5 shared verification
and real receiver/crash integration; P6 measured availability/retries/wallet
policy; P7 full coverage and a scoped readiness verdict. All execution packages
remain pending. Existing research fixtures are reused; green prior tests do not
count as implementation of the new contracts. This planning request did not run
new simulations, tests/benchmarks, change production/specifications or edit the
main CEH proposal. No new quorum, payment round, identity-recovery shortcut,
automatic ban or blanket retry/fallback policy is selected. DEC-001–052 and the
original Q-S3.3-01 are preserved. S2.1 remains the saved active prerequisite; the
broad investigation is not restarted by preparation of this plan.

### 7.56 Fundamental CEH review: permanent quorum loss, local conflicts and the payment promise

Record: K1-S5-CEH-REEVALUATION-001. Date: 2026-10-17 (Europe/Berlin).
Maintainer explicitly challenges CEH through an attached architecture review:
seven permanent old-member failures prevent handoff; independent UTXO/DAG roots
can merge without global order; owner sanctions and min-hash convergence might
justify autonomous HRW activation or a two-hour replacement fallback. This
authorizes bounded re-evaluation, not adoption of the attachment's claims or a
production change. Focus moves to K1.1, the payment promise/recovery tradeoff;
S2.1/S3.3 remain saved dependencies with original question meanings intact.

**Correction to the scope of earlier conclusions.** R-01/R-02 refute unrestricted
local activation WITH irreversible globally compatible payment acceptance under
their investigated fault/discovery model. They do not prove that this particular
CEH chain is the only possible architecture, or that eventual merge of a blind
registry is impossible. FINAL/VOID semantics remain OPEN-05/GAP-03; a completed
product decision covering every merge case was never recorded. The assessment
must not silently elevate the strict research target into an irrevocable human
choice, nor silently downgrade acceptance based on this challenge. A per-input
uniqueness requirement is enough to create the issue; no global transaction
order or monolithic blockchain is required.

**What is right about the challenge.** With fourteen old signatures required
and only thirteen old responders permanently remaining, the current candidate
cannot perform its normal handoff. Old checkout also lacks fourteen replies.
This is a serious permanent-loss recovery gap, not merely timeout tuning, and was
already recorded in R-06 and the operating envelope. A full root-lifetime fixed
committee was rejected for related availability reasons. Independent disjoint
spends can merge without affecting each other; a shard-wide halt may harm more
honest users than one conflict. CEH's extra complexity must earn its place against
that product cost. Worldwide hardfork/manual provisioning is not proved to be the
only possible recovery; additional preauthorized recovery authority is a different
candidate with explicit assumptions and state-preservation duties.

**Why convergence does not preserve the same merchant guarantee.** Starting from
an unspent input p, left accepts p->A and right p->B. Each local state is valid;
their union violates unique consumption. min(H_canon) can choose one final common
state, but the losing merchant may already have delivered goods and its dependent
payment chain may be affected. A local tie-break does not reverse that delivery
or reimburse it. Disjoint p->A and q->B do not have this problem. This is our own
invariant argument; the checked primary
[coordination-avoidance paper](https://www.vldb.org/pvldb/vol8/p185-bailis.pdf)
likewise distinguishes safely mergeable operations from application invariants
requiring coordination. Its database theorem is not a HuMoCo Byzantine proof.
An optimistic, explicitly revocable acceptance product is legitimate, but provides
a different merchant promise. It still has availability, data and fault limits.

**Unsupported limits in the attachment.** One attacked voucher is a witness, not
an upper bound on how many inputs an attacker can target in the same split.
Dependent descendants may be affected; unrelated roots need not be invalidated.
Neither1/100000 frequency,100% liveness, guaranteed deterrence nor sub-microsecond
network-wide convergence is established. Local hash/lookup timing excludes
discovery, transfer, verification and dependency reconciliation. R-02 does not
require a global cable cut. At N20 all shards share members, so seven unavailable
identities can affect every shard; larger groups overlap and share resources.
No measured loss/outage probability currently settles the proportionality question.

**Answers to autonomous HRW and two-hour fallback.** HRW is deterministic over a
given candidate set; signed heartbeats do not prove the set is complete or a
missing node has permanently disappeared. Waiting two hours does not distinguish
failure from delayed/partitioned operation, close old writes or transfer unknown
choices. Replacing voters can recreate R-02. A bounded set calculation checked:
old=B1..6+H1..14; A votes=B1..6+H1..8; new=B1..6+H8..14+X1..7;
B votes=B1..6+H9+X1..7. Both rosters contain20, both payments have14, only the six
Byzantine identities overlap the vote sets. H8 knows A and can refuse B, yet the
new group can still collect fourteen without it. This witness assumes no adequate
closure predicate; a real old-witness inclusion/fence protocol could prevent it.
It refutes timeout-plus-ranking as a sufficient proof, not every possible recovery
protocol using some new members.

**A smaller safe-recovery path worth investigating, not an adopted algorithm.**
Old payment14 and closure13 in C20 intersect in at least7 identities, at least1
honest under f<=6. Thirteen genuine fence endorsements contain at least7 honest
fences, leaving at most13 possible fresh old voters. With complete authenticated
own/inherited inclusion these are promising ingredients for old-write closure.
But two13-vote successor choices intersect only in6, which may all be Byzantine;
thirteen cannot simply replace fourteen throughout CEH. Investigate independently
unique preauthorized successor/recovery authority and a new-committee agreement
over valid closures, with data availability/install/replay rules. No general
safety/liveness proof is claimed. Arbitrary loss of all relevant state witnesses
cannot be fixed by hashing alone. Other explicit authority/lease/fault models can
be compared without silently changing assumptions.

**L1 sanctions: actual narrow source observations.** Targeted current inspection
finds a genuine owner ProofOfDoubleSpend/attribution path in the sibling core
(`src/models/conflict.rs:164`, `wallet/conflicts/ingress.rs`). Attribution may be
did:key, ephemeral linkage or anonymous depending on verified evidence. The read
`wallet/queries.rs:437` reputation path uses local proof-store decisions;
`wallet/transactions.rs:276` has an explicit force_accept bypass. The imported
offline-proof path at `wallet/conflicts/ingress.rs:345` uses earliest t_time and
quarantines voucher instances containing losing transactions. Separately,
humoco-sim-core resolver.rs uses min-hash/VOID, while node transport.rs:107 verifies
double attestations under the accused NodePubKey. Owner fraud and node equivocation
are different evidence/actors. These paths do not establish automatic global
identity destruction or a guaranteed merchant compensation mechanism. Human
deterrence may reduce practical attacks; it is not a quantified fault bound or
technical replacement for the chosen payment promise. No legal conclusion is
derived from the attachment's civil-liability assertion.

**Disposition.** Do not continue treating CEH as already selected implementation
architecture. Work plan v0.2 puts a bounded P0 comparison before its detailed
packages: current CEH14, independently authorized safe recovery (including the
closure13 subproblem), and explicitly revocable partition-tolerant acceptance.
Compare permanent-loss behavior, merchant/downstream loss, complexity and measured
correlated failure assumptions. Strict merchant acceptance remains the recommended
research target conditional on a viable bounded recovery/availability envelope;
current CEH without permanent-loss recovery is not a completed deployment design.
If the intended product instead accepts reversal risk, simplify against that
explicit invariant and communicate the risk, rather than claim identical FINAL.

Exact new product question, distinct from the original payment-round question:

> **Q-K1-FINALITY-01: Welche Zusage soll eine bestätigte Zahlung dem Empfänger geben?**
>
> **A – Empfehlung:** Eine als endgültig akzeptierte Zahlung darf durch spätere
> Netzverschmelzung nicht wieder verloren gehen. Dafür untersuchen wir die kleinste
> sichere Übergabe- und Recovery-Regel; das heutige CEH ist dabei nur ein Kandidat.
>
> **B:** Eine Bestätigung darf bei einem späteren Konflikt wieder entwertet werden.
> Dafür untersuchen wir ein einfacheres, stärker verfügbares Verfahren mit
> deterministischer Konfliktauflösung und ausdrücklich verbleibendem Händlerrisiko.

Status: unanswered; no selection inferred from the supplied critique. This asks
about economic/product behavior, not an algorithm name or permission for routine
work. DEC-001–052 remain unchanged, including their recorded limits. Q-S3.3-01
remains parked with exact original meanings; Q-S2.2-01 remains withdrawn as next
question. No threshold change, autonomous fallback or unconditional FINAL revocation.
Two independent agent reviews, primary-paper check, targeted source reads and
the printed bounded set arithmetic were performed. Newly present/modified CEH
source files from other workspace activity were observed, not audited or reverted.
No new Rust simulation/test/benchmark, production edit, commit or deployment.

### 7.57 Partition resilience selected and P0 reoriented

Record: P0-REGIONAL-DIRECTION-001. Date: 2026-10-17 (Europe/Berlin).
Maintainer explicitly orders P0 to prioritize regional payment availability,
derive local committees from the living mesh rather than yesterday's fourteen
signers, and reconcile genuine conflicts after reconnection with min(H_canon)
and L1 owner evidence. This is the substantive direction B of Q-K1-FINALITY-01,
recorded as DEC-053; do not ask that product choice again. It explicitly changes
the global irreversibility target rather than merely lowering a handoff threshold.
Active focus becomes S2.2 local-view constitution/partition operation. Original
Q-S3.3-01 A/B meanings stay parked/unanswered; Q-S2.2-01's old-group-based proposal
remains historical/withdrawn, not the next question.

**Chosen requirement and limits.** A qualified regional receipt may later lose
to an admissible competing branch, affecting its dependent descendants. Independent
roots/siblings should survive merge. Regional authority does not require old14
permission. Keep one frozen<=20 identity set, fourteen matching votes in the
N>=20 mode, adaptive N<20 PROVISIONAL,800ms collection, origin/owner validation,
durable immutable own choices, root expiry plus grace, local operator boundaries
and first-party-only fraud sanctions. Old labels/DTOs cannot continue presenting
unqualified global irrevocability. DEC-053 qualifies older strict-CEH/FINAL
interpretations without erasing historical selections. The six-Byzantine target
is per qualified view; different views need not have honest quorum intersection.

**What was not adopted as fact.** The maintainer's99.999% availability/low attack
rate,100% global cable-cut halt and guaranteed permanent L1/legal sanction are
not measured outcomes. Actual correlated partitions can disable a large fraction
of old global committees; an arbitrary physical cable event is not a specified
network topology. Local14 progress still requires enough qualified timely peers,
proofs and resources. A later merge does not compensate prior goods delivery.
Human deterrence remains a possible practical risk reducer, not a fault bound.
The already inspected owner ProofOfDoubleSpend/attribution and local KnownOffender
paths are distinct from L2 NodePubKey equivocation; honest regional losers are
not automatically fraudsters.

**Initial P0 contract produced.** Created
[PARTITION_RESILIENT_REGISTRY_P0.md](PARTITION_RESILIENT_REGISTRY_P0.md):
P0-A qualified local views and recipient trust, P0-B readiness/persistence without
old-quorum permission, P0-C supported deterministic merge over complete spends,
P0-D distinct immutable approvals/canonical observations and evidence categories.
It identifies local positive reachability, freshness, candidate omission/attack
resistance and independently verified recipient membership as the next executable
predicates. Heartbeats authenticate individual participants, not a complete global
list. An arbitrary twenty-key gateway roster cannot authorize itself. These are
technical tasks to investigate autonomously, not another product-preference question.

For merge, admitted owner/causal evidence is not the same as a raw lower hash.
Preserve the existing supported-conflict guard and define partial/PROVISIONAL
versus regional14 comparison. Select complete child bundles when one parent forks;
do not union competing split outputs into extra value. Keep an honest node's old
A approval even if B wins; reporting canonical B must use distinct semantics so
that it neither constitutes a contradictory normal approval nor frames the node.
Receipt reuse/status and B-descendant progress must be composed with this rule.

**Bounded quantitative work executed.** For ideal independent geographic placement
within a committee and an equal two-region split, X~Binomial(20,0.5): one specified
region has at least14 members with probability0.057659149; either region has14
with probability0.115318298; neither does with probability0.884681702. Expected
blocked old committees among65536 is57978.5. Finite uniform N1000 split500/500
hypergeometric arithmetic gives0.888313073 with neither region holding old14.
This is a placement model, not measured HRW/internet failure probability, and
does not assume independent outcomes across overlapping committees. It supports
the widespread-failure concern while qualifying the absolute global-halt claim.

Also evaluated343 combinations of three already-admitted candidate sets for
union/min associativity, commutativity and idempotence, plus a split-tree example
where the losing u->a branch and descendants lose usability while v/c and winning
b/e remain. Hashes and candidate validity were inputs, not cryptographic checks.
These finite checks do not establish protocol safety, adversarial admission,
network convergence time or the proposed acceptance rate.

**Concrete next verification.** P0-T01..T12 cover40->20/20 and100->80/20 regional
reconstitution without old14,90/10 and13/7 PROVISIONAL boundaries, disjoint-input
merge, expected R-01/R-02 regional conflicts, split descendants, honest merge
reporting, arbitrary attacker rosters, bad/expired proofs, delayed smaller evidence,
shared outages and coordinated many-input attacks. Required progress assumes
documented admission/maturity/readiness and timely local service. Existing tests
that classify any competing global FINAL as a bug need retargeted expected
properties; they must not simply be deleted or reported as proving the new design.

**Plan and specification disposition.** Work plan v0.3 makes this P0 contract
active and re-scopes P1–P7 to portable regional proofs, key/own-choice security,
composed merge modeling, actual client/QUIC integration and measured risk/availability.
Added a visible DEC-053 direction notice to the otherwise preserved main CEH
proposal. No production/source behavior changed; concurrently present code is
not audited or reverted here. Two independent agent reviews informed the contract.
Initial P0 direction/analysis is recorded, while its full design/model/wire gates
remain open. No large new research campaign or Rust tests/benchmarks were run.

### 7.58 P0 formal contract and twelve acceptance scenarios

Date: 2026-10-17. Active node: S2.2; dependencies S2.1/S5/O1/O2/C4.
Checkpoint: CP-0047. User task: elaborate the formal specification and all twelve
scenarios in PARTITION_RESILIENT_REGISTRY_P0.md under the newly supplied guardrails.
No new preference question; Q-K1-FINALITY-01 remains answered B and the original
Q-S3.3-01 A/B wording in §7.16 remains unchanged, unanswered and parked.

**Accepted guardrails — DEC-054.** Only identity-bound valid Argon2d tickets with
completed observed24h incubation and independently authenticated F2F admission
qualify regionally. A gateway cannot create its own authority by supplying20keys.
Only two personally signed incompatible approvals for one slot establish node
fraud; honest single-branch signers are not punished for a losing merge. Losing
causal dependencies become unusable through admitted min-hash selection while
unrelated trees/siblings survive. Terminals distinguish global and regional
confirmation and use merchant amount/exposure policies outside blind L2.
These are the maintainer's instructions; the exact candidate profile/support rules
below are engineering proposals, not invented further maintainer selections.

**Delivered contract.** P0 draft0.2 specifies versioned objects, observer-relative
eligibility/view/receipt predicates, independently recognized catalog cuts,
conservative observed maturity, bounded positive reachability, frozen exact HRW
rosters,24h population stability and1..19 provisional versus20/14regional modes.
P0-SIM-1 supplies concrete30s/120s background/view/lease parameters and bounded
probe concurrency as a test profile, not validated production tuning. Regional
activation has no predecessor14 dependency. Fourteen voters still need to accept
one view; local catalog skew can stall progress and must be measured, not assumed
away. Admission-context recovery and historical proof availability remain explicit.

**Payment promise guard.** A valid Regional14 proves qualified regional acceptance,
not absence of hidden conflicting regions. Ticket work/24h/F2F do not prove operator
independence or <=6Byzantine members. `GlobalProofSchemes={}` in the P0 baseline;
FINAL(Global) is reserved/unreachable until a separately justified verifier scheme
exists. Connectivity, quiet gossip,24h stability and reconnect do not set green.
The requested status distinction therefore stays honest; regional checkout remains
usable without this extension. No mandatory CEH activation is reintroduced.

**Merge/fraud and durable state.** Immutable OwnChoice uses network/root/consumed
output, independent of view/epoch. Commit own choice, approval context and effect
before releasing a vote; recheck view/root validity after delayed commit. A missed
response never frees the slot. Missing/rolled-back own history remains passive.
Canonical transaction hashes exclude signer subsets, gateways and delivery order;
complete split bundles are atomic. Candidate support ranks admitted Regional14
above adaptive provisional, with min-hash within the best admitted class. Hints/
partials cannot displace a supported branch. Real support promotion requires real
new evidence; nodes already excluding a branch need not sign it. This precise
mixed-mode rule is a candidate to validate, not another answered interview choice.

An A-approver may retain A, report canonical B in a separate observation domain,
serve B's original receipt and approve a legitimate B descendant at a new slot.
Observation never supplies payment votes or personal equivocation. VOID is derived
from admitted support/evidence and dependency status; evidence/own choices survive.
Conditional convergence needs finite evidence, eventual delivery and compatible
admission contexts. It does not bound merchant losses or guarantee convergence
across permanently incompatible trust policies.

**Twelve complete scenarios.** Each now has Given/When/Then, negative mutants and
required evidence: balanced/asymmetric partitions; small modes/promotion; disjoint
order/duplicate/signature-subset invariance; original R-01/R-02 witnesses; split
dependency isolation; honest merge continuation; fake admission and real mature
capture; invalid/partial/provisional/late evidence; delayed smaller receipts and
bounded repair; outages/view skew/crash/rollback/backpressure; and coordinated
multi-input attacks with cumulative merchant limits/uncertain-payment reconciliation.
All are explicitly NOT RUN for this revision. Terminal policies never change a
receipt's cryptographic class or expose amounts to L2. UNKNOWN does not silently
trigger a second payment; once-only goods release is not once-only debit.

**Evidence and integration limits.** Three independent read-only agent reviews
informed this elaboration and identified post-commit lease expiry and promotion
fixture issues, corrected in the draft. The current resolver derives hash entropy
from a smallest-node signature, conflicting with signer-independent H_canon; the
inspected L1 offline import also has earliest-time semantics. These are versioned
integration work, not repaired production code. Presence/code, historical keys,
context retention, exact receiver caps and rollback detection still require P1–P5.
The prior343 union/min examples and partition arithmetic retain their narrow
CP-0046 scope; no new protocol/model/Rust/QUIC run or performance claim is made.

**Next action/status.** Documentation elaboration is delivered. S2.2 scenario
verification is completed and fully verified (§7.59). Next: S2.1 admission prerequisites,
S3 committee turnover, and S4 automatic recovery integration.

### 7.59 P0 simulation suite and scenario verification (T01–T12)

Date: 2026-10-17. Active node: S2.2 completed; dependencies S2.1/S3/S5/O1/O2/C4.
Checkpoint: CP-0048. Verification status: S2.2 scenario test suite completely executed
and passed (12/12 scenarios verified, 0 failures).

**Execution record and test results:**
- Workspace check & lints: `cargo check --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` passed cleanly (0 warnings, 0 errors).
- `p0_partition_scenarios`: 6/6 passed (17.48s):
  - T01: Partition regional progress (20/20 regions with local 10/10 progress, cross-region delivery withheld until reconnect, no old14 permission).
  - T02: Bounded write collection (80/20 with 7/13; rejects cross-view, duplicate and rank21 votes; 13 by 799ms cannot obtain fourteenth at 800ms).
  - T03: Dynamic view evolution (90/10, 20/7, 13/7; adaptive 7/5/9; 23h59 maturity refused; 24h continuity and population-drop reset).
  - T04: Commutative merge (8 independent payments; 6 delivery permutations, duplicate invariance, associativity, signer/view-independent SpendId).
  - T05: Min-hash regional conflict (R-01/R-02 competing receipts converge via min(H_canon); personal double-signers banned, honest losers unpunished).
  - T06: Complete splits and descendants (atomic competing child bundles; losing fork/descendants VOID; sibling path survives; losing-ancestor spend refused).
- `p0_adversarial_scenarios`: 6/6 passed (464.79s):
  - T07: Own choice immutability (OwnChoice A survives canonical B; observation cannot serve as approval/fraud; legitimate B descendant progresses).
  - T08: Argon2d and F2F admission (forged/fresh/gateway views and false verified-work input refused; replay cannot renew lease; mature admitted capture passes).
  - T09: Comprehensive negative coverage (invalid signatures/bindings/origin/ancestry/expiry and partial support rejected; Regional14 promotion works; 31-day evidence accepted).
  - T10: Delayed evidence repair (C -> B -> A on delayed valid smaller evidence, 40-day late candidate; idempotent duplicates; scoped cursor repair).
  - T11: Fault injection and persistence (13/20 unavailable; qualified future view succeeds; bounded pending capacity, crash timing, unknown-history passive gate, 1ms skew refused).
  - T12: Large-scale conflict workload (1000 primary inputs, 100 double-spends, 1500 receipts, 1100 initial purchases, 100 voided payments, 200 voided descendants, 900 confirmed, 200 sibling outputs usable; terminal exposure limits verified).

**Conclusion and boundaries:**
All twelve model scenarios are deterministically verified in `crates/humoco-sim-core`. S2.2 scenario verification is completed. Boundaries noted in P0 v0.2 / P0_SIMULATION_RESULTS.md remain in effect: deterministic fixture/profile models regional convergence without global green; actual Argon2d proof verification on wire, production QUIC integration, and real durable redb power-loss tests remain scheduled for future gates.

## 8. Historical continuation summary

This pre-workflow continuation text is preserved for context. The compact state
is the live cursor; section 2 resolves selection status and superseded proposals.
Statements below about the latest files/progress describe the earlier checkpoint.

The maintainer explicitly requested a fresh-chat handoff on 2026-10-15. The consolidated
[ARCHITECTURE_INTERVIEW_HANDOFF.md](ARCHITECTURE_INTERVIEW_HANDOFF.md) is the current
continuation summary, including the mandatory decision-tree workflow and active S2–S4
branch map added after the maintainer clarified the systematic interview objective.
This document retains detailed decisions, code findings, research,
counterexamples and earlier proposals. Latest decisions take precedence over historical
pending statements.

Continue the architecture interview in German, with one substantive decision at a time
and A as the reasoned recommendation. Do not restart settled topics, force algorithm-name
choices or implement protocol changes merely because the discussion continues. The final
prioritized implementation plan is still pending substantial proof/integration work.

Current focus: the smallest safe committee/state handoff while respecting local views.
Latest selected A requires safe automatic progress after communication stabilizes with
an available relevant honest quorum, including competing proposals. The target remains
14/20 with up to six Byzantine identities conditionally, and indefinite eventual full
replacement of original members. Approximately hourly candidate checks are tentative;
no timer confers authority. Rank-21–23 extra querying is discussed, not approved vote
pool expansion. Globally identical HRW discovery is not required or selected.

Latest maintainer clarification (section 7.13): the existing N >= 20 FINAL policy is
already selected, with 14/20 checkout and existing stability requirements retained.
One organically growing global network is the normal operating assumption; spontaneous
independent twenty-node networks are regarded as unlikely, without a measured bound.
Withdraw the repeated S5.1a A/B as the next question. No FINAL revocation, common
anchor or committee-history mechanism was selected. Continue technical handoff
investigation within one growing network, keeping unresolved roster justification,
local-view compatibility and temporal/adversarial assumptions explicit.

Latest substantive question (section 7.14 / S3.3, still unanswered from section 7.5):
A preserve the current one-round payment confirmation and carry justified binding
obligations through handoff (recommended), or B investigate a redesigned two-round
payment completion with explicit safe incomplete-preparation rules. Await the answer;
do not infer a selection from the general request to keep the interview moving.
Latest clarification request (section 7.15): explain that existing signed/accepted
lock records are the data to reconcile; no separate reservation subsystem or
certificate-return round is implied. Focus on completeness and old-write cutoff.

Latest research direction (section 7.10): first assess established round-based BFT
agreement for narrowly scoped per-shard handoff, comparing dynamic lattice agreement if
needed. Round protocols require a justified participant set per instance. Neither that
scope condition nor any engine is a completed/approved solution to the maintainer's
local-view objection. Next establish initial participants/authority and safe closed-state
inclusion of earlier binding decisions; then successor installation, latest-context
verification and progress/retired-key assumptions. Ordinary synchronization, raw majority,
extra ranked signers or a matching snapshot do not solve these obligations.

Preserve selected durable signing-before-response, immutable own-choice redb storage,
same-key loss/rollback safety gate, bounded shutdown/expiry, private local administration,
shared minimal core/node protocol library, all-member checkout dispatch and protected
shard/background resource budgets. The rigid five-millisecond processing target is
removed; the 800 ms collection budget remains. Do not revive unconditional min-hash
confirmed-state takeover, hearsay punishment or checkout offline suppression.

After resolving/scoping handoff, return to read acceptance (including the maintainer's
hidden-query/multiple-witness proposal), FINAL/merge consistency, full core integration,
recovery across divergent partial sets, persistence/rollback details and measured P2P
limits. Core inspection already exposes certificate-verification/DTO/status-mapping
issues; inspect actual consumers before design completion. No final master plan until
material obligations are resolved or explicitly scoped by agreement.

Progress estimate remains about 60–70% topic coverage, not proven design or implemented
completion. Only these two untracked interview documents changed; abstract JavaScript
set/event checks were used, but no production changes, Rust/unit/QUIC tests, commits or
PRs occurred. Preserve both working documents in this checkout.

## 9. Persistent interview workflow checkpoint

### CP-0001 — Initialize compact navigation without restarting the interview

Date: 2026-10-15 (Europe/Berlin).

The maintainer requests a reusable starting prompt that creates missing memory
files, resumes existing decisions and systematically follows unresolved branches.
They prefer a compact maintained tree and detailed explanations in files; repeatedly
printing the entire tree in chat is unnecessary. The pasted example is input to
workflow design, not approval of its unconditional no-information-loss claim.

Created `prompts/architecture_interview.md` and
`docs/ARCHITECTURE_INTERVIEW_STATE.md`. The existing notes remain the detailed
record. The legacy handoff remains intact apart from a navigation notice and is
not a third live state file. Existing branch IDs, decisions and pending choices
are preserved. New interview records can use stable IDs without rewriting history.

The workflow writes details before updating the compact cursor, keeps matching
checkpoints, reads changes back and reconciles interrupted updates. It separates
requirement selection, design justification, implementation and verification.
It records exact pending question/option mappings and does not infer approval from
silence or a generic continuation request. Full coverage remains an obligation;
the initial tree is not evidence of an exhaustive review.

Resume action remains the clarification in section 7.15, followed by the unanswered
section 7.14 choice. Its stable question label is now **Q-S3.3-01**; wording and
A/B meanings are unchanged. No A/B selection, protocol/library approval or final
plan follows from this workflow setup. S2 membership justification remains open.

The state explicitly flags the selected removal of the rigid local 5 ms target
versus existing project instructions as a later consolidation obligation. Preserve
both sources; do not silently claim the code/specification already changed.

Workflow design references: OpenAI's
[persistent execution plans](https://developers.openai.com/cookbook/articles/codex_exec_plans)
and [long-running task example](https://developers.openai.com/blog/run-long-horizon-tasks-with-codex)
describe revisitable Markdown plans/status and decision records. The two-file
interview procedure here is a project-specific adaptation, not an OpenAI feature
or a guarantee of lossless memory. A new chat needs access to these same files.

Acceptance checks for this workflow:

- Fresh workspace: create missing state/notes and ask the first unresolved scope question.
- Existing workspace: preserve prior decisions and resume the saved action/question.
- Partial state: reconstruct only missing navigation/details from surviving evidence;
  do not invent lost answers. Mismatched checkpoints require reconciliation.
- A/B reply: bind to the saved question ID/options; preserve ambiguous replies as unresolved.
- New contradiction: record evidence, reopen affected dependencies and retain old rationale.
- Context recovery: read the compact state and targeted details, without replaying the
  entire transcript or re-asking settled thresholds.
- Completion: check actual coverage and explicit exclusions before final planning;
  planned implementation/tests remain separate from completed work.

These are workflow review criteria, not claims that model behavior was executed
and verified across fresh chats. Document/link consistency is checked locally.
No production code changes, Rust/QUIC tests, commits or PRs were made by this setup.

Completed checkpoint: **CP-0001**.

### CP-0002 — Complete one problem and present only useful alternatives

Date: 2026-10-15 (Europe/Berlin).

The maintainer clarifies the intended interview rhythm: work through one problem,
offer A as a recommendation where justified, and add alternatives only when they
are meaningful or uncertainty warrants comparing them. The prompt now explicitly
keeps the current bounded problem active through follow-up questions and design
consequences. Unrelated discoveries are parked; an early switch needs a prerequisite,
blocker or user steering and a saved return point.

No fixed A/B/C quota applies. Explain genuine alternatives' benefits and costs.
State uncertainty, its consequence and the evidence needed to resolve it; perform
technical investigation rather than outsourcing factual uncertainty to a preference
vote. Label conditional recommendations and do not invent a confident A without
sufficient support. Ask one substantive human decision question at a time.

This clarifies interview conduct only. The S3.3 clarification and Q-S3.3-01 remain
pending with unchanged option meanings; no protocol decision was inferred.

Completed checkpoint: **CP-0002**.


### CP-0003 — Audit and migrate pre-workflow decisions

Date: 2026-10-15 (Europe/Berlin).

Assignment: review existing interview files for faithfully retained decisions before
continuing under the new workflow. Read the full detailed notes, compare the 48
existing summary rows with chronology, handoff and compact state, and independently
cross-check later selections. Inspect relevant rule/spec excerpts for already-recorded
consolidation gaps. This is a documentation audit, not another protocol/security proof.

Findings and repairs:

- All 48 prior summary topics are retained as DEC-001 through DEC-048 with stable
  branch mappings, explicit selection status and evidence/provenance pointers.
- DEC-006 formerly left shared-interface versus thin-adapter packaging undecided;
  §7.3 had already selected shared-library direction DEC-038. Corrected the current
  summary while leaving crate details open and preserving the alternative history.
- DEC-039 formerly described selected fixed-context investigation without its later
  reopening. The register now retains the initial selection and the explicit later
  search for a smaller sufficient mechanism; no complete history/roster scheme approved.
- DEC-028 is a deferred optimization, not a selected suppression mechanism. DEC-043
  distinguishes accepted batching from the tentative, unmeasured hourly parameter.
- Added the alternatives/supersession map, OPEN-01 through OPEN-14 and GAP-01 through
  GAP-06 so old pending wording cannot silently override later selections or close
  unproved design. Kept the full historical reasoning and clarification paragraphs.
- Updated state navigation and legacy-handoff entry instructions to use the register
  and one live cursor. The saved protocol clarification/question is unchanged.

Coverage result: no additional explicitly selected main decision was found missing
from the existing summary across the available chronology. However, early selections
have legacy-summary-only provenance, and original chat evidence is absent. This
cannot certify completeness against unavailable conversations. Missing rationale
remains marked rather than invented; no blanket re-interview is required.

Verification: read back edited records; check that all original 48 topics remain,
selection anchors/branch links resolve, all pre-existing chronological sections are
preserved, there is one active leaf and both files name this checkpoint. Document
checks do not demonstrate behavior across fresh model chats. No protocol answer,
production change, Rust/QUIC test run, commit or PR is part of this audit.

Resume: answer §7.15, then the still-unanswered Q-S3.3-01 in §7.14. Keep S2/OPEN-02
as an unresolved prerequisite; do not re-ask N >= 20 or infer another A/B selection.

Completed checkpoint: **CP-0003**.

### CP-0004 — Resume the lock-transfer clarification

Date: 2026-10-15 (Europe/Berlin).

Resumed the existing S3.3 cursor without changing scope or accepted decisions.
§7.16 records the explanation of existing lock records, the copy/write race and
conditional A recommendation, with the exact German presentation of Q-S3.3-01.
Its option meanings are unchanged; no answer is inferred. Updated the current
alternative/open-question navigation. S2 and the remaining handoff proof obligations
stay open. Next action is awaiting the maintainer's substantive answer.

Verification: read back the new record and compact state; check matching CP-0004,
unchanged A/B mapping, one active leaf, and retained open prerequisites. No production
code/specification edits, new research, Rust/QUIC tests, commits or PRs.

Completed checkpoint: **CP-0004**.

### CP-0005 — Show decision progress separately from remaining technical work

Date: 2026-10-15 (Europe/Berlin).

The maintainer observes that almost every tree branch is labeled open despite the
long interview. This is a valid presentation problem: the previous tree described
remaining design obligations and hid accepted policy decisions behind the same label.
It must not suggest that prior selections are undone or need another preference vote.

The compact tree now shows the recorded decision outcome and, separately, the
remaining detail/proof/audit work. Decided means the named policy was selected or
is inherited from binding project rules; partial means selected aspects coexist
with unresolved design choices. Unresolved is reserved for genuinely unselected
mechanisms/questions. Finding marks an established counterexample, not an adopted
replacement protocol. Active marks the saved question awaiting an answer.

Examples: shared library, valid-prefix batches, frozen 14/20 checkout, durable
signing with an existing-redb choice table, bounded shutdown and private systemd-first
operation are visibly decided directions. Membership justification and safe handoff
remain unresolved mechanisms; the current one-round/two-round question is unanswered.
Selected automatic progress is distinct from a proved round/recovery algorithm.

The reusable prompt now requires this two-part presentation. Pending implementation
or testing cannot turn an accepted interview decision back into an open preference.
Conversely, displaying decided does not close a branch's substantive design/proof
obligations or authorize the final plan before material gaps are addressed/scoped.
No decision was added, reversed or marked proved; no completion percentage inferred.

Preserve CP-0004's latest resume point: await Q-S3.3-01, with §7.16's exact wording
and unchanged A/B meanings. This status-display discussion is not an answer to it.

Verification: compare each displayed selection with section 2/binding rules; check
stable IDs, preserved resume action, matching checkpoint and compact-state length.
No production/specification edits, Rust/QUIC test run, commit or PR.

Completed checkpoint: **CP-0005**.

### CP-0006 — Explain collected node confirmations and reaffirm takeover goal

Date: 2026-10-15 (Europe/Berlin).

Preserved the intervening CP-0005 display corrections. Added §7.17 for the current
terminology clarification and the maintainer's reliable-data-takeover requirement.
No new protocol selection follows. Keep Q-S3.3-01 unanswered and avoid repeating
the choice during an explanation request. Updated the compact resume action.
Read back both records and checked matching checkpoints and preserved option meanings.
No production/specification edits, external research, test campaign, commit or PR.

Completed checkpoint: **CP-0006**.

### CP-0007 — Draft the shared dictionary before review and alignment

Date: 2026-10-15 (Europe/Berlin).

Recorded the explicit terminology detour in GLOSSARY-001 / §7.18 and OPEN-15.
Extended the existing translation glossary with clearly provisional definitions,
source pointers, ambiguity agenda and the requested draft/review/alignment sequence.
Original mappings are preserved. K3 is the single active focus; S3.3 is parked with
its unanswered question and original options retained. Definitions are not yet approved.

Verification: read back changed records; check glossary IDs and relative links,
matching CP-0007 and compact-state size. Documentation checks are distinct from
reviewing meanings or auditing repository-wide consistency. No production/specification
changes, Rust/QUIC tests, commits or PRs.

Completed checkpoint: **CP-0007**.

### CP-0008 — Explain the glossary in German for review

Date: 2026-10-15 (Europe/Berlin).

Recorded the German walkthrough request in §7.19. K3 remains active; definitions
await review, repository-wide consistency checking remains pending, and the parked
architecture question is unchanged. No glossary meaning was marked approved.
Read back the record and state, checking matching CP-0008. No production/specification
changes, tests, commits or PRs.

Completed checkpoint: **CP-0008**.

### CP-0009 — Clarify three glossary entries

Date: 2026-10-15 (Europe/Berlin).
Updated G-014/021/049 and recorded their review status/evidence in §7.20.
Parent terminology is a maintainer suggestion; digest wording is a recommendation,
not a recorded final selection. K3 remains active and Q-S3.3-01 remains parked.
Read back edits and matching CP-0009. No production/specification changes, tests,
commits or repository-wide terminology alignment.

Completed checkpoint: **CP-0009**.

### CP-0010 — Compare names for authorization evidence

Date: 2026-10-15 (Europe/Berlin).
Recorded §7.21 and the G-021 naming-review alternatives without selecting a term.
Preserved the signature/combined-proof distinction, pending canonical rules and
parked architecture question. Read back glossary, notes and matching state.
No production/specification changes, tests, commits or repository-wide renaming.

Completed checkpoint: **CP-0010**.

### CP-0011 — Save the executable terminology alignment plan

Date: 2026-10-15 (Europe/Berlin).
Recorded GLOSSARY-002 / §7.22 and the reusable plan/index entry. Plan preparation is
complete; glossary approval and audit execution are separate pending work. Preserved
proposed-name statuses and the architecture return point. Read back changes and
matching CP-0011; check plan links and whitespace. No audit-execution claim or tests.

Completed checkpoint: **CP-0011**.


### CP-0012 — Execute and reconcile terminology alignment

Date: 2026-10-16 (Europe/Berlin).
Recorded GLOSSARY-003 / §7.23, added the continuation findings and explicit file
coverage, and reconciled compact state/glossary/plan status with the initial
alignment already present in Git. Source-comment and specification changes are
editorial. Naming proposals and substantive conflicts remain open; K3 stays active
and Q-S3.3-01 stays parked. Verification and its limits are recorded in report §7.5;
no new protocol choice, behavior/interface change, test suite, commit or PR.

Completed checkpoint: **CP-0012**.


### CP-0013 — Resume G-021 naming at the saved K3 cursor

Date: 2026-10-16 (Europe/Berlin).
Read the applicable instructions, complete compact state, decision/open-item index,
active glossary records and alignment findings. Both memory files exist and agree
on CP-0012. Recorded GLOSSARY-004 / §7.24 and exact Q-K3-G021-01 with A's meaning
before presenting it; no answer or name selection is inferred from resumption.
Updated the open-item index and navigation to one active focus, K3 / G-021.
G-014/049, substantive conflicts and the unchanged parked Q-S3.3-01 remain pending.
Only the two interview-memory files are edited in this continuation. No production
or binding-specification change, test campaign, commit or deployment is performed.

Completed checkpoint: **CP-0013**.


### CP-0014 — Record G-021 answer A and advance to parent terminology

Date: 2026-10-16 (Europe/Berlin).
Recorded the maintainer's `a` against Q-K3-G021-01 as DEC-049 / GLOSSARY-005,
updated the current decision/open-item index and adopted the two names in the
existing glossary. Preserved the previous question and unselected candidates as
history. Recorded exact Q-K3-G014-01 and its A meaning before asking it; K3/G-014
is the sole active focus. Q-S3.3-01 remains parked. Changes are interview/glossary
documentation only; no code, protocol format, test suite, commit or deployment.

Completed checkpoint: **CP-0014**.


### CP-0015 — Record G-014 answer A and advance to shard-digest terminology

Date: 2026-10-16 (Europe/Berlin).
Recorded `a` against Q-K3-G014-01 as DEC-050 / GLOSSARY-006, updated the
current decision/open-item index and adopted the predecessor/output names in
the glossary. Recorded exact Q-K3-G049-01 and its A meaning before asking it.
K3/G-049 is the sole active focus; Q-S3.3-01 remains parked and unanswered.
Only interview/glossary documents change; no code, wire format, test campaign,
commit or deployment. Readback and document whitespace checks are the validation.

Completed checkpoint: **CP-0015**.


### CP-0016 — Save glossary completion and autonomous-alignment steering

Date: 2026-10-16 (Europe/Berlin).
Recorded G-049 answer A as DEC-051 and the explicit no-more-glossary-questions
instruction as DEC-052 / GLOSSARY-007. K3 remains active for editorial work,
without a pending naming question. Q-S3.3-01 stays parked. Next action: complete
autonomous terminology alignment and document its checks before returning.

Completed checkpoint: **CP-0016**.


### CP-0017 — Finish autonomous terminology alignment

Date: 2026-10-16 (Europe/Berlin).
Recorded GLOSSARY-008 / §7.28 and report TA-031–035; glossary names are established
and future editorial maintenance requires no naming questions. Scoped wording
alignment is complete, with executable code, runtime strings and protocol fields
preserved. Updated the decision/open-item navigation and returned the sole active
focus to S3.3; Q-S3.3-01 retains its unanswered original A/B meanings. Validation:
readback, whitespace, vocabulary IDs, links/anchors, Rust non-comment and Markdown
Rust-example comparisons against the pre-edit working tree. No tests/commit/PR.

Completed checkpoint: **CP-0017**.

### CP-0018 — Resume handoff analysis without changing the pending choice

Date: 2026-10-16 (Europe/Berlin).
Recorded S3.3-INVESTIGATION-001 / §7.29: bounded current-code inspection, the
in-flight vote/closure race, conditional old-quorum fencing and inclusion bounds,
the two-A/twelve-B report counterexample, late-certificate preservation and durable
successor activation obligations. Rechecked the PBFT and Sui Lutris primary papers;
their different assumptions are retained. Findings are conditional research, not
an accepted handoff algorithm, completed proof or implementation.
Updated OPEN-01/03 and the pending-question index. The sole active leaf is S3.3;
Q-S3.3-01 is still unanswered and will be presented with §7.16's original wording
and A/B meanings. DEC-001–052 remain unchanged; no glossary question is reopened.
Validation: readback, checkpoint/ID/option and local-link checks, compact-state line
count and `git diff --check`. No production edits, Rust/QUIC tests, commit or PR.

Completed checkpoint: **CP-0018**.

### CP-0019 — Correct authority wording and explain the local-view safety gap

Date: 2026-10-16 (Europe/Berlin).
Recorded the maintainer's clarification request and S3.3-CLARIFICATION-001 / §7.30.
Distinguished local signing/query selection from compatibility of confirmations
accepted toward FINAL. Corrected the presentation of coordinated writing authority
as if already selected; no central grantor or globally identical ranking is assumed.
Reused §7.9's two-replacement, six-Byzantine schedule with explicit honest-voter
counts. S3.3 remains active with S2 as dependency. Explain before asking again;
Q-S3.3-01 is unanswered and unchanged. DEC-001–052 are preserved.
Validation: readback, original-question/decision-register preservation, compact-state
line count and `git diff --check`. No production edits or tests, commit or PR.

Completed checkpoint: **CP-0019**.

### CP-0020 — Research reconciliation and define the model-first work package

Date: 2026-10-16 (Europe/Berlin).
Recorded S3.3-RESEARCH-002 / §7.31: transfer options, authenticated snapshot/range
coverage requirements, primary-system comparisons and the conditional paused-handoff
candidate. Defined model state/events, safety and progress properties, adversarial
schedules, non-vacuity checks and later Rust/real-QUIC/benchmark gates. Inspected
existing digest/pagination and scripted handoff tests, including a scoped fixture
coverage warning. No procedure is approved or proved by these observations.
Updated OPEN-03/09 and the resume cursor; S3.3 stays active. No new maintainer
decision or A/B answer inferred; DEC-001–052 and Q-S3.3-01 meanings preserved.
Validation: readback, checkpoint/question/register checks, local link paths,
compact-state length and `git diff --check`. No model/test/benchmark execution,
production implementation, commit or PR.

Completed checkpoint: **CP-0020**.

### CP-0021 — Research online snapshot/delta transfer under sustained writes

Date: 2026-10-16 (Europe/Berlin).
Recorded S3.3-RESEARCH-003 / §7.32: PostgreSQL snapshot/change-stream pattern,
etcd non-voting catch-up and BFT-SMaRt collaborative checkpoint/log transfer;
checked their ordering/fault assumptions. Explained why request timestamps do not
close old writes, shard replicas can serve preparation data without gateway fanout,
and bounded delta replay/activation needs a justified endpoint. Inspected redb's
existing stable-read primitive and the live offset-pagination gap. Recorded the
conditional catch-up capacity inequality and additional model/benchmark obligations.
Updated OPEN-03/09 and the cursor. S3.3 remains active; DEC-001–052 and the exact
unanswered Q-S3.3-01 are preserved. No new logging subsystem or algorithm selected.
Validation: readback, checkpoint/question/register/link checks, compact-state line
count and `git diff --check`. No production edits, simulation/model/test/benchmark
execution, commit or PR.

Completed checkpoint: **CP-0021**.

### CP-0022 — Clarify QUIC loss recovery and the duplicate-request proposal

Date: 2026-10-16 (Europe/Berlin).
Recorded C3-N4-RESEARCH-001 / §7.33: reliable Quinn stream path, correct conditional
p-squared/p-cubed arithmetic, correlated failures and receipt/commit distinctions.
Retained DEC-027's one application attempt and DEC-009/042's same-intent bounded
retry; no three-send policy, post-quorum repair queue or extra checkout load selected.
Recorded real-QUIC fault/duplicate-accounting validation obligations. This is a
bounded interjection; S3.3 / §7.32 remains the sole active architectural focus.
DEC-001–052 and Q-S3.3-01 wording/options are preserved; no A/B answer inferred.
Validation: readback, checkpoint/question/register/local-link checks, compact-state
line count and `git diff --check`. No test/model/benchmark execution, production
implementation, commit or PR.

Completed checkpoint: **CP-0022**.

### CP-0023 — Assess solvability and separate repair from signer activation

Date: 2026-10-16 (Europe/Berlin).
Recorded S3.3-DESIGN-001 / §7.34: synchronization is conditionally tractable, but
HuMoCo's safe dynamic turnover is not yet proved or delivered. Defined separate
continuing-repair and successor-activation acceptance contracts, including the
source-local snapshot/delta endpoint relation. Identified membership, obligation
inclusion/partial conflicts and transition recovery as explicit missing model
predicates. No automatic all-node-equality condition or new protocol selection.
S3.3 stays active. DEC-001–052 and the original unanswered Q-S3.3-01 are preserved.
Validation: readback, checkpoint/question/register/local-link checks, compact-state
length and `git diff --check`. No production edits, model/test/benchmark execution,
commit or PR.

Completed checkpoint: **CP-0023**.

### CP-0024 — Investigate subjective-view robustness before adding common views

Date: 2026-10-16 (Europe/Berlin).
Recorded the maintainer's successive steering as S2.2-RESEARCH-001 / §7.35:
median/compact gossip considered, then priority placed on theoretical/research
analysis of the own-view baseline. Single active focus moves to S2.2 because it
is a prerequisite; S3.3 returns at §7.34 with Q-S3.3-01 parked and unchanged.
Consulted SWIM, T-Man, partial-view correctness, Rateless IBLT and SCP primary
sources, keeping their assumptions explicit. Executed only bounded set/arithmetic
checks; derived the conditional k-12 quorum-intersection bound and raw descriptor
sizes. Inspected local maturity/selection and limits of existing gossip tests.
Recorded targeted overlap/acceptance/cost metrics rather than assuming global
coverage proves safety. No new accepted policy, changed guarantee, production
implementation or simulation/test campaign.
Validation: readback, checkpoint/question/register/link checks, compact-state
length and `git diff --check`; no commit or PR.

Completed checkpoint: **CP-0024**.

### CP-0025 — Recommend a joint shard transition and record the F2F tradeoff

Date: 2026-10-16 (Europe/Berlin).
Recorded S2.2-RECOMMENDATION-001 / §7.36: unrestricted local activation is not a
valid safety justification under the already chosen fault target. Researched
SybilLimit/social-graph assumptions and preserved F2F's practical deterrence while
distinguishing it from fault/intersection guarantees. Prepared exact Q-S2.2-01:
local discovery with predecessor-quorum-certified changes and a waiting newcomer.
This asks about the concrete joint-transition/availability constraint; it neither
replays the withdrawn bootstrap question nor selects a payment round. No answer
yet. Q-S3.3-01 remains parked and unchanged; DEC-001–052 are preserved.
Validation: readback, checkpoint/question/register/link checks, compact-state
length and `git diff --check`. No production edits, model/test campaign, commit or PR.

Completed checkpoint: **CP-0025**.

### CP-0026 — Withdraw the premature transition question and resolve its premise

Date: 2026-10-16 (Europe/Berlin).
Recorded S2.1-CLARIFICATION-002 / §7.37 and the maintainer's objection to an
undefined "previous group." Q-S2.2-01 remains unanswered and is withdrawn as the
next question; its exact proposal is preserved. Corrected the recommendation's
premature decision-ready status. Active focus moves to S2.1 at the first FINAL/
19->20->21 growth boundary; S2.2 and S3.3 retain return points. Rechecked the
20/21/22 universe bounds and recorded why incremental growth helps but does not
itself establish compatible authority/history. No anchor, founder trust or
reduced guarantee is selected. Q-S3.3-01 and DEC-001–052 remain unchanged.
Validation: readback, original question/decision preservation, checkpoint/link
checks, compact-state length and `git diff --check`. Only bounded arithmetic and
static inspection; no protocol model/test execution, production edits, commit or PR.

Completed checkpoint: **CP-0026**.

### CP-0027 — Check growth witnesses and unknown-participant consensus premises

Date: 2026-10-16 (Europe/Berlin).
Recorded S2.1-RESEARCH-003 / §7.38: exhaustive bounded vote-set enumeration,
nested/concurrent additions and the two-replacement copy/activation race. Kept
ordinary signed roster reports distinct from exclusive membership decisions and
from conflicting lock votes. Consulted primary CUP/Stellar knowledge-connectivity
research; recorded its fixed-instance, identity, fault and graph assumptions and
the failed drop-in applicability gate against current F2F discovery/authorization.
No universal manual-founder requirement or automatically sufficient local signing
list is inferred. Next: concrete first-FINAL node/verifier admission contract and
its initial justification, before any genuine new policy tradeoff question.
S2.1 remains the sole active focus; Q-S2.2-01 is withdrawn as next question and
unanswered; Q-S3.3-01 stays parked with original meanings; DEC-001–052 unchanged.
Validation: readback, preserved question/register sections, checkpoint/ID/link
checks, compact-state length and `git diff --check`. The bounded set calculation
is not a full protocol model, Rust/QUIC test, performance or large simulation run.
No production/spec changes, commit or PR.

Completed checkpoint: **CP-0027**.

### CP-0028 — Autonomous simulation scope and parallel investigation

Date: 2026-10-16 (Europe/Berlin).
Recorded explicit maintainer authorization for autonomous design, subagents and
research-simulation implementation/execution (§7.39). Delegated independent
membership investigation, simulator construction and adversarial review; retained
one active prerequisite S2.1 and S3.3 return point. Isolated examples are in progress;
no result or protocol selection is inferred. Questions/DEC register unchanged.
Validation: saved notes before compact state; readback and whitespace checks.

Completed checkpoint: **CP-0028**.

### CP-0029 — Conditional design, executable simulation and validation

Date: 2026-10-16 (Europe/Berlin).
Recorded §7.40 and the standalone research report with the implemented local
closed-knowledge admission predicate, integrated 20/21/22 first-FINAL fixtures,
separate inclusion/BFT handoff candidate and explicit global-premise/integration
limits. Recorded independent review fixes, printed-source liveness discrepancy,
1,536 seeded handoff runs / 4,036,608 abstract steps, finite 34-state lifecycle
check, fourteen bootstrap checks and six virtual capacity checks. Twelve example
tests, workspace tests (loopback permitted), final all-target strict clippy and
format/whitespace checks passed within their stated scopes. General bootstrap,
canonical wire/TTL/key-lifetime proof and original S3.3 policy choice remain open.
No production/spec behavior changed or new human choice inferred. S2.1 is the
single active prerequisite. DEC register and exact original Q-S3.3-01 preserved.
Validation: notes-first/state-second save, readback, checkpoint/ID/link checks,
compact-state length and `git diff --check`. No commit or PR.

Completed checkpoint: **CP-0029**.

### CP-0030 — Direct decentralized-operation assessment

Date: 2026-10-16 (Europe/Berlin).
Recorded the maintainer's request for a clear operational verdict and §7.41:
current full design is not sufficiently justified/robust for irreversible FINAL;
original local activation is concretely unsafe, conditional handoff is not a
complete deployment solution. Distinguished safety, membership premises,
worst-case fourteen-responsive-correct availability and unmeasured real capacity.
No new protocol selection, test run or production edit. DEC-001–052 and exact
Q-S3.3-01 unchanged; S2.1 remains the sole active prerequisite.
Validation: notes-first/state-second, readback, checkpoint/ID/link and whitespace
checks; compact-state length retained. No commit or PR.

Completed checkpoint: **CP-0030**.

### CP-0031 — Prepare the executable robustness research assignment

Date: 2026-10-16 (Europe/Berlin).
Recorded §7.42 and created `prompts/decentralized_robustness_research.md`, indexed
from the prompt-suite README. The assignment defines precise blockers, preserved
decisions, online research, independent subagents, protocol/evidence requirements,
adversarial models, operational measurements and honest completion criteria.
Prompt creation only; no new research results, production changes or policy answers.
S2.1 and the original questions retain their states. Validation: notes-first/state-
second, readback, decision/question preservation, local links, compact-state length
and `git diff --check`. No tests, commit or PR.

Completed checkpoint: **CP-0031**.

### CP-0032 — Start the invoked robustness research

Read the current workflow, compact state, decision/open/gap registers, active
evidence and existing model. Distributed disjoint research work to three agents;
created the R-01–R-12 evidence ledger and §7.43. Active S2.1, selected decisions
and original questions retained. Research is in progress; no positive deployment
claim or new policy selection. Next: execute attacks, recognition alternative,
resource experiments and real QUIC/storage measurement, then reconcile reviews.

Completed checkpoint: **CP-0032**.

### CP-0033 — Complete the robustness investigation and save its policy boundary

Executed the invoked brief with three subagents; §7.44 and the focused robustness
report record a concrete organic-network first-FINAL incompatibility, independently
reproduced turnover/provenance attacks, tested externally recognized alternative,
measured QUIC/storage limits and explicit unimplemented gates. Final source-level
review fixed the new transfer crash/cursor defect and strengthened pure recipient
verification. Model/measurement manifests and checks are linked in the report.

DEC-001–052 and exact §7.16 question text byte-preserved. Original Q-S3.3-01 stays
unanswered; Q-S2.2-01 stays withdrawn as next question. S2.1 is the sole active
leaf at the recognition/admission-policy consequence, not an implicitly adopted
checkpoint or new production protocol. Notes saved first, compact state second;
readback verifies matching checkpoint, local links, source hashes and statuses.
No deployment, specification rewrite, production edit, commit or PR.

Completed checkpoint: **CP-0033**.

### CP-0034 — Explain project impact and architectural alternatives

§7.45 distinguishes the unsafe present FINAL/membership design from the viable
blind-registry purpose and reusable components. Compared recognized BFT notaries,
federated quorum trust and external consensus, retaining each assumption/cost.
Primary sources rechecked; no algorithm, onboarding policy or payment round
selected, no production/specification changes. S2.1 remains the sole active leaf.
DEC register and exact original question preserved; notes saved before compact
state and read back at the same checkpoint.

Completed checkpoint: **CP-0034**.

### CP-0035 — Audit the intended meaning of socially vetted growth

Maintainer steers S2.1 toward a potential missing trust premise. §7.46 and the
trust-audit artifact distinguish human entry checks, existing configured friend
keys and counted voting authority. Narrow runnable graph/handoff checks executed;
full qualitative human process remains unmodeled. Q-S2.1-TRUST-01 clarification
pending, no selection inferred. Existing verdict remains scoped to its modeled
rules; no checkpoint/consensus replacement adopted. DEC/original question preserved.
Notes saved first, compact state second; matching checkpoint and links read back.

Completed checkpoint: **CP-0035**.

### CP-0036 — Record recursive operator trust and stop investigation

Maintainer explicitly ends the investigation and clarifies Q-S2.1-TRUST-01: trust
in unmodified intended code, reliable operation and recursively careful friendship
selection. Recorded intent without turning belief into a fault bound or protocol
selection. Future directions summarized only; no research/tests/production edits.
Original decisions/questions preserved. Notes saved before compact state; matching
checkpoint and clarification status read back.

Completed checkpoint: **CP-0036**.

### CP-0037 — Prepare focused recursive-trust research assignment

Created and indexed the reusable trust-network blind-spot prompt (§7.48). It
requires premise fidelity, minimal mechanisms, independent attacks, executable
whole-system checks and honest practical evidence. Preparing it does not execute
it or resume the stopped research. DEC register and question meanings preserved.
Notes saved before compact state, then local links and statuses read back.

Completed checkpoint: **CP-0037**.

### CP-0038 — Review certified epoch handoff proposal without adopting it

Reviewed the user-supplied CEH v1.0.0 plan (§7.49). Recognized the explicit external
anchor plus predecessor chain as a conditional resolution of authority recognition.
Recorded a concrete eight/six honest split with six silent faults disproving the
stated handoff-liveness argument, and missing common-state/inclusion, durable
ordering, authenticated pruning, historical-key and shared-HRW input contracts.
Primary PBFT recovery source rechecked. No plan/production edits, new tests or
broad trust-research resumption. DEC register and original questions preserved;
notes saved before compact state, read back and whitespace/link checks completed.

Completed checkpoint: **CP-0038**.

### CP-0039 — Review the hardened CEH v1.1.0 proposal

Recorded §7.50: credited rounds, union reconciliation, durable install and explicit
cold-checkpoint trust. Identified the still-permitted prepared/private-inclusion
stall, fixed-timeout liveness gap, admitted-write closure details and the newly
introduced one-year voucher restriction conflicting with current eleven-year code.
Recorded candidate-completeness, certificate-size, latency and historical-key gaps.
Primary PBFT recovery reference checked; no plan/production edits, fresh tests or
broad research resumption. DEC register and original questions unchanged. Notes
saved before compact state and matching checkpoint/readback/link checks performed.

Completed checkpoint: **CP-0039**.

### CP-0040 — Review CEH v1.2.0 without adopting its verification claims

Recorded §7.51: credited explicit public prepared validity, restored eleven-year
TTL and corrected certificate bytes. Identified the sixty-second timeout cap versus
general partial-synchrony proof, timer-versus-admitted-work drain, and missing
checkable new-view/phase rules. Distinguished local singleton retention from
globally inherited exclusions and corrected permanent-retention/per-shard resource
claims. Catalog, checkpoint, historical-key and durable-latency gates remain open.
PBFT primary recovery source rechecked. No plan/production edits, fresh tests,
architecture selection or broad research resumption. DEC register and original
questions preserved; notes saved before compact state, then readback, matching
checkpoint, local-link, length and whitespace checks.

Completed checkpoint: **CP-0040**.

### CP-0041 — Review CEH v1.3.0 and preserve the verification boundary

Recorded §7.52: credited uncapped timeouts, authenticated new-view evidence,
counter-based drain intent and explicit conflict effects. Identified unsafe
timeout-to-abort inference, incomplete on-demand terminal authority verification
and the inability to distinguish partial-only locks from privately aggregated
quorums. Retained late-certificate handling and historical-key/catalog/checkpoint
gates; qualified assigned-shard and LRU resource claims. Primary PBFT recovery
source rechecked. Static review only; no plan/production edits or new experiments.
DEC register, original questions and stopped broad-research scope preserved.
Notes saved before compact state; readback, matching checkpoint, local links,
compact-state length and whitespace checked.

Completed checkpoint: **CP-0041**.

### CP-0042 — Review CEH v1.4.0 storage and historical-verification changes

Recorded §7.53: credited committed-write retention, mandatory terminal lineage and
late-certificate conflict resolution. Identified the thirty-day pruning versus
historical receipt authorization dependency, missing unified-manifest commitment
and unapproved common-committee policy through N=40. Recalculated certificate-only
storage at N=41/100/1000; under150MB is not a general bound or total live-state size.
Bounded static review/arithmetic only, no plan/production edits, tests, simulation,
broad investigation restart or architecture adoption. DEC register and original
questions preserved. Notes saved before state; readback, checkpoint, links,
compact-state length and whitespace checks performed.

Completed checkpoint: **CP-0042**.

### CP-0043 — Assess relative criticality across the interview and research results

Recorded §7.54: membership/turnover was the largest foundational blocker; recent
storage questions are a related verification/continuity subproblem. Distinguished
other critical fault/key, durability/rollback/expiry and client-acceptance gates
from availability/capacity and downstream tuning. Evidence remains conditional;
earlier static code findings are not a fresh production audit. Noticed CEH v1.5's
new30day late-receipt cutoff as an unapproved continuity tradeoff, without a full
version review. No policy adoption, experiments, production edit or broad research
resumption. Notes saved before compact state; question/register preservation,
readback, matching checkpoint, local links, length and whitespace checked.

Completed checkpoint: **CP-0043**.

### CP-0044 — Create the security closure work plan

Recorded §7.55 and the new CEH_SECURITY_CLOSURE_WORK_PLAN.md. Normalized supplied
answers into P0–P7 contracts, dependency gates, adversarial cases and measurable
acceptance criteria. Two independent agent reviews and primary/pinned-source checks
informed the plan. Historical-proof, key-copy and rollback assumptions stay open;
retry percentages, universal shard isolation and instant voucher fallback are not
adopted as facts. Requirements/questions and production behavior preserved. Notes
saved before compact state; readback, matching checkpoint, local links, state
length, question/register preservation and whitespace checked. Execution pending.

Completed checkpoint: **CP-0044**.

### CP-0045 — Re-evaluate CEH proportionality and ask about the payment promise

Recorded §7.56 and updated the work plan to v0.2. Accepted the permanent old-quorum
loss concern as a real design gap, narrowed earlier necessity claims to their
irreversible-acceptance target, and separated merge convergence from merchant
loss. Checked local L1 owner-proof/reputation versus L2 node-equivocation paths.
Recorded a bounded timeout-replacement witness and closure13 versus successor13
intersection limits. Added explicit P0 comparison of strict CEH, separately
authorized recovery and revocable acceptance. New Q-K1-FINALITY-01 is pending;
original questions/DEC register unchanged. Single active focus moves to K1.1.
Independent reviews, primary-source read and bounded arithmetic only; no production
edit or new simulation/test campaign. Notes saved before compact state, read back
with matching checkpoint, links, question/register preservation and whitespace.

Completed checkpoint: **CP-0045**.

### CP-0046 — Select regional availability and begin the new P0 contract

Recorded DEC-053 / §7.57 and Q-K1-FINALITY-01 direction B from explicit maintainer
instructions. Created the regional P0 contract/acceptance matrix, revised the work
plan to v0.3 and marked strict CEH as a historical/alternative activation design.
Computed ideal/finitely sampled partition-quorum bounds and343 finite merge cases,
with their limits disclosed. Independent reviews retained eligibility, proof,
honest-signing and fraud separation gates. Existing DEC-001–052 wording and exact
Q-S3.3-01 retained; newer DEC-053 explicitly qualifies global-finality interpretations.
S2.2 is the sole active design focus; no repeated product question. No production
edit or new Rust/network test campaign. Notes saved before compact state; readback,
checkpoint/links, decision/question preservation, state length and whitespace checked.

Completed checkpoint: **CP-0046**.


### CP-0047 — Elaborate the regional P0 specification under approved guardrails

Recorded DEC-054 / §7.58 and P0 draft0.2: admission/view/receipt/global predicates,
concrete reference timing profile, support ordering, complete splits, immutable
approvals versus observations and merchant risk/purchase boundaries. Expanded all
12scenarios with deterministic setup, required outcomes, mutants and evidence;
execution remains pending. Green is reserved behind a separately justified proof,
not inferred from regional14. Three independent reviewers contributed; production
integration mismatches are recorded without code changes. Work plan v0.4 updated.
Earlier DEC-001–053 rows and original §7.16 Q-S3.3-01 preserved. Notes saved before
compact state; readback, checkpoint, links, state length and whitespace checked.
No new product question, protocol simulation, Rust or real-wire test is claimed.

Completed checkpoint: **CP-0047**.
 
 
### CP-0048 — Verify P0 simulation suite and scenario test suite (T01–T12)
 
Completed deterministic verification of S2.2 via `p0_partition_scenarios` (6/6 pass, 17.48s)
and `p0_adversarial_scenarios` (6/6 pass, 464.79s). Workspace checks and clippy with `-D warnings`
passed cleanly (0 warnings, 0 errors). Confirmed all fixture counters for large-scale conflict
workload T12. S2.2 regional scenario verification completed and documented in
`P0_SIMULATION_RESULTS.md`, `ARCHITECTURE_INTERVIEW_STATE.md`, and `ARCHITECTURE_INTERVIEW_NOTES.md`.
Prior decisions DEC-001–054 and parked questions preserved.
 
Completed checkpoint: **CP-0048**.

### 7.60 Predecessor baton chaining and chained L2 receipts rejected (DEC-055)

The maintainer conducted a structural re-examination of the operational boundaries and explicitly directed the following architectural simplifications:
1. **Mandatory Predecessor Epoch Chaining is Permanently Rejected:**
   Requiring the previous epoch's 20 members to sign off on the next epoch's 20 members (as originally modeled in CEH `EpochCertificate`) is an architectural dead-end. If $> f$ members fail or an internet partition occurs, it produces a fatal, unrecoverable liveness deadlock (halting ~88.5% of shards globally). Shard succession derives autonomously from the living active mesh via HRW, with deterministic `min(H_canon)` convergence upon merge.
2. **Recursive Client-Side L2 Receipt Chaining on Spend is Rejected:**
   Recipients on Layer 1 do NOT verify a recursive chain of historical Layer-2 lock receipts from previous spends. Layer 2 is an atomic live collision registry: checking the parent lock in-RAM ($< 1\,\mu\text{s}$) is sufficient. The voucher on Layer 1 carries full ownership and causal history; the L2 receipt is purely a merchant checkout safety proof / backup insurance.
3. **Active Background Ping Storms are Rejected:**
   Active 30s background ping storms to refresh candidate windows violate Dunbar gossip economics. Network presence is strictly derived passively from hourly F2F Dunbar heartbeats.

### CP-0049 — Record negative guardrails DEC-055 and architectural simplification

Recorded DEC-055 in decision table and section 7.60. Added negative guardrails 6 and 7 to `AGENTS.md` and module warning to `crates/humoco-sim-core/src/ceh/mod.rs` to permanently prevent re-introducing predecessor baton chaining, recursive receipt chains, or active ping storms. Workspace checks clean. Prior decisions DEC-001–054 preserved.

Completed checkpoint: **CP-0049**.


### 7.61 Passive regional presence after DEC-055

Record: S2.1-PASSIVE-PRESENCE-001. Date: 2026-10-17 (Europe/Berlin).
Checkpoint: CP-0050. Active leaf: S2.1a; dependencies S2.2/S3/S4/N1.
Task: resume from CP-0049 using the interview prompt. No new production or binding
specification changes, experiments or test campaign authorized by this continuation.

**Checkpoint reconciliation.** CP-0049 is present in both memories; the state's
last evidence bullet still said CP-0048 and is corrected. DEC-001–055 remain
selected as previously recorded. CP-0048's twelve passing model scenarios are
preserved as historical evidence for their actual profile, not silently rerun or
claimed to verify the later DEC-055 constraint.

**Bounded source findings.** P0 draft0.2 §3.1/3.3 requires positive reachability
in addition to admission/presence and specifies 30-second refresh, 120-second
reachability leases and 30-second view leases. P0_SIMULATION_RESULTS.md §2 explicitly
says the successful partition variant refreshes local probes every 30 seconds.
`p0/admission.rs` gates `selectable` on `reachable_until`; the test fixture in
`tests/p0_support/mod.rs::Fixture::catalog` refreshes simulated responses every
minute while establishing continuity. Removing probes without changing this
predicate expires local eligibility too; it does not implement passive recovery.
These are source observations, not executed new tests.

Spec07 §3 and Spec11 distinguish initial 24h / eight-hourly-observation maturity
from slow ACTIVE/DORMANT hysteresis (at most 3/24 observed hours; roughly 21–24h
absence after regular hourly reception). P0's `admitted` instead requires >=8
observations continuously, and its report already discloses missing exact dormant
re-entry behavior. Spec07 §3's re-entry prose also differs from INV-0704; two
consecutive hourly observations alone do not establish two elapsed hours.
These state-machine details remain technical consolidation work, not accepted
changes or additional preference questions now.

`humoco-node/src/network/manager.rs::PRESENCE_FRESHNESS_SECS` is 2h;
`KnownNodeInfo::is_presence_fresh` applies it to population/routing paths.
`PeerManager::shard_committee` admits known mature non-banned identities without
that freshness filter and explicitly separates routing reachability from write
membership. Thus neither the current count nor the existing frozen write roster
is evidence of a delivered passive regional-reconstitution policy. Ticket age,
presence eligibility, signing readiness and actual RPC success remain distinct.

**Why this leaf comes first.** Regional successor selection cannot be integrated
until its selectable population is defined under DEC-055. This is a bounded
policy-consolidation dependency, not permission to restart §7.47's stopped broad
trust investigation or invoke its separate research prompt. DEC-055 already
settles passive hourly gossip; do not ask whether to restore active probes.

**Recommendation status: proposed, conditional baseline.** Prefer a separate
2h passive selection-freshness window for already admitted identities: keep ticket
maturity and historical evidence, exclude stale members only from future attempts,
then recompute exact HRW from the independently accepted passive catalog. Reuse the
existing duration as an initial candidate rather than claim it is measured optimal.
It trades sensitivity to delayed/lost gossip for earlier removal of stale members.
The slower existing ACTIVE/DORMANT policy remains a viable lower-churn alternative
if its longer payment interruption is acceptable. Neither choice establishes a
Byzantine bound, common views, direct RPC reachability or a restart deadline.

**Exact pending question — Q-S2.1-PRESENCE-01 (unanswered):**

> Wie lange sollen bekannte, ausgereifte Knoten ohne frischen authentifizierten
> Heartbeat noch für die Auswahl künftiger regionaler Komitees zählen?
>
> **A — Zwei Stunden als erste Entwurfsgrenze (Empfehlung):** Danach fallen sie
> aus neuen Komitee-Snapshots heraus. Ticket-Reife und alte Bestätigungen bleiben
> erhalten; verlorene oder verzögerte Heartbeats können dadurch früher zu einer
> anderen lokalen Auswahl führen.
>
> **B — Die bisherige träge ACTIVE/DORMANT-Regel:** Nach zuvor regelmäßigen
> Heartbeats erfolgt der Ausschluss grob nach 21–24 Stunden. Das vermeidet mehr
> Wechsel bei Gossip-Aussetzern, kann Zahlungen mit unerreichbaren alten
> Komiteemitgliedern aber entsprechend länger blockieren.
>
> Eine andere gewünschte Zeitgrenze kann frei genannt werden.

**Unchanged guards and validation obligations.** No replacement inside a frozen
checkout, no rank21 fallback on timeout, no aggregation across views, no hearsay
ban, no loss of own choices or historical receipt validity. Timeout alone does not
change membership. Qualification remains per independently admitted local context;
shorter silence is not fraud. Hourly gossip cannot promise second-scale partition
detection, and a partition that blocks RPC while preserving heartbeat delivery
need not change the passive roster at all. A selection threshold is not a total
recovery bound: enough accepting ready signers, local population continuity / 24h
mode hysteresis, safe time and state repair remain additional prerequisites.

After the answer, derive exact safe-time freshness boundaries, replay/dedup rules,
ACTIVE versus selection re-entry behavior and view-interval semantics. Track
long-retained ticket maturity separately from short selection freshness; do not
silently replace the existing dormant re-entry rule. Establish compatibility under
observer skew / 14-of-20 acceptance without assuming identical receipt times.
Revalidate T01–T03/T08/T11 with hourly passive events and no probe refresh, including
missed/jittered heartbeats, one-way paths, gossip-live/RPC-dead, restart, continuity
reset and neutral old-attempt cancellation. Later integration needs real adversarial
receiver-side QUIC tests; no model-only network-defense claim. Reconcile DEC-055's
receipt-chain exclusion separately in P1/C1; do not add recursive client receipts
as a workaround for this presence issue.

Design: open; recommendation and threshold unselected. Implementation/verification:
read-only repository inspection only in this continuation. Next action: ask the
recorded question, await an explicit answer, then derive the selected passive
policy before S3/S4 repair integration. Original parked question mappings unchanged.

### CP-0050 — Resume at passive presence integration

Reconciled CP-0049 and retained DEC-001–055. Recorded §7.61's conflict between
DEC-055 and the passing probe-dependent P0 profile; preserved the exact historical
test scope. Active leaf S2.1a / Q-S2.1-PRESENCE-01 asks passive exclusion tolerance:
A = proposed 2h selection freshness; B = slow existing ACTIVE/DORMANT hysteresis.
No answer inferred from the resume request. Broad trust research remains stopped.
Production, binding specifications and test results unchanged. Next: await answer,
derive precise passive policy and revalidation obligations, then resume S3/S4.

Completed checkpoint: **CP-0050**.


### 7.62 Three missed heartbeats selected and total-state-loss boundary

Record: S2.1-PRESENCE-DECISION-002 / S3-STATELOSS-001.
Date: 2026-10-17 (Europe/Berlin). Checkpoint: CP-0051.

**Answer / DEC-056.** The maintainer reports the choice from another chat and
explicitly adopts "3 gossip ausfälle" here, requesting the next question.
AGENTS.md §3 guardrail 6.3 now also names three consecutive missed hourly heartbeats
and exclusion from subsequent HRW snapshots. Record that policy as selected,
not as A or B of Q-S2.1-PRESENCE-01. Its original alternatives remain historical;
the proposed 2h baseline is superseded. No claim of an optimal measured threshold
or completed implementation follows from the maintainer's assessment.

Three missed expected heartbeat opportunities are not an unconditional exact
three-hour wall-clock deadline: slot definition, permitted delivery/clock tolerance,
deduplication, persistence and restart/re-entry boundaries still need precise
consolidation. Preserve 24h ticket incubation, immutable own choices, historical
evidence and the frozen committee within each checkout. Missing gossip alone is
not fraud evidence. Existing P0 30s probes / 120s leases and the runtime 2h counting
filter are not silently treated as compliant. Keep passive-profile/model and real
QUIC validation obligations from §7.61; do not reopen the chosen miss count.

**Concurrent changes.** Re-read both memories, git status and the relevant diffs
before editing. The other chat changed AGENTS.md, Spec03 and Rust architecture
comments; these edits are preserved. They clarify living-mesh selection versus
calendar epochs / ticket maturity. This interview changes only its two memory
files. Commentary in other files is not executed proof of automatic regional
recovery or of arbitrary-partition liveness.

**Next leaf / why it matters.** User steering moves to the next substantive
question; S2.1a's engineering obligations remain recorded. S3.4 makes the recovery
operating envelope explicit before justifying new regional signers. This is a
narrow failure case, not a return to predecessor permission or global finality.
P0 §4.1 requires completed available-state repair but does not define an empty-source
fallback. DEC-053 accepts hidden competing regional evidence and later revision;
it does not explicitly accept permanent disappearance of all conflict evidence.
DEC-026/031/032 still guard readiness and same-key history. The model's
`p0/state.rs::Signer::lose_own_history` disables signing and offers no hidden-history
recovery oracle. That guard is distinct from this next question.

Scenario: the identities proposed to resume are independently admitted and have
intact own signing histories (or are genuinely fresh eligible identities); the
missing data is the shard's live collision state. No reachable qualified replica
or client can provide the relevant previous lock records/receipts. Clients can
still present valid origin and L1 ownership/causal evidence for a new request.
Such evidence alone does not establish absence of a previously registered
incompatible spend. If older evidence later returns, ordinary supported merge
applies; if it is permanently gone, convergence cannot recover the missing proof.
This scenario is not an ordinary restart, transient peer outage, or proof that
all remote copies are globally gone.

**Exact pending question — Q-S3-STATELOSS-01 (unanswered):**

> Wenn für noch gültige Gutscheine kein erreichbarer Knoten oder Client den
> bisherigen Sperrzustand wiederherstellen kann: Soll die Region für diese
> betroffenen Ausgaben warten, oder darf sie allein auf Grundlage gültiger
> L1-Nachweise neue Sperren annehmen?
>
> **A — Warten auf wiederherstellbaren Sperrzustand (Empfehlung):** Die betroffenen
> Ausgaben bleiben nicht signierbereit; unabhängig wiederhergestellte Bereiche
> können weiterarbeiten. Das vermeidet einen bewussten Neustart ohne die alten
> Kollisionsdaten, kann die betroffenen Gutscheine aber bis zum Ablauf blockieren.
>
> **B — Neustart trotz fehlender Kollisionsdaten zulassen:** Mit gültigen
> Ursprungs- und L1-Nachweisen dürfen neue regionale Sperren entstehen. Frühere
> Ausgaben können dadurch erneut angenommen werden; bei dauerhaft verlorenen
> Nachweisen ist auch eine spätere Konfliktauflösung nicht gesichert.

**Recommendation and limits.** A retains recovery-before-signing and avoids silently
expanding the accepted partition risk into an empty-state recovery policy. Its
implementation still needs a justified scope/readiness predicate: there is no
claim that absence of missing records is detectable from a matching digest.
B is an explicit proposed relaxation for this loss scenario, not current approval
and not a cryptographic safety fix. Neither option permits lost-choice same-key
signing, weaker owner/origin checks, invented ticket maturity, recursive historical
client L2 receipt chains, raw unsupported min-hash takeover, hearsay bans or an
old-quorum activation veto. No new identity by itself repairs missing lock state.
Regional hidden-evidence risk already accepted under DEC-053 remains unchanged.

Design: miss-count requirement selected; presence implementation/verification pending.
State-loss fallback unselected. No tests, source or binding-spec edits in this turn.
Next: ask Q-S3-STATELOSS-01, await answer, then specify available-state recovery
sources, coverage and refusal scope under the selected operating envelope.

### CP-0051 — Adopt three missed heartbeats and ask about unrecoverable live state

Recorded DEC-056 from explicit maintainer instruction and corroborating AGENTS.md
changes. Q-S2.1-PRESENCE-01 answered with a third policy; original A/B preserved.
Active leaf moves to S3.4 / Q-S3-STATELOSS-01: A = wait for recoverable collision
state; B = explicitly permit client-assisted empty-state restart with duplicate-
acceptance and permanently missing-evidence risk. No answer inferred. Existing
DEC-001–055, other-chat edits, same-key loss gate and parked question meanings
preserved. Technical presence/recovery and wire validation remain pending.

Completed checkpoint: **CP-0051**.


### 7.63 Mandatory sync-readiness selected; recovery completeness still open

Record: S3-STATELOSS-DECISION-002 / S3-RECOVERY-CONTRACT-001.
Date: 2026-10-18 (Europe/Berlin). Checkpoint: CP-0052.
Active technical leaf: S3.4a; dependencies N3/O1/O2/S2.2.

**Answer / DEC-057.** The maintainer explicitly selects Q-S3-STATELOSS-01 A:
a node with an empty DB cannot distinguish genuinely new use from resubmission
after disaster. After restart/data loss it must pass a sync-readiness gate,
return FLAG_NOT_READY and issue no lock approvals/countable quorum vote until
its shard state has been successfully recovered by P2P digest-pull from shard
peers. If peers and state remain unavailable, the affected scope remains
unrecovered/blocked rather than accepting pure L1 evidence. Safety and collision
protection take priority over availability in this recovery case. B's deliberate
empty-state restart is rejected. No fixed deadline opens this gate.

This reinforces DEC-026/031 and specifies the restart/no-source case; it does not
replace DEC-032. Restoring visible confirmed locks cannot recover a hidden prior
individual signing choice. Loss/rollback of own choices retains the independent
same-identity signing gate. DEC-053's revocable regional acceptance and admitted
merge remain selected; this answer does not claim irreversible global exclusion
of conflicting regional spends or authorize predecessor-quorum permission.

**Current source evidence (read-only, not newly executed tests).**
- `humoco-node/src/daemon.rs` initializes `initial_sync_ready` from whether resolved
  configured peer endpoints are empty. In `run_shard_digest_pull_sync`, an empty
  `candidate_addrs` list explicitly marks the node ready. These are recovery-gate
  bypass paths to remove or narrowly distinguish from a justified initial network
  start; no peer availability/configuration condition proves recovered state.
- The sub-20/empty-local bootstrap branch sets ready after its pull loop. The
  larger-network path clusters digests and marks ready after local equality or
  successful page handling. Record-import results are discarded in the examined
  loops; page termination and import/durable-install success need explicit checks.
  The code comments themselves limit the digest's projected-state claim.
- `network/transport.rs` checks the shared sync-ready flag before LockVerify and
  returns FLAG_NOT_READY. `tests/phase5_pull_sync_and_readiness.rs` contains real
  QUIC request/response coverage of a false flag and then manually sets it true.
  This demonstrates the intended test structure, not verified completeness of the
  daemon's automatic transition. The test was inspected, not run here.
- Readiness uses a shared AtomicBool in the inspected daemon/transport. Per-shard
  or finer refusal scope is not established by the current boolean. Do not claim
  unaffected recovered shards continue independently without verifying that path.

**Minimal recovery contract derived from the selected requirement (proposed
engineering predicates, not a completed safety proof).**
1. Enter RECOVERING on every restart and on detected relevant loss/rollback. Serve
   no new approval for the affected scope. Retained authentic state/evidence must
   remain available for bounded learned-peer sync while signing is gated, otherwise
   simultaneous restarts could deadlock solely because every source is not ready.
2. Identify the exact shard/scope and independently admitted source identities.
   Source readiness/continuity cannot be inferred from an address, a completed RPC,
   or agreement between equally empty new/recovering replicas. Empty source sets
   never satisfy the recovery predicate by vacuous agreement.
3. Transfer authenticated, bounded, snapshot-bound records and necessary evidence;
   verify the complete canonical representation, scope, pagination endpoints,
   declared counts/digests and each admission/import result. Missing pages, stalled
   cursors, invalid records, cancellation or unacknowledged durable writes keep the
   gate closed. Existing limits, reservation-first and trusted expiry still apply.
4. Account for concurrent changes through a named source-local revision endpoint
   with complete deltas or another justified equivalent. Revisions across different
   peers are not a global order. A local transfer endpoint is not an old-committee
   fence, and no predecessor signature chain is required. Exact coverage of
   concurrent/partial accepted state remains an obligation, not an asserted result.
5. Activate only after the installed durable state and source/coverage basis are
   justified AND relevant own-choice history is intact/recovered AND current
   storage/membership/time conditions permit signing. Persist enough recovery
   basis to audit the transition. Admission to a frozen committee does not supply
   this missing evidence. Unknown or failed checks return NOT_READY neutrally.

**Counterexample / evidence limit.** Compare a never-used shard with a shard that
previously accepted A and then lost every accessible copy/evidence of A. If the
observable state in both cases is the same collection of empty replicas, equal
empty digests and valid new L1 requests are identical inputs. A rule consulting
only those inputs cannot distinguish these histories. Fourteen signatures over
that empty digest prove agreement on reported data, not survival of A. The same
problem exists if only the source holding a relevant accepted lock is omitted.
This is a logical indistinguishability witness, not an executed simulation or a
new global-impossibility claim. It motivates establishing source-state continuity
and a precise recovery premise before calling digest equality sufficient.

**Unresolved design work.** Specify the minimum justified surviving-state/source
coverage under qualified regional views, including partial prior writes and late
receipts. Determine how previously empty healthy shards and genuine first startup
are distinguished from disaster recovery without a configuration toggle that
silently clears existing-network history. This is an initialization/continuity
boundary, not a renewed product question about permanent networks or old14 vetoes.
Keep declared regional hidden-evidence risk separate from known recovery gaps.
No numeric source threshold is selected by the answer; derive it against the
stated fault/data-survival premise rather than ask the maintainer to guess one.

**Required validation, not executed here.** Real receiver-side QUIC/daemon cases:
restart rejects votes until justified install; no peers / DNS resolution failure
never marks ready; several empty fresh peers do not establish recovery of a used
shard; simultaneous restarts with intact stores can exchange recovery evidence;
truncated/replayed snapshot pages, skipped invalid imports, missing deltas and
failed durable commits keep the gate closed; unrelated ready scope behavior is
verified explicitly; same-key choice loss stays blocked despite matching visible
state. Combine with three missed-heartbeat selection, partitions and delayed valid
receipts in the model, then verify on wire. Existing test names or manually
flipping the flag are not proof of these automatic transitions.

Question status: Q-S3-STATELOSS-01 answered A; no new preference question pending.
Requirement: selected. Design: open at source-coverage/continuity predicate and
scoped activation; no claim of complete collision-freedom proof. Delivery: interview
memory only, no production/spec changes, tests or large research campaign.
Next action: continue bounded technical derivation of S3.4a's source/coverage
predicate; ask a human question only for a remaining operating-envelope tradeoff.

### CP-0052 — Require P2P recovery before restart signing

Recorded DEC-057 / Q-S3-STATELOSS-01 A with the mandatory FLAG_NOT_READY restart
sync gate and permanently unavailable-state block. Preserved the separate lost-own-
choice gate and revocable regional policy. Read-only inspection identified no-peer
ready bypasses and manual-flag test limitations. Recorded a proposed recovery
contract and empty-state indistinguishability witness, without claiming source
coverage established or tests executed. S3.4 policy decided; S3.4a is the single
active technical leaf. No new human choice is pending; engineering uncertainty
must be investigated before proposing a numeric recovery threshold.

Completed checkpoint: **CP-0052**.


### 7.64 Present the recovery-basis question with A and B

Record: S3-RECOVERY-BASIS-QUESTION-001 / WF-004.
Date: 2026-10-18 (Europe/Berlin). Checkpoint: CP-0053.
Active node: S3.4a. The maintainer asks for A/B proposals as the normal interview
format and requests the current question again. CP-0052 contained an unresolved
technical next action, not an unanswered A/B question. Assign a new stable question
ID; do not re-ask or change the answered Q-S3-STATELOSS-01 / DEC-057.

**Decision boundary.** Snapshot integrity, complete pagination/delta processing,
durable install and independent own-choice safety remain required in either
option. They establish agreement with the named source/reference state, not
unconditional absence of every hidden lock. The unresolved choice concerns the
basis on which that reference state is trusted as sufficient for local recovery.
A matching digest is not itself such a basis. This bounded recovery question does
not restart the stopped general recursive-trust research or select old14 authority.

**Exact pending question — Q-S3-RECOVERY-BASIS-01 (unanswered):**

> Welche Grundlage soll das Sync-Readiness-Gate verlangen, bevor es den
> wiederhergestellten Shard zum Signieren freigibt?
>
> **A — Überprüfbare Wiederherstellungsgrundlage (Empfehlung als Entwurfsziel):**
> Wir verlangen einen begründeten Referenzzustand aus fortgeführten Peer-Beständen,
> prüfen den vollständigen Snapshot samt nötigen Nachträgen und speichern ihn
> dauerhaft. Lässt sich die erforderliche Zustandsabdeckung nicht belegen,
> bleibt FLAG_NOT_READY gesetzt. Welche Nachweise dafür ausreichen, muss noch
> technisch hergeleitet werden.
>
> **B — Explizit vertrauensbasierte Wiederherstellungsquellen:** Der Betreiber
> benennt Quellen, deren Aussage über den vollständigen Shard-Zustand als
> zusätzliche Vertrauensannahme gilt. Übertragung, enthaltene Nachweise und
> Speicherung werden weiterhin geprüft. Verschwiegene oder bei diesen Quellen
> verlorene Einträge können damit aber unentdeckt bleiben.

**Recommendation status.** A follows the chosen preference for collision protection
and avoids adding a designated recovery-source trust assumption. It is conditional
as a construction: no source-continuity/coverage mechanism is established by
choosing it, and unprovable recovery remains blocked. A is not a promise of a
universal cryptographic completeness proof or automatic liveness after arbitrary
loss. B is a proposed explicitly trusted recovery model, not equivalent mathematical
assurance and not permission to use arbitrary peer majorities as authority. It
would refine DEC-057's justified-state premise only if explicitly accepted; no
such refinement or activation bypass is inferred now. Compromised or incomplete
trusted sources are an explicit residual risk. Source identity authentication
alone verifies neither honesty nor storage continuity under either model.

No automatic bootstrap on an empty DB, empty peer set, timeout or expired waiting
period is approved by either proposal. B still requires the configured P2P recovery
source and validated transfer; it does not permit pure-L1 restart. The separate
same-key own-history loss/rollback gate remains intact, as do frozen 14/20 checkout,
qualified membership, regional merge limits and first-party-only sanctions.
Implementation, source-count derivation and adversarial QUIC/crash validation are
pending. Existing source findings and counterexamples in §7.63 are unchanged.

Next: ask the recorded A/B question; await an explicit answer. Then derive/test
the selected recovery basis without treating preference as proof. DEC-001–057
remain unchanged. Only interview memory was edited; no new source inspection,
external research, production/spec edit or tests were needed for this presentation.

### CP-0053 — Restore A/B presentation at the recovery-basis leaf

Recorded WF-004 from explicit maintainer steering. Prepared and saved new
Q-S3-RECOVERY-BASIS-01: A = investigate a verifiable source/reference coverage
contract, stay blocked if unproved; B = explicitly designated trusted recovery
sources with residual omission/loss risk and unchanged transfer checks.
Both are unselected. DEC-057 remains answered A; no repeated state-loss choice.
S3.4a remains the sole active focus. Technical uncertainty and independent
own-choice protection remain visible; no completed safety proof is claimed.

Completed checkpoint: **CP-0053**.


### 7.65 Quorum digest-pull selected; stable transfer under write load

Record: S3-RECOVERY-BASIS-DECISION-002 / S3-SYNC-WRITES-QUESTION-001.
Date: 2026-10-18 (Europe/Berlin). Checkpoint: CP-0054.
Node S3.4a: mechanism selected, proof open. Active subleaf S3.4a.1.

**Answer / DEC-058.** The maintainer explicitly selects Q-S3-RECOVERY-BASIS-01 A
and cites Spec03 ShardDigest: query shard peers, require quorum agreement on a
cryptographic digest/root of active locks, fetch the snapshot, verify lock
signatures, and activate only when shard state is mathematically gap-free.
Until then remain FLAG_NOT_READY. Record quorum-backed verified digest-pull as
the selected mechanism and gap-free recovery as the required property, not as
an already demonstrated theorem. The designated-source trust alternative B is
rejected. No mandatory Merkle implementation is inferred: Spec03 uses BLAKE3
whole-state hashing, and the user mentions either representation.

**Bounded specification/code check.** Spec03 §5 describes a 14-of-20 digest
cluster and download from one matching peer; §2.1 requires distinct authenticated
identities in one justified frozen committee for checkout. Recovery needs its own
exact source/context binding; it must not count arbitrary duplicate responses or
assume the recovering node contributes a justified vote. `types.rs::
evaluate_digest_clusters` groups supplied simulation NodeIds by digest without
independent signature/membership/dedup verification. Its inputs need verification;
calling this helper alone proves no real quorum. Adaptive small-network mode is
retained; no forced fourteen-peer dependency for N<20 is newly selected.
`crypto.rs::compute_shard_digest_at` hashes a filtered projection of LockRecord
fields; the transport constructs synthetic HMC LockRecords for this projection.
That is not a demonstrated commitment to every required signed wire field,
root/expiry constraint, conflict proof or private own-choice history. These are
read-only observations, not new executions or production fixes.

**Proof boundary retained.** A digest verifies equality to its canonical encoded
reference state under the hash assumptions. Valid signatures verify the supplied
statements; they do not establish absence of omitted statements. Fourteen newly
assigned empty replicas can agree on an empty digest after inaccessible state
loss. The source-coverage witness in §7.63 remains unresolved by agreement alone.
A common justified committee, appropriate fault/data-survival bounds and preserved
honest state can support a quorum-intersection argument; changing committees or
honest history loss do not automatically satisfy those premises. This is local
mathematical reasoning, not a new external proof or a rejection of the selected
Spec03 transfer mechanism. Keep DEC-053 regional revision and DEC-057 loss gating.
No claims of unconditional global completeness, same-key history recovery, old14
permission, a third gossip stream or automatic readiness from empty agreement.

**Next bounded prerequisite.** Define the immutable state/cut that the quorum
digest commits to before completing the source-coverage argument. Locks and TTL
expiry can change during a multi-page transfer. Never silently combine pages
from different snapshots or compare different expiry cutoffs as one state.
Earlier §7.31–7.32 investigated snapshots/deltas but did not select this precise
live-transfer tradeoff. DEC-041's planned pause for affected takeover scope does
not select a pause of all serving source nodes during every recovery. Both
options below retain source-coverage checks, signature verification, durable
install and FLAG_NOT_READY until the full readiness predicate is satisfied.

**Exact pending question — Q-S3-SYNC-WRITES-01 (unanswered):**

> Wie soll der Wiederherstellungsabgleich mit neuen Locks umgehen, die während
> der Snapshot-Übertragung bei den weiterarbeitenden Shard-Peers eintreffen?
>
> **A — Fester Snapshot plus begrenzte Nachträge (Empfehlung):** Der Knoten lädt
> einen eindeutig gebundenen, unveränderlichen Snapshot und übernimmt danach
> die seit dessen Stand hinzugekommenen relevanten Änderungen. Das vermeidet
> wiederholte Vollübertragungen, benötigt aber zusätzliche Cursor-, Aufbewahrungs-
> und Vollständigkeitsregeln. Reicht das sichere Nachtragsfenster nicht, bleibt
> er nicht signierbereit und muss den Abgleich neu beginnen.
>
> **B — Vollabgleich ohne Nachtragsmechanismus:** Der Knoten lädt einen festen
> Snapshot und prüft anschließend erneut gegen den begründeten aktuellen
> Quorum-Zustand. Hat dieser sich relevant geändert, beginnt der Vollabgleich
> erneut. Das ist einfacher, kann bei häufigen Änderungen aber viel Bandbreite
> kosten und den Knoten dauerhaft auf FLAG_NOT_READY halten.

A is recommended for the previously stated sustained write workload (§7.32),
subject to bounded catch-up capacity and a justified activation endpoint. It is
not a global ordered log, mandatory predecessor fence or liveness guarantee.
B is a simpler initial design for a workload with sufficiently quiet intervals;
that workload restriction and possible recovery starvation would be explicit.
Neither final digest equality nor finishing deltas proves the source-coverage
premise; these transfer alternatives do not close it. No numeric retention size,
source count or protocol library is selected. Existing N2 protected budgets and
expiry/no-bloat rules constrain either design.

Next: ask Q-S3-SYNC-WRITES-01 A/B; after selection derive snapshot/context/expiry
and bounded transfer semantics together with the still-open source-coverage proof.
Implementation and adversarial model/real-QUIC verification remain pending. Only
interview memory updated; no production/spec changes, tests or new research campaign.

### CP-0054 — Select quorum-backed digest-pull and ask about concurrent writes

Recorded DEC-058 / Q-S3-RECOVERY-BASIS-01 A faithfully, separating required gap-free
recovery from unproved sufficiency of the present Spec03/code mechanism. Preserved
source-coverage, distinct-identity/context, durable-install and own-choice gates.
Prepared Q-S3-SYNC-WRITES-01: A = stable snapshot plus bounded deltas; B = stable
full-snapshot retry without delta machinery, with quiet-workload limitations.
No option selected. S3.4a.1 is the sole active leaf, a prerequisite within the same
recovery problem; previous decisions and parked questions unchanged.

Completed checkpoint: **CP-0054**.


### 7.66 Fixed snapshot+deltas selected; bucket sealing and retry boundaries

Current-status correction (CP-0056): §7.67 / DEC-061 withdraws
Q-S3-LATE-BUCKET-01; the maintainer rejects both added-structure proposals.
The historical witness concerned sync arrival, not a justified post-seal live
acceptance. Do not infer a required correction/version subsystem from this record.

Record: S3-SYNC-WRITES-DECISION-002 / S3-LATE-BUCKET-QUESTION-001.
Date: 2026-10-18 (Europe/Berlin). Checkpoint: CP-0055.
Active leaf: S3.4a.2; source/readiness dependencies unchanged.

**Answer / DEC-059.** The maintainer explicitly selects Q-S3-SYNC-WRITES-01 A:
fixed snapshot plus bounded deltas. Their concrete direction uses completed
5-minute windows, sealing after 30s grace, and unacknowledged RAM buffering of
current-window in-flight locks followed by deterministic merge. Repeated full-sync
B is rejected for high-load recovery. Record >1,000 Tx/s as stated motivation,
not a proven universal livelock threshold: affected-shard arrival rate, transfer/
verification capacity and overlap determine catch-up (§7.32).

Seal boundary is bucket END +30s, not every individual T_0+30s. Sealing grace and
authenticated root expiry+30s are different lifetimes. Buffered work receives no
application acceptance or approval before readiness, normal validation and durable
commit. QUIC transport acknowledgments are not application success. Buffering is
bounded and consumes admitted capacity; overflow must refuse safely rather than
create an unbounded queue. This is the explicitly proposed recovery-window buffer,
not permission for a generic server pending-intent service contrary to DEC-042.
Crash may lose unacknowledged buffered work; it never erases committed choices.
Exact capacity, persisted delta retention, atomic merge and replay endpoints remain
technical work. Five-minute closure cannot delay ordinary checkout until sealing.

**Additional instruction / DEC-060.** The maintainer explicitly includes exact
payload/T_0 preservation and the three-send fire-and-forget heuristic. This updates
prior DEC-027/§7.33's one-application-attempt policy; do not keep reporting the new
instruction as unselected. The referenced plan describes an initial request, a
second request on error and a third background request on another error, using the
same application bytes. This preserves SpendId/slot identity and does not permit
new timestamps to move a retry into a later bucket. It proves neither timely
arrival nor equal inventories. Preserve 800ms collection and neutral quorum
cancellation; define/cap background lifetime, concurrency, shutdown ownership and
no-success-yet/outcome handling. Retries must not silently become unlimited work
or extra votes. Existing timestamp/epoch freshness checks and quota accounting
require reconciliation with unchanged-payload retry. Cross-gateway/restart custody
of original T_0 and the actual bucket timestamp field remain open; same bytes for
one gateway's retry do not prove every gateway independently chooses the same T_0.
No measured 99.9999% delivery/synchronization claim is accepted: correlated outages,
QUIC retransmission, overload and crashes invalidate the simple packet p^3 inference.

**Repository evidence / provenance.** The workspace was clean at entry; previous
other-chat edits are now part of its current baseline. Existing
`docs/PLAN_BUCKETED_SHARD_SYNC.md` is marked draft/not executed but bucket/retry code
is now present. `types.rs` defines 300,000ms buckets and 30,000ms seal grace;
`is_bucket_sealed` only compares time, it does not freeze a stored snapshot.
`compute_shard_bucket_digest` hashes the supplied current non-VOID records, so late
insertion, canonical VOID and physical expiry can change the result after that
predicate is true. `transport.rs` returns this time flag alongside a freshly
computed digest and paginates live lists. No immutable committed snapshot/version
or enforced seal follows from that boolean alone.
`routes.rs::collect_peer_attestations` already has the conditional second request
and detached third request, while its doc comment still describes immutable
committee/800ms collection. This code is observed, not newly authored or verified.
The inspected tests in `humoco-sim-core/tests/
spec_03_bucketed_shard_sync_and_retry_tests.rs` cover timestamp/seal arithmetic,
static-list bucket hashing and envelope identity; they are not executed here and
are not real receiver-side QUIC proof of immutable buckets or late repair.

The present daemon compares a recent 288-bucket range before declaring bucket pull
success. Full live-root state can be older than 24h; complete historical-live
coverage and a correct current-window range need validation before readiness.
Do not equate the 24h fast index with the voucher retention lifetime. TTL pruning
remains mandatory; do not retain expired snapshots/receipts indefinitely to claim
immutability. Root/expiry, status/proof fields and HMC timestamp projections remain
part of the exact canonical digest/export contract. Park these concrete coverage
findings within OPEN-03/09/11 rather than silently closing the design.

**Late-evidence witness.** Window 12:00–12:05 is considered sealed at12:05:30.
A valid lock with T_0=12:04:59, already accepted in the relevant region, reaches a
recovering peer only at12:06. Byte-identical retries and three sends cannot rule
this out. Permanently rejecting all old-window state would violate DEC-053's
late-evidence repair and DEC-057/058 recovery requirements. Modifying an existing
snapshot under its unchanged digest/version would invalidate its commitment.
Need a late-update rule while retaining original T_0 and authenticated validity.
This is a deterministic reasoning example, not an executed network scenario.

**Exact pending question — Q-S3-LATE-BUCKET-01 (unanswered):**

> Wie sollen gültige, bereits anderswo angenommene Locks nachgetragen werden,
> wenn ihr 5-Minuten-Bucket hier schon versiegelt ist?
>
> **A — Unveränderlicher Basis-Snapshot plus begrenzte Korrekturen (Empfehlung):**
> Der versiegelte Basisstand bleibt gleich. Späte Locks werden ihrem ursprünglichen
> Bucket als separat überprüfbare Nachträge zugeordnet; der vollständige aktuelle
> Zustand umfasst Basis und Nachträge. Das bewahrt stabile Snapshot-Übertragungen,
> benötigt aber genaue Versions-, Größen- und Aufbewahrungsgrenzen.
>
> **B — Neue Version des betroffenen Buckets:** Späte Locks führen zu einem neu
> berechneten Bucket-Digest und einer neuen Snapshot-Version. Alte Versionen werden
> nicht verändert; laufende Übertragungen müssen die neue Version berücksichtigen.
> Das vermeidet eine separate Korrekturstruktur, kann aber erneute Übertragungen
> des betroffenen Buckets auslösen.

Both are unselected engineering directions and preserve accepted late-evidence
support checks, original intent/T_0, expiry pruning, quorum/source context and
bounded resources. Neither treats every late unconfirmed request as confirmed,
adds recursive client receipt chains or changes the frozen checkout committee.
A is recommended as a direct extension of selected bounded deltas, not a proven
unbounded append-only archive. B's new versions also require bounded retention
and fair catch-up; it is not a restart of the entire shard. Sealing describes an
immutable named snapshot version, not proof that no valid historical evidence
can ever arrive or that current canonical state can never change.

Next: ask Q-S3-LATE-BUCKET-01 A/B. Then define digest/version composition, complete
historical-live coverage and bounded tail catch-up; audit retry resource/freshness
composition in C3/N4. All production/spec changes and adversarial QUIC tests remain
pending. This turn edits only interview memory; no tests/benchmarks were executed.

### CP-0055 — Adopt bounded deltas, bucket direction and exact-payload retry refinement

Recorded DEC-059 / Q-S3-SYNC-WRITES-01 A and new DEC-060 from explicit maintainer
instructions. Retained new 5-minute/30s sealing and unacknowledged-buffer direction
as selected but unproved; corrected current retry index to reflect three-send
selection, preserving historical rationale and existing protocol bounds. Read-only
inspection found time-only sealing and current live-list export, so late historical
updates remain a prerequisite. Saved Q-S3-LATE-BUCKET-01: A = immutable base plus
bounded correction deltas; B = new immutable bucket versions. No answer inferred.
S3.4a.2 is the single active leaf. Source coverage/own-history/readiness obligations
remain open. No production changes or new test executions in this continuation.

Completed checkpoint: **CP-0055**.


### 7.67 Withdraw late-bucket choice; separate live freshness from sync repair

Record: S3-LATE-BUCKET-CORRECTION-002 / S3-TIMESTAMP-ALIGNMENT-001.
Date: 2026-10-18 (Europe/Berlin). Checkpoint: CP-0056.
Active technical leaf S3.4a.3. No new A/B question pending.

**Maintainer correction / DEC-061.** Neither Q-S3-LATE-BUCKET-01 A nor B is
accepted. The intended invariant is explicit, public wallet-created T_0
(`created_at_ms`), bound by `layer2_signature`, distinct from the voucher's
`encrypted_timestamp`. Wallet/gateway retries and gateway failover preserve that
signed creation-time payload. Live LockVerify uses the 30s freshness limit and
rejects stale requests with FLAG_UNAUTHORIZED. Completed five-minute windows
seal 30s after window end. Offline/new replicas recover historical locks via
ShardBucketRangeRequest and ActiveSyncRequest(target_bucket), verify the quorum
reference and records, and recompute the pure deterministic bucket digest.
No additional correction log, snapshot-version subsystem or A/B choice is needed
merely because a replica learns an old accepted lock by sync. "Stateless" here
means digest metadata is derived from retained locks, not that the registry has
no live collision state.

**Agent correction.** The previous example explicitly involved a lock already
accepted elsewhere and later arriving at a recovering peer; it did not establish
new post-seal live acceptance. Conflating those paths and presenting extra state
structures as necessary was an error. Direct state reconstruction can repair an
incomplete replica. Withdraw the question rather than map this answer to A or B.
Preserve its exact historical options and the remaining independent evidence
limits; do not silently promote implementation or universal immutability claims.
DEC-059's fixed snapshot/current open tail and DEC-060's exact-payload retries
remain selected as qualified by this clarification.

**Conditional timing argument.** Let window width D=300,000ms, grace/freshness
W=30,000ms, bucket end E=(b+1)D, and wallet T_0 in [bD,E).
If the live acceptance clock check uses that same T_0 and admits only
`abs(t-T_0)<=W`, then t<=T_0+W<E+W, whereas sealing starts at t>=E+W.
Thus that live check cannot pass at/after sealing on the same time basis.
The example T_0=12:04:59 passes freshness at most through12:05:29 and the window
seals at12:05:30. Equality at exactly30s is permitted by the observed `>` rejection
check, but does not change the strict bucket-end inequality. This proves the
stated single-time-basis live-admission property; it does not prove delivery,
source-state survival or globally identical replica clocks.

**Targeted local code evidence: intended invariant is not implemented end-to-end.**
- `api/hmc.rs::L2LockRequest` (line107) and `L2LockEntry` have encrypted_timestamp,
  but no separate public created_at_ms. `calculate_l2_payload_hash_raw` (line285)
  includes encrypted_timestamp, not a separate wallet creation-time field. The
  inspected local HMC DTO/verifier therefore does not establish the claimed public
  field and its layer2_signature binding. This is not a finding about an uninspected
  wallet implementation or another checkout.
- `network/transport.rs` line490 obtains `wire_payload.timestamp_ms()`;
  lines541–548 enforce the30s bound and FLAG_UNAUTHORIZED. This is the P2P envelope
  timestamp, authenticated under the node sender identity/envelope signature.
  `api/routes.rs` lines2025–2038 builds the HMC envelope with `timestamp_ms: now_ms`
  and the gateway's sender signature. A retry of that serialized envelope preserves
  its bytes, but a new gateway envelope is not thereby bound to wallet T_0.
- `network/transport.rs` lines1295 and1361 currently cast
  `entry.encrypted_timestamp as u64` for HMC bucket projection/filtering. That is
  explicitly the wrong semantic field under the maintainer's clarification.
- `types.rs::is_bucket_sealed` implements the time threshold, while
  `crypto.rs::compute_shard_bucket_digest` derives the digest from supplied records.
  These helpers require correct time mapping and state inputs; their existence
  alone does not verify the end-to-end invariant. No production change or test run
  in this continuation.

**Remaining technical obligations, not new product choices.** Use one canonical
wallet creation field in request, client signature, stored lock, live freshness,
bucket selection and sync export/import, retaining distinct node envelope time
where needed. Unknown/default time and encrypted bytes must not silently replace
it; exact versioned format and shared-library integration remain K2/C1 work.
Gate evaluation and durable acceptance/approval can be separated by asynchronous
work: specify rechecks or a justified drain boundary so pre-seal admitted work
cannot mutate an allegedly finalized reference after sealing. Bound inter-peer
clock uncertainty rather than infer a shared physical instant from local median
clocks. Preserve trusted protocol time, not unsanitized OS time.

Sealing closes fresh admissions; learning historical records by sync still changes
an incomplete replica until convergence. Root expiry/pruning changes retained data,
and DEC-053 canonical merge can change branch usability. Define digest projection
and common comparison scope/cutoff for these cases without inventing a version or
correction subsystem. A recovered same digest is equality to its reference, not
proof that a permanently lost earlier lock never existed. DEC-057/058's source
coverage and independent lost-own-choice gate remain open. The user correction
settles the desired architecture, not those implementation/proof obligations.

**Validation to add later.** Actual QUIC cases must bind wallet creation time
separately from gateway envelope time; reject a wallet-stale request behind a fresh
gateway envelope; preserve time/signature across gateway failover; prove encrypted
voucher timestamp does not select a bucket; test exact30s/end+30s boundaries,
commit delay crossing seal, clock skew, fresh-path rejection versus historical
sync acceptance, expiry and partition merge. No extra durable logs/versions are
assumed as an acceptance criterion. Keep resource/retention bounds and full live
root (>24h) coverage from earlier obligations. These are planned tests only.

Next action: retain the withdrawn A/B choice, finish S3.4a.3's end-to-end timestamp
and acceptance/seal contract, then return to full-root/source recovery coverage.
Ask a new A/B only for an actual remaining design tradeoff; correction handling
itself does not require inventing another preference question. Only interview
memory edited; no production/spec changes, commits or new test execution.

### CP-0056 — Accept live/sync correction and record timestamp integration gaps

Recorded DEC-061 from explicit maintainer direction: public wallet-bound T_0,
stale live rejection, historical bucket sync and direct deterministic digest
recomputation; neither extra corrections nor snapshot versions selected.
Withdrew Q-S3-LATE-BUCKET-01 and preserved its historical wording. Corrected the
live-versus-sync conflation, recorded the conditional time inequality and actual
local DTO/envelope/encrypted-time mismatches. DEC-001–060 remain qualified rather
than erased. S3.4a.3 is the sole active technical focus; no human choice pending.
Code alignment, clock/commit/expiry/merge composition and source coverage remain
unproved/unimplemented here. This is no claim of universal bucket immutability.

Completed checkpoint: **CP-0056**.


### 7.68 Fresh admission versus delayed durable completion

Current-status correction (CP-0058): DEC-062 / §7.69 withdraws this question.
RAM-first attestation replaces the earlier DEC-029/033 commit-before-response
premise. The original question remains historical; neither option was selected.

Record: S3-FRESH-COMMIT-QUESTION-001. Date: 2026-10-18 (Europe/Berlin).
Checkpoint: CP-0057. Active leaf: S3.4a.4; parent S3.4a recovery/sealing.
Maintainer asks to continue. This authorizes continuing the interview, not new
production changes or tests. DEC-001–061 and the withdrawn late-sync A/B remain.

**Reconcile concurrent work first.** The current worktree contains other-chat edits
to HMC DTO/signature, HTTP/P2P paths, storage and tests. Inspect only the relevant
parts and preserve every edit. `created_at_ms` now exists in `api/hmc.rs` request
and entry types and is included by the current payload hash. Bucket projections
prefer this field, retaining encrypted_timestamp fallbacks. The previous blanket
"field absent" finding in §7.67 is superseded by these observations, not by a
claim of a completed end-to-end fix. At this read, verifiers still accept zero-time
or legacy hash alternatives, and HTTP may fill missing creation time with now.
The transport still checks the sender-envelope timestamp and fills zero entry
creation time. These are remaining alignment/audit obligations under DEC-061,
not reasons to ask whether a wallet timestamp should be signed again. Source is
actively changing; these are dated static observations, no tests executed here.

**Why the next choice is distinct.** DEC-061 settles timestamp authority and stale
new-request rejection. DEC-029/033 require durable own-choice storage before vote
release. P0 §4.1 rechecks view/root validity after commit, but neither that rule
nor a freshness check at request entry states whether wallet T_0 must still be
within30s when the first binding approval is emitted. This is a real completion-
semantics tradeoff, not a repeat of historical sync repair or a demand for extra
correction/version structures. A fresh queued request is not yet a successful
payment. Frozen membership,800ms collection and normal expiry still apply.

Example on one trusted time basis: T_0=12:04:59; the request passes entry freshness
at12:05:28; durable commit returns at12:05:31. Nominal bucket sealing is12:05:30.
The gate at entry passed, but its result says nothing about elapsed queue/commit
time. This example does not involve an old live packet accepted at12:06; it is
work admitted while fresh whose durable completion crosses the boundary.

**Exact pending question — Q-S3-FRESH-COMMIT-01 (unanswered):**

> Ein Lock trifft innerhalb der30s-Frist ein, aber seine dauerhafte Speicherung
> wird erst danach fertig. Darf der Knoten dann noch eine neue Bestätigung signieren?
>
> **A — Nein: Frische auch unmittelbar vor der Signaturfreigabe prüfen
> (Empfehlung):** Ist T_0 dann älter als30s, gibt es keine neue Bestätigung.
> Bereits dauerhaft gespeicherte eigene Signierentscheidungen bleiben erhalten;
> der Vorgang darf nicht als ungeschehen gelten. Unter Verzögerungen können dadurch
> weniger Zahlungen rechtzeitig ein Quorum erreichen.
>
> **B — Ja: Die Frist gilt für den Eingang:** Ein rechtzeitig aufgenommener
> Vorgang darf nach erfolgreichem Commit noch bestätigt werden. Dafür gilt ein
> betroffener Bucket erst als wirklich versiegelt, wenn seine bereits aufgenommenen
> Schreibvorgänge abgeschlossen sind. Das toleriert Commit-Verzögerungen, lockert
> aber die feste Versiegelung nach Fensterende+30s.

A is recommended to preserve the intended strict temporal cutoff and avoid a
new pending-drain exception to fixed sealing. It defines a required behavior,
not a promise that a disk commit can be cancelled at an exact instant. If selected,
derive how late committed effects enter the collision index/digest versus immutable
own-choice protection; do not silently discard a durable choice or claim digest
immutability follows only from refusing a vote. Existing already-issued evidence
served later is not a new approval. Same intent retries never reset T_0.

B is a meaningful alternative only with an explicit conditional-sealing rule:
no blanket timer-only seal while relevant admitted work remains unfinished.
It does not permit new stale incoming requests, storage failure voting, expired
root approval, a longer gateway checkout budget or lower-rank replacement. The
local drain/source-quorum interaction and bounded waiting would require design;
there is no network-wide in-flight registry or old-quorum baton implied. B would
refine the nominal sealing completion rule, not undo the initial freshness gate.

Both retain original wallet binding, separate historical sync, durable-before-
approval, own-choice immutability and accepted regional merge semantics. Clock
uncertainty and concurrent source coverage remain technical premises, not solved
by the choice. No separate version/correction subsystem is proposed. No source
count, buffer sizing or implementation/library is selected here.

Next: ask the exact A/B, await answer, derive the selected completion/seal rule,
then return to S3.4a.3 alignment and full-live-root/source coverage. Production
and test edits from the other chat are untouched; only interview memory changed.

### CP-0057 — Ask about freshness at delayed durable completion

Re-read CP-0056 and concurrent implementation changes. Updated the evidence status:
public creation-time fields/hashing are now present, while legacy/zero/envelope
composition still needs verification. No stale "field absent" claim is current.
Recorded new Q-S3-FRESH-COMMIT-01: A = no first approval after wallet freshness
expires; B = entry-only freshness with seal delayed until admitted writes drain.
A is recommended, neither selected. Existing live/sync correction and rejected
extra structures remain settled. S3.4a.4 is the sole active decision leaf within
the same recovery problem. No production changes or test runs in this turn.

Completed checkpoint: **CP-0057**.


### 7.69 RAM-first attestation restored; durability ordering superseded

Record: O1-RAM-ACK-DIRECTIVE-001 / S3-FRESH-COMMIT-CORRECTION-002.
Date: 2026-10-18 (Europe/Berlin). Checkpoint: CP-0058.
Active technical leaf O1.1: volatile issued-choice loss versus recovery readiness.

**Maintainer directive / DEC-062.** The maintainer rejects Q-S3-FRESH-COMMIT-01's
premise: signed wallet T_0 alone fixes `floor(T_0/300000)`, while arrival/network
time is only the ingress freshness check. With <=30s drift, reserve capacity and
accept via in-memory collision check, then attest/respond within the <5ms SLA.
Do not await redb/fsync; persistence is fully asynchronous background work. No
post-admission freshness recheck or variable sealing grace is requested. The
bucket digest's caller gathers RAM and disk records, so a RAM-accepted lock need
not wait for flush to appear in the computed state. Retain nominal bucket-end+30s
seal and direct historical sync. Neither A nor B of the withdrawn question is
selected; entry-only freshness alone must not be mislabeled B, which also proposed
a delayed seal and commit-before-response completion.

**Reconcile prior selections explicitly.** DEC-029 previously selected waiting
for the bounded asynchronous worker's durable acknowledgment before vote release;
DEC-033 repeated this order. That did not require synchronous disk I/O inside the
request handler. The agent should have exposed this recorded policy conflict
before presenting another choice. The latest explicit direction now supersedes
that response ordering and the removal of the local <5ms SLA. DEC-033's existing-
redb immutable-choice layout is retained as a direction, not automatically deleted.
DEC-034 bounded shutdown/drain remains selected, with its prior guarantee that
all acknowledged choices are durable superseded. No change to binding specs,
production or other-chat code is made by this memory update.

**What stays selected.** Queue reservation before RAM mutation, bounded worker
capacity and refusal on unavailable capacity; immutable per-identity own choices;
no synchronous disk I/O or RAM lock across fsync; fixed<=20/14 checkout and800ms
collection; trusted time and authenticated root expiry; FLAG_NOT_READY after
restart/loss until justified recovery. DEC-032's same-key lost-choice gate is not
silently waived. Code/model proof must now explain these together with volatile
approvals; it cannot keep assuming durability-before-vote. The required latency
is a target/invariant to verify, not a measured or universal worst-case result.

**Current code check (read-only).** `storage/engine.rs::
ingress_hmc_lock_with_metadata` reserves an MPSC permit, takes the HMC RAM write
guard, performs insert/check, then sends FlushOp::PutHmcLock without awaiting a
commit acknowledgment. `transport.rs` calls this path and constructs an attestation
on acceptance. This observed order matches RAM-before-flush; it is not proof of
an atomic <1µs end-to-end path. The HMC path uses an awaited RAM write guard, and
quota/signature/fraud processing separates the early envelope freshness check from
mutation. Transport digest handlers gather retained disk and RAM entries and pass
the union/projection to pure hash helpers; the pure compute function itself does
not read the database. No benchmark, full code audit or test run here. Concurrent
other-chat DTO/time/test changes are preserved, not attributed to this interview.

**Sealing proof boundary.** Bucket membership was never chosen by arrival time
in §7.68's example; the actual issue was the now-superseded durability wait. Under
current semantics durable flush completion cannot delay a correctly inserted RAM
lock's digest visibility. Keep that correction. However, the timing inequality
in §7.67 bounds the instant at which freshness is checked. To lift it to actual
RAM insertion requires a bound/atomic relationship for the interval between that
check and insertion, and compatible source clocks. A <1µs CAS duration does not
bound scheduler suspension, an awaited guard, or verification before CAS. With
integer-ms T_0 in [bD,E), the latest passing check can occur at E+30000-1ms;
a later suspension could cross the seal. This is an unverified timing obligation,
not an observed failing test or a requirement for extra correction/version state.
No new post-signature freshness rule is selected. Nominal seal plus conditional
single-time-basis inequality must not be reported as a physical worst-case proof.

**Crash witness / next prerequisite.** An honest node emits approval A while the
choice/lock exists only in RAM/the flush queue; the requester keeps the genuine
signature. Crash/power loss before commit erases that local choice. Peer sync can
restore only evidence peers possess; an individual approval need not have reached
other peers or a payment quorum. Therefore matching visible lock digests alone
does not recover this node's own hidden A decision. If it later approves conflicting
B under the same key, two genuine incompatible signatures exist. The already
selected DEC-032 gate must prevent unjustified same-key resumption; RAM-first
approval increases the scope of possible unknown history after unclean restart.
This is a logical failure schedule, not an executed test or proof that current
startup bypasses every gate. Do not infer that an honest restart deserves a ban,
or silently select new identities, extra journals, deposits or hardware services.

The restored RAM policy can coexist with the safety gate by leaving uncertain
scope passive; availability of a safe automatic same-key recovery mechanism is
still unestablished. Ordinary shard recovery and complete personal vote-history
recovery remain different obligations. P0 draft0.2 §4.1/model prior crash tests
assume durable-before-vote and do not verify this new schedule. Retargeting them
requires explicit implementation/model work and real adversarial QUIC/crash tests,
not changing expected results to green or treating prior scenarios as a proof.

**Scope/status.** Requirement: RAM-first/entry-only selected. Previous question:
withdrawn. Design: crash/recovery and strict seal timing unresolved. Delivery:
interview memory only. No new human question is needed to reconfirm the directive
or the unchanged loss gate. Active focus switches from S3.4a.4 to prerequisite
O1.1 because safe recovery/signing under the new response ordering depends on it;
return to S3.4a.3 timing and full-root/source coverage after this composition.

Next action: derive a minimal explicit volatile-choice/restart model and determine
what evidence could justify same-key recovery under DEC-032 without reverting to
commit-before-response. Ask A/B only for an actual unselected tradeoff; do not
re-ask RAM-first attestation, a post-gate freshness check or a variable seal.

### CP-0058 — Restore RAM-first acknowledgments and expose the durability reversal

Recorded DEC-062 from explicit maintainer instruction, superseding DEC-029 and
pre-response durability clauses of DEC-033/034 while retaining the layout/drain
and loss-gate directions. Withdrew Q-S3-FRESH-COMMIT-01 without assigning A/B.
Corrected synchronous-handler-I/O versus async-worker-ack distinction and kept
wallet-time bucket identity unchanged. Inspected RAM enqueue/attestation/digest
paths without editing them. Saved gate-to-insertion proof limits and a volatile
own-choice crash witness. O1.1 is the single active prerequisite; no human question
pending. P0's durable-vote model evidence remains historical, not validation of
the new crash model. Only interview memory edited; no tests/benchmarks executed.

Completed checkpoint: **CP-0058**.


### 7.70 Remaining interview work and same-key crash-resume policy review

Record: O1-CRASH-RESUME-QUESTION-001. Date: 2026-10-18 (Europe/Berlin).
Checkpoint: CP-0059. Active leaf O1.1; Q-O1-CRASH-RESUME-01.
Maintainer asks to continue and asks whether many questions remain.

**Progress answer.** The current inventory has OPEN-01–14 unresolved engineering/
coverage packages; OPEN-15 naming/alignment is complete. These are not fourteen
questions for the maintainer and not an exhaustive coverage guarantee (F1 still
needs actual mapping). Many package entries are technical verification or already
selected policy awaiting implementation. The62 decision IDs also include clarified,
qualified and superseded choices; they are not a completion percentage or62
remaining questions. No justified fixed count of future human questions exists.
State that candidly and avoid an arbitrary "only a few left" estimate. Technical
work remains autonomous; WF-004 means A/B for substantive questions, not invented
preferences for every code/proof detail.

**Why this policy review is justified now.** DEC-032 previously selected same-key
withholding when relevant own signing choices are lost, even after ordinary shard
sync. It remains the default. DEC-062 newly permits issuance before durable commit,
so an ordinary unclean crash can create the previously exceptional history-loss
condition. That materially changes the operating consequences of the earlier
durability-based design. This question makes a possible relaxation explicit;
it does not pretend the previous loss gate was unanswered, ask to reapprove
RAM-first response or infer a relaxation from "continue". A retains DEC-032;
B would reopen its protection deliberately. The actual safe recovery algorithm
remains technical work under either answer, not a threshold for the human to guess.

**Evidence and limit.** §7.69 already establishes the minimal witness: a node's
valid A approval is held by its requester, a crash erases local A before flush,
and replicas need not possess that individual vote. Quorum equality of shared
lock state does not, without further proof, reconstruct private prior signing
choices. Genuine later B under the same identity can conflict with A. No new
experiment or assumption that this necessarily yields two complete certificates
is needed. Do not claim that successful quorum sync is useless for shared-state
repair; it establishes a different property from complete own-vote recovery.
The present bounded source search found no demonstrated own-choice rollback/
unclean-loss recovery in the inspected node paths; absence of a search result is
not a full repository audit or proof of no possible solution. No tests run here.

**Exact pending question — Q-O1-CRASH-RESUME-01 (unanswered):**

> Soll nach einem Absturz der normale Quorum-Sync bereits zur erneuten
> Signierfreigabe unter derselben Identität reichen, wenn dabei möglicherweise
> vor dem Flush abgegebene eigene Stimmen nicht rekonstruierbar sind?
>
> **A — Nein, die bestehende Sicherheitssperre beibehalten (Empfehlung):**
> Solange die Sicherheit der eigenen Signierhistorie nicht begründet ist,
> bleibt der betroffene Bereich auf FLAG_NOT_READY — auch nach erfolgreichem
> Shard-Sync. Das schützt die bisherige Regel gegen widersprüchliche eigene
> Stimmen, kann den Wiederanlauf aber länger oder unbestimmt blockieren.
>
> **B — Ja, Quorum-Sync als ausreichende Wiederanlaufbedingung zulassen:**
> Danach darf dieselbe Identität wieder signieren. Das ermöglicht den
> automatischen Wiederanlauf trotz ungeklärter eigener Einzelstimmen,
> akzeptiert aber das zusätzliche Risiko widersprüchlicher eigener Signaturen
> nach einem Absturz. Das würde die bisherige DEC-032-Garantie lockern.

**Recommendation and scope.** Recommend A because DEC-057 explicitly prioritizes
collision protection over availability and DEC-032 remains selected. This is a
review caused by the newly changed response-order requirement, not a request
for ritual confirmation without new context. Retaining A is not an implemented
history-recovery solution or a guarantee of available automatic restart. B is a
conscious weaker operating guarantee, not mathematically equivalent protection;
code that merely synchronizes the visible shard state does not erase the witness.
If B is selected, fraud/receipt/identity semantics and admissible crash-fault scope
would require explicit further reconciliation; no automatic crash exemption from
first-party evidence rules is approved here. No fresh-key shortcut, fsync on the
checkout path, extra receipt chain or change to fixed committee/maturity follows
from either option. If unchanged guarantees cannot yet be justified, keep the
safety gate rather than claiming the proof exists.

Next: ask the recorded A/B and await answer. Then derive the retained/changed
recovery contract, and distinguish its open proof from selected policy and delivery.
Only interview memory changed. No production/spec edit, model/test campaign or
external research needed for this risk presentation. Prior decisions and withdrawn
questions retained with their exact meanings.

### CP-0059 — Explain remaining work and review crash-resume consequences of RAM-first

Recorded inventory-based progress without inventing a remaining question count.
Saved Q-O1-CRASH-RESUME-01 in O1.1: A = retain DEC-032 same-key loss gate despite
successful ordinary shard sync; B = explicitly relax it and accept additional
volatile-vote-loss risk. The earlier gate remains current until an explicit change;
no answer inferred from the request to continue. The review is triggered by new
DEC-062 response ordering, not an erased prior decision. Technical recovery proof
and actual wire/crash verification remain pending. No production changes/tests.

Completed checkpoint: **CP-0059**.


### 7.71 Loss gate reaffirmed; bucket-quarantine proof and mixed-mode merge

Record: O1-CRASH-RESUME-DECISION-002 / S5-MIXED-SUPPORT-QUESTION-001.
Date: 2026-10-18 (Europe/Berlin). Checkpoint: CP-0060.
User-directed active decision: S5.1. O1.1 remains a technical proof dependency.

**Answer / DEC-063.** The maintainer unequivocally selects Q-O1-CRASH-RESUME-01 A:
DEC-032 remains unrestricted; B's knowingly weaker protection against own conflicting
signatures is categorically excluded. They emphasize permanent identity/ticket/WoT
consequences from verified equivocation and distinguish ordinary quorum-state sync
from recovery of a volatile individual choice. No further question about weakening
this gate is warranted without genuinely new maintainer steering.

**Bounded-quarantine proposal, faithfully retained.** The maintainer proposes that
an earlier14/20 lock is recovered by ordinary shard sync; an isolated choice is
bound to T_0 in a5-minute window, and after sealing at window-end+30s no colliding
new attempt for that interval is admitted. They intend a short deterministic
bucket-level quarantine rather than indefinite shutdown. Record the intended
bounded-recovery goal and proposed argument; do not label it an implemented or
proved activation predicate. Quorum recovery requires actual surviving/retrievable
evidence and justified source coverage (DEC-057/058);14 signatures alone do not
materialize a permanently missing data copy.

**Narrow technical finding.** Expiry of live admission for an exact old T_0 does
not imply expiry of the consumed-output collision slot. P0 §2 defines ApprovalSlot
as(network,root,consumed_output), independent of time bucket/view. In
`p0/evidence.rs::verify_node_equivocation`, same node and slot with different
spend IDs establishes the modeled proof after verifying both signatures; there
is no bucket-expiry exemption. `storage/engine.rs::HmcRamIndex::insert_or_check`
checks the existing lookup_tag and divergent t_id for client ingress, without
resetting that collision key in a later bucket.

Witness with a live root: node K emits isolated approval A at12:04:59 and loses
its unflushed choice in a crash. After the old bucket seals, a malicious authorized
owner creates a *different* spend B of the same output with fresh signed
T_0=12:10:00. This is not a retry or a gateway rewrite. B's freshness can pass and
its bucket differs, while its ApprovalSlot remains the same. If K has forgotten A
and approves B, a requester holding A has two incompatible node signatures.
The existing loss gate must prevent that outcome. The witness does not prove
that an indefinite block is unavoidable or that two complete payment receipts
exist; it shows the proposed time-window argument alone is insufficient for the
selected individual-choice guarantee. No new wire test executed. Keep the gate
closed where safety is unproved; do not silently change slot/fraud semantics.
Technical follow-up must derive a safe bounded recovery method under RAM-first
response, rather than have the maintainer vote on whether the counterexample is
true. No extra journal, key rotation or commit wait is selected here.

**Switch / return point.** The maintainer explicitly requests the next question.
The safety choice is now settled; the remaining O1.1 issue is technical proof,
not another preference to elicit. Park that proof until a concrete recovery model
can establish the activation rule; it remains a mandatory readiness/final-plan
gate, with unsafe scope passive meanwhile. User steering moves to independent
S5.1, where an actual product-policy choice remains. Resume O1.1 before claiming
safe bounded restart or delivery, and on any proposed activation-rule change.

**Existing solution first.** P0 draft0.2 §5.1 proposes support classes:
Regional14=2, valid adaptive PROVISIONAL=1, owner-valid hints/partial votes=0.
Highest admitted support class wins; within a class use min(H_canon). Its own
text calls this a policy choice; §7.58 preserves its candidate status. Model T09
exercises it, but passing a proposed predicate does not constitute maintainer
selection. DEC-053 allows regional revocation; DEC-022 disallows unsupported
single-node takeover; DEC-023 permits a genuinely unresolved affected branch.
No arbitrary raw hash, source-count shortcut or new global green proof is allowed.

**Exact pending question — Q-S5-MIXED-SUPPORT-01 (unanswered):**

> Beim Zusammenführen zweier Netzteile liegen für dieselbe Vorgängerausgabe
> zwei widersprüchliche, jeweils gültige Belege vor: einer mit14/20 regionalen
> Stimmen, einer mit dem regulären PROVISIONAL-Quorum eines kleinen Netzteils.
> Wie soll dieser Konflikt behandelt werden?
>
> **A — Der14/20-Beleg hat Vorrang (Empfehlung):** Der nur PROVISIONAL bestätigte
> Zweig verliert, auch wenn sein H_canon kleiner ist. Zwischen Belegen derselben
> Klasse entscheidet weiterhin min(H_canon). Das folgt dem bisherigen P0-Entwurf
> und schützt eine14/20-Bestätigung vor Verdrängung durch schwächere Unterstützung.
>
> **B — Den betroffenen Konflikt vorerst offenhalten:** Unterschiedliche
> Bestätigungsklassen entscheiden den Gewinner nicht automatisch. Die betroffene
> Ausgabe und abhängige Zweige bleiben blockiert, bis vergleichbare gültige
> Belege eine Entscheidung erlauben. Das vermeidet den automatischen Vorrang,
> kann den betroffenen Gutschein aber dauerhaft unbenutzbar machen.

Both candidates must first pass owner/causal/root validity and independently
justified membership/quorum checks. A single unsupported vote cannot qualify as
PROVISIONAL merely by labeling itself so; genuine admitted sub20 operation still
uses its specified adaptive quorum. A selects evidence priority, not a theorem
of global honesty. B is a conservative conflict-blocking policy, not permission
for a weak candidate to take over or a new old-quorum authorization requirement.
It introduces a blocking/DoS surface from genuine weak conflicting receipts;
limits and evidence admission still apply. Obtaining comparable receipts may be
impossible because prior signing choices remain immutable. The already accepted
risk of losing branch descendants persists under A; B accepts affected-branch
unavailability. Independent roots and unaffected siblings continue in either case.
No automatic ban of honest regional losers; fraud remains personally verified.

Next: ask Q-S5-MIXED-SUPPORT-01 A/B and await answer. Keep O1.1 proof gap explicit,
then consolidate selected merge order with receipt promotion and descendants.
Only interview memory changed; no production/spec edits, test campaign or broad
trust research. No promise of a fixed remaining question count.

### CP-0060 — Retain DEC-032 and ask about mixed-mode merge priority

Recorded DEC-063 / Q-O1-CRASH-RESUME-01 A; no weaker own-signature guarantee.
Preserved the finite bucket-quarantine proposal without claiming its proof:
a fresh new conflicting spend can target the same output in a later bucket.
O1.1 remains a required technical proof/readiness gate; user steering moves the
single active decision to S5.1. Saved Q-S5-MIXED-SUPPORT-01: A = Regional14
priority over PROVISIONAL, min-hash within class; B = leave affected mixed-class
conflict blocked until comparable evidence. Neither selected. Existing P0/model
policy evidence is retained as a candidate, not retroactive maintainer assent.
No production changes or tests executed in this continuation.

Completed checkpoint: **CP-0060**.


### 7.72 Class priority selected; retention after VOID remains open

Record: S5-MIXED-SUPPORT-DECISION-002 / S5-VOID-RETENTION-QUESTION-001.
Date: 2026-10-18 (Europe/Berlin). Checkpoint: CP-0061.
Active decision S5.2; S5.1 policy decided with implementation/proof obligations.

**Answer / DEC-064.** The maintainer unequivocally selects
Q-S5-MIXED-SUPPORT-01 A and adopts the explicit hierarchy: class2 FINAL14/20,
class1 valid adaptive PROVISIONAL for N<20, class0 subquorums/unconfirmed intents.
Higher class defeats lower class; use min(H_canon) only among equal highest
admitted confirmation classes. Mixed-class blocking B is rejected because a weak
colliding receipt could otherwise freeze a fully supported payment. This removes
that particular freeze-by-weaker-receipt policy, not every computational/storage
DoS risk. Receipt validity, independently justified identities/membership and
cheap-first resource defenses remain prerequisites.

Class0 must not acquire confirmed usability merely because it has the lowest
hash when no complete quorum exists. It remains a hint/pending submission;
unsupported singleton takeover is still prohibited. This qualification preserves
DEC-022/023 and P0 §5.1 rather than inventing class0 merchant confirmation. A valid
larger-class evidence must actually exist; relabeling a receipt or combining votes
from different snapshots cannot promote it.

The losing transaction's causal branch becomes VOID consistently with the chosen
winner; unrelated roots/siblings survive. Honest nodes that signed only their
local branch committed no personal equivocation and suffer no identity/ticket/WoT
sanction from loss alone. OwnChoice remains protected; a node which approved the
loser may report the winner without issuing a second conflicting approval for
the same consumed output. Exact derived-state/atomic publication and support
promotion remain integration work, not a claim of an existing atomic wire path.

**Status terminology and guarantee boundary.** The maintainer calls class2
FINAL/green, consistent with the existing spec label, and emphasizes protection
against weaker provisional receipts. They explicitly retain FINAL-vs-FINAL
min-hash selection, so this is not selection of global irreversibility or reversal
of DEC-053. P0's REGIONAL14 label and separate reserved FINAL_GLOBAL status still
need deliberate presentation/spec consolidation; no separate global proof is
silently approved or new naming preference question opened. The accepted guarantee
here is evidence-class priority under the stated BFT/membership assumptions.

**Existing retention solution and unresolved scope.** P0 §5.2/5.3 separates derived
VOID from original evidence and immutable own choices, requires minimum sufficient
winning/excluding proof while the root is usable, and assigns portable ancestry/
receipts to clients. VOID is not an expired-lock tombstone; genuine later support
promotion may change a prior class1 outcome. These are why deleting every record
associated with a loser is not automatically safe. Conversely, the blind server
need not automatically mirror every full client branch. DEC-033 protects own
choices, not an unbounded archive of all foreign losing payloads. No earlier
maintainer choice between the two concrete full-payload retention policies below
was found in the current register. Keep the minimum live exclusion requirement
and TTL+30s rule mandatory under either option.

**Exact pending question — Q-S5-VOID-RETENTION-01 (unanswered):**

> Welche Daten eines unterlegenen VOID-Zweigs soll der Node bis zum Ablauf
> der Gutschein-Wurzel weiter aufbewahren?
>
> **A — Nur die notwendigen Sperr- und Beweisdatensätze (Empfehlung):**
> Der Node behält den gültigen Gewinner, die zur sicheren Ablehnung des
> unterlegenen Zweigs nötigen Nachweise und seine eigenen Signierentscheidungen.
> Vollständige darüber hinausgehende Verlierer-Zweige bleiben beim Client.
> Das spart Speicher; bei späterem zusätzlichem Beweisbedarf müssen die Daten
> erneut vom Client oder von Peers verfügbar sein.
>
> **B — Auch vollständige gültige Verlierer-Zweige aufbewahren:**
> Der Node hält zusätzlich deren Lock- und Quorum-Nachweise bis zur Wurzel-TTL
> vor. Das erleichtert spätere Reparatur und Neubewertung ohne aktive Clients,
> benötigt aber mehr Speicher und strengere Aufnahme-/Kapazitätsgrenzen.

Recommend A as the P0 minimum-sufficient-evidence direction aligned with client
custody/KISS. This does not prove which exact minimal record set is sufficient.
It may not evict a live exclusion or own-choice evidence just to meet a cache size;
proof missing for a required decision means UNKNOWN/NOT_READY, not blind approval.
B retains only admitted, unexpired evidence within explicitly bounded resources,
not dead history or every attacker hint. At capacity, refuse/suspend safe admission
rather than delete protected exclusions; it cannot promise unlimited archival
service. Neither option guarantees recovery if all relevant copies disappear.

Both preserve TTL expiry+30s physical purge, existing fraud/identity records under
their applicable rules, no permanent expired-lock tombstones, no lock gossip and
no recursive client L2 receipt chain on ordinary spend. Client retrieval in A
means fetching specifically needed conflict/repair evidence, not forcing wallets
to verify all historical L2 receipts on each payment. Under B, automatic repair
still needs the separate readiness/source-context proof; retaining data alone is
not that proof. Later class1->class2 promotion requires an actual valid new receipt,
not an in-place status edit. Track descendant and promotion counterexamples when
deriving the selected retention set.

Next: ask Q-S5-VOID-RETENTION-01 A/B; derive exact retention/pruning and sync proof
composition after the answer. Preserve O1.1's bounded-recovery proof and other
parked obligations. No production/spec edits or new tests in this continuation.

### CP-0061 — Select strict class hierarchy and ask about losing-branch retention

Recorded DEC-064 / Q-S5-MIXED-SUPPORT-01 A and rejection of weak-receipt freezing.
Kept verified class priority distinct from an irreversible global-finality claim;
class0 does not establish confirmed acceptance. Honest losing signers remain
unsanctioned. Active focus moves to S5.2 / Q-S5-VOID-RETENTION-01: A = minimum
sufficient node exclusions/own choices plus client custody of excess full losing
branches; B = additionally retain full admitted unexpired losing branches.
Neither selected. TTL, bounded resources and no-extra-receipt-chain constraints
remain. Notes/spec candidate retention checked; no production or test changes.

Completed checkpoint: **CP-0061**.


### 7.73 Minimal retention selected; conflict-response payload open

Record: S5-VOID-RETENTION-DECISION-001 / C1-CONFLICT-RESPONSE-QUESTION-001.
Date: 2026-10-18 (Europe/Berlin). Checkpoint: CP-0062.

**Answer / DEC-065.** The maintainer unequivocally selects
Q-S5-VOID-RETENTION-01 A. Retain the winner that occupies the parent/output
collision slot, the minimum sufficient collision/exclusion evidence and the
node's own immutable signing decisions until the applicable root expiry.
Wallets custody the excess complete losing branches and their causal proofs;
L2 is a blind Collision Lock Registry, not an archive of dead losing trees.
Reject B's additional full losing-tree retention as unnecessary state bloat.
Physically purge root-bound state at root.valid_until+30s. This does not remove
separately governed permanent identity sanctions or add expired-lock tombstones.

The maintainer proposes a compact winner-vs-loser hash record for immediate
409 rejection. Record this as the selected compact direction, not a completed
proof format: hashes identify payloads but independent verification must also
bind the consumed slot, authenticated records and the claimed support class.
Derive exact sufficient retained data autonomously; do not ask the maintainer
to select cryptographic correctness. Preserve own choices even after a different
canonical winner is learned. Check descendant exclusion, later genuine support
promotion and recovery from compact records; missing required proof cannot
justify approving a collision. These are technical obligations, not reopened
preferences or a requirement to retain every losing subtree.

**Next bounded interface tradeoff.** Retention policy does not determine what
is included in the initial HTTP conflict response. Read-only inspection found
`L2Verdict::Conflict { existing_lock: L2LockEntry }` in
`crates/humoco-node/src/api/hmc.rs`; Spec06 section 5 describes a 409 collision
response, and its sequence uses ExistingLockHash. Neither establishes a selected
portable, class-qualified compact proof envelope. Existing response data is not
independent evidence of a confirmed canonical winner. OPEN-06 already tracks
output/wire details. Move the active human decision to C1.1; S5.2's selected
policy remains decided with the proof/engineering obligations above.

**Exact pending question — Q-C1-CONFLICT-RESPONSE-01 (unanswered):**

> Was soll die Wallet bei einem Konflikt direkt mit `409 Conflict` erhalten?
>
> **A — Kompakten Nachweis direkt mitliefern (Empfehlung):**
> Die Antwort enthält die betroffenen Lock-IDs und den bereits vorhandenen,
> signierten Kollisionsnachweis einschließlich seines Bestätigungsstatus.
> So kann die Wallet den Konflikt ohne zusätzliche Abfrage prüfen.
> Es werden dafür keine vollständigen Verlierer-Bäume übertragen und keine
> zusätzlichen Nachweise im Kassenpfad nachgeladen.
>
> **B — Nur Konfliktkennungen, Nachweis bei Bedarf abrufen:**
> Die Antwort enthält zunächst nur die betroffenen Lock-IDs und eine
> Abrufreferenz. Die Wallet lädt den Nachweis nur dann separat nach,
> wenn sie ihn prüfen oder zur Klärung aufbewahren will.
> Das verkleinert die erste Antwort, benötigt dafür gegebenenfalls eine
> weitere Netzwerkanfrage.

Recommendation A concerns packaging of already available bounded evidence,
not mandatory quorum acquisition before a local collision rejection. A genuine
local signed exclusion, a provisional receipt and a 14/20 certificate must not
be mislabeled as equivalent. A local response authenticates only the statement
actually proved; it does not establish remote committee membership or global
irrevocability. B's identifiers are references, not cryptographic proof; refusal
of goods may be conservative while unresolved evidence remains unresolved.
Neither option authorizes node sanctions based on a 409 or new approval of an
occupied slot. No on-demand disk/peer retrieval is added to the shard signing
hot path by either option; any separate proof retrieval is bounded and outside
that path. Exact envelope, size limits and retrieval authorization are later
technical work under K2/C1/N4. Client custody, no recursive L2 receipt chain,
no lock gossip and existing public-ingress/P2P separation remain unchanged.

Next: ask the recorded A/B, then derive the bounded response/retrieval contract
from the selected policy. Preserve the O1.1 recovery proof gate. No production,
binding-specification changes or tests were performed in this continuation.

### CP-0062 — Select minimal live retention and ask about conflict-response evidence

Recorded DEC-065 / Q-S5-VOID-RETENTION-01 A; full losing-tree archival B rejected.
Retain winner, sufficient compact exclusions and own choices until root TTL+30s;
client custody and no expired-lock tombstones remain. Exact authenticated record
sufficiency is pending engineering work. Active focus moves to C1.1 /
Q-C1-CONFLICT-RESPONSE-01: A = include already available compact authenticated
evidence with 409; B = identifiers/reference first, separate retrieval on demand.
Neither response option selected. Read-only interface check performed; no code,
binding-specification edits or tests.

Completed checkpoint: **CP-0062**.


### 7.74 Inline conflict evidence selected; checkout veto policy open

Record: C1-CONFLICT-RESPONSE-DECISION-001 / C2-CONFLICT-VETO-QUESTION-001.
Date: 2026-10-18 (Europe/Berlin). Checkpoint: CP-0063.

**Answer / DEC-066.** The maintainer unequivocally selects
Q-C1-CONFLICT-RESPONSE-01 A. Embed the already available compact collision
proof directly in `L2Verdict::Conflict` / the 409 envelope: colliding lock ID,
parent/output binding, timestamp and cryptographic attestation, with the proof's
actual confirmation status. No full losing-tree transfer or additional proof
retrieval on the signing hot path. The wallet/terminal can verify and retain
the evidence offline even if the responding node later disappears. Reject B's
reference-first response as extra latency and accidental gateway complexity;
retain the stateless messenger boundary and client custody.

**Evidence and limits.** The maintainer estimates 100–300ms avoided on mobile
links and a few hundred bytes fitting one MTU. These are rationale/size targets,
not measurements or transport guarantees: exact canonical/JSON/base58 encodings,
signature count and HTTP/TLS/QUIC overhead need bounded sizing. Do not claim
one network packet or an independently verified quorum from one signature.
Local RAM presence of existing_lock supports avoiding an extra record lookup;
it does not by itself establish that every required signed proof is already
stored in every path. Derive the exact authenticated envelope and storage
alignment without adding hidden synchronous I/O. B would not inherently force
a stateful gateway cache (a stable content reference could be served elsewhere),
but that engineering possibility does not reverse the explicit selection A.

The current response type in `crates/humoco-node/src/api/hmc.rs` contains
existing_lock. Targeted inspection of `collect_peer_attestations` in
`crates/humoco-node/src/api/routes.rs` found a collision flag/payload path which
retains the first successfully deserialized L2LockEntry separately from the
verified positive votes. The idempotent path checks `remote_collision` before
`cert.is_quorum_reached()`, and the general remote path likewise returns 409
for any retained collision. This establishes a response-priority observation,
not an audit of every rejection path. The shown collision arm does not perform
the positive-vote verifier; audit authenticity, parent/output binding, signer
membership and proof status separately. Invalid/unrelated claims must not be
promoted into authenticated evidence under either pending option.

**Why another question is necessary.** DEC-064 already chooses support-class
priority for canonical merge. DEC-066 chooses response packaging. Neither
explicitly chooses whether checkout should conservatively refuse a transaction
when there is an authenticated weaker colliding record despite a valid current
14/20 certificate for the submitted lock. Merchant refusal can be stricter than
canonical winner selection without voiding that certificate. This is a real
availability-versus-conservative-acceptance tradeoff; do not ask again whether
one partial proof may replace a confirmed canonical winner. Move the active
human decision to C2.1; C1.1 stays decided with envelope/verification work pending.

**Exact pending question — Q-C2-CONFLICT-VETO-01 (unanswered):**

> Der eingereichte Lock erreicht 14 gültige Stimmen im festgelegten
> 20er-Komitee. Ein weiterer Shard-Knoten meldet einen tatsächlich signierten
> kollidierenden Lock, legt dafür aber keinen gleich- oder höherwertigen
> Quorum-Beleg vor. Soll diese schwächer belegte Kollision den Checkout stoppen?
>
> **A — Das gültige Quorum entscheidet (Empfehlung):**
> Die einzelne schwächere Kollisionsmeldung hat kein Vetorecht gegen die
> 14/20-Bestätigung. Der Checkout kann erfolgreich abschließen.
> Ein ausreichend belegter konkurrierender Zweig wird nach der bereits
> gewählten Klassen- und Hash-Regel behandelt.
>
> **B — Bei belegter Kollision vorsorglich abbrechen:**
> Bereits der authentische kollidierende Einzel-Lock führt zu `409 Conflict`,
> auch wenn der eingereichte Lock 14/20 erreicht. Das Terminal verweigert
> diesen Checkout vorsorglich; die gültige Quorum-Bestätigung wird dadurch
> nicht für ungültig erklärt. Das ist konservativer, gibt aber auch einem
> schwächer belegten oder veralteten Konflikt eine Blockademöglichkeit.

Recommend A for consistency of checkout availability with the selected 14/20
and class-priority policy, avoiding a minority response veto. B is an explicit
conservative service refusal, not canonical takeover or node punishment. Both
require genuine correctly bound evidence; a bare flag, deserializable payload,
gateway signature over an unverified claim or mismatched quorum is insufficient.
Do not wait beyond the frozen committee/deadline or introduce ranks21–40.
A single transport peer may carry a complete strong competing certificate;
that case is not a weak single-vote report and remains subject to DEC-064.
Neither option resolves the independently open authorization, membership,
same-class merge, global-finality or lost-own-choice proof obligations.

Next: ask saved A/B, then derive the ordered collector/response decision table,
including invalid claims, partial-only outcomes, pre/post-quorum arrival and
sufficient competing certificates. Validate in later real adversarial QUIC tests;
none executed in this interview. No code or binding-specification edits.

### CP-0063 — Select inline conflict evidence; ask about checkout minority veto

Recorded DEC-066 / Q-C1-CONFLICT-RESPONSE-01 A, preserving compact RAM-backed
inline evidence and client custody. Reference-first B rejected. Distinguish
payload/latency targets from verified sizes, and local attestations from quorums.
Targeted source inspection found single-collision response priority over positive
quorum. Active C2.1 / Q-C2-CONFLICT-VETO-01: A = valid 14/20 may complete despite
weaker authenticated collision; B = conservatively return409 even then without
voiding the certificate. Neither selected. DEC-064 merge policy remains settled.
No production/spec changes or tests.

Completed checkpoint: **CP-0063**.


### 7.75 Quorum checkout priority selected; uncertain-payment follow-up open

Record: C2-CONFLICT-VETO-DECISION-001 / C3-UNCERTAIN-FOLLOWUP-QUESTION-001.
Date: 2026-10-18 (Europe/Berlin). Checkpoint: CP-0064.

**Answer / DEC-067.** The maintainer unequivocally selects
Q-C2-CONFLICT-VETO-01 A: a valid14/20 certificate from the fixed committee
completes checkout. An authenticated colliding singleton or other weaker
support has no veto. Reject B because a minority response could sabotage the
checkout despite sufficient valid votes, undermining the intended BFT
availability. This is consistent with DEC-022 and DEC-064's class hierarchy.
The maintainer treats a sufficiently supported competing branch as the basis
for a genuine conflict decision; apply the existing class/hash winner rule,
not automatic refusal merely because another certificate exists. An equal-class
competitor that loses min(H_canon) does not by itself invalidate the winner.

Keep the claimed six-fault tolerance conditional on the relevant fixed-view
model, distinct identity/signature checks and existing safety/liveness premises.
Removing the minority veto restores this availability requirement; it does not
prove membership convergence, dynamic transition safety or an adversary bound.
A single peer can transport14 valid signatures: classify evidence by its actual
support, not number of connections or first-arriving flags. Receipt/slot/context
checks and first-party-only identity sanctions remain mandatory.

**Derived collector/response contract; no new preference question needed.**

| Evidence available within the frozen attempt | Required direction |
| --- | --- |
| Valid target14/20; weaker conflicts only | Successful target checkout; no minority409 veto. |
| Sufficient competing proof | Verify context and apply DEC-064 class priority, then same-class min-hash. If target loses, return409 with available bounded authenticated evidence under DEC-066. No automatic honest-loser node sanction. |
| Neither target nor competitor sufficiently confirmed | Unresolved outcome; no payment success, no fabricated winner and no release/rollback of an occupied slot. DEC-009/023 already settle these properties. Use structured temporary/uncertain feedback; exact HTTP/envelope mapping remains technical work. |
| Invalid, unrelated or incorrectly bound collision claim | Cannot establish a conflict or override a verified certificate. Apply appropriate bounded input defenses; no hearsay identity ban. |
| Quorum impossible before800ms | Exit early with truthful evidence/outcome; no replacement members beyond the frozen20. |

Quorum fast-exit and neutral cancellation remain. It cannot discover evidence
that has not arrived: specify handling of received competing proof versus later
shard-direct repair, without waiting indefinitely or promising global
irreversibility. Keep partial evidence distinct from confirmed receipts and
original immutable choices. Regression obligations include a weak collision
before/after14 positive votes, one-peer transport of a strong competitor,
malformed/unrelated evidence,13/7 partial split and neutral cancellation, over
real QUIC. This table is a selected/derived contract, not executed verification.

**Next actual user tradeoff.** DEC-009 selects bounded exact-payload automatic
retries and no replacement spend after uncertain outcome; their detailed horizon
is open. DEC-060 retains exact bytes/T_0. DEC-061/062's live gate means retries
cannot remain fresh forever. After T_0's30s freshness window (relative to the
accepted time basis), do not refresh the timestamp or reissue the old request
as a new live write. Status/proof reconciliation remains possible and does not
itself approve a new lock. Decide client follow-up behavior after the short
automatic submission/retry phase, not a new server pending queue or relaxation
of the freshness gate. C2.1 stays decided; activate C3.1.

**Exact pending question — Q-C3-UNCERTAIN-FOLLOWUP-01 (unanswered):**

> Eine Zahlung bleibt nach Checkout und kurzen automatischen Wiederholungen
> ungeklärt. Soll die Wallet sie anschließend selbstständig weiter nachverfolgen?
>
> **A — Automatischer Statusabgleich mit begrenztem Budget (Empfehlung):**
> Die Wallet bewahrt den ursprünglichen Auftrag und prüft bei verfügbarer
> Verbindung mit zunehmenden Abständen den Status beziehungsweise vorhandene
> Nachweise. Nach Ende der 30-Sekunden-Frischefrist erfolgen nur noch Leseabfragen.
> Sie zeigt eine nachgewiesene Klärung automatisch an; sonst bleibt die Zahlung
> ungeklärt. Intervalle und Gesamtlast werden begrenzt.
>
> **B — Nach kurzer Automatik nur auf Nutzeraktion prüfen:**
> Die Wallet bewahrt den Auftrag ebenfalls, beendet aber die automatische
> Nachverfolgung nach dem kurzen Wiederholungsfenster. Weitere Statusprüfungen
> starten beim Öffnen der Zahlung oder auf ausdrückliche Nutzeraktion.
> Das spart Hintergrundverkehr; die Klärung wird möglicherweise später sichtbar.
>
> Unter beiden Optionen entsteht ohne bestätigten Abschluss keine Zahlungsfreigabe
> und kein neuer Zahlungsversuch mit verändertem T_0 für dieselbe Vorgängerausgabe.

Recommend A to surface recovered outcomes without requiring the user to remember
an interrupted checkout. Bounds must cover per-intent frequency, total client
concurrency/traffic, offline suspension and expiry; no unlimited tight polling
or claim of guaranteed mobile background execution. Retain uncertain outcome
honestly when no sufficient evidence can be recovered. B trades slower automatic
visibility for less unattended network use, preserving the same proof and
custody requirements. Both use recipient-selected sources, keep gateway/node
stateless messenger boundaries, and require no historical L2 receipt chain,
notification subscription service or server-side pending-intent queue.
Historical proof transport/verification still needs its proper sync/read contract;
a status lookup alone must not be relabeled a14/20 completion certificate.
No fresh success may be created for an expired root; expiry is not retroactive
proof that an old ambiguous payment never completed.

Next: ask saved A/B, then derive resource bounds and the client uncertain-state
transition table from the selection. Keep O1.1 and source/admission proof gaps
open. No production or binding-specification edits and no tests this turn.

### CP-0064 — Select quorum checkout priority; ask about client uncertain-state follow-up

Recorded DEC-067 / Q-C2-CONFLICT-VETO-01 A and rejection of minority-veto B.
Derived target/competitor/partial/invalid collector outcomes from existing choices;
partial-only uncertainty is not a new canonical takeover preference. Active
C3.1 / Q-C3-UNCERTAIN-FOLLOWUP-01: A = bounded automatic client status/proof
reconciliation after short retries; B = user-triggered checking after that phase.
Neither selected. Live writes retain the original T_0 and its30s gate; later
reconciliation is read-only. No code/spec changes or verification execution.

Completed checkpoint: **CP-0064**.


### 7.76 Bounded client reconciliation selected; completion evidence retrieval open

Record: C3-UNCERTAIN-FOLLOWUP-DECISION-001 / C4-COMPLETION-EVIDENCE-QUESTION-001.
Date: 2026-10-18 (Europe/Berlin). Checkpoint: CP-0065.

**Answer / DEC-068.** The maintainer unequivocally selects
Q-C3-UNCERTAIN-FOLLOWUP-01 A. Under Smart Client, Dumb Server, the wallet
custodies the original ambiguous payment and initiates bounded automatic
reconciliation; nodes/gateways do not maintain historical-order push connections.
Timeout is uncertain, not proof of failure (DEC-009). Use growing/exponential
backoff and a strict attempt budget to limit battery/network use. The suggested
5s/15s/45s checks and maximum5 attempts are explicitly examples, not fixed protocol
constants; delay-versus-absolute schedule, jitter, total elapsed horizon,
persistence across app restarts and aggregate per-wallet bounds remain design
work. Do not convert examples into selected production settings.

After the original T_0's30s live-freshness window, use only read requests such
as POST /v1/status with challenge_ds_tag, never renewed timestamps or a new
spend to resolve uncertainty. Ordinary status uses the selected INV-0310
1-of20 routing and protected read budget, not the write queue or an automatic
fresh write-vote collection. Reconnect can resume a still-available campaign
budget; it must not silently turn finite attempts into unlimited rapid retries.
On exhausted budget without proof, stop that automatic campaign and preserve
uncertain status, original intent and custody; do not free the consumed output,
roll back accepted locks or mark success. Later explicit reconciliation remains
possible. These consequences follow DEC-009 and the chosen strict budget;
no redundant preference question on whether to invent success/failure is needed.

**Correctness boundary.** The maintainer describes zero consensus load and
deterministic clarification. Preserve the intended low-cost read-only operation,
not a zero-resource or guaranteed-resolution theorem: requests still consume
network/transport/crypto/rate-limit resources and may fail or reach stale peers.
Fast RAM lookup is the target for the lookup itself, not measured end-to-end
latency or proof that every route performs zero I/O. A finite budget and1-of20
sampling cannot guarantee discovery of an accepted lock or recover its14/20
certificate. No new writes can be approved for an expired root; expiry or
absence now does not prove an earlier ambiguous payment never completed.

**Targeted read-path check.** `api/hmc.rs` defaults read_quorum to1. The status
handler in `api/routes.rs` queries HmcRamIndex and on UnknownVoucher routes to
one top20 peer chosen from BLAKE3(challenge_ds_tag). It can return a full lock
as Verified or construct a minimal Verified entry from an attestation with zero
owner-signature fields. The optional read_quorum>1 path separately collects
status attestations; no automatic historical checkout-certificate recovery was
established. This is a bounded source observation, not a full security audit.
Existing notes §3–5.3 already distinguish owner authorization, local possession,
request-bound replies and quorum acceptance, including honest unconfirmed copies.
Spec06's stochastic/random/failover wording and current deterministic implementation
still need consolidation; repeated queries to the same fixed view/tag need not
sample independent peers. Do not silently change INV-0310 or claim optional
status attestation collection recovers original checkout approvals.

**Next bounded user tradeoff.** Ordinary single-peer reads remain cheap. If no
sufficient completion proof accompanies them, either permit a separate bounded
client-driven retrieval of existing proofs in exceptional reconciliation, or
preserve uncertainty while staying strictly status-only. Both retain the same
proof threshold and do not add a mandatory round to a successful checkout.
This does not ask to weaken evidence, choose algorithm names or restore recursive
historical L2 receipt chains. Move active focus from decided C3.1 to C4.1.

**Exact pending question — Q-C4-COMPLETION-EVIDENCE-01 (unanswered):**

> Eine Statusantwort findet den gesuchten Lock, enthält aber keinen ausreichenden
> Abschlussnachweis. Darf die Wallet zur Klärung zusätzliche vorhandene Nachweise
> abrufen, oder soll die automatische Nachverfolgung strikt bei Statusabfragen bleiben?
>
> **A — Vorhandene Abschlussnachweise gezielt nachladen (Empfehlung):**
> Nur im ungeklärten Ausnahmefall darf die Wallet innerhalb ihres begrenzten
> Gesamtbudgets zusätzliche Leseabfragen veranlassen, um bereits vorhandene
> Signier- beziehungsweise Quorum-Nachweise zu erhalten. Es entstehen keine
> neuen Locks und keine neue Schreib-Abstimmung. Sind ausreichende Nachweise
> nicht verfügbar, bleibt die Zahlung ungeklärt.
>
> **B — Ausschließlich normale 1-of-20-Statusabfragen:**
> Die Wallet beschränkt die automatische Nachverfolgung auf den günstigen
> Statuspfad. Liefert dieser keinen ausreichenden Abschlussnachweis, bleibt
> die Zahlung auch bei gefundenem Lock ungeklärt. Das spart zusätzliche
> Beweisabfragen, kann aber mehr Fälle für eine spätere Klärung offenlassen.

Recommend A conditionally on deriving a justified bounded retrieval contract
for already available evidence. One peer may already carry a complete proof;
otherwise historical signer/context discovery and availability are open design
obligations, not guaranteed by this preference. No request for new binding votes,
server pending queue, proof-reference cache, mandatory new finalization round or
full losing-tree archive is selected by A. Reusing stored evidence must preserve
original slot/identity/context and actual support class; it cannot fabricate an
old certificate from current nodes merely agreeing that a record exists. Any
new fields, storage amplification, extra-return protocol or unavailable evidence
must be reviewed before implementation, not inferred from this question. B does
not downgrade proof requirements; it explicitly accepts more unresolved cases.
Both retain recipient-selected sources, INV-0310 ordinary routing and total
attempt/byte/CPU limits; multiple gateways must not multiply a campaign budget.
The parked Q-S3.3-01 one-versus-two-payment-round question is not answered here.

Next: ask saved A/B; then derive exact proof availability/retrieval and client
state transitions under selected resource scope. Read-safety and historical
membership/source completeness remain open; do not declare DEC-068 deterministic
payment recovery. No production/spec edits or tests in this continuation.

### CP-0065 — Select bounded automatic reconciliation; ask about exceptional proof retrieval

Recorded DEC-068 / Q-C3-UNCERTAIN-FOLLOWUP-01 A; manual-only B rejected. Retained
original intent, growing backoff, strict budget and only reads after30s. Example
parameters remain examples. Budget exhaustion stays uncertain; single-node
possession is not a14/20 completion proof. Targeted status-path inspection
preserves that evidence gap. Active C4.1 / Q-C4-COMPLETION-EVIDENCE-01: A = bounded
retrieval of existing completion evidence beyond ordinary status when needed;
B = status-only automatic reconciliation, unresolved without sufficient proof.
Neither selected. Ordinary1-of20 routing, no new write votes and no extra normal
checkout round remain. No code/spec edits or tests.

Completed checkpoint: **CP-0065**.


### 7.77 Original approval retrieval selected; technical contract and storage gap

Record: C4-COMPLETION-EVIDENCE-DECISION-001 / C4-ORIGINAL-APPROVAL-AUDIT-001.
Date: 2026-10-18 (Europe/Berlin). Checkpoint: CP-0066.

**Answer / DEC-069.** The maintainer unequivocally selects
Q-C4-COMPLETION-EVIDENCE-01 A. The wallet custodies its causal evidence and
quorum certificate and may collect missing already-issued approvals of the
original frozen20-member checkout committee. Read existing attestations, not
full trees; initiate no new lock or write-vote round and retain original T_0.
Keep the retrieval within the existing strict retry/traffic budget. If14 valid
approvals cannot be assembled, stop that attempt and preserve uncertain status.
Reject status-only B because a deliberately minimal status reply must not
artificially prevent recovery of an actually available completion certificate.
The cited maximum one committee roundtrip is an example; no fixed production
count, one packet, latency guarantee or complete delivery is inferred. A parallel
fan-out to20 peers still has bounded per-peer requests/bytes/concurrency costs;
it is not one free network operation. Retaining client evidence does not impose
recursive historical L2 receipt-chain verification on ordinary spend (DEC-055).

**Derived technical contract, not another human choice.**

1. The wallet retains the original request plus its exact committee/context
   locator and any verified partial approvals. A valid completion uses14 distinct
   NodePubKeys from that same admitted snapshot; no current-roster substitution,
   mixed-view assembly or double-counted ticket identities. Exact historical
   membership admissibility remains S2/S3 work, not proved by a roster hash.
2. Exceptional retrieval reads the original issued approval payload/signature
   and all fields required to verify it. A freshly signed current status response
   or observation cannot be relabeled the original checkout approval. Context
   must distinguish approval from observation and provisional from14/20 support.
3. Protected own-choice retention (DEC-033/065) must support the required original
   evidence representation. The selected retrieval presupposes available original
   approvals; choosing it does not prove that current lock records preserve them.
   Derive a minimal representation, RAM/persistence ownership, TTL+30s handling,
   bounded capacity/backpressure and storage-time accounting. Reuse existing
   justified own-choice storage where sufficient rather than invent an archive.
4. Serve only existing evidence; missing original data returns a truthful
   unavailable/unknown result without signing a replacement or mutating the lock
   registry. Validate bounded requests cheaply; protect read budgets and keep
   public-client ingress distinct from learned-node shard-direct transport.
5. Successful recovery reconstructs a verified regional14/20 receipt and updates
   the wallet. It does not create acceptance or global irreversible finality.
   Partial/absent/timeout responses, lost original signers or expired/pruned data
   leave an outcome uncertain unless other sufficient evidence exists. Neither
   expiry nor budget exhaustion retroactively proves nonpayment. DEC-053/064
   later-merge semantics and DEC-032 lost-own-choice safety gate remain.

**Bounded source findings (observed, not a repository-wide absence proof).**
`network/transport.rs` LockVerifyRequest HMC paths create an attestation using
`create_attestation_for_network`, serialize it and return it. The inspected status
path likewise calls that signing helper when a matching record exists; tag-only
lookup can return the client-signed L2LockEntry. Thus that status path is not a
literal read of an original stored node approval. `storage/engine.rs` HmcRamIndex
holds locks, voucher/root/TTL indices and a filter; no original-node-attestation
field was found there, nor did the targeted storage-source attestation/own-choice
search establish the proposed archive. `api/hmc.rs` L2LockEntry's layer2_signature
is client authorization, not the node's checkout vote. This is a concrete
implementation gap to audit/integrate, not a reversal of the selected architecture.
The helper signs with domain_approve_final/prov and zeroed context arguments;
exact membership/context binding must be checked before declaring historical
retrieval verifiable. Preserve other chats' concurrent edits and do not implement
these changes under interview-only authority.

A further bounded field review found:

| Component | Observed representation | Consequence for original-approval recovery |
| --- | --- | --- |
| `types.rs::LockRecord` | Lock fields/status plus a set of signer IDs; no signature bytes | A signer-ID set cannot reconstruct14 genuine node signatures. |
| `api/dto.rs::AttestationDto` | Full signer key, parent/lock, shard, timestamp and signature; no explicit frozen-roster/context identifier | Store/transport an exact verifiable context through the shared protocol contract; do not infer original eligibility from current peers. |
| `api/dto.rs::QuorumCertificateDto` | Status/counts/signatures/bitmap; `is_quorum_reached` checks vector length against count-based threshold | It is a threshold helper, not proof verification; deduplicate full identities, verify signature/context and exact authorized roster separately. |
| `api/routes.rs::create_attestation_for_network` | Real Ed25519 signature over domain, parent/lock digest, shard/status; three context arguments passed as0 | Current historical view/epoch/committee binding is not established by those zero fields. |
| Same signing helper | `timestamp_ms` is assigned to DTO metadata, not passed to the signed digest | DTO timestamp alone cannot prove when a node issued the original approval; do not transplant historical authority using editable metadata. |
| `storage/engine.rs::DualTierEngine` | RAM indices, redb, bounded flush queue and ancillary state; no original-approval store field identified in this review | Plan explicit reuse/extension of justified own-choice storage and bounded flush operations; an existing lock entry alone is insufficient. |

Minimum implementation dependency order: (1) shared signed approval/context
contract under K2/S2/S3; (2) immutable original-approval representation and its
RAM/async-persistence lifecycle under O1/C4.2; (3) bounded public-to-gateway and
learned-peer retrieval messages; (4) client validation/assembly and budgeted
uncertain-state transitions; (5) adversarial wire verification. This is a
reviewable dependency slice, not the completed overall architecture plan or
permission to change production. Persist-before-response is still superseded
by DEC-062: storing an original approval in RAM is not a durability claim, and
missing volatile data after crash remains subject to DEC-032/063.

**Scope and next focus.** C4.1's policy is decided. Active C4.2 is technical
retention/context/retrieval design; no new A/B is manufactured for consequences
already selected. Complete a bounded data-format/storage/wire dependency review,
then return to F1's coverage inventory and identify only genuine unresolved human
tradeoffs. Keep original question IDs/answers, same-key crash proof, historical
membership, source coverage and ordinary read-safety obligations open. Ordinary
INV-0310 status routing is not silently expanded by exceptional proof retrieval.

Acceptance obligations for the later implementation: real QUIC replay of original
approvals after30s without new signing or lock mutation; exact context/signature
verification; duplicates and mixed views rejected; strict aggregate read budget;
missing/pruned/unavailable evidence stays uncertain; RAM-first/background flush
and restart gates preserved. No test was run and no source/spec was changed.

### CP-0066 — Select original-approval recovery; advance to technical retrieval audit

Recorded DEC-069 / Q-C4-COMPLETION-EVIDENCE-01 A and rejected status-only B.
The wallet may assemble original14/20 evidence with bounded reads, no new votes
and no committee substitution. Current inspected paths generate attestations;
a literal stored-original retrieval path was not established. Active C4.2 tracks
its exact evidence/context/storage/wire contract. No pending human choice;
continue technical work without re-asking settled safety or budget policies.
No production/spec edits or tests.

Completed checkpoint: **CP-0066**.


### 7.78 Retrieval design skeleton, provisional coverage map and approval-retention question

Record: C4-ORIGINAL-APPROVAL-AUDIT-002 / F1-COVERAGE-INDEX-001 /
C4-APPROVAL-RETENTION-QUESTION-001. Date: 2026-10-18 (Europe/Berlin).
Checkpoint: CP-0067. No new maintainer decision this turn; DEC-001–069 retained.

**Technical progress / C4.2.** Use an exceptional read-only lookup keyed by original
approval identity: network, shard, consumed output/parent, spend ID, confirmation
class and the original frozen committee/context reference. Exact canonical fields
belong in shared K2 types; this tuple is a semantic contract, not a final binary
schema or new epoch-permission chain. The response returns stored original bytes
plus required verification context, or a truthful missing/unavailable outcome.
The wallet can reuse partial signatures and asks only for missing approvals, with
one aggregate byte/attempt/concurrency budget. The gateway is a transient relay;
it does not archive receipts, queue historical intents or initiate new binding
votes. Authenticated learned-node shard-direct RPC remains separate from public
client ingress. Ordinary1-of20 status routing is unchanged. Verify full identities,
original membership/context, signature domain and exact target binding before
counting14; later/current members cannot replace missing original voters. Neither
an endpoint name nor an opcode is selected here; align existing wire registries
and parsers before implementation. Retain §7.77's storage/context and crash gates.

Do not bind immutable receipts to an ephemeral transport sequence: returning an
original approval over a new authenticated QUIC session must remain possible.
Keep transport anti-replay/session validation separate from the original signed
approval statement. Bound complete frame sizes, pagination/response counts and
crypto work; no peer-wide archive scan or blind attacker-length allocation.
Read budget refusal is neutral unavailability, not identity fraud or a free slot.
Planned acceptance cases:14 valid originals complete;13 remain uncertain;
duplicates/mixed contexts/current-member substitutions fail; a returned original
survives a new transport session; missing originals never cause replacement
signing; exhausted budget stops further work; TTL rules preserve protected state.
These are design/verification obligations, not completed implementation/tests.

**Actual unresolved product/resource tradeoff.** DEC-065 requires winner,
minimum sufficient exclusions and own signing choices until root TTL+30s.
DEC-069 permits fetching original approvals but does not explicitly settle how
long every exact returned approval packet must remain fetchable at its original
signer. An immutable local choice is not automatically the complete original
signature packet and all contextual verification data. The original-response
retrieval lifetime therefore needs a separate explicit selection; mandatory
signing-safety retention and acceptance of valid late client-held evidence are
not put to a vote again. Root lifetimes can span years (Spec09 §1; existing
maximum eleven years), so the storage/availability difference is consequential.

**Exact pending question — Q-C4-APPROVAL-RETENTION-01 (unanswered):**

> Wie lange soll ein Knoten die exakten eigenen Attestierungen samt notwendigem
> Kontext zum Nachladen durch die Wallet bereithalten?
>
> **A — Bis zur Wurzel-TTL plus 30 Sekunden (Empfehlung):**
> Die Originalattestierungen folgen derselben Aufbewahrungsfrist wie die ohnehin
> geschützten eigenen Signierentscheidungen. Auch eine länger offline gewesene
> Wallet kann vorhandene Belege später noch nachladen. Dafür bleiben die
> Signatur- und Kontextdaten gegebenenfalls mehrere Jahre gespeichert.
>
> **B — Nur während eines kürzeren, fest begrenzten Nachladefensters:**
> Danach dürfen zusätzliche Abrufdaten entfallen, soweit sie nicht für die
> Sicherheit benötigt werden. Das spart Speicher; eine Wallet ohne vollständigen
> Beleg kann ihre Zahlung danach möglicherweise nicht mehr automatisch klären.
> Bereits beim Client vorhandene gültige Belege bleiben prüfbar.
>
> Unter beiden Optionen bleiben notwendige eigene Signierentscheidungen und
> Kollisionsnachweise bis zur Wurzel-TTL plus 30 Sekunden erhalten.

Recommend A to reuse a single root-bound lifecycle and avoid an arbitrary earlier
retrieval cutoff. This is a recovery-availability policy, not a guarantee that
14 original signers survive or that volatile approvals become durable. Bound
admission and count actual retained bytes/context multiplicity under N2/O1;
refuse unsafe capacity rather than evict live signing-safety records. B is a
viable lower-storage service policy only for additional retrieval material that
is genuinely unnecessary for collision/equivocation safety and admitted proof
revalidation. It introduces an explicit limited recovery SLA; it must not reject
a valid old client-held receipt merely because the cache window ended. The P0
§5.3 rejection of a30-day late-receipt cutoff concerns proof admissibility; B
cannot silently override that rule. No short-window length is selected. Exact
storage proof and canonical context are engineering obligations under either A/B.

**F1 provisional numbered-spec coverage map.** Read headings/invariant mentions
for all current numbered documents and checked relevant storage/type sections.
There are24 physical files in22 numbered families (00–20 plus99), including
English/German pairs for15 and16; a literal regex inventory found113 distinct
mentioned INV-xxxx IDs across those files. Mentions include cross-references;
this is not113 independently defined or verified requirements, a completeness
percentage or test coverage. Preserve both language files until canonical source
and translation drift are checked; no binding-spec edits were authorized here.

| Spec family / scope | Interview branches and remaining integration |
| --- | --- |
| 00 mental model | K1/K2; blind scope, client custody and KISS consolidation. |
| 01 organic start/topology | S2/S3/S6/N1; passive admission and phase transitions. |
| 02 lock states/conflicts | C1/S4/S5/O1; support classes, immutable choices, dependent VOID and progress. |
| 03 routing/sharding | C2/C4/S2/S3/N2; frozen membership, ordinary reads and verified bucket recovery. |
| 04 types/encodings | K2/C1/C4.2/S5; signed context, exact sizes and parser bounds. |
| 05 game theory/attack matrix | S1/S2/S5/S6/N4; explicit coordinated adversary assumptions and executable counterexamples. |
| 06 client flow | C1–C4; retry/read/recovery/409 receipt contracts and merchant release. |
| 07 admission/WoT | S2/S6/O3; tickets, observed maturity, historical admission and corroborated time. |
| 08 topology/merge | S2–S5/N1; phase modes, three-miss eligibility, class/hash convergence. |
| 09 thermometer/quotas | N2/N4/O1; time-based accounting, full identities and actual storage cost. |
| 10 wire/session | K2/N1/N4/C4.2/S5; signed domains, replay, original-proof retrieval and frame limits. |
| 11 presence/gossip | S2.1a/N1; three missed hourly heartbeats, F2F barrier and no lock gossip. |
| 12 RAM/TTL | C2/O1/O3/C4.2; reservation-first RAM admission, immutable originals and expiry. |
| 13 client access tiers | N4/C1/C4/O5; cheap checks, protected read/write budgets and private versus public surfaces. |
| 14 persistence | O1–O4/C4.2; async storage, failed flush, recovery, drain and original-proof lifecycle. |
| 15 transport, both language files | N1/N2/N4/C2/C4.2; ephemeral sessions, neutral cancellations and separate resource caps. |
| 16 testing, both language files | F1/S1–S6; deterministic models plus real adversarial QUIC gates, no unit-only claims. |
| 17 telemetry | O5/O6/N1; non-authoritative diagnostic observations, no hearsay sanctions. |
| 18 shard/percolation memo | S2/S3/N1/N2; distinguish passive eligibility, checkout and background assumptions. |
| 19 anti-cascade memo | N1/N2/N4/S6; local dampening, bounded load and first-party sanctions. |
| 20 operations/ecosystem | K1/K2/O4–O6; operator veto, private administration, custody/backup and protocol evolution. |
| 99 FAQ/attack scenarios | S1–S6/C3/C4/N4; scenario-by-scenario mapping remains to be completed. |

Next F1 work is exact invariant definitions/owners, endpoint+wire/control surfaces
and scenario-to-proof/test acceptance mapping, including non-numbered operations,
merchant and handoff documents. The old architecture audit report is a historical
source at its named2026-10-13 revision; its old test counts and findings were not
rerun or promoted into current verification. Existing significant clock bootstrap,
root/shard alignment, sender-accounting, crypto context, receiver admission and
shutdown ordering gaps map to OPEN-01–14; do not create duplicate human questions
from technical gaps. This initial map reduces the navigation gap but does not
close F1, C4.2, membership/source completeness or O1.1 crash safety.

Next active leaf: C4.2a, ask the saved retention A/B; then use that selection to
finish the bounded retrieval-lifecycle design and continue F1's exact coverage
review. No production/spec changes, commit or tests this turn.

### CP-0067 — Derive retrieval skeleton and ask about original-approval availability lifetime

C4.2 now has a bounded read-only request/response and verification skeleton with
explicit context/transport separation and wire-test obligations. Added provisional
mapping of all22 numbered spec families (24 files,113 distinct mentioned IDs),
not semantic completeness or executed verification. New pending human question
Q-C4-APPROVAL-RETENTION-01: A = original approvals fetchable until root TTL+30s;
B = shorter explicit retrieval window, preserving all safety-critical state and
valid client-held late evidence. Neither selected;69 decisions remain. Active
focus C4.2a. No production/spec edits or tests.

Completed checkpoint: **CP-0067**.


### 7.79 Root-lifetime original approval retention selected; wallet send order open

Record: C4-APPROVAL-RETENTION-DECISION-001 / C3-WALLET-SEND-DURABILITY-QUESTION-001.
Date: 2026-10-18 (Europe/Berlin). Checkpoint: CP-0068.

**Answer / DEC-070.** The maintainer unequivocally selects
Q-C4-APPROVAL-RETENTION-01 A. Retain exact own original attestations and required
verification context until root.valid_until+30s, using the existing immutable
own-choice record/lifecycle in redb rather than a second shorter cache timer.
Reject B because a separate retrieval deadline complicates pruning and can leave
a wallet that was offline for days/weeks unable to recover an otherwise available
receipt. Wallet custody, original fixed20,14 distinct valid signatures, bounded
read-only collection and uncertain status without sufficient evidence remain.
Ordinary INV-0310 reads and node RAM-first/async persistence are not reopened.

**Engineering qualifications.** A shared lifecycle reduces machinery; the actual
retained64-byte signature plus contextual fields/index overhead is not literally
zero bytes. Reuse fields where possible and account for measured RAM/disk bytes
under N2/O1. This is not permission to discard safety data when capacity is full.
The requested complete purge covers lock, collision, own-choice and attestation
records at the common authentic root expiry+30s; independently governed identity
sanctions remain separate. Preserve DEC-035 bounded background pruning and
immediate logical expiry checks: do not claim a single instantaneous atomic
operation across RAM and asynchronous disk. Design coherent visibility, root-group
cleanup and crash-resumable deletion without resurrecting expired state. These
are technical obligations, not reasons to re-ask the selected TTL. Original
signer disappearance/data loss still prevents a guaranteed14-signature recovery.

**Wallet recovery data derived from existing choices.** Preserve the exact signed
request bytes/T_0, voucher root and consumed output, the local uncertain/outgoing
state, available partial approvals, the original admitted committee/context and
routing locators as they become known, plus consumed retry budget. Resolve node
addresses by authenticated identity; stale IPs are not identity changes. A current
roster must not substitute for the original approval context. Do not require
unknown committee metadata before it has been received or infer an extra checkout
preflight/finalization round. This derives what client custody needs; the exact
client persistence point remains a separate real crash/latency tradeoff.

A targeted read of adjacent `human-money-core` found request builders/verifiers
in `src/services/l2_gateway.rs` and encrypted wallet storage with atomic file
replacement/sync helpers in `src/storage/file_storage.rs`. Transfer APIs describe
saving wallet state, but this inspection did not establish an exact durable
L2-intent-before-outbound-request guarantee or a persisted original-committee
recovery record. `tests/wallet_api/proof_persistence.rs` concerns conflict-proof
retention, not an executed L2-send crash test. No adjacent files were changed.
Existing storage is the preferred reuse candidate; do not invent a new journal
or claim that the test filename proves wire/crash ordering.

**Exact pending question — Q-C3-WALLET-SEND-DURABILITY-01 (unanswered):**

> Soll die Wallet den ursprünglichen signierten Zahlungsauftrag dauerhaft lokal
> sichern, bevor sie ihn erstmals an ein Gateway sendet?
>
> **A — Erst lokal sichern, dann senden (Empfehlung):**
> Die Wallet speichert den exakten Auftrag mit T_0 und der betroffenen
> Vorgängerausgabe sowie deren ausstehendem Zahlungsstatus dauerhaft, bevor
> sie sendet. Nach einem App-Absturz kann sie denselben Auftrag wiederfinden
> und gezielt weiter abgleichen. Der erste Versand wartet dafür auf den lokalen
> Speichervorgang.
>
> **B — Erst aus dem RAM senden, parallel dauerhaft sichern:**
> Die Wallet wartet vor dem Versand nicht auf den lokalen Speicher.
> Das spart diese Wartezeit; bei einem Absturz im Zwischenfenster kann der
> letzte Auftrag fehlen. Der Wiederanlauf muss dann mit möglicher erfolgter
> Zahlung umgehen, statt die betroffene Ausgabe einfach erneut freizugeben.
>
> Diese Entscheidung betrifft die Wallet. Die Shard-Knoten bleiben bei der
> bereits gewählten RAM-first-Verarbeitung mit asynchroner Persistierung.

Recommend A to make exact-intent recovery survive an ordinary app/process crash,
reusing existing client storage and atomic pending-output/intent transition.
Count local preparation separately from the gateway800ms collection budget;
no local latency measurement was made. This does not cover lost devices or stale
wallet backups automatically. B explicitly trades crash recovery for earlier
submission; it cannot weaken DEC-009 or authorize a replacement spend when an
original payment may already exist. Derive its safe unknown/affected-output
recovery boundary before implementation; do not assume an asynchronously written
flag survives a crash. Both keep no node-side intent queue, no changed T_0,
no automatic rollback and no extra checkout round. Unknown future committee
metadata is persisted as received, rather than being invented before dispatch.

Next active leaf C3.2: ask saved A/B, derive the chosen client crash/state
transition contract and then return to C4.2 storage/context/wire and F1 exact
coverage. O1.1 node lost-choice recovery remains a separate proof obligation.
No code/spec changes, commits or tests in this continuation.

### CP-0068 — Select one root-lifetime approval horizon and ask about wallet send durability

Recorded DEC-070 / Q-C4-APPROVAL-RETENTION-01 A; shorter-window B rejected.
Exact original own approvals follow root TTL+30s with own choices; costs and
coherent RAM/disk pruning remain engineering work. Derived minimal wallet
recovery data and checked adjacent client storage boundaries read-only. Active
C3.2 / Q-C3-WALLET-SEND-DURABILITY-01: A = durable original wallet intent/pending
output before first send; B = RAM-first client send with explicit crash recovery
cost. Neither selected; node RAM-first is unchanged. No code/spec edits or tests.

Completed checkpoint: **CP-0068**.


### 7.80 Wallet durable-before-send selected; PoS receipt order open

Record: C3-WALLET-SEND-DURABILITY-DECISION-001 / C2-POS-RECEIPT-DURABILITY-QUESTION-001.
Date: 2026-10-18 (Europe/Berlin). Checkpoint: CP-0069.

**Answer / DEC-071.** The maintainer unequivocally selects
Q-C3-WALLET-SEND-DURABILITY-01 A. The wallet durably saves the exact signed
outgoing bytes, unchanged T_0 and the affected output's pending state before
first gateway dispatch. This makes ordinary app/OS crash recovery preserve the
original intent for idempotent retries and prevents incorrectly displaying that
output as unspent after a send-before-save crash. Reject B's client RAM-first
send window. Client custody and no automatic rollback/replacement spend remain;
this does not reinstate durable-before-response at shard nodes (DEC-062).

The maintainer mentions WAL/SQLite as examples. Prefer existing client storage
if it can supply the required atomic durability contract; no new storage engine
or separate log is selected. The claimed200-byte request, sub0.5ms local write,
50–150ms mobile RTT and100% protection are rationale/estimates, not measurements
or unconditional guarantees against device loss, faulty storage or stale backups.
Specify the actual application/OS-crash durability boundary and test it. No network
or storage benchmark was run; no external time-varying latency claims are made.

**Derived wallet crash contract.** Before successful local commit, no external
dispatch is allowed. The commit atomically binds outgoing intent to pending
output state; failure refuses dispatch. A crash after commit but before observed
network send is recovered conservatively as pending and can resume the identical
request while fresh. A crash after dispatch but before receipt persistence remains
uncertain; after the original30s freshness window, only bounded read/proof recovery
is allowed. Append original committee context and verified partial/final receipts
as actually received, without requiring an extra preflight to learn unknown data.
A generic transaction snapshot or generated signature alone is not proof that
this exact pending-intent transition was durably committed. Reuse existing client
storage and test crash cuts before commit, after commit, during dispatch and before
response persistence. The earlier adjacent-core read does not establish those cuts.

**Next bounded tradeoff: receiving merchant.** The sender retaining its intent
does not itself preserve the merchant's verified checkout receipt or purchase
binding. DEC-009 requires a verified completion before finally paid goods release,
but the register has no explicit maintainer selection of whether local merchant
receipt persistence must finish before that release. P0 §7 proposes
ReleaseGoodsOnce requiring a durable purchase record; this is an existing design
candidate, not new retroactive assent. §7.58 distinguishes accepted guardrails
from exact candidate rules. Make this persistence-order tradeoff explicit once;
keep the actual quorum/evidence requirements mandatory under either alternative.

**Exact pending question — Q-C2-POS-RECEIPT-DURABILITY-01 (unanswered):**

> Das PoS-Terminal hat ein gültiges Quorum-Zertifikat geprüft. Muss es den
> Beleg und die Zuordnung zum Kauf dauerhaft lokal speichern, bevor es
> „Bezahlt“ anzeigt und die Ware freigibt?
>
> **A — Erst Beleg und Kauf dauerhaft sichern, dann freigeben (Empfehlung):**
> Das Terminal wartet auf die lokale Speicherung des geprüften Zertifikats
> samt Kaufzuordnung. Nach einem Absturz kann es die bestätigte Zahlung
> wiederfinden und denselben Kauf zuordnen. Die Warenfreigabe wartet dafür
> auf diesen lokalen Speichervorgang.
>
> **B — Nach Prüfung sofort freigeben, im Hintergrund speichern:**
> Das Terminal zeigt nach erfolgreicher kryptografischer Prüfung sofort
> „Bezahlt“ an und speichert anschließend asynchron. Das spart die lokale
> Wartezeit; bei einem Absturz im Zwischenfenster muss es den fehlenden Beleg
> später nachladen, was bei nicht erreichbaren Signierern scheitern kann.
>
> Unter beiden Optionen bleibt ein gültiger Zahlungsnachweis Voraussetzung.
> Die RAM-first-Verarbeitung der Shard-Knoten bleibt unverändert.

Recommend A to preserve the merchant's local evidence/purchase binding before
an external release signal, consistent with client custody and the existing P0
candidate. This does not make physical handover atomic with storage: persist a
ready-for-release transition, distinguish it from actual goods released and use
an idempotent sale/release reference. A crash in an uncertain physical handover
requires honest local reconciliation, not automatic duplicate release. Keep
amount/purchase/exposure logic outside blind L2. B is a weaker merchant crash-
recoverability choice, not acceptance without a valid quorum or waiver of fraud
checks. If chosen, update the proposed P0 persistence predicate explicitly; do
not silently change canonical proof validity, node persistence or receipt class.
No guaranteed local storage latency or global irreversible-finality claim follows.

Next active leaf C2.2: ask saved A/B, then derive one consistent sender/merchant
client crash-state contract and return to C4.2/F1 integration. Pending source,
membership, own-vote-loss and real-wire proof obligations remain. No code/spec
changes, commits or tests this turn.

### CP-0069 — Select wallet pre-send persistence and ask about merchant pre-release persistence

Recorded DEC-071 / Q-C3-WALLET-SEND-DURABILITY-01 A; client RAM-first B rejected.
Derived atomic pending-output/original-intent ordering and crash recovery cuts,
without selecting SQLite/WAL or changing shard RAM-first. Active C2.2 /
Q-C2-POS-RECEIPT-DURABILITY-01: A = durable verified receipt/purchase binding
before paid display/release; B = verified-in-RAM release with async client save.
Neither selected. Existing P0 purchase-journal proposal cited with its provenance;
no production/spec edits or tests.

Completed checkpoint: **CP-0069**.


### 7.81 Merchant L1 custody selected; completed-checkout receipts ephemeral

Record: C2-POS-RECEIPT-DURABILITY-CORRECTION-001 / C3-ALTERNATE-PAYMENT-QUESTION-001.
Date: 2026-10-18 (Europe/Berlin). Checkpoint: CP-0070.

**Answer / DEC-072: corrected A, not literal §7.80 A.** The maintainer selects
save-before-release with an explicit change of the stored object: the received
L1 voucher deed/ProofChain and its purchase-journal binding must be durably local
before goods release. The14-node quorum certificate is a live checkout clearance
signal, not the negotiable instrument and not proof of current unspent status at
a later spend. Once checkout completes, clients/merchants need not retain or
back-fill that historical signature bundle. Post-restart/current checks use the
live registry through POST /v1/status. Reject the earlier proposed requirement
that the merchant must durably archive the quorum certificate before release.
No new renamed option or silent interpretation of a bare A: preserve the old
question and record this explicit content correction. The async-L1-purchase-save
alternative B was not selected.

**Reconcile scope without deleting history.** DEC-055 already rejects recursive
L2 receipt chaining. This instruction strengthens the completed-checkout client
boundary and qualifies DEC-069's earlier certificate-custody wording: original
approval recovery for a still-uncertain attempt is not a duty to reconstruct an
archive for a completed purchase. DEC-070 separately selected node-side retention
of original own approvals/context until root TTL+30s; a client forgetting a
completed-checkout bundle does not itself instruct every node to erase protected
own history. Keep that selection and minimum necessary collision/fraud evidence,
DEC-032 lost-choice gate and original-byte retries. No new all-certificates archive
at each node, receipt-return round or historical chain is implied. Revisit only
if the maintainer explicitly changes unresolved-attempt recovery or node retention.

The current on-disk AGENTS.md was re-read because another chat changed it.
Its updated guardrail7 explicitly says completed-checkout clients/merchants need
not hoard/chain/back-fill historical certificates, distinguishes L1 instruments
from L2 clearance and retains live checks. Updated guardrail6 also distinguishes
24h ticket maturity, calendar quota epochs, passive liveness and per-request
living-mesh HRW; no committee tenure/epoch baton is selected. These concurrent
AGENTS/source edits are preserved; no production audit is claimed by their presence.

**Read-proof boundary remains technical.** An old verified receipt may prove a
historical approval statement; it cannot prove the voucher remains unspent now.
Equally, a single current peer returning an owner-signed lock proves possession/
authorization, not automatically14/20 acceptance or absence of hidden conflicts.
Existing notes §3–5.3 give the colluding-owner and honest-unconfirmed-copy witnesses.
Thus selecting a simple live status interface does not resolve OPEN-04's evidence
predicate. Do not pretend to prove it by vote, reintroduce mandatory historical
certificates as the only possible solution, or silently require a read quorum
in every INV-0310 request. Derive sufficient current-state evidence within the
chosen model; otherwise keep uncertainty explicit. Current absence or later spend
also cannot erase the purchase journal's previously recorded historical event.

**Derived client boundary.** Sender: DEC-071 original intent/pending output durable
before send. Receiver: verified live clearance plus durable L1 voucher/purchase
before release. Separate purchase payment outcome, release-ready and actual goods
handover states. A journal record is not an atomic physical handover; restart does
not automatically release goods twice. Later resale/spend checks current output
state, not an old certificate. Amount, purchase ID, sale status and any repayment
policy stay in merchant/wallet clients, outside blind L2.

**Next real tradeoff.** DEC-009 forbids automatic rollback/replacement spend for
the same consumed output after a timeout. A different voucher uses a different
slot, so both original and replacement can validly pay one purchase. L2 cannot
deduplicate them by purchase/amount because it is blind. P0 §7 already warns
that once-only goods release does not imply once-only debit and requires an
explicit merchant/wallet rule before such a switch; no earlier A/B selection
for this case was found in the current register.

**Exact pending question — Q-C3-ALTERNATE-PAYMENT-01 (unanswered):**

> Der erste Zahlungsversuch für einen Kauf bleibt nach einem Timeout ungeklärt.
> Darf das Terminal automatisch eine Ersatz-Zahlung aus einem anderen Gutschein
> anstoßen, obwohl die erste Zahlung noch erfolgreich gewesen sein könnte?
>
> **A — Kein automatischer zweiter Zahlungsauftrag (Empfehlung):**
> Wallet und Terminal klären zunächst den ursprünglichen Versuch über den
> begrenzten Statusabgleich. Ein Wechsel des Zahlungsmittels erfordert eine
> bewusste Nutzer-/Kassiererentscheidung mit Hinweis auf das Doppelzahlungsrisiko.
> So entsteht aus einem Timeout keine automatische zweite gültige Zahlung.
>
> **B — Ersatz-Zahlung mit ausdrücklicher Doppelzahlungsbehandlung zulassen:**
> Das Terminal darf nach einer definierten Wartezeit einen anderen Gutschein
> für denselben Kauf verwenden. Es hält beide Versuche unter derselben Kaufkennung
> nach und erkennt einen möglichen Doppelerfolg. Für diesen Fall ist eine
> Rückabwicklung durch Händler und Wallet vorgesehen. Das kann den Checkout
> beschleunigen, benötigt aber zusätzliche Abgleich- und Erstattungslogik.

Recommend A as the minimal default preserving uncertainty without automatic extra
debit. A manual switch still needs honest purchase reconciliation; it is not proof
that the original failed. B is a separately configured merchant/wallet payment
policy, not L2 rollback, reusing T_0 on a different payload or automatic network
refund. Any refund is a separate authorized L1 transfer under the actual owner's
custody; receipt disposal does not make historic double success magically visible
or recoverable. Required durable records retain original intents, purchase binding
and both outcomes; no amounts/accounts are added to shard nodes. No specific
waiting interval or refund implementation is selected by this question.

Next active C3.3: ask saved A/B, then consolidate the client crash/uncertain-payment
contract under DEC-072 and continue C4/F1 current-read verification. No production,
binding-spec edits, commit or tests this turn.

### CP-0070 — Correct merchant storage to L1 custody and scope completed-checkout certificate disposal

Recorded DEC-072 / corrected Q-C2-POS-RECEIPT-DURABILITY-01 A: durable L1 voucher
and purchase record precede release; no post-completion certificate hoarding or
back-fill. Preserved unresolved-attempt recovery and node own-history retention
as separate scopes, not silently superseded wholesale. Re-read concurrent AGENTS
changes; recorded current-read evidence gap without imposing historical receipts.
Active C3.3 / Q-C3-ALTERNATE-PAYMENT-01: A = no automatic new-voucher substitute
while the first payment is uncertain; B = alternate payment with explicit dual-
outcome/refund handling. Neither selected. No code/spec edits or tests.

Completed checkpoint: **CP-0070**.


### 7.82 Client-only payment policy selected; repeated node stop-signal question

Record: C3-ALTERNATE-PAYMENT-DECISION-001 / O4-SECOND-SIGNAL-QUESTION-001.
Date: 2026-10-18 (Europe/Berlin). Checkpoint: CP-0071.

**Answer / DEC-073.** The maintainer explicitly selects
Q-C3-ALTERNATE-PAYMENT-01 A. Automatic second payment is prohibited in wallet/
PoS policy. For a multi-voucher purchase, preserve successful components as
partial payment and the timed-out component's uncertain outcome. A deliberate
customer/cashier decision changes tender for the remainder; no hidden automatic
substitute or refund machinery follows from a timeout. Do not treat the uncertain
component as definitively failed or assume the whole purchase was rolled back.

**Explicit scope correction.** This belongs exclusively to human-money-core and
merchant-terminal commercial logic. humoco-node is a blind registry of independent
parent_lock -> child_lock decisions and knows no basket, purchase ID, remaining
amount, substitute payment or refund. The prior question's client scope is now
explicitly reaffirmed, not an instruction to implement payment orchestration in
the node. Multi-voucher commercial grouping is not a new distributed all-or-nothing
node batch; existing valid-prefix causal-path batch semantics remain separate.
DEC-072 L1 custody/ephemeral completed-checkout receipt and DEC-071 exact original
intent persistence remain. Record this client decision, then stop expanding
commercial subquestions absent a node/interface dependency or explicit user request.

**Return to node scope / O4.1.** DEC-034 already selects a bounded graceful stop:
stop admission, drain eligible in-flight work/persistence, stop within a configured
deadline and report incomplete drain honestly. It does not select how a second
ordinary termination signal behaves. OPEN-11 already records signal escalation;
this is a bounded unresolved operational tradeoff, not a new subsystem or a
repeated question on whether shutdown may wait forever. C3.3 policy is decided;
C4 read-safety, original-approval integration and F1 proof/coverage work remain
pending and are revisited before the final plan or any relevant implementation.
Broad trust research remains stopped; node same-key-loss gate remains mandatory.

**Targeted source findings.** `daemon.rs` registers SIGTERM/ctrl_c and uses a
single tokio::select! to enter cancellation. The inspected graceful tail closes
transport, sequentially awaits listener/background handles, then cancels and
awaits the flush worker. No explicit second-signal escalation policy or overall
wall-clock deadline was found in that tail. `storage/engine.rs::drain_on_shutdown`
caps batch count, which is not an elapsed-time bound if commits stall; its warnings
and daemon stop message do not independently prove durable completion. The
systemd unit has TimeoutStopSec=30, an existing deployment setting, not a measured
approved drain bound. No actual stop/crash or blocked-disk experiment was run.
Preserve existing concurrent edits; this inspection does not establish that every
QUIC producer is tracked/joined before drain.

**Exact pending question — Q-O4-SECOND-SIGNAL-01 (unanswered):**

> Der Node fährt nach einem ersten SIGTERM oder Strg+C bereits geordnet herunter.
> Wie soll er auf ein weiteres solches Beendigungssignal reagieren?
>
> **A — Den begrenzten geordneten Stopp fortsetzen (Empfehlung):**
> Weitere normale Stoppsignale verkürzen oder verlängern die ursprüngliche
> Shutdown-Deadline nicht. Bereits angenommene Arbeit wird innerhalb dieser
> Frist weiter abgearbeitet und persistiert. Ein bewusst erzwungener sofortiger
> Abbruch bleibt über SIGKILL möglich.
>
> **B — Das zweite Signal erzwingt sofortigen Abbruch:**
> Ein zweites SIGTERM oder Strg+C beendet den Node vor Ablauf der Drain-Frist.
> Das ist für den Betreiber bequem, kann aber noch nicht persistierte
> RAM-Daten verwerfen und einen ungeordneten Wiederanlauf verursachen.

Recommend A: idempotent stop signaling avoids accidental early destruction of
volatile issued choices and needs no separate user-space force-stop mode. B is
a viable explicit operator convenience policy; document the data/recovery cost.
Both retain a finite original deadline, operator sovereignty, stopped admission
and honest incomplete-drain reporting. Neither option promises to prevent loss
under SIGKILL/power failure or clears DEC-032/063 on reboot. DEC-062 permits
issued-but-unflushed approvals; ordinary14/20 sync alone is not proof all own
choices survived. Recovery/readiness and dirty-stop detection remain engineering
obligations. A repeated signal must not reset the deadline into an unbounded wait.
No numeric deadline or implementation kill mechanism is selected by this question.

Next: ask saved A/B; derive the chosen signal/drain ordering and supervisor
contract, including incomplete stop, stuck storage and producer shutdown. Then
return to node/interface coverage and consequential proof gaps. No source/spec
edits, commits, tests or external process signaling this turn.

### CP-0071 — Record client-only no-substitute policy; return to node shutdown signaling

Recorded DEC-073 / Q-C3-ALTERNATE-PAYMENT-01 A with explicit human-money-core/
PoS-only scope and partial-purchase/tender handling. No purchase logic is added
to humoco-node. Active O4.1 / Q-O4-SECOND-SIGNAL-01: A = repeated ordinary stop
signals preserve bounded original drain; B = second signal forces early abort.
Neither selected. Source/systemd settings inspected read-only, with no operational
experiments or implementation change. Other proof/coverage obligations remain.

Completed checkpoint: **CP-0071**.


### 7.83 Idempotent stop signals selected; deadline-enforcement boundary open

Record: O4-SECOND-SIGNAL-DECISION-001 / O4-DEADLINE-OWNER-QUESTION-001.
Date: 2026-10-19 (Europe/Berlin). Checkpoint: CP-0072.

**Answer / DEC-074.** The maintainer explicitly selects
Q-O4-SECOND-SIGNAL-01 A. Repeated SIGTERM/SIGINT during shutdown must not abort
the drain or restart/extend its original deadline. Preserve pending MPSC work
and allow eligible async redb flush within the existing finite budget; habitual
extra Ctrl+C is not a force-stop command. Reject B's second-signal immediate abort.
An explicit OS SIGKILL remains the operator's emergency stop. The estimated
few hundred milliseconds for normal flush is rationale, not measured performance.
No numeric runtime deadline or production readiness claim was selected.

**Derived bounded shutdown contract, not another preference question.** On first
stop, record one monotonic deadline, close new ingress/mutation admission and
cancel background producers according to dependencies. Quiesce/join all producers
that can still enqueue accepted work before closing/draining persistence; do not
equate a listener's completion with every detached QUIC handler being joined.
Repeated ordinary signals are idempotent. Use only the remaining original time
budget for each wait; a fresh full timeout per handle would multiply the stop
limit. A batch-count cap is not a wall-clock bound. Report clean stop only after
required work has truly committed and required producers have ceased; timeout,
commit failure or abandoned pending work reports incomplete stop, not success.
DEC-034 already requires finite shutdown, so reaching a stuck-I/O deadline is
not permission to extend indefinitely or silently leave the node serving votes.
Do not re-ask that settled safety/availability policy.

Under DEC-062, undrained RAM may include already issued approvals. On unclean
restart retain DEC-057 FLAG_NOT_READY and the independent DEC-032/063 own-history
gate. Boot sync is necessary where specified but ordinary quorum-state repair
alone does not prove every issued individual choice was recovered. Successful
queue send, task cancellation or a clean-exit log is not a durable commit proof.
Dirty-stop detection, blocked sync storage and failure propagation are explicit
engineering/verification obligations; no new journal, synchronous hot-path fsync
or rollback is selected by this derived contract.

**Evidence / unresolved enforcement owner.** The read-back daemon shutdown tail
still awaits handles without an explicit overall timer in the inspected section;
flush cancellation follows those waits. The systemd unit supplies TimeoutStopSec=30.
That service setting is the current outer stop boundary, not a daemon-enforced
or measured production guarantee. A direct CLI invocation does not inherit a
systemd service-unit setting. DEC-036 selected systemd-first documentation while
retaining other invocation modes; DEC-034 did not explicitly choose whether
elapsed-time enforcement belongs inside the daemon or only in deployment.
This is the next bounded core-versus-supervisor tradeoff. No external supervisor
semantics beyond the shown configured boundary were tested in this turn.

**Exact pending question — Q-O4-DEADLINE-OWNER-01 (unanswered):**

> Wer soll die feste Shutdown-Deadline durchsetzen: der Node selbst oder
> ausschließlich der Prozessmanager wie systemd?
>
> **A — Deadline im Node, Prozessmanager als äußere Absicherung (Empfehlung):**
> Der Node begrenzt seine Shutdown-Wartezeiten selbst. Das gilt auch beim
> direkten CLI-Start. systemd beziehungsweise der Container-Prozessmanager
> erhält eine etwas längere äußere Stop-Frist als Absicherung.
>
> **B — Deadline ausschließlich im Prozessmanager:**
> Der Node versucht den geordneten Drain; systemd beziehungsweise der
> Container-Prozessmanager erzwingt das Ende bei Fristablauf. Das spart einen
> eigenen Deadline-Pfad im Daemon. Beim direkten CLI-Start muss der Betreiber
> eine entsprechende äußere Begrenzung selbst bereitstellen.

Recommend A for consistent bounded behavior across supported CLI/service/container
invocations and an explicit node outcome before the outer supervisor stop. B is
viable with an explicit supervised-deployment contract, not a claim that standalone
run has an intrinsic bound. Neither policy makes an in-flight blocking fsync
instantly cancellable; runtime/worker teardown, incomplete-stop propagation and
hard-stop fallback must be designed and tested. A timed-out future alone does not
prove a blocking task or process terminated. Preserve supervisor margin without
inventing a measured duration or guaranteeing persistence by timeout. Both keep
idempotent normal signals, operator SIGKILL, safety gates and no node hot-path I/O.

Planned checks: signal repetition never changes the recorded deadline; waits share
one budget; new writes stop; accepted producers finish or yield explicit incomplete
outcome; pending/failed/stalled commits cannot log a clean drain; outer stop margin
is honored; direct CLI behavior matches the selected contract; reboot with lost
choices never bypasses gates. No process signaling, tests or implementation ran.

Next: ask saved A/B, derive the chosen daemon/supervisor boundary and continue
O4/F1 acceptance mapping. Numerical budgets remain measurement tasks, not an
arbitrary next preference question. No source/spec changes or commits this turn.

### CP-0072 — Select idempotent stop signals; ask who enforces the deadline

Recorded DEC-074 / Q-O4-SECOND-SIGNAL-01 A and rejected second-signal early abort.
Derived common remaining-time budget, producer quiescence, truthful completion and
restart gates from existing decisions. Active O4.2 / Q-O4-DEADLINE-OWNER-01: A =
internal node deadline with outer supervisor margin; B = supervisor-only timeout
with explicit standalone-run responsibility. Neither selected. Client date is
2026-10-19. No code/spec edits, commits, tests or external process signals.

Completed checkpoint: **CP-0072**.


### 7.84 Internal deadline selected; stop-CLI completion contract open

Record: O4-DEADLINE-OWNER-DECISION-001 / O4-STOP-CLI-QUESTION-001.
Date: 2026-10-19 (Europe/Berlin). Checkpoint: CP-0073.

**Answer / DEC-075.** The maintainer explicitly selects
Q-O4-DEADLINE-OWNER-01 A. The daemon enforces its own finite graceful-stop
limit, including direct humoco run without an external supervisor. A longer
systemd/container stop limit is the outer fallback. Reject B's supervisor-only
boundary. Internal5–10s and external30s are examples, not selected measured
production constants. Local diagnostics should identify deadline expiry before
an outer hard kill when possible. No claim that a failed/stuck disk flush can
be forced to succeed: preserve finite shutdown and honest incomplete result
under DEC-034 rather than assuming a log entry or timeout creates durability.

**Consolidated node lifecycle.** First stop sets one monotonic deadline and
blocks new mutation admission. Quiesce all accepted mutation/flush producers,
join tracked work within the remaining budget, then finish asynchronous commits
and cleanup. Duplicate ordinary signals preserve the same deadline (DEC-074).
Clean requires verified commits and required producer completion; otherwise
propagate incomplete/failure and terminate using the bounded process teardown
path. A timed-out future does not cancel a blocking storage task; specify an
actual end-of-process strategy and supervisor fallback, preserving redb's valid
committed state and allowing uncommitted work to remain lost/uncertain. Do not
claim an application can defeat an indefinitely uninterruptible OS/kernel I/O.
Stop outcome/reboot detection must not rely solely on best-effort logging or a
marker written only after a disk already failed. Reuse justified startup/clean
metadata where possible, but its exact durability/rollback predicate remains
O1/O2 engineering work. Restart never bypasses DEC-032/063 or FLAG_NOT_READY
merely because a bounded timer elapsed or ordinary shard-state sync finished.

Node policy is now selected; remaining O4 runtime work includes producer tracking,
shared budget propagation, truthful flush result, CLI/control response coordination,
process teardown and measured supervisor margin. No extra fsync on the PoS path,
new signing journal or unbounded final drain is selected. Numeric settings are
measurement/configuration work, not another arbitrary preference question.

**Targeted control/CLI finding.** The inspected `control/server.rs` Shutdown arm
spawns a50ms-delayed token cancellation and returns ControlResponse::Ok before
shutdown. `control/client.rs::shutdown` optionally waits for the socket path to
vanish; timeout_secs==0 skips that wait. `cli.rs::execute_stop` then prints stopped
success. The daemon awaits control-server termination before cancelling/awaiting
the flush worker. Therefore acceptance/socket disappearance alone is not evidence
of completed durable drain. This is a bounded source finding, not an executed
failure reproduction. Preserve the existing wait/nonwait capability; its default
user-facing contract has not been explicitly selected in the decision register.

**Exact pending question — Q-O4-STOP-CLI-01 (unanswered):**

> Was soll `humoco stop` standardmäßig bestätigen: den abgeschlossenen Stopp
> oder nur die Annahme des Stoppauftrags?
>
> **A — Auf das Abschlussresultat warten (Empfehlung):**
> Der Befehl wartet begrenzt auf den bestätigten Shutdown-Ausgang. Erfolg
> bedeutet einen nachweislich sauber abgeschlossenen Stopp; unvollständiger
> Drain oder Zeitüberschreitung wird als Fehler beziehungsweise ungeklärt
> gemeldet. Das ist für Betreiber und Wartungsskripte eindeutig.
>
> **B — Sofort die Auftragsannahme bestätigen:**
> Der Befehl meldet lediglich „Stopp angefordert“ und kehrt sofort zurück.
> Der Node arbeitet seinen begrenzten Shutdown selbstständig ab.
> Für die Feststellung, ob er sauber beendet wurde, ist eine spätere
> Prüfung durch Betreiber oder Prozessmanager nötig.

Recommend A to preserve the existing wait intent while correcting evidence and
completion reporting. B is a legitimate explicit asynchronous CLI contract with
less coupling, never a false claim that durable shutdown already completed.
Existing code/defaults are evidence of current intent, not a new maintainer
selection. An explicit nonwaiting mode may remain available regardless of default;
no flag name or protocol layout is chosen. Request acceptance, daemon completion
and client wait timeout are distinct states. Losing the CLI/control connection
must not revoke operator stop or reset the daemon's deadline. Coordinate final
result delivery without waiting on a control task before the flush that task's
reply needs; avoid this producer/control lifecycle deadlock. Socket unlink/EOF/PID
absence alone is insufficient evidence of clean flush. Reuse existing local
control boundary and return truthful known results; do not invent an unbounded
historical shutdown-log service. Exact lifetime/result transport remains engineering
work. No source changes, test run or actual process signaling occurred.

Next active O4.3: ask saved A/B, then complete the stop/control result table and
return to F1 node-interface verification. Other safety/read/membership proof gaps
remain open; no claim the overall architecture is finished.

### CP-0073 — Select daemon deadline with supervisor fallback; ask stop-CLI acknowledgment scope

Recorded DEC-075 / Q-O4-DEADLINE-OWNER-01 A; supervisor-only B rejected. Derived
finite lifecycle/teardown and honest flush limits, preserving example-versus-fixed
parameters and recovery gates. Source control/CLI acceptance/socket wait does not
prove completed flush. Active O4.3 / Q-O4-STOP-CLI-01: A = bounded wait for verified
shutdown outcome; B = immediate truthful request acceptance. Neither selected.
No code/spec changes, tests, commits or external process signals.

Completed checkpoint: **CP-0073**.


### 7.85 Stop-CLI completion selected; shutdown acceptance table and metrics exposure

Record: O4-STOP-CLI-DECISION-001 / O4-ACCEPTANCE-001 / O5-METRICS-EXPOSURE-QUESTION-001.
Date: 2026-10-19 (Europe/Berlin). Checkpoint: CP-0074.

**Answer / DEC-076.** The maintainer explicitly selects Q-O4-STOP-CLI-01 A.
Default humoco stop waits for actual shutdown completion and released redb file
ownership, so maintenance chaining can rely on exit0. A stuck task, timeout,
incomplete drain or otherwise unverified completion returns nonzero. Reject B's
acceptance-only default. A disconnect/client timeout cannot cancel the node's
operator-requested stop or change its original deadline. This is local operator
control, not public ingress or a new remote shutdown interface.

**Current implementation qualification.** The maintainer identifies execute_stop
as already implementing that intent. Read-back confirms a wait-capable control
client and success/error propagation, but the inspected code watches socket-path
existence and execute_stop treats no socket as already stopped. ControlServer
unlinks that socket on cancellation; daemon shutdown awaits this server before
cancelling/joining the final flush worker. Thus the full clean-completion/process-
exit/DB-release guarantee is not established by that check. A vanished/missing
socket alone is insufficient, and an old clean result must not identify a new
process instance. No live process, lock-release or failure experiment was run.
Reuse the existing control boundary; fix the proof/lifecycle rather than claim
that a polling loop or clean log message already supplies the guarantee.

**Consolidated O4 acceptance table (planned, not executed).**

| Case | Required behavior / evidence |
| --- | --- |
| First stop signal/control request | Close admission once and record one monotonic deadline; subsequent signals do not move it. |
| Accepted in-flight work | Stop/quiesce all possible producers before final persistence drain; track detached QUIC work explicitly. |
| Normal completion | Verify required commits, cleanup and target-process termination/DB release before default CLI exit0. |
| Stalled/failed disk, producer hang or deadline expiry | Finite teardown attempt; truthful incomplete/error result and nonzero CLI status, no invented successful flush. |
| Socket removed/EOF but flush still active | Not stop-success evidence; no early exit0. |
| CLI disconnect or its own wait timeout | Node continues original bounded stop; CLI reports unknown/error, not a successful or cancelled stop. |
| Already stopped / stale socket / replacement daemon | Verify the actual target instance's state; do not infer clean stop only from a path or stale result. |
| Subsequent maintenance | Database can be opened by the authorized next operation; no wrong-instance/PID-reuse confusion. |
| Forced/incomplete exit then reboot | FLAG_NOT_READY and lost-own-choice gates remain; no claim ordinary sync alone recovers all individual approvals. |

O4.1–O4.3 policies are selected. O4 design/delivery is not closed: exact stop-result
transport, complete producer accounting, blocking-worker teardown, crash metadata,
exit-status mapping and measured internal/outer limits remain explicit engineering
and lifecycle-test gates. Do not ask arbitrary duration/micro-policy questions to
substitute for those tasks. C4 read-safety and F1 coverage remain open.

**Next access-boundary review / O5.1.** DEC-037 already selects local/private
dashboard and administrative authority with SSH forwarding, not public admin.
Spec17 §4 and Spec20 observability describe Prometheus metrics but do not explicitly
select whether a public base subset is desirable. `api/routes.rs` currently mounts
/metrics on the same router as payment ingress with body/CORS/trace layers. The
inspected `prometheus_metrics` accepts State only and emits activity, storage,
queue/flush-error, quota and connectivity aggregates; it also performs state/peer
reads. No handler-specific authorization was found in that inspection. Exposure
still depends on listener/deployment and was not tested remotely. Spec17 additionally
proposes peer-labelled metrics; do not assert those labels already appear in the
current exporter. Private admin is settled; only this read-only metrics exception
needs an explicit public-versus-operator choice. Preserve public node-status/health
and payment-client access independently of operator diagnostics.

**Exact pending question — Q-O5-METRICS-EXPOSURE-01 (unanswered):**

> Soll der Prometheus-Endpunkt `/metrics` ausschließlich für den Betreiber
> erreichbar sein, oder soll es eine öffentlich abrufbare Basis-Auswahl geben?
>
> **A — Prometheus-Metriken nur am privaten Betreiber-Endpunkt (Empfehlung):**
> Vollständige Metriken bleiben lokal beziehungsweise über den geschützten
> Betreiberzugang erreichbar. Für öffentliche Clients bleiben die vorgesehenen
> Status-/Health-Endpunkte. Das hält interne Last-, Speicher- und Peer-Diagnosen
> aus dem öffentlichen Gateway heraus.
>
> **B — Öffentliche Basis-Metriken, Details weiterhin privat:**
> Zusätzlich darf das öffentliche Gateway eine ausdrücklich begrenzte Auswahl
> aggregierter Betriebsmetriken liefern. Peer-Identitäten, Topologiedetails und
> detaillierte Quoten-/Fehlerdiagnosen bleiben privat. Das erleichtert externes
> Monitoring, benötigt aber eine gepflegte Trennung der öffentlichen Daten.

Recommend A to reuse the selected operator boundary without an additional public
metrics policy/filter surface. B is viable for an explicit transparency/monitoring
requirement; use an allowlist, bounded cached output/refresh and read admission so
scraping cannot monopolize lock/peer state or write service. Private export also
needs bounded cost; locality alone is not proof of cheapness. No numeric limits,
new backend framework or full metrics overhaul is selected by either option.
Telemetry remains non-authoritative and cannot trigger identity bans. Payment
clients remain permissionless; choosing private diagnostics does not apply the
P2P friends barrier to public ingress. Existing private admin choice is not reopened.

Next active O5.1: ask saved A/B, then fold selected exposure into F1's endpoint/
authority/resource matrix and continue consequential node security/interface gaps.
No production/spec changes, tests, process signals or DB-open experiments this turn.

### CP-0074 — Select verified stop completion; return to node access-boundary review

Recorded DEC-076 / Q-O4-STOP-CLI-01 A: CLI exit0 requires clean completion, process
exit and DB release. Current wait intent was credited; socket unlink alone is not
that proof. Consolidated O4 acceptance/failure table; implementation remains pending.
Active O5.1 / Q-O5-METRICS-EXPOSURE-01: A = private operator metrics; B = explicit
public basic subset with private details. Neither selected. Administrative privacy
remains settled. No code/spec edits, tests, commits or operational experiments.

Completed checkpoint: **CP-0074**.


### 7.86 Private metrics selected; endpoint boundary and client gateway discovery

Record: O5-METRICS-EXPOSURE-DECISION-001 / F1-ENDPOINT-BOUNDARY-001 / O5-GATEWAY-DISCOVERY-QUESTION-001.
Date: 2026-10-19 (Europe/Berlin). Checkpoint: CP-0075.

**Answer / DEC-077.** The maintainer explicitly selects
Q-O5-METRICS-EXPOSURE-01 A. Prometheus metrics and dashboard are exclusively
operator diagnostics through the already selected private endpoint (DEC-037).
Queue, RAM, quota and peer/topology diagnostics belong to the operator; public
export can disclose bottlenecks and internal infrastructure. Reject B's public
base-metrics subset and its extra filtering policy. Public clients retain the
intended status/health and payment interfaces. This is not a P2P friend whitelist
for HTTP clients, a new public-admin exception or automatic banning from telemetry.

**Derived endpoint/authority matrix (requirement, not implementation).**

| Surface | Authority and remaining acceptance obligation |
| --- | --- |
| Lock, chain-lock, client sync and PoW routes | Intended public client functions retain their access tiers and receiver-side bounds; private diagnostics do not restrict permissionless client admission. Exact per-route input/output/resource audit remains F1. |
| /v1/status | Public scoped lock query under the existing read policy; no operator topology dump. A returned lock or a single node's assertion is not automatically a valid14/20 certificate; OPEN-04 remains. |
| /v1/node-status and public health aliases | Minimal client-facing identity/network/service status as required by clients. Do not re-export private metrics under a status alias. Review current storage/quota counters and detailed readiness causes against this boundary. Exact DTO compatibility and cheap bounded readiness computation remain engineering tasks. |
| /metrics and /dashboard including data/history/events/detail routes | Private operator listener/access boundary; verify every subroute and alias. Locality alone does not establish bounded CPU, memory, storage or peer-lock cost. |
| Dashboard administration and local control socket | DEC-037 protected local authority/SSH forwarding, preserved operator veto; audit binding, authentication, permissions and request-origin handling. A bearer check on a public listener does not establish selected local isolation. |
| /peers and /api/v1/network/peers | Current learned-node dump contains internal P2P addresses. Keep internal peer diagnostics private. Whether clients additionally need an explicitly public gateway directory is the next separate question; do not silently turn every learned shard peer into a public gateway. |
| Internal QUIC shard RPC and F2F gossip | Existing learned-peer and friend barriers apply only to internal P2P. A public gateway URL does not establish P2P friendship, membership, ticket maturity or signing authority. |

**Bounded source findings.** `api/routes.rs::build_router` mounts metrics,
dashboard, public status and both peer aliases on the same router. get_node_status
is shared by /health and /v1/node-status and currently returns lock/storage/quota
aggregates alongside node identity/version/network. health_ready returns storage,
peer and sync booleans on failure and reads storage; the public/private split and
bounded-cost gate are not yet verified. These are source observations, not an
external exposure experiment or a complete listener/deployment audit.

`get_peers` calls `network/manager.rs::get_pex_peers`, which snapshots learned
known_network_nodes filtered for banned/suspended status. PeerEntryDto includes
NodePubKey, url formed as https:// plus the same known P2P socket address,
advertised_p2p and a last_seen_epoch filled from response time. This does not
prove a working HTTP gateway, explicit operator publication consent, or the
peer's actual last-seen time. Do not describe the returned list as a verified
public gateway directory. Internal peer listing privacy follows DEC-077/037;
there is no need to ask that same privacy question again.

`human-money-core/src/models/discovery.rs` already defines BootstrapSeedFile
(with network, URLs, mirrors and optional key pinning) and CustomServerEntry.
These are data containers, not evidence of an implemented authenticated download,
refresh or admission policy. The node config contains bootstrap_gateways, but the
bounded source search found config/example/tests rather than a production consumer.
The inspected core source search did not find consumption of the node's /peers
aliases. External wallet/app consumers were not audited. Existing seed/custom
models therefore support a simpler direction, not a claim of complete client
failover delivery. DEC-015 source choice and exact-payload failover remain intact.

**Exact pending question — Q-O5-GATEWAY-DISCOVERY-01 (unanswered):**

> Wie sollen Wallets und Kassen zusätzliche öffentliche Gateways finden,
> wenn bekannte Zugänge ausfallen?
>
> **A — Bootstrap-Listen und eigene Gateway-Adressen verwenden (Empfehlung):**
> Clients nutzen mitgelieferte beziehungsweise aktualisierbare Bootstrap-Listen
> und vom Nutzer ergänzte Adressen. Sie wechseln zwischen diesen Gateways.
> Der Node benötigt dafür kein zusätzliches öffentliches Gateway-Verzeichnis;
> interne Peer-Listen bleiben privat. Dafür müssen die Listen außerhalb des
> P2P-Sperrregisters gepflegt werden.
>
> **B — Zusätzlich öffentliche Gateway-Suche anbieten:**
> Gateways dürfen weitere ausdrücklich zur Veröffentlichung freigegebene
> HTTP-Gateway-Adressen liefern. Interne P2P-Adressen und Topologiediagnosen
> bleiben privat. Das erleichtert das Finden neuer Zugänge, benötigt aber
> zusätzliche Regeln für Veröffentlichung, Aktualität und Missbrauchsschutz.

Recommend A for reuse of existing client configuration models and fewer node
responsibilities, unless decentralized automatic gateway discovery is an explicit
requirement. B is a meaningful resilience/operability tradeoff, not permission
to publish learned P2P sockets. Neither option trusts a directory for payment
truth, forces a central provider, blocks custom gateways, changes frozen checkout
membership, or authorizes node-to-node discovery through public ingress. Seed
provenance, malicious/stale endpoints, client choice, bounded fallback and secret
handling still require acceptance criteria under either option. Avoid sending
provider-specific bearer credentials to a different gateway during failover.
This last boundary is an engineering security obligation, not a new user choice.

Next active O5.2: ask the saved A/B. After selection, finish the public/private
interface matrix and F1 acceptance mapping without manufacturing more privacy
microquestions. Exact router split, client compatibility, auth and resource checks
remain pending implementation/verification. No production/spec changes, test run,
commit, network probe or process operation occurred.

### CP-0075 — Select operator-only metrics; separate gateway discovery from internal topology

Recorded DEC-077 / Q-O5-METRICS-EXPOSURE-01 A, rejected public metric-subset B,
and derived the endpoint/authority boundary. Source findings distinguish current
public diagnostic counters and learned P2P socket listing from intended client
interfaces and explicit public gateway publication. Active O5.2 /
Q-O5-GATEWAY-DISCOVERY-01: A = bootstrap/custom client gateway lists without a new
node directory; B = additional opt-in public HTTP-gateway discovery. Neither
selected. Internal topology privacy stays settled. No code/spec edits, tests,
commits or operational experiments.

Completed checkpoint: **CP-0075**.


### 7.87 Dynamic gateway discovery selected; passive advertisement and stale-cache policy

Record: O5-GATEWAY-DISCOVERY-DECISION-001 / O5-GATEWAY-STALE-CACHE-QUESTION-001.
Date: 2026-10-19 (Europe/Berlin). Checkpoint: CP-0076.

**Answer / DEC-078.** The maintainer explicitly selects
Q-O5-GATEWAY-DISCOVERY-01 B. Expose additional public HTTP gateways through a
simple read interface, with /v1/gateways as an example name. Reuse the node's
passively learned active mesh information rather than relying exclusively on
aging static bootstrap files. Clients should automatically fail over among
available gateways for Hydra resilience. Bootstrap/custom lists still serve as
initial entry points; A's prohibition on an additional node directory is rejected.
The maintainer expects practically every node to provide free-tier ingress and
considers this a small extension. Neither universal public reachability nor
endpoint implementation cost is established by this interview answer.

The exact saved B included explicitly published HTTP endpoints and private
internal topology. The answer selects B and does not explicitly revoke those
bounds. Retain them without another privacy/opt-in preference question. Reusing
known-node data is compatible with storing only public gateway advertisement
metadata alongside the existing entry, not publishing friendship edges, internal
P2P sockets, load counters or diagnostic history. Existing local admin and
operator veto remain unchanged. Public discovery does not authorize client
traffic on internal QUIC or node admission outside the learned/F2F barriers.

**Targeted source findings and technical consequences.**
`network/framing.rs::HeartbeatWirePayload` currently contains node_id, one addr,
time, ticket fields, signature, suite mask, observations and TTL; no distinct public
HTTP URL was found. `network/manager.rs::KnownNodeInfo` similarly contains the
P2P socket and local observation metadata, not a separate gateway URL. Config
NetworkConfig distinguishes rpc_listen_addr, p2p_listen_addr and advertised_addr
(SocketAddr), but has no distinct published HTTP URL in the inspected struct.
The current get_peers construction of https:// plus the known socket therefore
does not establish the required endpoint. NAT, reverse proxy, DNS and TLS may
make the actual public ingress URL different from a local bind or QUIC address.
This is bounded static inspection, not a connectivity experiment.

Derive the missing public-URL advertisement/integrity contract as engineering:
explicit operator publication, origin identity/network binding, authenticated
updates and removal/expiry semantics with bounded representation. Reuse the
existing hourly heartbeat stream and learned-node store where justified; do not
add a third gossip stream, active background pings, a separate consensus service,
or synchronous work on the checkout path. The exact signed encoding/version
transition remains K2/N1 integration work, not established by the current presence
of a heartbeat signature field. An identity signature alone does not prove URL
ownership, public reachability, honesty or committee authority. Clients validate
normal endpoint security independently and treat advertisements as routing hints.

The directory is a bounded public read service: restrict output to intended
public gateway fields, bound response/refresh/allocation work and enforce read
admission without consuming write reservations. Selection/pagination/cache sizes
are engineering tasks rather than arbitrary new user choices. Existing ban and
local eligibility filters need explicit scope; no diagnostic failure becomes
network-wide fraud evidence. Real request failures may drive bounded local
fallback, never gossip bans. Keep the exact original signed payment bytes/T_0,
read-only reconciliation after freshness, total retry budget, and gateway-scoped
credentials. Discovering an alternative does not authorize a new payment or
trusting that gateway's unsupported payment assertions.

**One remaining client availability tradeoff.** Hourly passive presence and
three missed heartbeats (DEC-056) are not instantaneous HTTP reachability. A
client may lose contact with its directory while still holding previously learned
public URLs. Cached contact attempts do not re-admit a node to HRW or establish
payment truth. Whether to retain this last-resort automatic client behavior is
not explicitly selected by discovery B. Distinguish stale routing data from
invalid TLS, explicit withdrawal and verified bans; cached fallback must never
silently override security failures or explicit operator/user revocation.

**Exact pending question — Q-O5-GATEWAY-STALE-CACHE-01 (unanswered):**

> Wenn die Gateway-Suche vorübergehend keine aktuelle Liste liefert: Darf die
> Wallet automatisch auch zuletzt bekannte öffentliche Gateway-Adressen versuchen?
>
> **A — Zuletzt bekannte Adressen als begrenzten Rückfall nutzen (Empfehlung):**
> Die Wallet darf gespeicherte Gateway-Adressen mit ihrem bestehenden Zeit- und
> Versuchsbudget ausprobieren. Eine veraltete Liste allein sperrt dadurch keinen
> noch erreichbaren Zugang. TLS-Prüfungen und ausdrückliche Sperren bleiben gültig;
> erfolglose Versuche verursachen begrenzte zusätzliche Wartezeit und Netzlast.
>
> **B — Automatisch nur mit aktueller Discovery-Liste wechseln:**
> Veraltete Discovery-Einträge werden nicht mehr automatisch ausprobiert.
> Die Wallet nutzt ihre weiterhin konfigurierten Zugänge oder wartet auf eine
> aktuelle Liste. Das vermeidet Versuche zu alten Adressen, kann aber erreichbare
> frühere Gateways während einer Discovery-Störung ungenutzt lassen.

Recommend A for the selected Hydra availability goal without active background
probe traffic. B is a stricter discovery-freshness preference with lower futile
contact cost and possible temporary loss of automatic alternatives. No numeric
cache TTL or attempt count is fixed. Neither option changes the three-missed-
heartbeat HRW policy, cryptographic identity, ticket maturity, signature checks,
quorum membership or payment uncertainty semantics. Stale data does not imply
safe success, and a successful transport connection is not a payment certificate.

Next active O5.2a: ask the saved A/B, then consolidate gateway advertisement,
bounded discovery/failover and public/private endpoint acceptance obligations.
Implementation and wire/HTTP/client failure validation remain pending. No source/
spec changes, test run, commit, external network access or process operation.

### CP-0076 — Select dynamic public gateway discovery; ask stale-client-cache fallback policy

Recorded DEC-078 / Q-O5-GATEWAY-DISCOVERY-01 B and rejected bootstrap/custom-only A.
Derived public HTTP advertisement requirements from the missing distinct URL in
current heartbeat/known-node/config structures while retaining the two-stream
passive gossip and private topology boundaries. Active O5.2a /
Q-O5-GATEWAY-STALE-CACHE-01: A = bounded last-known public-address fallback;
B = automatic discovery failover only from a current list, with configured
entry points still available. Neither selected. No code/spec edits, tests,
commits or operational experiments.

Completed checkpoint: **CP-0076**.


### 7.88 Client cache fallback selected; return to single-status acceptance

Record: O5-GATEWAY-STALE-CACHE-DECISION-001 / O5-DISCOVERY-ACCEPTANCE-001 / C4-SINGLE-STATUS-ACCEPTANCE-QUESTION-001.
Date: 2026-10-19 (Europe/Berlin). Checkpoint: CP-0077.

**Answer / DEC-079.** The maintainer explicitly selects
Q-O5-GATEWAY-STALE-CACHE-01 A and emphasizes its strictly client-side scope.
Wallet/app connection logic (human-money-core and its consumers) may fall back to
locally cached last-known public gateways within the existing bounded attempt/time
budget when directory discovery is unavailable. Reject B's fresh-directory-only
automatic discovery fallback. The maintainer considers cached fallback a normal
resilience practice; this is a rationale, not external research or a new node
consensus invariant. Do not add node-side wallet cache management or negotiate
cache validity through shard consensus. Endpoint authentication, explicit revocation,
provider-specific credentials, exact payment bytes/T_0 and uncertainty semantics
remain. Concrete cache lifetimes and retry tuning are client engineering tasks,
not further node-interview preference questions.

**Consolidated gateway acceptance obligations (planned, not executed).**

| Component | Required scope and verification |
| --- | --- |
| Node directory read | Bounded public gateway metadata only; test field/alias isolation from private P2P topology, metrics and admin, plus read admission and bounded allocation/response cost. |
| Gossip/known-node data | Advertise actual public HTTP URL through existing passive presence only, with justified identity/network/update binding; real QUIC checks for malformed, forged, stale and oversized announcements when delivered. No third stream or active probe loop. |
| Client discovery/failover | Bootstrap/custom initial entries plus dynamic hints; bounded local cached fallback during directory outage, endpoint security and credential isolation, unchanged original request bytes and no extra replacement payment. Client behavior tests belong to core/app, not a new node consensus state machine. |
| Status/payment truth | Gateway discovery and successful connectivity do not establish valid votes, support class, committee authority or a payment outcome. This separate C4 prerequisite remains unresolved. |

O5.1/2/2a human policies are selected. Their implementation, authentication,
resource sizing, compatibility and verification remain pending. No claim of a
complete operational design follows from selecting them. Avoid more preference
questions about cache eviction, URL encoding or response pagination where existing
requirements already permit autonomous engineering.

**Reason for branch return / C4.3.** Resume OPEN-04's consequential acceptance
contract after the bounded O5 policy sequence. This is not a new broad trust
investigation, a re-vote on 1-of-20 routing, a mandatory historical certificate
archive, or a return to predecessor epoch chaining. The exact current interface
claim matters before final-plan closure. A source re-read of Spec06 §3.1 case1
still explicitly permits immediate green goods release for an owner-signed
matching t_id returned by L2Verdict::Verified. DEC-072 selected live-status
rechecking and discarded completed-checkout archive duties, but explicitly did
not prove that a single matching record establishes quorum acceptance. Earlier
notes §3–5.3 and §7.81 already preserve this gap. Retain DEC-015's equal proof
requirements across access tiers and DEC-016's coordinated malicious-owner model.

**Concrete witness, without dynamic committee assumptions.** Fix one legitimate
20-node committee and one consumed output/parent. A malicious owner creates two
genuine authorized divergent candidates X and Y, and pre-shares X with one
colluding shard node before a recipient query. The owner gets Y accepted by14
other committee identities, then presents X to another merchant. If its status
query reaches the colluding node, that node can return the exact genuine X even
when the query discloses only the predecessor challenge tag. A correct owner
signature, matching t_id, and even that one node's response signature do not
establish14 votes for X. No owner signature forgery, committee turnover, clock
boundary or more than six Byzantine nodes is needed for this witness. Even an
honest gateway may transport that one malicious peer reply. This is logical
analysis of the permitted attacker model and documented acceptance predicate,
not an executed end-to-end exploit or a measured attack probability.

Transport-source count and evidence support are distinct: one peer could carry
sufficient independently verified evidence, while one matching owner-signed
record alone is insufficient to infer it. A historical approval bundle likewise
is not automatically a fresh current-unspent proof. The mechanism reconciling
current status, support and conflicts remains C4/S3/S5 engineering/proof work.
Do not silently solve it by always collecting a new14-vote write certificate,
mutating T_0, restoring recursive L2 receipt chains, or claiming every ordinary
read requires14 network round trips. Existing bounded unresolved-attempt recovery
DEC-069 and node approval retention DEC-070 remain available requirements, not
proof that the ordinary read protocol already supplies the needed evidence.

**Exact pending question — Q-C4-SINGLE-STATUS-ACCEPTANCE-01 (unanswered):**

> Darf eine einzelne Statusantwort mit passendem, vom Eigentümer signiertem Lock
> allein die Warenfreigabe auslösen, obwohl sie keine Quorum-Annahme nachweist?
>
> **A — Einzelantwort allein genügt nicht für quorumgesicherten Erfolg (Empfehlung):**
> Die Antwort liefert den gefundenen Lock. Für „Bezahlt“ braucht die Kasse
> zusätzlich einen überprüfbaren Nachweis der erforderlichen Netzwerkbestätigung.
> Fehlt er, bleibt die Zahlung ungeklärt. Wie die Live-Abfrage diesen Nachweis
> effizient liefert, ist technische Arbeit; ein dauerhaftes Archiv alter
> L2-Belege bei der Kasse wird dadurch nicht verlangt.
>
> **B — Einzelantwort als ausdrückliche Vertrauensannahme akzeptieren:**
> Die Kasse darf aufgrund dieser einen passenden Antwort freigeben. Der Ablauf
> bleibt besonders schlank, hängt für diesen Fall aber von der Ehrlichkeit der
> antwortenden Quelle ab. Das wäre eine bewusst schwächere Zusage als die
> 14/20-Absicherung; eine Eigentümersignatur allein schließt den beschriebenen
> Angriff nicht aus.

Recommend A for the existing proof-based checkout target. B is viable only as an
explicitly weaker consumer trust/risk contract, not as a proof of BFT safety or
an inferred prior selection from the live-status interface. Choosing B would
require reconciling that exception with DEC-009/015 and documenting the actual
merchant risk; do not silently redefine FINAL or make paid providers exempt.
A selection establishes an acceptance requirement, not a finished read-evidence
algorithm or a global-finality guarantee under DEC-053. No unsupported probability
or latency guarantee is attached to either option. No option has been selected.

Next active C4.3: ask the saved A/B, then derive the evidence contract and acceptance
checks from the answer while preserving selected client custody/routing and node
scope. O1.1 crash/lost-choice recovery, source continuity and membership proof
obligations remain open before justified readiness/final plan. No source/spec
changes, test run, commit, external research or process operation this turn.

### CP-0077 — Select client-only cached fallback; return to the open read-success contract

Recorded DEC-079 / Q-O5-GATEWAY-STALE-CACHE-01 A with explicit app/core scope;
rejected current-directory-only B. Consolidated gateway delivery/verification
obligations without adding node cache rules. Active C4.3 /
Q-C4-SINGLE-STATUS-ACCEPTANCE-01: A = matching record alone cannot establish
quorum-backed success; B = explicit weaker single-source trust for goods release.
Neither selected. Re-read Spec06's immediate-green predicate and retained the
existing coordinated-owner witness; no current end-to-end exploit/test claimed.
No code/spec edits, tests, commits or operational experiments.

Completed checkpoint: **CP-0077**.


### 7.89 Quorum-backed release selected; status verification scope

Record: C4-SINGLE-STATUS-ACCEPTANCE-DECISION-001 / C4-READ-PATH-AUDIT-001 / C4-STATUS-VERIFICATION-SCOPE-QUESTION-001.
Date: 2026-10-19 (Europe/Berlin). Checkpoint: CP-0078.

**Answer / DEC-080.** The maintainer explicitly selects
Q-C4-SINGLE-STATUS-ACCEPTANCE-01 A. A single matching owner-signed lock without
quorum support must never produce paid or authorize goods release as a confirmed
payment. The PoS requires mathematical14/20 BFT evidence; blind trust in one
source would permit coordinated owner/server double spends. Reject B's weaker
single-source trust exception. Retain DEC-015 equal proof requirements for all
access tiers and the original coordinated attacker model.

One peer/gateway response may carry valid14-distinct-signer evidence; number of
HTTP responses is not number of verified approvals. Verify exact intended lock,
consumed output/parent, network, shard, admissible committee/context, support
class and signatures before promotion. In the already selected N<20 regime,
PROVISIONAL remains explicitly provisional/yellow under its separate policy;
this answer does not invent14-member availability there, declare yellow FINAL,
or silently abolish the island regime. No historical client-certificate archive,
recursive receipt chain, new ordinary checkout round or synchronous node flush
is selected. DEC-072's completed-checkout custody boundary stays intact.

**Evidence distinctions derived from the selection.**

| Evidence | Claim allowed / remaining limit |
| --- | --- |
| Owner signature and matching t_id | Candidate authorization/binding only; cannot imply14/20 acceptance, current canonicality or current unspent status. |
| Single node/gateway signature | Authenticates that source's statement; does not create quorum support. |
| Valid original approval bundle | Establishes the approved statement in its justified original context; not automatically a fresh current-unspent proof or immunity to DEC-053 regional revision. |
| Newly signed live observation | Must use explicit observation semantics/context, freshness and support rules; cannot masquerade as the node's original immutable approval or upgrade an unsupported lock to FINAL. |
| Missing/insufficient/unverified evidence | Remains unconfirmed/uncertain; no paid, no automatic retry with changed bytes, no inferred free slot. |

**Bounded current source audit.** `api/hmc.rs::L2StatusQuery` defaults
read_quorum to1. `api/routes.rs::query_status` performs a local lookup and on
UnknownVoucher may read one tag-selected Top20 peer; it can expose a Verified
lock without a quorum certificate. It invokes assemble_status_quorum_certificate
only when read_quorum>1. This is current implementation structure, not evidence
that consumers enforce DEC-080. Review the meaning of Verified and certificate
absence across core/app consumers; do not let a misleading verdict name authorize
release. Exact output naming/DTO design is K2 engineering, not a new naming vote.

The status collector creates local attestations with
create_attestation_for_network, and remote StatusQuery processing in
network/transport.rs similarly signs currently matching entries. The helper
selects APPROVE_FINAL/APPROVE_PROV domains and uses zero values for three context
arguments. The optional read path therefore is not established as returning exact
stored original approvals. Its requested-count threshold is capped by the local
active-node count and is not proof of the required support class. A small requested
quorum or arbitrary read_quorum parameter must never weaken FINAL14/20 validation.
Audit local self-vote eligibility and actual local record/state before counting
self; choosing a node in HRW alone is not authority to attest a remotely supplied
candidate. These are static findings, not an executed exploit or a complete
collector/consumer security audit.

Do not patch this merely by changing the default read_quorum to14: original
approval recovery, current observations, membership/context, signer validation,
failed/partial responses and replay domains still need their own contracts.
Re-signing after a canonical merge can conflict with a preserved own choice;
separate observations from approval/fraud semantics as already required by P0
and OPEN-05. Preserve DEC-069 bounded read-only retrieval of already issued
approvals and DEC-070 node retention, without pretending those obligations are
implemented or that a historical bundle alone answers current-unspent status.

**Next human tradeoff: scope of expensive verification, not proof strength.**
DEC-080 settles what paid means. It does not explicitly require every monitoring,
reconciliation-progress or data lookup to collect a full quorum. Existing INV-0310
and read_quorum1 favor cheap ordinary lookup; the interface also has an opt-in
collector. The maintainer should choose whether that distinction remains or the
new requirement intentionally changes ordinary status collection. Both options
must enforce the same evidence gate before goods release. No numerical throughput
or exact amplification claim is made: work depends on cached usable evidence and
any necessary collection, which must be bounded and accounted for.

**Exact pending question — Q-C4-STATUS-VERIFICATION-SCOPE-01 (unanswered):**

> Soll die Quorumprüfung gezielt für die Zahlungsfreigabe erfolgen oder bei jeder
> Statusabfrage, auch wenn ein Client nur den vorhandenen Datensatz nachschlägt?
>
> **A — Günstige Statusabfrage und gezielte Quorumprüfung unterscheiden (Empfehlung):**
> Normale Nachschlageabfragen behalten die 1-of-20-Abfrage. Ihre Antwort weist
> klar aus, welcher Nachweis tatsächlich vorliegt. Für die Warenfreigabe fordert
> die Kasse ausdrücklich eine quorumgesicherte Prüfung an; ohne ausreichenden
> Nachweis gibt es kein „Bezahlt“. Das erhält die günstigen Lesezugriffe,
> verlangt aber eine klare Trennung in API und Client-Verifikation.
>
> **B — Jede Statusabfrage quorumgesichert beantworten:**
> Auch reine Nachschlageabfragen verlangen den vollständigen Quorum-Nachweis.
> Das vereinheitlicht den Erfolgsfall der Schnittstelle, verursacht aber bei
> fehlendem vorhandenen Nachweis zusätzliche Abfragen und geringere Verfügbarkeit.
> Die bisherige 1-of-20-Regel für gewöhnliche Statusantworten müsste dafür
> ausdrücklich angepasst werden. Fehlt das Quorum, gibt es keinen bestätigten Erfolg.

Recommend A to retain the selected low-cost read routing while removing the unsafe
inference from found data to paid. B is a deliberate stronger all-status service
contract requiring explicit revision of ordinary INV-0310 behavior, not an automatic
consequence of DEC-080. Neither alternative authorizes new signing decisions on
a read, weak FINAL certificates, silently treating current observations as original
approvals, or using status absence as proof that a slot is free. Exact route/mode
shape, safe defaults for payment consumers, evidence transport and budgets remain
engineering work under either choice. No option has been selected.

Next active C4.3a: ask saved A/B, then consolidate the read/verification matrix
and explicit client acceptance gates before further mechanism analysis. Mandatory
adversarial QUIC checks must cover forged single-peer match, duplicate/wrong
signers/context, partial collection, class downgrade and observation/approval
confusion; HTTP/core consumers must prove no paid transition on insufficient
proof. These are planned acceptance checks, not executed tests. O1.1 recovery,
regional membership/source continuity and current-state proof remain open.
No code/spec changes, test run, commit, external research or process operation.

### CP-0078 — Require quorum evidence for paid; ask verification scope for ordinary status reads

Recorded DEC-080 / Q-C4-SINGLE-STATUS-ACCEPTANCE-01 A; rejected single-source
trust B. Derived explicit evidence categories and checked current default1/optional
status collection, including fresh approval-domain signing versus original-byte
retrieval. Active C4.3a / Q-C4-STATUS-VERIFICATION-SCOPE-01: A = ordinary cheap
lookup plus explicit quorum-backed release verification; B = quorum evidence on
every status request with explicit ordinary-routing revision. Neither selected.
No implementation or read-safety proof claimed; no code/spec edits, tests,
commits or operational experiments.

Completed checkpoint: **CP-0078**.


### 7.90 Targeted quorum verification selected; batch derived details

Record: C4-STATUS-VERIFICATION-SCOPE-DECISION-001 / WF-005 / DETAIL-BATCH-001.
Date: 2026-10-19 (Europe/Berlin). Checkpoint: CP-0079.

**Answer / DEC-081.** The maintainer explicitly selects
Q-C4-STATUS-VERIFICATION-SCOPE-01 A. Keep ordinary lightweight status requests at
read_quorum1 using INV-0310's one-shard-node read policy. For payment/goods release,
the PoS explicitly requests and validates full quorum evidence (read_quorum>=14
in FINAL mode). Reject B's quorum requirement on every ordinary read. Reasons:
scale routine reads, avoid unnecessary multi-peer work, and use the distinction
already represented in L2StatusQuery. A request count alone never substitutes
for valid14 distinct qualified signatures, correct context and support semantics.
Local count capping must not turn an incomplete FINAL query into confirmed success.
Do not infer20-of20 for a parameter20, a new committee, relaxed membership or new
read-time approval decisions. Existing adaptive PROVISIONAL rules remain separate.

The maintainer mentions wallet balance queries; this describes client use of
status data. The blind node still stores no accounts, amounts or balances; the
wallet derives its own view. Sub-microsecond RAM lookup is a target for the local
lookup, not an established end-to-end latency or an audit that every current
read path avoids disk/locks. Avoiding14-way routine collection is a rationale,
not a measured exactly14-fold network saving.

**Workflow change / WF-005.** The maintainer asks whether many detail questions
remain and requests a faster list-based treatment of small details: state each
problem and the intuitively clear solution; important decisions retain normal
A/B presentation. Apply immediately. No fixed question count is justified by
the inventory: many remaining items are engineering/proof/testing obligations,
not maintainer choices. Do not continue converting each such obligation into
a separate interview decision. A batch of derived consequences adds no new
accepted protocol policy. A genuinely new tradeoff still requires a saved exact
question/options and an actual answer. No blanket waiver of safety proof or
implementation validation is inferred from the requested pace.

**DETAIL-BATCH-001 — derived work, not new preference questions.**

| Item | Problem | Derived direction and basis |
| --- | --- | --- |
| DB1-01 | A found lock or a successful HTTP response can be mistaken for paid. | Represent found data and actual confirmation evidence distinctly; payment consumers enforce the quorum gate. DEC-080/081; exact DTO names/shape are engineering. |
| DB1-02 | read_quorum>=14 or signer_count14 can be claimed without sufficient valid votes. | Verify distinct full identities, signatures, justified membership, exact target/context and confirmation class; no threshold downgrade on partial results. Existing checkout rules/DEC-080/081. This is a mandatory validator obligation, not a completed proof. |
| DB1-03 | Timeout/partial collection could trigger a new spend or falsely free the parent. | Preserve uncertain state and exact original request; use bounded read-only reconciliation after freshness. DEC-009/060/068/073. |
| DB1-04 | A learned P2P socket is not necessarily a usable public HTTP gateway. | Publish actual intended public HTTP endpoint metadata through existing passive discovery; expose no internal topology dump. DEC-077/078. Authentication/encoding remains technical work. |
| DB1-05 | Automatic gateway fallback could disclose a provider-specific bearer secret. | Keep credentials scoped to their authorized gateway/provider; use only access actually configured for the alternative, including normal free-tier PoW where applicable. DEC-015/078/079 and access-tier separation; no automatic credential portability. |
| DB1-06 | Private diagnostics might remain reachable through aliases/subroutes. | Apply the selected private boundary to the whole metrics/dashboard/admin route families and equivalent aliases; audit public status DTOs for private diagnostic re-export. DEC-037/077. |

These directions follow selected requirements; they are neither a new approval
request nor a claim of production changes. Translate them into the eventual
component/acceptance plan. Sizes, field names, pagination, cache tuning and test
fixtures are autonomous engineering unless a concrete new tradeoff emerges.

**Material remaining work — not small-detail batch items.**
1. C4/S5: define a sound live-read/current-state evidence contract, separating
   immutable original approvals from current observations and regional revision.
   Existing optional collector does not become safe merely by setting14.
2. O1.1/O2: justify same-key resumption after issued-but-unflushed choice loss;
   the finite bucket-quarantine claim still has the later-fresh-conflict witness.
3. S2/S3: justified regional membership/source continuity and safe recovery during
   turnover. Keep DEC-053 availability/revocability and no predecessor baton.
4. F1: finish semantic invariant/interface/failure-scenario coverage and a
   prioritized plan with explicit proof and adversarial wire-test gates.

These are work packages, not four promised remaining questions. Broad trust
research remains stopped; existing accepted policies are not reopened to manufacture
choices. Return point after this batch is C4.3b, technical consolidation of the
read-evidence contract with OPEN-04/05/06. No human question is pending at this
checkpoint. Before another A/B, investigate which consequential tradeoff actually
needs maintainer intent. No source/spec edits, tests, commits or external operations.

### CP-0079 — Retain cheap reads and targeted quorum verification; batch routine details

Recorded DEC-081 / Q-C4-STATUS-VERIFICATION-SCOPE-01 A and rejected all-status
quorum B. Recorded WF-005, refining WF-004: grouped problem/solution treatment
for derived details; A/B retained for important unresolved choices. Saved
DETAIL-BATCH-001 with six derived obligations and their decision bases. Active
C4.3b is technical read-evidence consolidation, not a pending preference question.
No remaining-question count, complete read proof or implemented delivery claimed.
No code/spec edits, tests, commits or operational experiments.

Completed checkpoint: **CP-0079**.


### 7.91 Confirmed detail batch and live-read verification contract

**Current qualification (DEC-083 / §7.93):** LRC-001 is historical where it requires
original-payment approval proof for current live clearance. Use LRC-002 instead.
Full-key validation, freshness, truthful outcomes and own-choice safety remain.

Record: DETAIL-BATCH-001-CONFIRMATION / LRC-001 / C4-CORE-NODE-RECONCILIATION-001.
Date: 2026-10-19 (Europe/Berlin). Checkpoint: CP-0080.

**Answer / DEC-082.** The maintainer explicitly confirms all six directions in
DETAIL-BATCH-001 as requirements for later implementation and requests the next
steps. Preserve the exact DB1-01–06 meanings in §7.90. No new alternatives were
posed, no other policy was selected, and this is not authorization to implement
production changes or alter binding specifications. WF-005's grouped treatment
of routine details and separate important A/B choices remains in force.

**Inspection basis.** Bounded static source re-read at node HEAD03b5e2e and core
HEADb9bbdf7; node working changes are the two interview memory files only. Core
has unrelated untracked fuzz/ and a simulation __pycache__; neither was touched.
No executed protocol/consumer exploit or test run is claimed. Relevant sources:
node api/routes.rs::create_attestation_for_network and
assemble_status_quorum_certificate; api/hmc.rs::wrap_and_sign_verdict_with_quorum;
api/dto.rs::QuorumCertificateDto; network/transport.rs StatusQuery;
core services/l2_gateway.rs::verify_quorum_plausibility,
evaluate_quorum_certificate and process_l2_verdict; P0 §§4–6.

**Observed integration gaps, requalified against selected policies.**
- Node status collection and StatusQuery handling mint signatures through the
  APPROVE_FINAL/APPROVE_PROV helper. The helper binds parent+lock, network domain,
  shard/status and three zero context fields. DTO timestamp is not in that
  helper's signed digest. Updating that timestamp cannot establish freshness.
  Current status signatures are not proven exact-original approval retrieval.
- The status collector counts self when selected in the committee; the inspected
  local self-signing branch does not itself establish local record/own-choice
  authorization. A noncustodial gateway must not create a vote merely because it
  received an entry remotely or appears in a selected roster.
- The core plausibility helper uses short u16 node IDs, count-derived thresholds
  and hash-score statistics. The inspected helper does not cryptographically
  verify each node signature or establish full-key eligible roster membership.
  Its evaluate_quorum_certificate caller can return ConfirmFinal from that result;
  absence of a certificate can return ConfirmLocal. The outer gateway signature
  and owner-proof checks do not establish the missing14-node proof. This records
  a bounded observed path, not a claim that every external app releases goods.
- The node envelope wrapper signs the serialized verdict, not the optional
  certificate or a client read challenge. Hence outer authenticity alone cannot
  authenticate a substituted certificate or its freshness. Independently valid
  signed evidence may protect a field; do not require redundant signing blindly,
  but bind every fact that influences acceptance through a justified proof.
- Node QuorumCertificateDto::is_quorum_reached is documented as a length check,
  not a cryptographic verifier. No caller may promote its boolean to paid.
- P0's explicit observation/approval distinction is useful, but P0's durable-
  before-response wording was superseded by DEC-062 and its historical client
  receipt-custody/recursive-validation language by DEC-055/072. Current DTO
  comments also broadly reject historical node-certificate requirements. These
  sources cannot be copied wholesale as the final contract; needed active
  collision/support proof and client archive duties are different questions.

**LRC-001 — conditional verification contract, derived design draft.** This
consolidates accepted requirements and necessary verification boundaries. It is
not a newly approved wire format, a complete live-read algorithm, or a safety
proof under missing membership/state-transfer premises.

| Rule | Contract / owner |
| --- | --- |
| LR-01: explicit purpose | Cheap lookup returns data and actual evidence class at default1. Payment verification is an explicit strong operation; found/HTTP200/ConfirmLocal alone cannot release goods. Node DTO, core consumers and PoS all enforce this distinction. |
| LR-02: exact target | Verify the canonical requested voucher/root, consumed output/parent and spend binding, network and shard, owner authorization and authentic root lifetime. Use checked canonical commitments rather than trusting server-selected fallback shard IDs or duplicating fields unnecessarily. Shared protocol/core domain rules own this mapping. |
| LR-03: evidence roles | Distinguish owner intent, immutable node approval, current node observation, and transport/gateway authenticity. Each role has unambiguous authenticated type/domain/context. A collection of observations is not relabeled original payment approvals or node fraud evidence. |
| LR-04: real quorum | FINAL validation needs14 distinct qualified full NodePubKeys from one applicable frozen at-most20 committee/context, individually verified signatures and correct class/target. No count, bitmap, short ID, statistical score, available-node cap or request parameter substitutes for it. PROVISIONAL remains explicitly separate. |
| LR-05: historical versus current | An original valid approval proves its original statement. Current usable state needs its own justified live predicate. Neither a stale receipt alone nor fresh signatures over unsupported found data automatically satisfy both. Define admissible live-quorum semantics before accepting it as a clearance signal. |
| LR-06: freshness | Current-state assertions bind the actual read context/challenge and their statement to the verifier's request, or an equivalently justified replay defense. Unbound DTO timestamps and a fresh transport session do not prove a record is current. Exact encoding/window is engineering; timing assumptions and read linearization/compatibility need proof. |
| LR-07: read-only discipline | Repeated status reads do not create a new lock, change OwnChoice, renew wallet T_0 or issue a contradictory original approval after merge. Existing original approvals may be returned verbatim; optional current observations remain separate. No sync disk write on the checkout path. |
| LR-08: canonical/conflict handling | Validate competing support using DEC-064 before class/hash resolution. Weak hints cannot veto a valid14/20 result or promote an unsupported candidate; partial/absent data cannot prove a free slot. Regional revision risk remains DEC-053. |
| LR-09: truthful failure | Missing, insufficient, incompatible or invalid evidence never yields paid. Report bounded incomplete/unknown versus invalid as appropriate; preserve existing intent and permit justified later reconciliation. No new commercial payment/refund state in the node. |
| LR-10: bounded collection | Reuse existing direct shard RPC and read budgets. Freeze relevant collection context, bound bytes/CPU/concurrency/total attempts, stop on quorum or impossibility, and treat NOT_READY/quorum cancellations neutrally. No automatic second write round, new gossip stream or expanded signer pool is selected. |
| LR-11: custody/availability | Completed merchants keep the L1 deed/purchase journal, not a mandatory L2 certificate archive. Nodes retain their own original approvals per DEC-070. Required live exclusion/support evidence must survive justified recovery/turnover; how to achieve this without a historical receipt chain is still an explicit design gate. |
| LR-12: one verifier contract | The selected shared Rust protocol library defines signed preimages, domains, full identities and proof-validation results. Node, gateway and core use the same validation semantics. Provider payment/tier changes admission priority, never the proof predicate. |

The acceptance expression is deliberately conditional:

```text
CanReleaseFinal(request, response, recipient_basis) :=
    ExactAuthorizedTargetAndLiveRoot(request, response)
    AND QualifiedConfirmationEvidenceValid(response, FINAL14, recipient_basis)
    AND CurrentUsableStateEvidenceValid(request, response, recipient_basis)
```

QualifiedConfirmationEvidenceValid must not count an observation as an original
approval, or accept sender-supplied membership solely because it is self-consistent.
CurrentUsableStateEvidenceValid is not implemented/proved by this expression.
It must state which assertions, knowledge/canonical basis, timing and recovered
state permit acceptance. Do not implement it as true after parsing14 signatures.
The expression implies neither global finality nor atomic physical goods handover.

**Component/delivery sequence (candidate, not final master plan).**
1. Specify the two proof predicates and request/slot/context mapping in the
   shared protocol work (K2), preserving living-mesh regional authority and no
   predecessor baton. This is prerequisite to changing the production collector.
2. Define original-approval retrieval versus live observation messages, safe
   signing preconditions, and necessary active evidence retention/repair. Resolve
   the historical-proof/current-observation wording conflict explicitly.
3. Replace plausibility-only promotion in core with the shared verifier and
   make payment consumers fail closed. Preserve ordinary data lookup behavior.
4. Wire node/gateway collection, response proof binding, budgets and neutral
   cancellation to those verified types; do not let unsupported self votes count.
5. Validate node QUIC behavior, HTTP boundaries and actual client release gates
   against the same fixtures; only then claim the gap closed.

**Adversarial acceptance matrix (planned; not executed).**

| Case | Required result / boundary |
| --- | --- |
| Genuine matching owner lock, one colluding peer, no quorum | Data may be found; no paid. Real QUIC -> HTTP -> core release-consumer fixture. |
| Fourteen entries with forged signatures or repeated full key under varied short IDs | Reject proof; count each genuine eligible full identity at most once. Shared verifier plus wire/API consumer checks. |
| Valid signatures for another network/parent/spend/shard/context | No transplant; no mixing membership snapshots to reach14. |
| Optional certificate added/replaced after a valid gateway verdict signature | Accept only if independently complete target/context-bound evidence passes; outer signature alone is insufficient. |
| Old signed response retimed via unsigned DTO timestamp or replayed under a new read challenge | Not a fresh live-state proof. |
| Thirteen valid FINAL approvals or requested14 capped to a smaller local set | No FINAL success; explicit incomplete/unknown, not silent downgrade. |
| Honest node approved A, then canonical state selects B | Preserve OwnChoice A; no fresh B approval from a status read; lawful observation B cannot be reused as approval or fraud proof. |
| Noncustodial gateway qualifies for HRW but lacks justified local signing state | No local approval invented from remote candidate possession. |
| Missing source/history after turnover, valid old bundle or matching empty digests | No fabricated current readiness/acceptance; expose the actual missing prerequisite. |
| Quota exhaustion, oversized proof, NOT_READY or cancelled stragglers | Bounded failure, no write-queue pollution or false peer misconduct; no paid without proof. |

**Unclosed gates and next action.** LRC-G1 = sufficient live-current-state evidence
under the selected regional/1-of20-plus-targeted model. LRC-G2 = compatible authority
and state/support continuity after turnover/loss. LRC-G3 = issued-own-choice safety
and observation/approval separation after crash/merge. LRC-G4 = concrete shared
encoding, storage cost and executed wire/client validation. These map to OPEN-04,
02/03/09,05/10 and06/08/14 respectively; they are not four new interview questions.
Active C4.3b remains on G1, with G2/G3 dependencies. Next investigate which surviving
RAM/persistent state can justify a live assertion after merge or turnover and what
minimal authenticated evidence must accompany it. Investigate technically before
asking another A/B; no routine field/nonce naming vote is needed. Do not reopen
broad trust research or erase client no-archive policy to bypass the gap.
No source/spec edits, tests, commits or external network operations this turn.


**LRC-STATE-001 — stored-state follow-through.** A further targeted read confirms
that HmcRamIndex::locks stores lookup_tag -> L2LockEntry. That entry describes
the owner-signed transaction, not a14-full-key signed approval bundle or verified
confirmation class. put_hmc_lock serializes that entry to TABLE_HMC_LOCKS.
SyncPayload transports (lookup_tag, L2LockEntry) for HMC records; legacy LockRecord
has status and a BTreeSet of short NodeIds, which is not a signature bundle.
Therefore the inspected containers alone cannot answer whether a found entry
was owner-valid only, individually approved, or quorum-supported. No whole-repo
absence claim is made; this is a concrete missing integration in the shown path.

HmcRamIndex::insert_or_check(PartitionSync) verifies the owner entry signature
and resolves divergent candidates by canonical hash in the inspected branch.
It has no verified support bundle/class input there. This is insufficient to
implement DEC-064's class-first rule and cannot by itself establish a safe source
for newly minted status approvals. Do not claim exploitation without checking
all upstream gates and real wire behavior; record the structural integration gap.

Derived repair boundary: keep per-entry owner data, verified admitted support and
the node's own immutable signing choice semantically distinct. A replica copy is
not a local original vote; an unconfirmed synced record remains unconfirmed until
its support is independently validated. Reuse existing storage/TTL and selected
own-choice work where justified, rather than adding an unrelated history service.
Digest equality over owner-lock content cannot alone prove support completeness;
include authenticated support coverage in recovery acceptance, whether committed
as part of the chosen state representation or verified through associated evidence.
Exact representation, evidence availability after full turnover, storage cost and
safe activation remain LRC-G1/G2/G3 work. No change to the selected fixed-bucket
seal, digest projection or client no-archive requirement is silently approved.
This establishes where the proof must connect to storage/sync; it does not finish
the live-current-state algorithm. The next concrete step is to specify the minimal
admitted-support/own-choice fields and their preservation/import rules against
these source containers, then check the merge/crash witnesses before implementation.

### CP-0080 — Confirm implementation batch; consolidate live-read verifier and acceptance gates

Recorded DEC-082 confirming DB1-01–06. Added conditional LRC-001 with evidence roles,
12 verification boundaries, source findings at node03b5e2e/coreb9bbdf7, delivery
sequence and ten planned adversarial cases. No proof, tested exploit, deployed
fix or final implementation plan claimed. Active C4.3b remains technical analysis
of LRC-G1 live evidence, dependent on membership/state continuity and own-choice
safety; no human question pending. No code/spec edits, tests, commits or operational
experiments; unrelated core untracked work preserved.

Completed checkpoint: **CP-0080**.


### 7.92 Active support proof across full turnover: storage versus confirmation availability

**Withdrawn premise (DEC-083 / §7.93):** The maintainer rejects this archival
versus unavailable framing. Neither option is selected. This preserved question
does not impose old-certificate retention or block current qualified shard replies.

Record: C4-ACTIVE-PROOF-CONTINUITY-001 / LRC-G2-PREREQUISITE-001.
Date: 2026-10-19 (Europe/Berlin). Checkpoint: CP-0081.

**Prerequisite and branch reason.** LRC-STATE-001 shows that the inspected HMC
state/SyncPayload preserves owner records without verified quorum support.
Before claiming the live-read contract buildable, resolve the conjunction of
DEC-045 (full original-signer turnover must remain serviceable), DEC-072 (completed
merchants have no certificate archive duty), DEC-070 (each node retains its own
original approval) and DEC-080 (no confirmed release without valid quorum proof).
DEC-065 already requires minimum sufficient winning/exclusion proof; it does not
specify its representation or demonstrate surviving proof availability after all
original holders disappear. This question makes the storage/availability impact
explicit rather than silently introducing a full certificate archive at each node.
C4.3b stays partial with LRC-001; C4.3c is active on this G2 prerequisite. Return
to the live-evidence predicates after selection. No broad trust research is reopened.

**Bounded witness / not an executed test.** Committee C accepts X with14 original
approvals. The completed merchant discards its L2 bundle while retaining its L1
deed/purchase. Over time all original approval holders leave; replacement nodes
receive only X's owner entry and unauthenticated class/signers metadata. A later
request cannot reconstruct14 genuine original approvals from those bytes. The
same entry bytes could also have been copied before any quorum accepted X.
Fresh observational signatures establish current holders' statements, not the
missing original approval history. Treating those observations as payment approvals
would require a separately justified protocol/acceptance model and signing-safety
rules; it is not a free consequence of a successful lookup or matching digest.
LRC-G1's current-state predicate remains necessary even if original proof survives.

This is not a theorem that every possible live-state-quorum protocol needs old
receipts forever. A sound alternative authenticated support construction may
replace a retained original bundle, but none is established in the inspected
path/selected draft. Do not use an unexplained live14 observation bundle as that
replacement. Conversely, retaining old proof alone does not prove current unspent
state or remove DEC-053 regional revision risk.

**Concrete resource consequence.** With the selected individual64-byte Ed25519
approvals,14 signature values alone occupy14*64=896 bytes for a complete bundle,
before signer/context/reference/encoding overhead. This is a representation-size
arithmetic bound, not a measured per-node footprint: deduplication, proof placement,
replication and context sharing can change actual costs. Current144-byte Byte-Years
assumptions cannot silently be treated as including every possible proof layout.
No new compression/signature scheme, all-node full-bundle replication, price change,
mandatory extra checkout round or new gossip stream is selected here. A minimal
active-state proof must still respect TTL, bounded admission and async persistence.

**Exact pending question — Q-C4-ACTIVE-PROOF-CONTINUITY-01 (unanswered):**

> Wie soll der erforderliche Bestätigungsnachweis verfügbar bleiben, wenn alle
> ursprünglichen Unterzeichner eines noch gültigen Locks ausgeschieden sind?
>
> **A — Notwendigen Nachweis mit dem aktiven Shard-Zustand erhalten (Empfehlung):**
> Das Netz bewahrt den für aktive Locks erforderlichen überprüfbaren
> Bestätigungsnachweis und übernimmt ihn bei der Zustandsübertragung. Das kann
> ein kompakter Quorum-Beleg oder ein nachweislich gleichwertiger Beweis sein.
> Die Kasse benötigt weiterhin kein Belegarchiv. Dafür müssen zusätzlicher
> Speicher und Übertragungsaufwand ehrlich eingeplant werden; nach Wurzel-TTL
> plus Grace-Period wird der zugehörige Lock-Zustand bereinigt.
>
> **B — Bei verschwundenem Nachweis keine bestätigte Freigabe mehr ermöglichen:**
> Knoten behalten nur ihre eigenen Zustimmungen und den sonst nötigen
> Sperrzustand; ein dauerhaft verfügbarer übernommener Quorum-Nachweis wird
> nicht zugesichert. Sind die ursprünglichen Nachweise nicht mehr erreichbar,
> bleibt eine Prüfung ungeklärt, auch wenn der Lock selbst noch vorhanden ist.
> Das spart Beweisspeicher, schwächt aber die bisher gewünschte Nutzbarkeit
> nach vollständigem Wechsel der Unterzeichner.

Recommend A to preserve the combined selected continuity, no-client-archive and
quorum-evidence requirements. B is a deliberate narrower confirmation-availability
contract and would explicitly qualify DEC-045 rather than falsely claim all earlier
serviceability promises remain met. Neither permits accepting an unproven lock,
new contradictory original signatures, synchronous hot-path commits, historical
client receipt chains, predecessor-committee permission or permanent expired-lock
tombstones. A does not choose physical proof replication or a settled alternative
proof algorithm; those require a concrete bounded design and validation. Choosing
A also does not justify safe state recovery, current-live acceptance or same-key
crash recovery by itself. Both options keep LRC-G1/G3 and all original safety gates.
No option has been selected.

Next: ask saved A/B, then determine minimal active evidence/retention and transfer
acceptance without silently choosing an unmeasured whole-certificate-per-node
layout. Preserve the existing no-archive client boundary and current-state proof
gap. No new code/spec edits, tests, commits or external operations.

### CP-0081 — Expose active proof continuity as the next consequential tradeoff

LRC-001 follow-through identifies a concrete prerequisite: active owner records
alone do not preserve authenticated support through loss of every original proof
holder. Recorded the source-bound witness, existing-policy conjunction and896-byte
raw-signature arithmetic without claiming a full footprint or impossible alternative
protocols. Active C4.3c / Q-C4-ACTIVE-PROOF-CONTINUITY-01: A = preserve necessary
proof with active shard state, accounting for cost; B = explicitly accept loss of
confirmation availability when original evidence vanishes. Neither selected.
DEC-082/DETAIL-BATCH-001 acceptance from CP-0080 retained. No production/spec
changes, tests, commits or operational experiments.

Completed checkpoint: **CP-0081**.


### 7.93 Current state authority selected; historical proof archive premise withdrawn

Record: C4-ACTIVE-PROOF-CONTINUITY-CORRECTION-001 / LRC-002.
Date: 2026-10-19 (Europe/Berlin). Checkpoint: CP-0082.

**Explicit correction / DEC-083.** The maintainer rejects the premise of
Q-C4-ACTIVE-PROOF-CONTINUITY-01. Do not map this answer to either A or B.
The transaction/deed lives on the L1 voucher. L2's parent->child record is the
atomic collision barrier. Once that state has been safely registered and
synchronized, a competing spend is refused against the existing RAM/redb record,
independently of the identities that originally signed it. Current qualified
shard nodes answer and attest from their synchronized state. A lock does not
become unconfirmed merely because old signers leave. Historical14-signature
bundles are not to be carried across shard generations; the proposed896-byte
archive burden is explicitly rejected. No weakening of DEC-045 serviceability
or selection of §7.92 B's unconfirmed-after-turnover contract is inferred.

**What was wrong in the previous framing.** It made preservation/reconstruction
of original approvals a prerequisite for current clearance, then presented an
archive versus availability tradeoff. That was not a logical consequence of
DEC-080/081, which demand quorum-backed live verification, and conflicted with
the state-based model/no-receipt-chain boundary. Preserve §7.92 as historical
rejected reasoning. The arithmetic14*64=896 remains arithmetic only; it is not
a required per-lock footprint or justification for a new archive requirement.
LRC-001's original-approval gate and LRC-STATE-001's proposed inherited support-
proof necessity are superseded for current clearance by LRC-002 below.

**Bounded source alignment.** Re-read crypto.rs::compute_shard_digest_at at node
HEAD03b5e2e. It filters active non-VOID records, sorts by parent and hashes the
parent/receiver/nonce/id projection, not historical node signature bundles.
This matches the selected state digest purpose. Do not silently add old signatures
to its projection, add receipt-chain migration or make readiness depend on
historical signer reachability. Digest equality alone still establishes equality
of its encoded projection, not committee authority, source completeness, safe
old-write cutoff or lost-own-choice recovery. Those already recorded independent
proof obligations remain; the correction is a selected contract, not an executed
end-to-end recovery or safety proof.

**LRC-002 — replacement current-state verification contract.**

| Area | Current direction and limits |
| --- | --- |
| Cheap lookup | Preserve DEC-081 default1 and honest indication of what is actually attested. One match cannot yield quorum-backed paid by itself. |
| Strong live verification | The PoS verifies14 distinct currently qualified shard identities attesting the exact requested live lock/state in a compatible current context. Sufficient current live-state evidence is the selected basis; original approval bundles are not an additional prerequisite. PROVISIONAL stays separately labelled. |
| Signing purpose | Give current-state attestations an authenticated read-state purpose, exact target and freshness binding. They count toward the live-read quorum, not as reconstructed original write approvals. A current read may sign a state response without initiating a new spend/write decision. |
| Merge and own choices | A node that originally approved A may report synchronized canonical B in its current-state role while retaining OwnChoice A. Such a report is not a second original approval or automatic equivocation proof. Original approval domains/fraud checks must not confuse these roles. |
| Live authority/readiness | Count only justified current shard participants with safely recovered relevant state. Raw owner data supplied by a caller, membership-by-count, a single digest or an unverified snapshot does not replace that prerequisite. Existing FLAG_NOT_READY, DEC-057/058 and same-key gates retain their actual scope. |
| State handover | Transfer the necessary active collision records and enforce owner/root/canonical integrity and existing class-first conflict rules. No old-quorum archive, original-signer permission or predecessor baton is introduced. Exact state validation/metadata and coverage remain technical work. |
| Retention | Keep live exclusion state and the separately selected own signing-safety records under their TTL policies. Do not turn the latter into a requirement to retain/forward every retired node's approval bundle. No permanent expired-lock tombstones. |
| Client custody | Keep the L1 voucher/purchase locally before goods release. No completed-checkout certificate archive/back-fill duty. Missing historical receipts alone cannot invalidate a valid current-state quorum. |
| Uncertainty | Missing/invalid current quorum, unready or incompletely recovered state, expired root, incompatible context or unresolved genuine conflict can still prevent confirmed success. Retired original signers alone cannot. |

The revised acceptance shape is:

```text
CanReleaseFinal(request, response, recipient_basis) :=
    ExactAuthorizedTargetAndLiveRoot(request, response)
    AND QualifiedCurrentLiveStateQuorumValid(request, response, FINAL14, recipient_basis)
```

The current-quorum predicate includes authentic full-key signatures, exact
state/request binding, replay resistance, justified current committee/readiness
and applicable canonical/exclusion checks. It has no extra OriginalApprovalBundle
predicate. Encoding this predicate or selecting it as policy does not prove its
membership, state-transfer or crash-safety premises. Keep those as named gates;
do not declare global objective knowledge from one local view or reopen DEC-053.

**Reconcile earlier records.** DEC-080's14/20 proof requirement is satisfied by
the selected valid current-state quorum, not necessarily an original checkout
bundle. DEC-081 retains the cheap-versus-strong split. DEC-069's existing-original-
approval recovery remains a possible bounded exceptional operation; it must not
be a mandatory path when a valid current-state quorum can answer. DEC-070/032
own signing-safety retention and lost-history safeguards are not erased by rejecting
old shared bundles. DEC-065 minimal state does not become a full receipt archive.
Historical P0 text saying observations never count toward14 applies to original
payment-approval aggregation; it cannot prohibit the distinct live-read14 quorum
selected here. P0/DTO/core/source alignment is future authorized implementation/
specification work, not a silent production modification in these notes.

**Bundled implementation implications (derived, no new preference vote).**
- Shared protocol/core: introduce explicit current-state proof semantics and
  full-key signature verification; do not use short-ID plausibility as proof.
- Node/gateway: emit/collect current-state responses from justified ready peers,
  bind the read context/freshness, and stop using a write-approval signature as
  an ambiguous current-state answer. Existing count/budget/neutral-cancellation
  constraints remain.
- Storage/sync: preserve actual active exclusions through validated digest-pull,
  with no historical-signature expansion. Verify class/canonical handling and
  own-choice independence without requiring prior committee approval.
- Acceptance checks: all original signers can leave; after justified sync the
  current quorum can confirm the existing lock without old receipts. Also test
  competing live spend rejection, forged/duplicate/wrong-context state signatures,
  replayed state responses, read-after-merge without false slashing, incomplete
  sync/readiness refusal and truthful quorum shortfall. These are planned checks.

**Next action.** Return active focus to C4.3b, applying LRC-002 to current read
signature/verifier and recovery contracts. No human question is pending; do not
re-ask the rejected archive/availability choice. The next safety prerequisites
are justified state coverage, current membership/freshness and same-key own-history
recovery, kept separate from historical certificate availability. Follow WF-005:
derive routine details in batches, ask A/B only for actual unresolved intent.
No source/spec edits, tests, commits or external operations this turn.

### CP-0082 — Correct historical-archive premise; select current synchronized state quorum

Recorded DEC-083 and withdrew Q-C4-ACTIVE-PROOF-CONTINUITY-01, neither A/B.
LRC-002 supersedes LRC-001's original-proof prerequisite: qualified current nodes
attest synchronized state; no inherited historical signature archive, no unknown
solely from retired original signers. Confirmed digest projection excludes old
signatures; own-choice, source coverage/readiness and regional membership proof
gates remain. Active C4.3b resumes live-state protocol integration, no human
question pending. No production/spec changes, tests, commits or operations.

Completed checkpoint: **CP-0082**.


### 7.94 New-chat handoff after the current-state correction

Record: INTERVIEW-HANDOFF-CP0083.
Date: 2026-10-19 (Europe/Berlin). Checkpoint: CP-0083.

The maintainer requests a saved handoff/summary for a new chat. No new architecture
decision or question is introduced. DEC-001–083 remain indexed in §2; compact state
is the resume cursor. Use these two memory files, not a new parallel handoff file.

**Resume procedure and scope.** Read applicable AGENTS.md, prompts/architecture_interview.md,
the whole compact state, the decision/open-item indexes in §2, and §§7.90–7.94.
Read older referenced evidence only as needed. German maintainer communication,
English repository documents. The interview authorizes targeted research/inspection
and its own notes/state, not production/spec changes, commits, deployment or a broad
test campaign. Preserve concurrent work. Last source observations were node03b5e2e
and coreb9bbdf7; inspect current revisions/working changes before repeating claims.
The only node modifications at handoff inspection were the two interview documents.

**Critical correction — DEC-083 / LRC-002.** L1 holds the transaction/deed. L2 holds
and synchronizes active parent->child collision exclusions. Current qualified shard
nodes attest their safely synchronized state; FINAL clearance requires14 distinct
verified currently qualified signers in the applicable context. No historical
quorum-bundle archive or original-signer availability is required after turnover.
Do not reconstruct the rejected896-byte archival premise or declare a recovered
lock unknown solely because original signers left. Q-C4-ACTIVE-PROOF-CONTINUITY-01
is withdrawn, neither A/B. LRC-002 (§7.93) supersedes conflicting original-proof
prerequisites in LRC-001/P0 draft reasoning. Those earlier texts are not accepted
requirements merely because they are detailed. Preserve independent own-choice/
crash safeguards; rejecting shared old bundles does not erase DEC-032/063/070.

**Recent accepted requirements.**
- DEC-080/081: default read_quorum1 / INV-0310 remains cheap lookup; only explicit
  quorum-verified payment clearance can mean paid. A matching owner lock, HTTP200,
  request parameter or plausibility/count check is insufficient on its own.
- DEC-082 confirms the six-item implementation batch: found versus confirmed,
  actual full-key quorum validation, honest timeout/original-intent handling,
  real public HTTP advertisements, provider-scoped credentials and private
  diagnostics on every alias/subroute (§7.90–7.91).
- DEC-077–079: operator-only metrics/dashboard; additional public gateway
  discovery via existing passive knowledge; bounded cached gateway fallback is
  strictly client/app policy. No internal topology dump or new gossip stream.
- DEC-074–076: duplicate ordinary stop signals preserve the original bounded
  deadline; node has internal deadline plus longer supervisor fallback; stop CLI
  exit0 requires actual clean completion/process exit/DB release, not socket unlink.

**Working style — WF-005.** Group routine derived details into short problem/solution
lists; analyze implementation choices autonomously. Ask one saved A/B question only
for consequential unresolved human intent, with a justified A recommendation when
available. Do not manufacture micro-questions, re-ask accepted choices or promise a
remaining-question count. Requirement selection, design proof, implementation and
executed verification are different states. Broad recursive-trust research remains
stopped unless explicitly invoked separately.

**Immediate next action.** Active C4.3b: integrate the current live-state proof
contract into the component/acceptance plan. Check authenticated read-purpose
signatures, exact target/context and replay binding, current full-key membership,
ready synchronized sources, and core fail-closed verification. Inspect the known
source gap where node status uses approval-domain signatures and core's considered
path uses short-ID/statistical plausibility; those are static findings, not executed
wire exploits. A read-state quorum is distinct from a new original spend approval:
a lawful post-merge state report must not become false equivocation evidence.
No human question is pending at handoff.

**Keep remaining safety gates explicit.** Safe state coverage/activation during
turnover and data loss; current regional membership and timing assumptions; same-key
resumption after issued-but-unflushed own-choice loss (O1.1); actual class-first merge
and own-choice separation. Finish semantic invariant/interface/failure-scenario
coverage before the final prioritized plan. Existing22-family/113-ID inventory is
provisional, not verified completeness. Planned adversarial QUIC/HTTP/core-consumer
checks have not been executed by this interview. No historical certificate archive
is an acceptable shortcut around these proofs.

### CP-0083 — Save new-chat handoff without reopening architecture choices

Saved §7.94 resume summary, DEC-083/LRC-002 correction, WF-005 batching, latest
accepted requirements, scope limits and concrete C4.3b next action.83 decisions
retained, no new question. No source/spec changes, tests, commits or operations.
The compact state and this checkpoint are the durable handoff; the chat reply
provides a copyable German resume prompt.

Completed checkpoint: **CP-0083**.


### 7.95 Live-state proof integration: request binding, signer readiness and proof boundaries

Record: LRC-002-INTEGRATION-001 / DETAIL-BATCH-002 / C4-READINESS-FINDING-001.
Date: 2026-10-19 (Europe/Berlin). Checkpoint: CP-0084.
Active node: C4.3b. Decisions remain DEC-001–083. No question/options or new
maintainer selection: the following derives from DEC-017/032/038/053/057/058/
064/080–083. It elaborates LRC-002, without reinstating LRC-001's archive premise.
Design is conditional on unresolved authority, state-coverage and crash premises;
implementation and executed verification remain pending.

**Targeted source evidence.** Node HEAD03b5e2e, core HEADb9bbdf7. The inspected
files retain these SHA-256 prefixes at the end of inspection: node api/routes.rs
639ae64aeb6b6ba9, api/hmc.rs 6268d0b8a3a0e0b4, network/transport.rs
86ced3f70bd86a76, network/framing.rs 729c53af5e6e8158; core
services/l2_gateway.rs 8c5cf57cd3ca705b. These are static source observations,
not reproduced wire attacks or a whole-repository security audit. Concurrent
edits appeared in AGENTS.md, sim-core crypto.rs/types.rs and node daemon.rs;
they were left untouched. The added AGENTS.md historical-signature guardrail
agrees with DEC-083. Do not infer recovery correctness from concurrent comments.

- routes.rs::create_attestation_for_network (539–579) still signs the approval
  domain over parent+lock, network/shard/class and three zero context values;
  its DTO timestamp is unsigned. StatusQueryPayload (framing.rs 374–388) and
  L2StatusQuery (hmc.rs 234–243) have no explicit recipient live-read nonce.
  challenge_ds_tag locates a collision slot; its name does not make it a fresh
  unpredictable verifier challenge. The gateway's signed request envelope is
  distinct from a shard response bound to the recipient's request.
- routes.rs::assemble_status_quorum_certificate (1201–1349) constructs a local
  status attestation without the write collector's sync-readiness condition or
  a local record validation in that self-signing branch. It also caps requested
  support by total_active and calls collection with expected_members=None.
  Inspected peer collection does perform Ed25519 verification and full-key/TLS
  checks when available (680–792, 975–1002); it also has a legacy short-ID fallback.
  This is useful existing verification, not the complete LRC-002 membership,
  read-purpose or freshness predicate. Do not claim node collection has no
  signature verification merely because the core consumer lacks it.
- transport.rs checks is_sync_ready in LockVerifyRequest (357–368), but not in
  its StatusQuery branch (859–1153) before the matching-record signature at1133.
  That branch checks record match/shard/validity and request-side admission; those
  do not establish safe recovered state or independently justified membership.
  **New finding:** the inspected status-signing path can reach its signing helper
  without the write-path readiness test. Its practical exploitability and full
  deployment path are untested. A signed ready=true field would not repair this.
- core verify_quorum_plausibility (80 onward) still checks short IDs/count/score,
  without verifying the supplied node signatures. evaluate_quorum_certificate
  (537 onward) can produce ConfirmFinal from it. A target-bound owner signature
  or gateway envelope does not replace the missing current-shard proof.

**DETAIL-BATCH-002 — problem → derived solution, not a new policy vote.**

| Item | Problem | Derived integration contract / owner |
| --- | --- | --- |
| DB2-01 | Original spend approval and a lawful post-merge report could be confused. | Use distinct authenticated proof kinds/domains for original write approval and current live-state response. The shared library defines canonical length-prefixed domains. Read signing never inserts a spend or overwrites OwnChoice. A report of canonical B after own approval A is not a second original approval or automatic fraud proof. |
| DB2-02 | A valid signature might concern another output or a weaker statement. | Bind protocol/network, read purpose, canonical root/shard, exact consumed-output/parent and requested lock/state predicate, returned state/class and collection context. Commit canonical data transitively where justified; avoid redundant fields. Confirmation that a payment lock is registered is not an unqualified proof that every descendant/output remains unspent. C1/K2 must map each query to the actual slot/predicate. |
| DB2-03 | A gateway could replay/retime an old response, or manufacture the challenge itself. | For strong verification, the recipient originates a fresh unpredictable read nonce and retains the outstanding target/context locally. Every counted shard response authenticates that nonce and its exact answer; verification requires the same outstanding request and a bounded local collection lifetime. A new independent check uses a fresh nonce, including after client restart. This adds no server challenge registry, no new wallet T_0 and no write retry. Nonce size/encoding and bounded parameters are engineering. |
| DB2-04 | Fourteen genuine keys need not be the current qualified committee. | Freeze one at-most20 full-key committee context per strong collection; authenticate its canonical commitment in the responses. Validate tickets, admission, presence and HRW selection against a justified recipient basis, not only a sender-supplied roster/hash. Signers also validate their own authority. No mixed-context union, rank21 replacement, count/statistics shortcut or short-ID fallback for strong proof. A commitment binds a roster; it does not prove that roster legitimate. |
| DB2-05 | A stateless gateway or recovering replica might sign from copied input. | At every countable self/remote live-state signing site, require current authority and safely installed relevant state, a coherent local slot observation, valid root and canonical/class handling. Input possession and roster inclusion are insufficient. Unready sources may serve bounded retained recovery data or clearly qualified lookup data; they supply no countable strong-state vote. Keep ordinary read_quorum1 routing and lookup cost. |
| DB2-06 | A collector could silently weaken the requested proof. | Group only compatible answers for the same request/target/context; count each verified full key once, require14 for FINAL and distinguish PROVISIONAL. Return explicit incomplete/invalid/unknown on failure. Do not cap FINAL to reachable support or treat absence as a free slot. Existing collection/CPU/byte/concurrency bounds and neutral NOT_READY/cancellation rules apply; read timing is not silently changed to the write800ms deadline. |
| DB2-07 | A request may be fresh while its source state is incomplete or changes during collection. | Require the separate readiness/coverage premise and a coherent observation during the bounded request. Bind any claimed observation time/basis if used; unsigned timestamps and fresh TLS are insufficient. A nonce proves request linkage, not global recency, a common atomic shard snapshot, safe turnover or irrevocability. Mixed lawful observations may yield no matching quorum without proving fraud. |
| DB2-08 | A valid gateway envelope or existing DTO boolean could bypass client checks. | Shared verification returns an explicit verified live-state result only after target/root, signatures, distinct current members, purpose/context and replay checks pass. Payment consumers enforce it plus durable L1 purchase custody. Raw DTOs, requested read_quorum, is_quorum_reached, ConfirmLocal and plausibility-only ConfirmFinal cannot supply that result. All ingress tiers use the same predicate. |

This is a semantic contract, not a selected byte layout or a new persistent
epoch/version mechanism. No common whole-shard digest is required for every
per-slot live read merely to bind its answer. The existing authenticated context
must express the actual chosen scope. There is no new gossip stream, historical
receipt migration, server purchase logic or client certificate archive.

**Signing and readiness must have separate predicates.**

```text
CountableLiveStateResponse :=
    CurrentAuthorityJustified(scope, collection_context)
    AND RelevantStateSafelyRecoveredAndUsable(scope)
    AND CoherentAuthorizedSlotObservation(target, root, canonical_state)
    AND AuthenticatedReadPurposeAndRequestBinding(response)

NewOriginalWriteApproval :=
    CurrentWriteAuthorityAndStateUsable(scope)
    AND OwnSigningChoiceSafetyJustified(identity, consumed_output)
    AND the selected live-write collision/admission rules
    AND authenticated original-approval purpose and write binding
```

This separation prevents read reports from rewriting OwnChoice or posing as
new spend votes. It **does not authorize** a lost-history node to count for live
clearance merely because it downloaded visible locks. Whether a proposed recovery
basis establishes the live-state predicate while the own-choice gate remains closed
requires a concrete safety argument. DEC-032/063 stays unrestricted for new
binding votes; no blanket extension or relaxation of its scope is selected here.
No synchronous disk wait is added to RAM-first write acceptance by this contract.

**Coverage boundary — why fresh signatures alone do not finish the design.**
For two14-member sets inside the *same fixed20-member universe*, intersection
is at least14+14-20=8; under an actually enforced six-Byzantine bound, at least
two intersecting identities are honest. This arithmetic only helps preserve a
prior accepted exclusion if the relevant honest holders retain and serve that
state and the transfer/read protocol uses it correctly. Full turnover has no
such same-set intersection guarantee. Safe transfer can preserve the exclusion
without preserving old signature bundles or asking old members for permission;
its actual coverage construction remains S3.4a/OPEN-03/09 work.

Concrete counterexample obligation:14 new/partially recovered nodes can freshly
sign the same nonce and matching incomplete state. All their signatures can be
genuine while an earlier live exclusion is absent. Thus neither freshness nor a
self-reported readiness bit can establish the premise they rely on. Distinguish
this known recovery omission from DEC-053's accepted risk of later discovery of
a competing admissible regional branch. No unknown global-history oracle is
required, and no retained old-quorum certificate is proposed as the solution.

**Planned acceptance obligations; none executed.**

| Case | Required outcome / verification boundary |
| --- | --- |
| All original signers retired; justified active state recovered | Current14 can verify the existing lock without old receipts; a fresh conflicting live write is rejected. Real QUIC/HTTP/core consumer. |
| is_sync_ready=false but a matching lock remains in RAM/disk | No countable state signature from QUIC or gateway self-signing; bounded recovery serving may continue. Verify automatic gate, not a fixture that merely hides the response. |
| Gateway obtains a remote lock but lacks justified local shard state | No invented self vote, even if HRW lists it. |
| Replayed response, retimed DTO, wrong nonce/purpose/root/output/network/context | No current FINAL proof; a correctly signed gateway wrapper cannot repair the mismatch. |
| Forged signatures, duplicate full keys, legacy short IDs, authentic nonmembers | Shared verifier rejects/counts only genuinely eligible distinct full keys; receiver and client release-gate coverage. |
| Thirteen matching votes, mixed committee contexts or incompatible state replies | No FINAL or silent downgrade; preserve uncertainty and bounded reconciliation. |
| Honest A approval followed by canonical B live report | OwnChoice A unchanged; report B cannot satisfy original-approval aggregation or alone trigger equivocation sanctions. |
| Matching fresh digest/state replies from incomplete recovery; omitted page/delta or bad install | No readiness from self-consistent agreement alone; fail the concrete recovery acceptance predicate. |
| Partial/oversized/flooded proof, cancellation, root expiry during verification | Bound resources, enforce actual root lifetime with justified time, keep NOT_READY/quorum cancellation neutral; no false paid result. |

**Next action and closure status.** C4.3b's interface/verification duties are now
consolidated against LRC-002. It remains active and technically incomplete:
derive a concrete source/coverage and activation predicate under DEC-058/059/061/
062, then apply the same-key lost-own-choice witness of §7.71 separately.
Membership/time premises remain explicit; do not reopen broad trust research.
The next bounded analysis must distinguish an intact authoritative state source,
a replica still recovering and a new current member, and explain why their
readiness cannot be established by circular empty/matching responses. Keep
snapshot/delta/expiry and class-first state integrity in that proof without
introducing signature archives or mandatory predecessor permission.
No genuine new human-intent tradeoff has been established, so no A/B is pending.
F1 specification/interface/scenario reconciliation remains mandatory before a
final prioritized plan. Only the two interview documents were edited; no tests,
production/specification edits, commits or external operations were performed.

### CP-0084 — Consolidate LRC-002 and expose the status-signing readiness gap

Recorded DETAIL-BATCH-002, dated source evidence, separate write/live-state
signing predicates and nine planned adversarial acceptance cases. Added the
static finding that inspected status signing lacks the write-path sync-ready
check; did not claim an executed exploit. Replay binding and fixed-set quorum
intersection are explicitly insufficient to prove safe full-turnover coverage.
DEC-001–083 retained; no new decision or question. Active C4.3b continues on
readiness/authority premises, with S3.4a and O1.1 dependencies. Concurrent
production changes were preserved. No tests or production/spec edits by this
interview; only notes/state updated.

Completed checkpoint: **CP-0084**.
