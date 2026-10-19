# 99. FAQ: Attack Vectors, State Continuity and Evidence

> **Status:** Explanatory consolidation of accepted requirements through DEC-089. The numbered specifications and [invariant/evidence registry](INVARIANT_REGISTRY.md) define the rule locations. Examples below do not establish implementation or executed protection.

## 1. Can a gateway split its quota across many shards?

Receiving shard nodes must enforce the authenticated ingress quota and bounded admission locally; a gateway promise or HTTP-side test alone is insufficient. Monotonic signed accounting can expose an actual same-author contradiction when the necessary statements meet. A digest alone neither transports every signed counter nor guarantees detection of all forks. Cross-shard detection/coverage needs explicit evidence.

Do not add a third receipt-sampling gossip stream. Mesh gossip remains hourly presence plus verified first-party equivocation. Capacity rejection is backpressure, not automatic fraud. Counter fraud needs its complete specified signature/context predicate before permanent node sanctions.

## 2. Does a botnet merge force a historical database dump?

No unsolicited global history dump is accepted. L1 deeds/causal proofs remain client-custodied. Authorized active collision state is nevertheless synchronized by bounded shard-direct digest PULL when needed; otherwise old active spends could be forgotten. Validate root, authorization, state coverage and durable install before a new shard votes.

A botnet's topology, work and rate determine what reaches peers. Bounded admission and pacing are defenses; “zero bytes of processing” or “zero bots can ever qualify” is not proved. Blind L2 cannot infer real-world value or humanity from arbitrary lock bytes.

## 3. What if a genuine friend is bribed to introduce Sybils?

One F2F edge can introduce identities. Work validation, 24-hour observed ticket maturation, bounded newcomer pacing and edge budgets constrain injection. They do not prove a universal 99.9% drop rate, permanent immaturity of every bot or at most six adversaries per committee. Multiple malicious bridges and pre-aged valid tickets must remain in the threat model.

Operators choose social peers; private topology diagnostics aid that choice. The friend has no financial liability and is not banned for association. Sanction the actual author only after verified first-party fraud evidence.

## 4. Why no global linear hash chain of a gateway's locks?

A per-gateway chain spread over many shards can require fetching foreign links or larger proof structures. No such chain is selected for checkout. Authenticate each specified request/context and enforce receiver-side quotas within bounded resources. Missing historical chain links cannot be silently replaced by claims that digest collision detection proves every ingress fork.

## 5. How does a real village differ from an isolated bot cluster?

The intended operating model is one organically connected network; small startup meshes and deliberate islands are exceptions. An honest village may have genuine users, valid L1 roots and several independent links. A malicious cluster may also have valid work, multiple bridges and formally valid L1 material. L2 cannot distinguish their social meaning from bytes alone.

PROVISIONAL communicates small-mesh risk. Social attachment, mining costs and limits are defenses, not a mathematical classifier of genuine communities. No fixed half-second merge, automatic zero-impact attack rejection or universal failure-free upgrade is claimed.

## 6. Can an attacker spend in both sides of a partition?

Yes, consider colluding agents, prearranged requests or different connectivity. Physical separation does not prove dual ingress impossible. If each side forms a qualified regional committee, accepted policy permits regional confirmations which may conflict later; FINAL is not a theorem of global irreversibility.

On healing, admit valid confirmation classes: class2 FINAL/Regional14 outranks class1 adaptive PROVISIONAL; class0 partials cannot establish a confirmed winner. Within the highest admitted confirmed class choose `min(H_canon)`. Goods already delivered cannot be recovered by convergence alone.

Two disjoint honest committees can each approve a different branch without any one node double-signing. Do not ban honest losing signers. Node equivocation requires two genuine incompatible original decisions by the same NodePubKey in the same protected slot; L1 owner fraud is a different predicate.

## 7. Is joining with one friend safe?

One reciprocal configured friend can introduce the node. The new identity still needs valid work, full identity/ticket binding and observed ticket maturation. Admission does not prove the Byzantine bound or globally common membership. A single friend can censor its gossip; at least three independent neighbors improve resilience.

After three consecutive missed hourly heartbeats an admitted peer is excluded from later snapshots. This is separate from 24-hour ticket incubation, network FINAL stability, calendar accounting and per-shard readiness. Exact restart/reentry and slot timing need their own consolidated proof. No active background presence probes or global bad-peer gossip are added.

## 8. Do extra friends buy more ingress quota?

No friend-count billing or financial staking is selected. Friendship edges support topology, not transferable quotas or liability. More physical nodes may add capacity but must independently satisfy admission and rate constraints; they do not automatically create independent adversary ownership or guaranteed linear throughput.

Billing, VIP Byte-Years access and operator administration remain outside the blind consensus core through the local control boundary. NodePubKey is never a client bearer secret. Public ingress is open under its tier's admission rules.

## 9. Can clients escape a censoring gateway?

Clients may discover public gateways and select alternates. Cache fallback, endpoint rotation and bounded hedging belong to client logic. Retain and retry the exact signed intent, including original context where required, rather than inventing a new payment after a timeout.

A gateway cannot manufacture proof: payment release verifies fourteen distinct qualified full-key signatures from one justified frozen twenty-member committee, with the exact target/purpose/context and freshness. Six missing contributions can be tolerated only when the remaining fourteen are timely and ready. Network-wide denial of service or additional misses can still prevent checkout.

Shard-direct access remains subject to the internal P2P learned-peer authorization rules. A public client is not granted an arbitrary direct QUIC session merely to bypass its gateway. Public gateway discovery exposes no private dashboard or metrics.

## 10. Do lazy nodes get replaced by rank 21 during checkout?

No. Freeze the at-most-twenty roster once. At fourteen valid FINAL votes cancel stragglers neutrally; otherwise fail at 800 ms or sooner when the remaining eligible votes cannot complete quorum. Do not query ranks 21–40 as replacement signers.

A later justified snapshot can change membership after passive presence changes. New assignments stay NOT_READY until safe recovery. A gateway's signer bitmap is not a global bad-peer report; other nodes must not accumulate hearsay penalties from it. NOT_READY, NOT_IN_SHARD, capacity rejection, unsent local-admission work and post-quorum cancellation are neutral. Local diagnostic timeout counts do not prove maliciousness or authorize permanent bans.

## 11. Can floods exhaust RAM, CPU or disk?

Finite resources can be exhausted unless every relevant path is bounded. The required defenses are checked frame lengths and bounded allocation, cheap stateless BLAKE3 work/token buckets before expensive crypto, storage-time quota, persistence reservation before RAM mutation, bounded workers/batches/coalesced waiters and protected shard/sync budgets. HTTP 429 plus `X-Required-Difficulty` pushes work back to free-tier clients; valid work still does not override capacity.

Actual memory includes indexes, own signing choices, root/verification context, pending state, queues and allocator overhead. A 144-byte accounting basis or 192-byte record example is not a bound on total RAM. redb is not assumed to recycle all locks daily; locks live to root expiry plus 30 seconds. Reject unknown-origin successor TTLs. No universal OOM/disk immunity or unmeasured sub-microsecond end-to-end claim is made.

## 12. What happens from one node to twenty?

Below twenty, all participating nodes cover all 65,536 shards with `Q(N)=floor(2N/3)+1`: 1/1, 3/3, 7/10, 13/19 are examples. This is PROVISIONAL. At stable `N >= 20`, the existing 24-hour network hysteresis permits FINAL with fourteen of twenty. There is no third HIGH_ASSURANCE tier.

Network size alone cannot promote a lock or prove roster authority. Reattestation needs actual qualified current evidence after safe synchronization; a status bit, timer or bitmap alone cannot prove it. A failed FINAL request never becomes PROVISIONAL simply because only thirteen members answered.

## 13. What if village and larger-mesh locks conflict?

Validate both intents, contexts, confirmation classes and available support. A lone conflict report is not permission to replace a confirmed branch with a smaller hash. Apply class priority before same-class canonical hash. An honest reporter or honest losing signer receives no fraud sanction.

L1 ownership/causality remains client-held; L2 transfers active locks. Causal VOID effects retain required own-choice safety information until TTL plus grace. A current canonical report may truthfully name B while that node's immutable original approval remains A; separate signature purposes prevent treating those as contradictory original approvals.

## 14. What if every original signer has left?

Departure alone does not invalidate a safely synchronized lock. Current authoritative ready shard nodes attest their current objective state. No original fourteen-signer archive, recursive receipt chain or periodic re-signing of every idle lock is required. Original own choices are retained by their authors for signing safety through `root.valid_until + 30s`; optional exceptional original-evidence retrieval is distinct from current clearance.

The hard question is safe transfer: a new assignment is NOT_READY; an admissible request starts one bounded job for the shard. Establish justified complete snapshot coverage for every still-relevant root, including locks older than 24 hours, bounded concurrent deltas and durable installation. Matching digests from fourteen unready empty nodes do not establish continuity. Neither an old founder manifest nor arbitrary current rosters solve authority or omission detection. Source/authority/activation proof remains required, without a mandatory unavailable-predecessor permission chain.

## 15. Can heartbeat spam frame an honest neighbor?

Bounded parsing, authentication, freshness and exact-replay deduplication precede admitted forwarding. Do not charge stale or duplicate traffic to honest forwarding allocation; bound its receive cost separately. The proposed ±60-second window uses approved network-adjusted time, not naive OS time.

A permanent ban requires the author's own fully verified incompatible signed statements under the complete fraud predicate. The old shortcut “two timestamps less than fifty minutes apart” omits duplicate identity/context, restart and clock proof obligations. A one-hour startup delay alone does not establish universal safety; detector-slot collisions can miss proof, never create guilt. See Spec 11 for the explicitly qualified detector sketch. Timeouts, remote accusations and private telemetry never establish fraud.

## 16. Does rolling denial of service cause a punishment cascade?

Avoid automatic global guilt from local delays. A transport timeout cannot by itself distinguish crash, selective silence, overload or packet loss. Quorum-completion cancellation is neutral; receiving capacity failures do not propagate blame. No global bad-peer rumors, signer-bitmap punishment or reputation-driven bans are introduced.

Local F2F backoff follows direct observations and the approved forgiving/circuit-breaker policy; it is separate from passive hourly eligibility and permanent first-party fraud sanctions. Keep essential gossip and bounded recovery progress available. The old proposed repair “query ranks 21–27 until fourteen answer” is rejected because it expands the frozen signer set. Under sufficient loss checkout honestly fails; convergence and safety are not a guarantee of uninterrupted availability.

## 17. Does a matching ordinary status entry mean paid?

No. INV-0310 keeps ordinary reads cheap at `read_quorum=1`. A genuine matching LockEntry proves neither current quorum nor safe current authority. For payment release, request and verify complete live evidence: all signatures, full distinct keys, justified single frozen roster, exact network/shard/root/target/state/purpose/context and a fresh recipient challenge. Mixed snapshots, reused challenges and gateway booleans are insufficient. Share the verifier and enforce its result in every payment consumer.

Live-state answers are purpose-separated from original writing approvals. Reporting current state does not archive or recreate historical bundles and cannot overwrite own original decisions. An unready source may serve clearly qualified data without supplying a countable strong-state vote.

## 18. What prevents crash-induced contradictory own votes?

Durable-before-Release (DEC-087 restoring DEC-029): reserve bounded capacity before RAM mutation; the asynchronous worker atomically persists exact lock plus immutable own choice; await its exact durable acknowledgment before releasing any binding original signature, including idempotent/cache replies and gateway self votes. No RAM guard is held across that wait, and unmanaged blocking disk I/O stays off runtime request threads.

Before commit no original vote has escaped; after commit the decision is recoverable if committed storage remains intact. Ordinary process crashes require no root-risk markers, quarantine or automatic identity abandonment. Actual storage loss/rollback, failed recovery and concurrent same-key operation remain separate safety boundaries. Disk-commit expectations such as 1–5 ms are unmeasured; the local durable SLA target never permits early release.

Bound batch age, size and count; coalesce identical work with bounded waiters; preserve successful commits when a requester times out. A timeout means unresolved, not rollback or proof of no side effects. Shutdown has finite admission/drain deadlines and never emits an uncommitted vote.

## 19. Is the architecture now proved and implemented?

The five interview blocks are approved requirements. This documentation reconciliation is not a production implementation, executed test campaign or complete security proof. Outstanding work includes independently justified current authority, complete source coverage/safe activation, exact clock/slot/reentry/seal behavior, all-path durable acknowledgments and actual storage-loss safety.

For each rule, acceptance needs the affected interface, positive/adversarial scenario, expected result and evidence status. Security defenses require real receiving-side QUIC checks, relevant HTTP/payment-consumer checks and actual crash ordering tests. Unit simulations and plausible names/counts alone cannot certify deployed protection. Metrics/dashboard remain private and diagnostic; they never decide truth or bans.
