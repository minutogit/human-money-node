# Quorum Resilience, Membership Continuity, and Web-of-Trust Operations

Date: 2026-10-13  
Scope: Architectural research against the supplied research brief and current source.  
Status: Recommendation and mathematical counterexamples; no production implementation or wire-level validation performed.

## Recommendation

Keep the checkout rule at **14 distinct signatures from one authenticated, fixed 20-member shard committee**. Contact its members concurrently and return immediately after the fourteenth valid signature. Use bounded client gateway failover for path failures and local operator diagnostics for repair. Heartbeat expiry may drive routing hints and reconfiguration proposals; it must not independently redefine the set authorized to issue a competing FINAL certificate.

This combines Option 1 and Option 5 with a restricted version of Option 4. Actual membership changes require a separately specified, proven background handover. They cannot be made safe merely by waiting two hours, computing HRW deterministically, or assigning a configuration hash.

There is no unconditional combination of irreversible finality, service through arbitrary partitions, and uncoordinated membership replacement. If seven incumbent members remain unavailable, a 14/20 shard must refuse new FINAL certificates until sufficient members recover or an independently justified recovery mechanism becomes available. Moving this limitation to the background does not eliminate it.

## 1. What the current source establishes

The following are source observations, not claims that an exploit was executed over QUIC:

| Location | Observation | Consequence |
| --- | --- | --- |
| `crates/humoco-node/src/api/routes.rs:972` | The initial fanout is capped at 20 peer candidates; after 300 ms remaining candidates are launched. Several failure branches also immediately launch the next candidate. | Expansion is not limited to the staged timer. |
| `crates/humoco-node/src/api/routes.rs:1210` | The peer candidate list is truncated to 40 while `required_q` comes from `required_quorum(total_active)`. | FINAL collection retains the 14-signature threshold across the expanded pool. |
| `crates/humoco-node/src/network/transport.rs:473` | The shard receiver accepts responsibility through rank 40. | Fixing only the gateway collector leaves the server voting policy inconsistent. |
| `crates/humoco-node/src/network/manager.rs:1934` | `active_hrw_nodes()` uses local presence freshness and local suspension state. | Identical HRW code can rank different local candidate sets. |
| `crates/humoco-node/src/network/manager.rs:38` | Presence freshness is two hours, measured from local receipt. | The proposed TTL already has a local implementation; it is not global membership agreement. |
| `crates/humoco-node/src/api/dto.rs:87` | `is_quorum_reached()` checks signature count against the reported network-size threshold. | This helper alone is not a cryptographic certificate verifier. |
| `crates/humoco-node/src/api/routes.rs:832` | The approval digest call uses epoch/session/flags zero and carries no committee commitment. | The examined approval path does not authenticate a shared committee version. |
| `crates/humoco-sim-core/src/types.rs:894` and `docs/03_routing_und_sharding.md:65` | A score threshold uses `K_max = 40` while quorum size is capped by `R = min(20, N)`. | Statistical eligibility does not establish BFT intersection. |
| `crates/humoco-sim-core/src/client_flow.rs:305` | The light-client helper checks Bloom membership and score anchors. | These checks cannot substitute for an authenticated committee and intersecting quorum family. |
| `crates/humoco-node/src/api/routes.rs:1951` | Quorum shortage currently returns HTTP 503. | A proposed 504 deadline response is an API design change, not current behavior. |

Local self-signing also needs to be included in the exact same 20-member list. A list of 20 peers plus the gateway is not automatically a 20-member committee. Membership must be counted by the full `NodePubKey`, with exactly one active ticket per member, never by socket address or a 16-bit identifier.

## 2. Safety arithmetic

For two quorum sets of size `q` inside the same eligible universe `C` of size `K`:

`minimum intersection = max(0, 2q - K)`.

If at most `f` members may sign contradictory locks, a sufficient intersection requirement is:

`2q - K > f`, equivalently `q >= floor((K + f) / 2) + 1`.

This additionally assumes that honest nodes retain their signing commitments, every vote binds the same network/shard/parent/proposal/configuration, and membership is authenticated. Signature validity by itself proves neither membership nor honesty.

For fixed `q = 14`, `f = 6`:

| Eligible universe K | Minimum intersection | Safe against six equivocators? |
| ---: | ---: | --- |
| 20 | 8 | Yes |
| 21 | 7 | Yes, if the same fixed 21-member universe is authorized everywhere |
| 24 | 4 | No |
| 27 | 1 | No |
| 28 | 0 | No, even without equivocation |
| 40 | 0 | No, even without equivocation |

At K=40, one conflicting spend can collect votes from ranks 1–14 and the other from ranks 15–28. Every server can obey first-seen and sign only once. No individual equivocation proof exists. Later choosing `min(H_canon)` repairs the eventual state but cannot undo goods already handed over or justify both certificates having been called FINAL.

The guarantee is per committee. An overall network Byzantine fraction below one third does not imply that every 20-member shard contains at most six Byzantine members. HRW distributes tickets; it does not prove operator independence. Any probabilistic shard-security argument needs assumptions about admission, ticket grinding, adversarial resources, and the number of shards and epochs considered. Resource-based identity admission is not an absolute Sybil exclusion theorem. [Douceur, The Sybil Attack](https://www.microsoft.com/en-us/research/publication/the-sybil-attack/).

## 3. Assessment of the five options

### Option 1: strict 14/20 and gateway failover

Recommended for checkout, provided all gateways and signers use the same authenticated committee. Five slow nodes leave fifteen potential timely signatures; six leave fourteen. The gateway waits for the fourteenth successful vote, not for the slowest node.

Gateway rotation helps when the problem is the gateway or its paths. It does not revive seven truly unavailable shard nodes. Five slow nodes plus six other withholding Byzantine nodes exceed the six-nonresponse availability budget; the tolerances cannot be added independently.

### Option 2: increasing q(K)

For one fixed, agreed K, `q(K) = floor(2K/3) + 1` supports an ordinary less-than-one-third fault assumption, subject to retained state. Examples: 20/14, 24/17, 27/19, 40/27.

However, independent per-request choices of K are unsafe even with nested HRW prefixes:

`q(20) + q(40) - |C40| = 14 + 27 - 40 = 1`.

An explicit conflicting pair is ranks 1–14 and ranks 14–40; the only common signer can equivocate. A certificate must therefore identify an agreed quorum policy, and all simultaneously accepted policies need a cross-intersection or safe transition proof. Merely writing K into each certificate does not supply that proof.

A fixed 40-member committee with 27 signatures is mathematically possible, but it increases replication and RPC work and changes HuMoCo's 20-member architecture. It is not the minimal remedy for one to five stragglers.

### Option 3: Top-20 anchors

For a 14-signature certificate with at least `a` incumbent signatures and replacements from ranks 21–25, the exact worst-case intersections are:

| Required incumbent signatures a | Minimum intersection between valid certificates |
| ---: | ---: |
| 11 | 3 |
| 13 | 6 |
| 14 | 8 |

For eleven anchors, the incumbent subsets may overlap in two members, while their three-member replacement subsets overlap in one. All three common members may be Byzantine under f=6. With a larger replacement pool, even that third intersection member disappears. Thirteen anchors still permit an intersection consisting only of six Byzantine incumbents. Fourteen anchors restores safety but removes the proposed replacement benefit.

### Option 4: heartbeat TTL and ticket aging

Useful for local discovery, stale endpoint handling, and candidate proposals. Unsafe as an independently authoritative FINAL committee transition.

A timeout cannot distinguish a crash from delayed communication. Even an authentic signed heartbeat may reach only one side of a partition. Equal TTL constants, a median clock, and 24-hour incubation do not make receipt histories equal. The failure-detector literature explicitly separates accuracy from completeness. [Chandra and Toueg, Failure Detectors](https://www.cs.cornell.edu/info/people/sam/FDpapers.html).

Two 20-member committees differing by `r` replacements have a union of size `20+r`, and their 14-signature quorums can intersect in only `max(0, 8-r)` members. With two replacements, six common equivocators suffice to defeat the same f=6 bound. With eight replacements, disjoint certificates are possible without any equivocation.

Even a single-replacement overlap bound is not a general handover mechanism: several small changes accumulate, while old certificates and voucher roots can remain live for much longer. Checking only adjacent rosters leaves that historical continuity obligation unresolved.

Calling a replacement "inactive membership" rather than a "ban" does not fix this: it is still a consensus-authority change. Signed voluntary departure and verified bans also require membership/state continuity if live locks remain.

### Option 5: human repair and WoT diagnostics

Recommended as a non-authoritative operations layer. Operators can diagnose failed paths, contact friends, restore service, add independent links, and voluntarily revoke local friendships. These actions cannot retrospectively prove a missing heartbeat or turn a local suspicion into a safe global committee change.

## 4. Checkout algorithm

1. The client constructs one immutable lock request and retains its `lock_id`. All retries send the identical proposal, network, parent, and committee version.
2. The gateway applies bounded parsing and the existing PoW/token/quota filters before expensive signature work. Root validity comes from authenticated origin evidence and `P2pClock`; unknown origin is rejected. Transport deadlines use monotonic time.
3. Resolve an authenticated shard committee descriptor and its transition proof from an existing trust anchor. Freeze that descriptor for this attempt. A locally computed descriptor hash without authorization is insufficient.
4. Launch concurrent requests to the twenty committee members, counting a local vote only if the gateway itself is a member and has performed authoritative shard admission. Reach only peers authorized under the existing F2F-learned shard-direct rule. Missing routes cause unavailability, not replacement of committee members.
5. Each shard reserves bounded persistence capacity before RAM mutation, checks the parent collision atomically, and returns a signature only for an allowed idempotent or new lock. It rejects requests claiming an unauthorized committee, role, or root.
6. Verify each returned signature over the exact expected fields. Count each full `NodePubKey` once and require membership in the frozen descriptor. A statistical HRW score, bitmap bit, IP address, or reported signer count is insufficient.
7. At fourteen valid votes, return the certificate immediately: HTTP 201 for a new lock, HTTP 200 for an identical replay. The client independently verifies the certificate before accepting FINAL. Abort outstanding RPCs without recording cancellation as a peer failure.
8. Stop early if valid votes plus all unresolved eligible members cannot reach fourteen. Return explicit unavailability, normally HTTP 503. If the configured attempt deadline actually expires, HTTP 504 is a reasonable distinct response. A timeout is not proof that no shard accepted the lock; retry idempotently.
9. Report HTTP 409 only from verified conflict evidence, according to the existing collision contract. Distinguish a competing local signed proposal from a competing finalized payment; a single rejection does not prove a competing FINAL certificate.

Suggested timing policy, to be measured rather than advertised as a guarantee:

- One end-to-end client budget of 1,500 ms, including client–gateway transport and response verification.
- Gateway RPC budget initially 800–1,000 ms, capped by the remaining client budget and response margin.
- At most one secondary gateway request, optionally hedged around 350–400 ms. Both requests use the identical proposal and committee. No unbounded retries.
- The secondary gateway gets only the remaining budget. Two sequential 800 ms attempts already exceed 1,500 ms before network overhead.
- Report latency from the fourteenth valid completion, including connection establishment and queueing. CPU processing below 5 ms does not bound Internet RTT.

Two gateways may perform up to forty shard RPCs in total. This is bounded amplification, not zero additional load. Hedging therefore needs an explicit client retry budget and existing ingress backpressure. No lock gossip or recursive shard retry cascade is introduced.

## 5. Background membership continuity

The minimal architectural boundary is a committed committee descriptor plus a transition proof. A small descriptor is an authenticated configuration, not a global failure-gossip mechanism. Clients can carry relevant proof chains; nodes can cache current shard descriptors and fetch proofs through existing shard-direct control/sync exchanges. No third F2F gossip stream is required merely to express this design.

The slow path must prove all of the following before issuing FINAL under a successor configuration:

1. The predecessor configuration authorizes a unique successor through a proven transition rule, rooted in an agreed initial configuration. HRW determines the proposed roster from agreed eligible tickets; local membership snapshots do not establish agreement.
2. A durable fence prevents enough old members from producing further old-configuration certificates. Freeze/activation races and competing transition proposals are accounted for.
3. Every still-live finalized collision and every signing commitment needed to preserve it survives state transfer. Gateway-held certificates may never have been returned to the signers. Transferring only already assembled certificates visible at servers is therefore insufficient by itself.
4. Successors verify the transferred state and reach a defined ready condition before signing. In-flight requests cannot create a gap between the snapshot and activation.
5. Clients reject unauthorized successor descriptors, forks, certificate mixing, and rollback to an unsafe old committee. Late old certificates are handled by the proved transition semantics.
6. Removed nodes cannot become fresh independent authorities merely by rejoining or changing tickets. The 24-hour incubation wall remains admission friction, not the continuity proof.

These are proof obligations, not a complete new handover algorithm. Simply adding fourteen old signatures and fourteen new signatures to a state hash is not, without the above rules, a finished Byzantine reconfiguration protocol. Dynamic Byzantine storage work explicitly treats continuity across changing server sets as a distinct problem. [Martin and Alvisi, A Framework for Dynamic Byzantine Storage](https://www.cs.utexas.edu/~lorenzo/papers/dsn04.pdf). Open heterogeneous membership likewise requires preservation of quorum-system properties. [Li and Lesani, Reconfigurable Heterogeneous Quorum Systems](https://mohsenlesani.github.io/companion/disc24/DISC24Full.pdf).

A handover requiring an old 14/20 quorum does not restore availability once only thirteen old members can participate. Plan graceful maintenance and replacement while the old committee is still quorate. Beyond that, wait for recovery or explicitly adopt a stronger recovery assumption; unilateral resets must not preserve the FINAL label.

## 6. State and invariants

Proposed logical records, to reuse existing types wherever possible:

```text
CommitteeDescriptor
  network_id, shard_id, configuration_id, predecessor_hash
  members[20]: { node_pubkey, active_hrw_ticket }
  quorum = 14
  authorization / transition proof reference

QuorumCertificate
  committee_hash, network_id, shard_id, parent_lock, lock_id
  status, root_valid_until (directly or through authenticated lock/root binding)
  distinct member signatures

ActiveSigningState
  parent_lock -> accepted lock_id, root_valid_until
  current configuration / durable handover fence

RoutingHints
  node_pubkey -> learned endpoint, local presence freshness, path health

LocalDiagnostics
  observed RPC outcomes, latency histogram, eligible completed attempts
  best_ingress_friend, observed hop_count, observation time
```

The signatures must commit to the committee hash and exact network/shard/parent/lock/status context. Use canonical bounded serialization and length-prefixed BLAKE3 domain separation. The outer certificate's metadata is not trusted merely because a gateway signs its envelope. A committee hash identifies a roster; a proof rooted in accepted prior authority authenticates it.

Required invariants:

- One authorized committee/quorum policy per decision context, or a proven safe overlap/transition between accepted contexts.
- Every counted signature belongs to that committee, binds the expected proposal, and is unique by full public key.
- Routing freshness and local peer penalties never silently modify the certificate's electorate.
- A node never signs conflicting successors for one live parent, including after restart or membership transition.
- A timeout does not erase accepted signing state. State remains bounded by voucher-root expiry plus existing grace, then is physically removed.
- `FINAL` cannot be replaced by an equally green certificate from an unrelated local view. Island certificates remain PROVISIONAL, and their reconciliation semantics are separate.
- No equivocation penalty without independently verified offender signatures. Two disjoint certificates are a protocol failure and need not identify a guilty node.
- The public ingress stays permissionless under its own filters; friend relationships and bans govern internal P2P authorization.
- Client friend tokens remain random secrets, never node public keys. Billing stays outside the blind consensus core.

## 7. Limits that quorum counts alone do not solve

**Concurrent proposals:** With twenty honest reachable nodes, two competing first-seen proposals can receive ten votes each. Neither reaches fourteen, and repeating either proposal does not change the recorded commitments. Without additional proved recovery rules, this one-round registry offers safe refusal, not guaranteed eventual agreement under adversarial contention. `min(H_canon)` convergence is not by itself permission to sign a new conflicting FINAL approval. PBFT includes separate ordering and view-change machinery; a signature threshold alone does not provide all those properties. [Castro and Liskov, Practical Byzantine Fault Tolerance](https://pdos.csail.mit.edu/6.824/papers/castro-practicalbft.pdf).

**Crash recovery:** Reserving an MPSC slot guarantees queue capacity, not durable storage. If six equivocators participate, the minimum overlap of two 14/20 certificates can contain only two honest nodes. If both forget their pending RAM commitments after crashes and resume signing without safe recovery, the overlap argument no longer prevents a second certificate. Treat memory loss/recovery in the fault model and prohibit signing until safe state recovery. If stronger crash durability is needed, await a background durable barrier or use another proved recovery design; measure the resulting latency. No synchronous disk work or fsync lock may be inserted into the RAM collision operation.

**Statistical membership:** A Bloom filter has false positives. A normalized score threshold selects an expected number of nodes, not an exact agreed electorate. Even a perfectly authentic filter does not prove intersection between accepted quorum sets. Network-size estimates and 24-hour stability hysteresis cannot independently authenticate a globally unique committee.

## 8. Incentives and social repair

No staking does not mean no operator incentives. Reliable merchants and gateways have an incentive to protect their own checkout availability, retain customers, reduce support work, and maintain valued friendships. Hosting/SLA revenue can remain external to the blind node, using existing Byte-Year control interfaces without adding amounts or accounts to consensus.

Repeated cooperation is conditional. In a simple illustrative repeated-game model, reliable service has per-period benefit B and cost c; one-period shirking saves c but has detection probability p and discounts future benefit by delta. Cooperation can be attractive when `c <= p * delta * (B-c)/(1-delta)`, assuming B>c and credible withdrawal of those future benefits. These assumptions can fail. This is not a proof that honest operation is a dominant strategy, especially for saboteurs or anonymous operators with little future value.

Use local diagnostics to improve incentives without turning reputation into consensus weight:

- Show completed valid RPC success rates, timeout rates, p50/p95 latency, connection-vs-validation failures, sample counts, and observation windows.
- Display opportunities from actual work, not presence in a winning signer bitmap. Honest stragglers cancelled at fourteen are censored observations, not measured failures.
- Give operators useful local cluster-health reports and optional progress markers based on real observations. Avoid global competitive leaderboards, transferable reputation scores, or rewards for mere node count; these invite Sybils, fake traffic, and pressure to consolidate independent infrastructure.
- Encourage independent providers, power supplies, and upstream paths. A socially close cluster sharing one failure domain does not provide twenty independent replicas.
- For persistent issues, guide operators to a known direct friend and let them communicate using their own channels. Friendship revocation is voluntary; it does not transfer financial liability or erase live signing commitments.

The current `KnownNodeInfo` stores `best_ingress_peer`, `min_hops`, and an ingress diversity mask. That supports a truthful message such as "learned through your direct friend Bernd; observed hop count 3." It does not establish that Alice lies on the path, that the path is globally shortest, or that Bernd controls the remote node. Do not invent missing path segments. Only run shortest-path search over a graph actually available and appropriately authenticated, and label its scope and freshness. A global WoT crawler or new topology-gossip stream is not needed for the first useful diagnostic feature.

Keep the dashboard an offline diagnostic window below 128 KiB; bounded counters or exported metrics belong behind the existing control interface. No log buffers, financial penalties, automatic friend removal, or consensus-changing health scores are introduced.

## 9. An optional mathematical alternative

A fixed, shared **21-member committee with quorum 14** has intersection seven and remains safe for f=6 under the same signing-state assumptions. It can obtain fourteen votes with seven silent members. This is a deliberate committee policy change, not permission for each gateway to choose a different rank-21 replacement. It cannot tolerate seven equivocators, and it still requires membership continuity.

This is an elegant one-member expansion if HuMoCo later chooses to change the twenty-member invariant. It is unnecessary for the requested one-to-five-straggler case and does not solve arbitrary long-term churn. Keep 14/20 for the present recommendation.

## 10. Required implementation verification

No production source was modified and no Cargo or QUIC test suite was run for this research request. The numerical tables and set counterexamples were independently checked by a delegated mathematical verifier. A future implementation must follow the workspace's mandatory adversarial wire-test rule and verify the server, gateway, and client policies together.

Required scenarios over real QUIC connections include:

1. Five delayed members: fourteen distinct eligible signatures return before delayed completions; cancellation causes no failure penalty.
2. Seven unavailable members: no FINAL certificate, no rank-21 vote counting, bounded failure time.
3. A peer outside the authorized committee: server refuses a FINAL approval even if its local HRW rank is within forty.
4. Two concurrent conflicting proposals aimed at disjoint subsets of an expanded candidate pool: never two accepted FINAL certificates under the repaired policy.
5. Two different local heartbeat/suspension views: no self-authorized successor committee and no mixed-configuration certificate.
6. Two membership changes during a delayed write: fence, state transfer, replay, and old/new approval races preserve every previously finalized live parent.
7. Crash between RAM acceptance and disk flush: no conflicting approval after restart before proven safe recovery.
8. Concurrent first-seen vote split: explicit conflict/unavailability, with no claim of unproved liveness.
9. Duplicate public keys, mismatched parent/shard/network/committee hashes, invented descriptors, and false-positive filter membership: rejected at the relevant verification boundary.
10. Two gateway attempts with a common client budget: bounded requests, idempotent retries, no infinite amplification.

The shortest implementation sequence is: fix and centralize certificate eligibility across gateway/server/client; establish authenticated committee continuity and crash assumptions; add the wire-level counterexample tests; then add bounded diagnostics and measured latency tuning. Existing green unit tests or historical audit labels cannot replace these checks.
