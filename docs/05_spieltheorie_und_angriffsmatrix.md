# 05. Game Theory and Attack Matrix

> **Status:** Normative requirements reconciled with DEC-053–089. Requirements, assumptions and evidence are separate. This matrix is not an exhaustive security proof or a claim of deployed protection.

## 1. Security assumptions and consequence boundaries

L2 is a blind Collision Lock Registry for `parent_lock -> child_lock`; L1 carries the deed, transaction, values, ownership and `ProofChain`. A valid owner signature authenticates intent, not current unspentness. Current qualified shard nodes attest safely synchronized live state; historical quorum bundles are not inherited through generations of nodes.

FINAL requires fourteen distinct verified members of one justified, frozen twenty-member HRW snapshot. The collection budget is 800 ms, with no rank-21 replacement. Fewer than fourteen votes in FINAL mode means unresolved/failure, not a smaller provisional quorum. PROVISIONAL applies to sub-twenty meshes with `Q(N) = floor(2N/3) + 1`; the existing 24-hour network-stability condition governs transition to FINAL. FINAL is regional confirmation under the selected membership assumptions, revisable on a justified merge (DEC-053/064), not a proof of global irreversibility.

Two fourteen-member subsets of the same twenty identities overlap in at least eight identities. Under a bound of at most six Byzantine identities, at least two intersection members are honest; immutable own choices prevent both conflicting original approvals. This argument assumes one authorized committee and sound signing/recovery. It does not establish the adversary bound, common network views or safe changes between disjoint committees. Argon2d, WoT and pacing constrain attacks but do not prove that bound.

## 2. Class A: node and gateway attacks

| Vector | Failure or attack | Required defense and response | Remaining boundary |
| --- | --- | --- | --- |
| A1 | Silent, overloaded or unready shard member | Query only the frozen members; exit on fourteen valid votes or impossibility/deadline. NOT_READY, non-membership, capacity rejection and quorum cancellations are neutral. | Six absent contributions consume all FINAL headroom; an additional missing vote prevents completion. No rank-21 rescue or availability guarantee. |
| A2 | Node signs incompatible original decisions in the same protected slot | Verify both full signatures, same author and incompatible context before first-party equivocation sanctions; revoke identity/ticket and WoT edges. Atomically persist lock plus immutable own decision before releasing any original vote. | A conflicting client spend, honest losing branch, or current-state report differing from a past original choice is not by itself node equivocation. |
| A3 | Gateway censorship or selective dropping | Client rotates gateways and retries the exact intent within a bounded budget. Verify the actual quorum, never a gateway success flag. | Network-wide denial of service remains possible; no universal latency or censorship-immunity theorem. |
| A4 | Eclipse, bribed bridge or Sybil cluster | Verified F2F edges, admission work, ticket maturation, bounded edge forwarding and newcomer pacing ([INV-1104](11_organische_praesenz_und_dunbar_gossip.md)). Private topology diagnostics support operator action. | No fixed drop percentage or guarantee that all bots remain immature. Telemetry is not authority to ban. |
| A5 | Split ingress counters, forged load or contradictory envelopes | Receiving shards enforce authenticated quotas locally. A ban needs a precisely verified same-author contradiction under the specified proof predicate. | A digest alone does not expose every counter fork; detection coverage and wire enforcement require evidence. No receipt-gossip stream. |
| A6 | Ticket grinding or targeted committee capture | Validate Argon2d work and identity binding, monotonic ticket renewal and observed 24-hour ticket incubation. Score full tickets with deterministic full-key tie-breaking. | Mining costs depend on hardware; grinding is constrained, not mathematically impossible. Admission does not prove at most six attackers per committee. |
| A7 | Heartbeat flooding, cross-domain replay or presence displacement | Cheap bounds/freshness/deduplication, bounded edge budgets, network-bound authenticated heartbeats ([INV-1106](11_organische_praesenz_und_dunbar_gossip.md)); only two mesh gossip streams ([INV-1006](10_p2p_wire_format_und_session_framing.md)). | Invalid/duplicate traffic is rejected or limited. Signed heartbeat fraud needs the complete protocol predicate, verified evidence and reboot/clock-safety proof; timeouts or clock observations alone do not justify bans. |

Legacy references `INV-1101` and `INV-1102` had no located authoritative definitions. They are not silently repurposed; pacing, domain isolation and the two-stream rule are referenced explicitly above.

## 3. Class B: client and resource attacks

| Vector | Failure or attack | Required defense and response |
| --- | --- | --- |
| B1 | Free-ingress flood | Validate cheap framing, token buckets and stateless BLAKE3 Hashcash before expensive crypto or disk work. Push back with HTTP 429 and `X-Required-Difficulty`; separate read and write budgets. |
| B2 | Fake genesis, malformed causality or oversized history | Validate the signed Voucher Root Anchor and owner authorization, bounded lengths and proof links; reject unknown origin rather than accept a client-chosen TTL. L1 history stays client-custodied; no unsolicited history dump. |
| B3 | Duplicate submission or replay | Same lock is idempotent; different child on the same parent is a conflict. Coalesce identical in-flight work with bounded waiters. No signature from pending RAM/cache, and no write use of QUIC 0-RTT. Live replies bind recipient challenge, exact target and purpose. |
| B4 | RAM, CPU, queue or disk exhaustion | Bounded admission/frames/workers/batches, reservation before RAM mutation, bounded background recovery and protected shard/sync capacity. No unmanaged blocking disk I/O in handlers. Root TTL plus 30 seconds drives coordinated purge. Actual lock/index/own-choice overhead must be measured; no fixed total-RAM or disk-immunity promise. |
| B5 | CGNAT collateral damage or identity confusion | Public client ingress remains permissionless and separate from P2P authorization. Scope malformed-client handling to the responsible session/credential, never blanket subnet guilt. A public NodePubKey is never an ingress friend secret. |

## 4. Crash, synchronization and merge attacks

A new shard assignment starts NOT_READY. An admissible request triggers at most one bounded recovery job for that shard. Full relevant active-root lifetime coverage, snapshot plus bounded concurrent deltas, admissible source authority and durable installation are required before any countable write or live-state vote. Empty matching digests from unready peers do not prove continuity. Available partial data may be served to authorized peers without promoting its sender to a quorum witness.

For original decisions, the bounded persistence worker atomically commits lock and immutable own choice before signature release, including idempotent replies and gateway self votes (DEC-087). A normal process crash with intact committed storage therefore requires no root-risk marker, quarantine or identity abandonment. Storage loss, rollback and concurrent use of the same key are separate unresolved safety boundaries. An 800 ms deadline or a local durable SLA target does not establish physical disk latency.

On merge, admit authenticated confirmation classes before comparing hashes: class2 FINAL/Regional14 outranks class1 adaptive PROVISIONAL; class0 partials cannot displace a confirmed branch. Within the highest admissible confirmed class, `min(H_canon)` selects the branch. Honest nodes that signed only a losing branch are not banned. Convergence does not undo already delivered goods or prove safe dynamic activation.

## 5. Invariants and revised legacy meanings

The existing identifiers remain stable. Earlier unconditional immunity, timing and economic-dominance claims are explicitly revised as follows:

1. **[INV-0501] First-party fraud sanctions:** Every fraud family requires its specified cryptographic self-proof and full context verification before identity/ticket revocation and WoT severance. No guilt by association, hearsay or telemetry ban. The former unconditional three-pillar timing claim is withdrawn pending per-predicate evidence.
2. **[INV-0502] Conditional censorship tolerance:** Fourteen verified fixed-committee votes suffice; at most six missing contributions can be tolerated if all other members are timely and ready. Hedging stays client-side and never expands that committee.
3. **[INV-0503] Bounded edge saturation:** Apply local edge budgets and newcomer pacing; the former universal 99.9% botnet-rejection claim is not a normative guarantee.
4. **[INV-0504] Asymmetric ingress brake:** Stateless BLAKE3 work and dynamic HTTP 429 pushback precede expensive processing. Capacity remains bounded even when work is valid; exact performance needs measurement.
5. **[INV-0505] No garbage-history replication:** Reject unsolicited history dumps; client L1 custody is distinct from required authorized active-lock synchronization.
6. **[INV-0506] Safe replay idempotency:** Identical locks do not create a new decision; conflicting locks return conflict. Every binding original response waits for the exact durable decision. Live-state replies need a fresh challenge and separate purpose.
7. **[INV-0507] Binary bootstrap rule:** `R = min(20, N_active)` and adaptive provisional `Q(N)` for `N < 20`; fixed fourteen-of-twenty FINAL after the existing stability condition. No third assurance tier or FINAL downgrade on timeout.
8. **[INV-0508] No collateral client sanction:** Isolate responsible sessions/credentials; do not ban shared IPv4/CGNAT networks on a client's fault.
9. **[INV-0509] Heartbeat anti-flood safety:** Freshness, deduplication and bounded forwarding prevent duplicate traffic consuming honest forwarding allocation. Signed-heartbeat sanctions require a complete anti-framing predicate; the former two-timestamps-alone ban shortcut is insufficient.

Economic penalties impose identity, ticket and social costs without financial deposits. They are deterrents, not a theorem of strictly dominant honest behavior for every actor or a guarantee that double-spends have zero economic harm.

## 6. Required evidence

Real receiving-side QUIC scenarios must cover unauthorized peers, over-quota/flood senders, malformed/replayed frames, duplicate and conflicting originals, frozen membership and neutral cancellation. Relevant HTTP/client tests must enforce cheap lookup versus verified payment release. Crash tests must interrupt before/after commit and before/after signature release, including coalesced/idempotent/self paths. Sync tests must include omitted old-but-active locks, unready empty sources and concurrent deltas. These are acceptance requirements; this reconciliation runs none of them.
