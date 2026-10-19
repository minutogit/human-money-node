# 06. Dumb Server / Smart Client Lock Flow

> **Status:** Normative requirements reconciled with DEC-072/080–089. Described behavior is a contract for implementation and verification, not a claim that every production path satisfies it.

## 1. Custody and responsibilities

L1 carries the voucher deed, transaction, values, ownership and causal `ProofChain`. The buyer passes the signed L1 transaction to the recipient locally by QR/NFC/BLE or another channel. The recipient validates L1 ownership and causality and durably retains its purchase state. L2 stores the active collision barrier `parent_lock -> child_lock`, not balances, amounts, real identities or a global transaction history.

Node original signing decisions are retained separately for safety until `root.valid_until + 30s`. This does not create a recursive L2 receipt chain, merchant certificate-custody duty or inherited historical quorum-bundle archive. Current qualified nodes attest their safely synchronized live state even if the original signers departed.

The recipient handles online ingress; the buyer need not have mobile connectivity. An offline transfer remains pending. Neither a valid owner signature nor a gateway's success flag establishes current payment safety.

## 2. Checkout contract

```mermaid
sequenceDiagram
    actor Buyer
    actor Recipient
    participant Gateway
    participant Shard as Frozen current shard committee
    participant Disk as Bounded persistence worker
    Buyer->>Recipient: Signed L1 transaction and causal proof
    Recipient->>Recipient: Validate ownership and retain exact intent
    Recipient->>Gateway: Authorized lock request
    Gateway->>Gateway: Cheap admission checks; freeze justified HRW snapshot
    Gateway->>Shard: Direct lock RPC; same exact request context
    Shard->>Shard: Validate root, authorization, membership and per-shard readiness
    Shard->>Shard: Reserve persistence capacity before atomic RAM collision decision
    alt New or pending original approval
        Shard->>Disk: Exact lock plus immutable own choice
        Disk-->>Shard: Exact atomic durable commit acknowledgment
        Shard-->>Gateway: Release original approval only after commit
    else Conflicting lock
        Shard-->>Gateway: Conflict and bounded available authenticated evidence
    else Not ready or no capacity
        Shard-->>Gateway: Neutral rejection; no vote
    end
    Gateway->>Gateway: Collect distinct qualified votes, at most 800 ms
    Gateway-->>Recipient: Complete evidence or honest unresolved/failure result
    Recipient->>Recipient: Verify full proof and exact target before payment release
```

All binding original responses, including identical-lock idempotent responses, cached responses and gateway self votes, require the exact durable lock and own-choice acknowledgment. Signature computation may happen in RAM; bytes cannot leave the node before commit. Release RAM guards before awaiting the worker. A completed commit survives requester timeout or cancellation; do not roll it back automatically. Pending/unknown outcomes remain unresolved and the client retries the exact intent (same parent, child and original request context).

Coalesce identical in-flight operations with bounded waiters; bound batch bytes, count, age and global work. An admissible request can trigger bounded recovery, but the server never stores a queue of pending payments. No write 0-RTT or unbounded synchronous history/sync work belongs in this flow.

## 3. Lookup, current clearance and original approval are different

| Observation | What it establishes | Payment action |
| --- | --- | --- |
| Ordinary `read_quorum=1` / INV-0310 lookup finds the expected owner-signed lock | One node reports a matching entry; client authorization may be genuine. | Request and verify strong current evidence; do not release goods on the match alone. |
| Lookup finds a different valid lock | Evidence of a conflicting intent/state requiring validation and resolution. | Stop release; validate context and confirmation class. A single report cannot authorize arbitrary canonical takeover. |
| Lookup reports no entry or unknown root | The queried node reports absence; it may be unready or incomplete. | No proof of unspentness. Supply valid root/authorization where required, or submit the exact intended lock; require a successful quorum. |
| Fully verified current live-state quorum | Qualified current nodes agree on the exact target/state and fresh recipient challenge under one authorized snapshot. | Release only for the expected acceptable state and valid L1 purchase. |
| Timeout or partial quorum | Outcome is uncertain, possibly with durable side effects. | Retry/reconcile the original intent within client budget; never reinterpret a FINAL minority as PROVISIONAL. |

Ordinary reads retain the cheap one-of-top-twenty policy. Setting `read_quorum >= 14` is a request, not proof. Read selection/failover does not alter the write committee or authorize bans from failed observations.

Live-state attestations use a purpose distinct from original write approvals. Bind the network, shard, full target/root, exact reported state, status/class, committee/request context and fresh unpredictable recipient challenge in a canonical authenticated payload. Reject wrong purpose, changed target, duplicate identities, challenge reuse and mixed snapshots. An old write approval cannot substitute for a fresh challenged report; a later valid current-state report does not rewrite the node's immutable original choice.

At every countable live-signing site, including self, recheck current authority and safely installed relevant state. No new durable write is required merely to repeat a read of already durable state, but pending RAM state cannot be dressed up as durable clearance. Clock/slot/seal validity and atomic observation boundaries still need their specified proof and implementation.

## 4. Exact quorum verification

The verifier needs independently justified committee authority, not a gateway-supplied arbitrary roster. Validate identities, Argon2d tickets and observed maturation; rank distinct full `NodePubKey` identities by full 256-bit HRW scores with deterministic identity tie-breaking. Ticket validity and social attachment alone do not establish a globally complete roster or at most six adversaries.

Freeze at most twenty members for the request, including self only if eligible. FINAL requires a justified twenty-member snapshot and fourteen distinct valid signatures. All signatures must verify against full keys and exactly the same purpose, target/state, freshness/challenge and confirmation context. A bitmap indexes that authenticated snapshot; `count_ones`, Bloom filters, statistical score cutoffs and a gateway envelope cannot establish membership or quorum validity. The exact new live-state schema and roster-provenance mechanism remain implementation/proof work.

At fourteen valid FINAL votes cancel stragglers neutrally. Fail at 800 ms or sooner if eligible remaining members cannot meet quorum. Do not substitute later HRW ranks. NOT_READY, NOT_IN_SHARD, capacity rejection and cancellation after success are neutral. Six missing members include all causes combined; this is no promise that an additional synchronizing node will fit the headroom.

For `N < 20`, adaptive PROVISIONAL uses `floor(2N/3) + 1` of the participating local identities. The transition to FINAL retains the 24-hour network stability condition. This is separate from ticket maturation and hourly presence. There is no HIGH_ASSURANCE tier. Regional FINAL can be revised by an admissible merge; it does not prove global irreversibility.

## 5. Causality, splits and bounded reconciliation

Genesis registration validates the signed L1 root and establishes `root.valid_until`; successor locks inherit that anchor. A client cannot set a longer successor TTL. Unknown origin rejects the successor rather than inventing authority. Owner authorization and disclosed-key/predecessor-output binding are distinct from node attestations.

If an offline L1 chain has missing required lock steps, the client may provide bounded authorized catch-up material. Verify each relevant link and imported state; do not infer final clearance from the final leaf alone. Locator-prefix responses are hints, not authenticated proof of completeness. There is no recursive predecessor L2 certificate requirement.

For a split, the transaction consumes the parent output and creates independent child identifiers. Later spends of child A and child B use different `parent_lock` keys and do not collide with each other. L1 validates split ownership and values; L2 remains blind. Causal VOID handling follows the confirmation-class resolver; do not forget the original own choice when current canonical state changes.

If two competing locks split the twenty votes 10:10, neither is FINAL and neither checkout releases goods. A later merge uses valid class2 over class1 over unconfirmed class0; within the highest admissible confirmed class compare `H_canon`. A matching single lock or a smaller unsupported hash cannot displace a confirmed branch. Honest single-branch signers are not sanctioned for losing.

## 6. Readiness, retries and latency boundaries

New/unknown shard responsibility is NOT_READY until complete justified state transfer and durable install. The first admissible relevant request starts at most one bounded background recovery job per shard. Cover all still-relevant active roots, including locks older than 24 hours, plus bounded concurrent deltas. Empty digests from unready peers do not establish safe history. Other independently ready shards continue; retained partial data can still be served under P2P authorization without becoming a countable vote.

The 800 ms collection budget, local durable SLA target and ergonomic 0.5–1.5 second checkout range describe targets/limits, not measured end-to-end guarantees. Disk latency, batching, RTT, recovery and client retries affect availability. A presumed 1–5 ms redb commit is unmeasured and never permits early release. Public gateway discovery is allowed; stale cached gateway fallback belongs solely to the client. Metrics/dashboard stay private.

## 7. Existing lock-flow invariants

These identifiers retain their topics; obsolete historical-receipt and release-before-commit wording is explicitly replaced:

1. **[INV-0601] Bounded active-state retention:** Keep active locks and required own-choice/verification context until root TTL plus grace; discard unnecessary supplied L1 history. No recursive receipts or inherited old quorum bundles. Every original vote follows atomic durable commit.
2. **[INV-0602] Atomic First-Seen:** Reserve bounded persistence capacity before atomic per-parent collision handling. Concurrency cannot authorize incompatible original decisions; RAM acceptance is pending until exact durable acknowledgment.
3. **[INV-0603] Recipient safety:** The recipient validates L1 custody and full required quorum evidence before release. Buyer connectivity or a gateway boolean is not the safety predicate.
4. **[INV-0604] Authenticated causality:** Validate owner authorization against the exact predecessor output and root; the former mandatory preceding L2 QuorumCertificate chain is withdrawn by DEC-072/083.
5. **[INV-0605] Exact quorum verification:** Require justified snapshot authority, distinct full eligible identities, all signatures and exact purpose/target/state/request/challenge context. Cardinality/bitmap/statistics alone are insufficient.

## 8. Evidence still required

Real QUIC tests must exercise conflicting concurrent writes, wrong members, duplicate signers, neutral stragglers, unready sources and blocked durable acknowledgments. HTTP/client tests must show that one matching entry, false success flags, replayed challenges and partial/mixed-context quorums never authorize payment. Crash tests must cover all original-signature release sites, including idempotent/cache/self paths. Current authority, transfer completeness and safe dynamic activation need explicit arguments plus adversarial checks; this document does not claim they have been proved or executed.
