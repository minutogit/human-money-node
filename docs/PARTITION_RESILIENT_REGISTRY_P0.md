# P0: partition-resilient Collision Lock Registry

Date: 2026-10-17 (Europe/Berlin). Draft: **0.2**. Checkpoint: **CP-0047**.
Direction: DEC-053; admission, fraud and merchant guardrails: DEC-054.
Status: formal design baseline and twelve specified acceptance scenarios.
Implementation, executable protocol validation and production qualification: pending.

## 1. Scope, authority and payment promise

Regional committees derive their working view from their independently admitted,
currently reachable F2F mesh. Activation does not require fourteen signatures from
a predecessor committee. Different regions may accept conflicting spends during a
partition. Authentic competing evidence later selects a canonical branch; an
honest recipient can lose a previously regionally confirmed payment and dependent
outputs. This is the selected DEC-053 product tradeoff, not evidence that losses
are rare or compensated. No 99.999% availability, loss rate or immediate regional
failover is established.

This document specifies a candidate protocol revision, not changes to deployed
wire formats or binding specifications. MUST/MUST NOT below define its acceptance
contract. Technical choices introduced here, including the mixed-mode support
ordering and reachability test profile, are proposed engineering rules to validate;
they are not additional answers attributed to the maintainer. Prior decisions and
original Q-S3.3-01 retain their meanings. No extra payment completion round is
silently selected. Strict CEH remains a historical/alternative design.

### 1.1 Evidence status versus merchant decision

| Protocol result | Required evidence | Terminal meaning |
| --- | --- | --- |
| `REGIONAL_CONFIRMED` | Admitted frozen regional view of 20 and 14 valid distinct approvals | **REGIONAL CONFIRMED 🔵**; potentially reversible after admissible conflict evidence |
| `PROVISIONAL` | Admitted local view of 1..19 and Q(n)=floor(2n/3)+1 valid distinct approvals | **PROVISIONAL 🟡**; separate, weaker support class |
| `FINAL_GLOBAL` | Applicable receipt plus a separately approved, verified global-finality proof | **FINAL (Global) 🟢**; reserved; unreachable in the P0 regional-only baseline |
| `UNKNOWN` | Missing authority/proof/readiness, uncertain timeout or incomplete collection | No claim of completed payment or free parent slot |
| `REJECTED` | Demonstrably invalid request/evidence | No approval; distinguish invalidity from unavailable proof |
| `VOID` | Candidate loses at its slot or depends on a losing ancestor under current admitted knowledge | Not currently usable; derived, evidence-relative status, not an accusation |

`MerchantAccept` and `GoodsReleased` are separate local decisions, never quorum
or evidence classes. A valid blue receipt may be refused by merchant policy.
An unsigned gateway label, HTTP200 or a single status answer does not establish
any receipt class. Previously retained receipts remain authentic even if their
current branch becomes VOID. Status responses MUST identify their knowledge basis.

### 1.2 The global guard

```text
GlobalProofSchemes := {}                 // P0 baseline: intentionally empty
CanDisplayGlobal(v, receipt, proof) :=
    ApplicableReceiptValid_v(receipt)
    AND proof.scheme IN GlobalProofSchemes
    AND VerifyGlobal_v(proof, exact_intent, receipt, configured_authority)
```

Consequently `CanDisplayGlobal` is always false in this baseline. Global proof is
a distinct extension gate: a proposed scheme must justify recognized authority,
compatible acceptance across every allowed region, inherited obligations, historical
key security and the promised exclusion of later conflicting acceptance. A local
certificate chain alone cannot forbid autonomous acceptance in an unseen region.
Fourteen votes, a complete local catalog, quiet gossip,24h stability, apparent
internet connectivity and successful reconnect MUST NOT substitute for that proof.
Regional operation does not wait for this extension. This avoids making the new
green label a cosmetic restoration of the old unproved irreversible promise.

## 2. Formal objects and cryptographic bindings

Let `v` be an independently verifying node or recipient. Every judgment below is
relative to its authenticated trust inputs and observed evidence; the simulator's
global knowledge MUST NOT leak into a node's state.

| Object | Required content / role |
| --- | --- |
| `RootAnchor` | Authenticated network, root identity, owner/issuance proof and `root.valid_until`; successors cannot choose their own expiry |
| `ApprovalSlot` | `(network_id, root_id, consumed_output_id)`; independent of view, epoch, gateway and transport attempt |
| `Intent T` | Versioned blind lock transaction: slot, authenticated root binding, complete canonical child/output bundle and required owner-authorization commitments |
| `SpendId`, `H_canon` | The same domain-separated256-bit digest of canonical T; excludes collected node signatures, receipt class, view, arrival order and gateway |
| `AdmissionRecord_v` | Independently learned authenticated identity/ticket, verified work, conservative first observation/maturity, heartbeat history, replacement and verified revocation state |
| `CatalogCut_v` | Immutable local selection snapshot and policy ID, referencing eligible tickets, positive reachability and the local stability state at its cutoff |
| `ViewManifest V` | Version, network, shard, catalog reference/cutoff, admission/reachability policy, local mode, exact ordered roster and ticket digests, creation/validity interval |
| `Approval A` | Signature over approval domain/version, slot, SpendId, root expiry, exact mode, view ID, roster commitment and issuance-time/clock-policy context |
| `Receipt R` | T and its ownership/ancestry proof references, V and distinct verified approvals for the same payload |
| `Observation O` | Separate signed domain: slot, current winner, support class, admitted evidence references and knowledge-root; never an original payment approval |
| `NodeEquivocationProof` | Two authentic incompatible approvals by the same full NodePubKey for the same slot |
| `OwnerDoubleSpendEvidence` | Two authentic owner-authorized incompatible spends; distinct from node fraud, requiring the L1 verifier/attribution contract |

Canonical encoding MUST be unambiguous: versioned fixed-width integers, bounded
length-prefixed variable fields, exact ordered lists and rejection of duplicate
identities/outputs or noncanonical alternatives. Protocol hash domains use the
project's length-prefixed domain encoding. Distinct approval, observation, view,
transaction and fraud domains are mandatory. Proposed domain names must receive
versioned wire IDs in the shared protocol library before implementation.

`SpendId` commits to the whole owner-authorized blind transaction projection, not
to the transport representation of its proof. Equivalent proof/signature subsets
must produce identical SpendId. Node signatures are witnesses of T, never entropy
for its canonical hash. All domain-required owner fields must be covered; no
amount, currency, account or merchant risk profile is added to the blind registry.
Children are identified through their complete originating transaction and output
index/commitment; competing bundles cannot alias outputs into a fabricated union.
A tie at equal digest requires byte-identical T; a detected nonidentical collision
fails closed instead of selecting by arrival order. Owners can search among valid
intents for lower hashes: min-hash is convergence, not impartial loss allocation.

## 3. Admission, regional views and mode transitions

### 3.1 Individually eligible participants

```text
Admitted_v(n, t) :=
    AuthenticIdentityAndTicket(n)
    AND Argon2dWorkAndIdentityBindingValid(n.ticket, applicable_admission_policy)
    AND IndependentlyLearnedThroughAuthenticatedF2F_v(n)
    AND ConservativeObservedTicketAge_v(n.ticket, t) >= 24h
    AND MaturePresence_v(n, t)
    AND TicketActiveUnderReplacementRules_v(n.ticket)
    AND NOT VerifiedPersonalRevocation_v(n)

Selectable_v(n, shard, t) :=
    Admitted_v(n, t) AND PositiveReachabilityFresh_v(n, t)
```

Use existing ticket work verification, monotonic work replacement and one active
plus at most one pending ticket per identity. A replacement starts its own24h
incubation; the old active ticket remains usable until the valid transition.
Changing IP does not create an identity or transfer maturity. A new NodePubKey
requires normal friendship approval and incubation. Neither `T0`, a gateway's
claimed first-seen timestamp nor a self-signed old date proves observed maturity.

Persist receiver-owned admission evidence. Use conservative elapsed-time bounds;
clock uncertainty, rollback or lost observation records cannot create24h of age.
The reference presence policy preserves [Spec11](11_organische_praesenz_und_dunbar_gossip.md):
24h observation plus at least 8 authenticated hourly presence slots in the last24h;
dormancy at at most3/24, and normal re-entry after two consecutive hourly heartbeats
with the existing stricter flap rule. Ticket maturity, presence re-entry and short
regional reachability are distinct predicates. Lost age evidence requires renewed
observation or an explicitly trusted recovery source, never a silent backdate.
Presence slots are locally observed hours, or hours attested by an independently
recognized observer. Eight old self-dated heartbeats delivered together do not
create eight observed hours. Forwarded/replayed heartbeats cannot manufacture age.

F2F provenance means authenticated forwarding/learning within the configured mesh,
not a global certificate of honest behavior. A gateway cannot install its own
admission catalog in the verifier. Ticket work,24h incubation and F2F learning are
the same entry conditions regionally and globally; they prove neither independent
human operators nor at most six Byzantine identities in a particular regional view.
A set of mature attackers already admitted through the recipient's real trust
basis is a capture boundary, not something these checks magically reject.

### 3.2 Independent verifier context and frozen HRW window

Each signing node MUST evaluate V using its own independently recognized catalog
cut and safe-time bounds. A recipient uses its own authenticated mesh observation
context or an explicitly configured observation provider chosen independently of
the payer/gateway. Delegating catalog observation is an explicit trust assumption;
it is not a claim that a supplied list or a self-signed catalog proves completeness.
The terminal still verifies ticket bindings, receipt signatures and transaction
bindings locally. It caches independently authenticated admission context off the
checkout path; absence of sufficient context yields UNKNOWN, not blind acceptance.
Provider disagreement does not get averaged into authority.

```text
AcceptView_v(V, t) :=
    CanonicalAndContextValid(V, configured_network, requested_shard)
    AND RecognizedCatalogCut_v(V.catalog_ref, V.policy, V.cutoff)
    AND ViewIntervalValid_v(V, t)
    AND EveryRosterMemberAdmittedAtCut_v(V)
    AND V.roster == HRWTop(V.mode, SelectableCatalog_v(V.catalog_ref))
    AND ModeValid_v(V.mode, V.catalog_ref)
    AND V.view_id == HashView(all_required_manifest_fields)
```

HRW uses the existing full256-bit scores and full NodePubKey tie-breaker. Regional
mode takes exactly20 distinct eligible identities. Provisional mode takes every
identity of its qualified1..19-node local view. Ticket duplicates or two tickets
for one identity cannot supply two votes. A digest commits to a catalog; it does
not prove its completeness. Cached local catalog references avoid transmitting
million-node snapshots with each receipt. A roster alone, a Bloom filter or a
statistical score cutoff cannot replace exact membership verification.

A node cannot silently ignore a higher-ranked selectable identity in its recognized
cut merely because a gateway proposes another roster. Honest nodes may recognize
different cuts and refuse one another's proposed V. Receipts remain view-relative;
progress requires 14 members accepting one view. P0 does not assume that local
catalog agreement is automatic or force a mythical global catalog. This is an
explicit availability condition to measure in T01–T03/T11, including small view
skew. Recipient contexts must retain or explicitly trust historical admission
material for live receipts; current unreachability is not historical invalidity.

### 3.3 Positive reachability and finite reference profile

Regional selection runs in bounded background work, using authenticated shard-direct
responses only from learned peers. It does not add lock gossip or a global bad-peer
stream. Refresh candidate reachability, freeze a catalog cut and publish its cached
view; checkout performs no whole-network scan. Probe a bounded HRW candidate window,
advance it incrementally if needed, and yield explicit NOT_READY when no qualified
view is available. A time-based local miss can remove a candidate from a future
selection window, never prove fraud, revoke its ticket or erase its old choices.

For deterministic models, use **P0-SIM-1**, a reference test profile, not a validated
production tuning claim:

| Parameter | Test value / rule |
| --- | --- |
| Background reachability refresh | Every30s; response must authenticate the probed identity and fresh challenge |
| Positive reachability lease |120s measured conservatively by the observer; later failure cannot extend a lease |
| View lease |30s, bounded by its selection evidence validity; expired views cannot issue new approvals |
| Candidate batch |64 learned HRW candidates per shard job; at most16 concurrent probes per node, round-robin shard scheduling |
| Local scan behavior | Continue bounded cursor batches between jobs until a view is found or known catalog exhausted; no unbounded queue |
| Checkout collection |800ms; one application dispatch to each frozen member, parallel where resource-admitted; QUIC handles stream retransmission |
| Root retention | Authenticated expiry plus 30s; no new spend approvals after expiry |

These probe limits do not promise refreshing65,536 shards on one node every 30s.
Only locally assigned/actively requested windows are serviced within fair budgets;
lease expiry can temporarily make a hot window unavailable. Deadline, bandwidth
and scheduling behavior require measurement before selecting a production profile.
A verifier may obtain a different truthful reachability cut; agreement sufficient
for a collection is a liveness premise, not guaranteed by signing a heartbeat.
Reachability evidence names observer, challenged peer, network, unpredictable
single-use challenge and conservative response interval. Its lease is measured
on that observer's trusted local time basis. Forwarding/re-receiving an old response
never refreshes it. Other observers use their own probes or an explicitly trusted
observer context with conservative time-uncertainty mapping; monotonic timestamps
from different machines are not compared directly. Unknown/excessive uncertainty
fails freshness rather than extending the lease.
A lease valid when an approval was issued remains part of historical evidence;
late collection/delivery does not retroactively turn it into a fresh approval.
Honest signers enforce conservative view/root time bounds at issuance. A signed
timestamp alone does not cryptographically prove real-world issuance time; receipt
time validity relies on the stated clock and historical-key/fault assumptions.
Changing a claimed timestamp cannot rescue a context the verifier never admitted.

### 3.4 Mode state machine

```text
NO_QUALIFIED_VIEW -> PROVISIONAL(n=1..19) or WAIT_STABLE(n>=20)
WAIT_STABLE      -> REGIONAL20 after 24h continuously qualified local population>=20
REGIONAL20       -> REGIONAL20 with another frozen top20 between attempts
REGIONAL20       -> PROVISIONAL when qualified local population<20
any mode        -> NOT_READY if required local safety/readiness is unavailable
```

The24h stability anchor measures the qualifying local population, not an unchanging
exact top20 roster. If a region already had at least 20 mature selectable members
continuously before separation and retains them, the anchor can survive replacement
of remote members by local ones. A newcomer or region without that evidence waits;
first discovery of 20 does not instantly pass24h stability. Dropping below 20 resets
the anchor. Readiness loss suspends signing and invalidates any unproved continuity.
Existing presence re-entry and new-ticket incubation still apply independently.

Freeze one V per attempt. It remains the sole signer pool until the attempt ends.
No rank21 replacement, combined old/new votes or quorum reduction occurs inside
an attempt. Between attempts an honestly reconstituted V may be used, still for
the same idempotent SpendId if retrying. It requires fresh collection; partial
approvals from different views MUST NOT be summed. This maintains the existing
one-collection payment interface without selecting a new completion round.
Under20, retain the existing all-shards validation model for qualified local
participants; only the adaptive quorum/evidence class changes with n. Sharding
does not let a small component invent20 independently eligible voting identities.

## 4. Approval, persistence, readiness and receipt verification

### 4.1 Binding own choices

Each identity maintains durable `OwnChoice[ApprovalSlot] = SpendId`. It is immutable
across view/epoch/mode changes until authenticated root expiry plus grace. The
following abstract operation is serialized atomically per slot:

```text
Approve_v(T, V):
    verify format, admission/resources, AcceptView_v, owner/root/ancestry and expiry
    require v IN V.roster and Readiness_v(affected_scope)
    reserve bounded persistence capacity BEFORE RAM/state mutation
    if OwnChoice[slot] exists and differs from SpendId(T): return CONFLICT, no vote
    if admitted canonical evidence excludes T: return CONFLICT, no vote
    atomically persist own choice + exact approval context + authenticated effect
    await successful durable commit acknowledgment
    recheck view/root validity before issuing the approval
    emit LOCK_APPROVAL(T, V)
```

The worker may batch asynchronously; no RAM lock is held over disk I/O. Enqueue,
RAM insertion or queue reservation is not durable success. Repeated same T is
idempotent. Same T may receive a new contextual approval in a later valid view,
without changing the choice; use only approvals for one V per receipt. An expired
view may serve retained proof of an already issued approval, never authorize a
fresh contextual signature. Crashes after durable commit and before response
return UNKNOWN to the client; they do not free the slot.
If commit finishes after view/root expiry, retain the committed choice but emit
no new expired approval. A new valid view may approve the same T later only while
the root remains live. The existing choice never becomes a conflicting-signature
amnesty because a response or deadline was missed.

Readiness requires intact own-choice history for the affected identity/scope,
healthy durable storage, validated origin/causal proof and completed available
state repair against explicitly named admitted sources. A new regional assignment
may repair from reachable shards and client-carried evidence without old 14.
A single matching digest proves equality of named data, not global completeness
or recovery of a hidden individual approval. If relevant own history was lost or
rolled back, remain passive under the same identity until signing safety is
justified; ordinary peer sync does not unlock this gate. Undetectable rollback,
clones and historical key copies remain P2/P3 threat-model obligations.

Available-state repair uses bounded authenticated snapshots/deltas with exact
scope, digest and cursor completeness, plus client proofs for needed ancestry.
Unknown remote conflicting evidence is the selected regional risk. Missing origin,
missing required causal links or detected incomplete transfer is NOT that risk's
permission to invent state. Persist the local readiness basis; reject/suspend a
scope whose required evidence is absent, corrupt or exceeds safe resource limits.

### 4.2 Receipt predicate

```text
ReceiptValid_v(R, class) :=
    AcceptHistoricalView_v(R.V)
    AND OwnerAndOriginAndAncestryValid(R.T)
    AND RootLiveAtApprovedTimeAndUsableNow(R.root)
    AND CanonicalPayloadExactlyMatches(R.approvals, R.T, R.V)
    AND AllApprovalSignaturesValidWithDistinctFullIdentities(R)
    AND CountEligibleApprovals(R) >= Threshold(class, R.V)

Threshold(REGIONAL14, V) :=14, requiring roster size20 and regional mode
Threshold(PROVISIONAL, V) :=floor(2*|V.roster|/3)+1, requiring1<=|V.roster|<20
```

Ancestry validity here means authentic complete ownership/creation evidence, not
that every ancestor is already the local canonical winner. Conflicting authentic
evidence must remain importable; current causal usability is evaluated separately
in §5.2. A losing ancestry cannot be used to authorize a fresh usable payment.

Historical view evaluation verifies the independently recognized eligibility and
policy at issue time, not today's roster/lease. Required old view and transaction
proofs must remain portable and available for a live root. Missing history yields
UNKNOWN/fetch; bad history yields REJECTED. A later verified personal fraud proof
bars fresh participation; it is not authority to falsify the historical fact of
an authentic approval. Treatment of compromised historical keys and revocation
timing must be jointly fixed by P1/P2 before deployment.

For new collection, fail fast when remaining eligible members cannot reach the
threshold or when800ms expires. NOT_READY, wrong-view refusal, resource refusal
and cancellation after enough votes do not justify failure-based global bans.
Thirteen responses, duplicated keys or late votes from another view are not14.
Transport retries do not authorize a different intent. Read routing may return
one node's report; it does not change the required completion proof.

## 5. Admission and deterministic canonical merge

### 5.1 Support ordering

Before selecting a hash, authenticate the complete candidate transaction and
its proof. This candidate revision fixes the previously open mixed-mode rule:

```text
Support_v(T) =
    2 if at least one ReceiptValid_v(T, REGIONAL14) exists
    1 if at least one ReceiptValid_v(T, PROVISIONAL) exists, otherwise
    0 for owner-valid hints, individual approvals and incomplete receipts
    invalid for malformed/unauthorized evidence

EligibleCandidates_v(slot) := {T for slot | Support_v(T) >=1}
best_support := max(Support_v(T) for eligible candidates)
Winner_v(slot) := argmin H_canon(T)
                 over eligible candidates with Support_v(T) == best_support
```

No candidate means UNKNOWN/unresolved, not a fabricated free slot. Compare minima
only among independently admitted candidates of the highest present support class.
Regional14 against Regional14 uses exactly min(H_canon). PROVISIONAL cannot displace
a Regional14 winner, even with a smaller hash. A real14/20 receipt can promote the
same T to class2; relabeling, combining views or status signatures cannot. Two
provisional candidates compare by min within class1. This prioritizes actual
fourteen-vote support and preserves DEC-022's single-source takeover prohibition.
It is a protocol policy choice to test, not a theorem that one view is globally
correct. Promotion may be unavailable because signers retain conflicting choices.

A raw low hash, partial quorum or owner double-spend proof may trigger bounded
retrieval/diagnostics, but cannot manufacture a supported winning payment or
invalidate a supported branch on its own. If no sufficiently supported candidate
can be established, retain an unresolved slot/affected descendants per DEC-023.
One transport peer may carry an authentic14-signer receipt: support counts verified
signers, not the number of senders that happened to transmit it.

### 5.2 Evidence merge and causal usability

Store authenticated evidence separately from derived winners and immutable own
choices. Let E be the retained admitted evidence set with exact content IDs.
`Merge(E1,E2) = ValidateAndDeduplicate(E1 union E2)`; compute support, winner and
causal usability from that set under the same verifier policy/context. No unverified
candidate participates in the union's canonical decision. Receipt admissibility is
verifier-relative: convergence requires eventual compatible admission contexts as
well as delivery; two permanently conflicting trust policies need not converge.

For a live output, `Usable(output,E)` requires an authenticated valid root and every
creation/consumption transaction on its actual causal path to be the relevant
winner with sufficient support. The transaction-level child bundle is atomic.
If `P->[u,v]` is valid and only u later has competing spends A/B, only the losing
u-subtree and dependent descendants become unusable; v survives. If two spends of
P propose different complete bundles, choose one entire transaction. Never create
a union `[u,v,w]` from rival bundles. Legitimate splits still undergo L1 value and
ownership conservation checks; the blind registry operates on verified commitments.

VOID is derived relative to the admitted evidence/support revision. It is not an
irreversible tombstone: a later real support promotion can change a class1 winner.
Evidence and OwnChoice are never erased to accommodate that change. Within the
fixed Regional14 class, a retained smaller admitted candidate continues to exclude
larger candidates. An independent root or sibling with no dependency on the losing
transaction is unchanged by the merge.

### 5.3 Convergence, retention and repair boundaries

For finite authentic candidate/support evidence, fixed compatible verification
contexts and eventual complete delivery to all relevant replicas, set union is
associative, commutative and idempotent; deterministic support/min selection and
causal traversal yield the same result. This is a conditional convergence argument,
not prevention of conflicting regional acceptance. Unbounded new evidence, withheld
receipts, permanent admission disagreement or unavailable ancestors defeat a
finite completion-time claim. Reconnect or a quiet period proves no global absence.

Exchange lock/evidence digests and bounded repairs through shard-direct RPC only.
Use scoped snapshot/delta identifiers, exact range/cursor verification, incremental
hash/range comparison and bounded proof/CPU/byte queues. A Merkle root may locate
state differences; it does not establish completeness of unknown remote state.
Preserve both existing F2F streams: presence and verified equivocation evidence.
No lock-gossip stream is introduced.

Retain minimum sufficient winning/excluding proof and immutable own choices while
the root can still be used; clients custody their portable ancestry/receipts and
historical admission context. Client custody does not remove necessary node-side
active exclusions. Root lifetime may reach the existing eleven-year limit; there
is no30-day late-receipt cutoff. Reject expired roots independently of physical
pruning, then remove root-bound state after authentic expiry plus 30s with bounded
background work and no permanent expired-lock tombstones.

Candidate flood storage is not assumed constant. Charge bounded admission/work
budgets; reject or suspend affected scope on exhausted safe capacity rather than
delete a live exclusion. Benchmark retained evidence, revalidation and proof-fetch
costs separately. Exact production frame/depth/batch/storage caps remain P1/P5
measurement gates; adversarial fixtures must instantiate finite profile limits.

## 6. Honest merge continuation and personal fraud

```text
NodeEquivocation(A,B) :=
    VerifyNodeApproval(A) AND VerifyNodeApproval(B)
    AND A.full_NodePubKey == B.full_NodePubKey
    AND A.ApprovalSlot == B.ApprovalSlot
    AND A.SpendId != B.SpendId
```

Both signatures must be verified and both statements must be original approvals,
not observations. Different views, epochs or regional modes do not excuse a second
conflicting approval for that slot. Duplicate same-spend approvals are not fraud.
Hash-derived short IDs cannot replace full-key identity equality.

An honest node which approved A and later learns that B wins MUST keep OwnChoice=A.
It returns B's original supported receipt and may sign `CANONICAL_OBSERVATION(B)`;
it MUST NOT create a fresh B approval for that consumed output. The observation
references its evidence/knowledge root and proves only that local assessment.
It counts neither toward14 nor toward personal equivocation. Replays in an
approval context fail domain/type verification. Two differing observations across
new knowledge are not automatically fraud.

The same node may approve a new spend of an output created by B: this is a different
ApprovalSlot. Verify B's original receipt and current ancestry; do not demand that
all original A approvers personally approve B anew. Missing B proof leaves the
new spend UNKNOWN, not a fabricated observation-based payment certificate.

Two regional receipts or a losing branch do not by themselves prove any node's
personal equivocation. Only provable double-approvers are subject to the existing
NodePubKey/ticket/WoT sanction path. Honest single-branch signers are never punished
for losing a merge. Owner double-spend evidence is handed to the separate L1
attribution/policy verifier; it is not an L2 node proof unless that identity itself
also double-approved. The registry promises neither automatic legal liability,
compensation nor destruction of an unidentified owner's social identity.

## 7. Merchant risk and uncertain payment outcomes

Only the wallet/terminal evaluates authenticated L1 amount, currency, goods and
merchant exposure. Its versioned local risk policy may authorize regional or
provisional acceptance, require a particular evidence class, impose per-purchase
limits, cumulative/per-customer/time-window regional exposure limits and require
manual handling on unknown/conflicting proof. No universal safe monetary threshold
is asserted. Receipt validity and merchant permission are separately recorded.

```text
MerchantAccept(purchase,R) :=
    CryptographicReceiptValid(R)
    AND RequiredClassSatisfied(local_policy,R)
    AND AuthenticL1AmountAndPurchaseBinding(purchase,R)
    AND LocalExposureLimitsSatisfied(purchase, durable_local_counters)

ReleaseGoodsOnce(purchase) requires MerchantAccept and a durable local
purchase record; retries/restarts must not create a second release.
```

Amounts and policy counters stay outside L2. Risk appetite never turns blue into
green, reduces14 or admits an otherwise unqualified committee. Single-purchase
limits alone do not prevent many small purchases; evaluate cumulative exposure
and concurrent terminal updates. Independent merchants can each lose their local
budget; no global damage ceiling follows from one merchant's policy.

A timeout can hide a completed payment. Retry the identical intent and reconcile
against retained proof. A transparent switch to another voucher can create a
second valid payment. Do not perform that switch without an explicit merchant/
wallet double-payment reconciliation rule; once-only goods release alone does
not guarantee once-only debit. Separate `payment UNKNOWN`, `receipt verified`,
`risk accepted` and `goods released` in the purchase journal. No lower-than 1ms
fallback or more-than 95% retry recovery claim is adopted.

## 8. Twelve specified acceptance scenarios

Execution status for **every scenario below: NOT RUN for draft0.2**. These are
precise test obligations, not newly executed simulations or production evidence.
Each executable report must contain seed/profile/source hashes, local admission
and event traces, signed proof fixtures, observed result and mutant outcome.

Common fixture: deterministic keys, valid work/ticket vectors, injected safe time,
explicit per-observer F2F catalogs and no omniscient membership. Unless a case tests
admission, tickets have completed the24h/heartbeat/stability conditions before the
fault. Use P0-SIM-1 and fixed HRW scores/identities to realize the stated rosters.
Use actual cryptographic verification in the protocol model; wire cases later use
real QUIC receivers. Record profile caps and queue sizes with each run. All tests
also apply the global guard and honest-fraud oracle, even after full reconnect.

### P0-T01 — Balanced partition without predecessor permission

**Given:**40 eligible honest identities; regions L20/R20; prior selected committee
L10/R10. Each local region already satisfies its20-node continuity conditions.
**When:** Partition all cross-region paths, expire remote positive leases, refresh
local cuts, and submit independent owner-authorized transactions to both regions.
**Then:** Each forms its own frozen20 and collects14 after local gates; no old 14
handoff is requested. Both receipts are blue, never green. Measure detection,
view settling and first useful checkout separately; immediate switching is not
an oracle. **Mutant:** retaining old 14 activation must stall this fixture and be
detected. **Evidence:** node-local view/lease traces and the two verified receipts.

### P0-T02 — Asymmetric partition and mixed-vote rejection

**Given:**100 mature identities split80/20; prior committee split7/13. Settle
independently valid regional top20 views; retain delayed prior-view replies.
**When:** Submit local independent payments; inject old-view signatures, duplicate
identities and an attempted rank21 replacement into a partially collected receipt.
**Then:** Both regions can collect14 from their respective exact windows; every
mixed, duplicated or expanded receipt is rejected. The manifest stays frozen
through 800ms even if a new view becomes available. **Mutants:** accept7 old+7new;
count a duplicate as member14; append rank21. **Evidence:** exact signer/payload
sets, refusal reasons and attempt boundaries.

### P0-T03 — Small components and genuine mode promotion

**Given:** Separate90/10,20/7 and 13/7 partition runs, with the local 20+ populations
where present meeting stability. Later add qualified participants to one small
component; also test a fresh ticket at23h59m and exactly24h with sufficient presence.
**When:** Collect local receipts; pass through 19->20 and through a reachability
flap below 20; wait/preserve/reset the stability anchor as defined in §3.4.
**Then:** n10 needs7, n7 needs5, n13 needs9, all PROVISIONAL; local 20+ uses14 only
after actual gates. Fresh/backdated/insufficient-presence tickets cannot accelerate
promotion. Count continuity, not an unchanged exact roster. **Mutants:** keep an
old global N to label a tiny region regional; reuse an old ticket's incubation;
promote immediately on first seeing20. **Evidence:** local clocks, admission
records, mode/anchor transitions and support classes.

### P0-T04 — Independent transactions, delivery order and signer subsets

**Given:** Each region makes at least four valid payments on distinct outputs.
Choose a bounded three-transaction subset for exhaustive delivery permutations;
include differently ordered valid14-signature subsets for the same transaction.
**When:** Merge in all selected orders, parenthesizations and duplicate deliveries,
then eventually deliver the complete relevant set to every verifier.
**Then:** All disjoint payments survive; normalized evidence/support/causal state
matches. SpendId/H_canon is identical for the same intent across signer subsets,
views and gateways. **Mutants:** replace the complete shard snapshot with the last
sender's snapshot; use the smallest-node signature as hash entropy. **Evidence:**
canonical transaction bytes, hashes and final normalized state digests.

### P0-T05 — Original bridge and newcomer witnesses under regional semantics

**Given R-01:** Views `{B,L1..L19}` and `{B,R1..R19}` with independently established
regional trust; A signed by `B+L1..L13`, Z by `B+R1..R13` for the same consumed output.
**Given R-02:** Old `{F1..F6,H1..H14}`, new `{F1..F6,H3..H14,X,Y}`. X/Y first copy
an actually empty slot; old A then gets `F1..F6+H1..H8`, new B gets
`F1..F6+H9..H14+X+Y`; X/Y meet admission/readiness gates before their signatures.
**When:** Verify each receipt locally, then exchange complete compatible evidence.
**Then:** Both competing regional receipts may be authentic. All verifiers converge
to the supported min-hash transaction. Only bridge B or F1..F6 with their two actual
approvals are node-fraud candidates; no honest loser is banned. Never assert two
irreversible global FINALs were produced. **Mutants:** classify any regional rival
as impossible; ban every signer of the loser. **Evidence:** original event ordering,
real signature pairs, winner and individual ban decisions.

### P0-T06 — Complete splits and exact dependency damage

**Given:** An authenticated root creates complete bundle `(u,v)`; only u has
supported conflicting spends A/B, both with descendants; v has its own descendants.
A second fixture conflicts `P->[a,b]` with `P->[a,c]` as complete transactions.
**When:** Exchange admitted receipts in both orders, derive winners and traverse
output paths; then replay a descendant of a losing ancestor.
**Then:** Only the losing u spend and its dependent descendants are unusable; v
survives. The second fixture selects one complete bundle, never `[a,b,c]`.
Descendant replay cannot bypass its ancestor's status. **Mutants:** void the entire
root on any fork; union child lists; validate only the leaf. **Evidence:** before/
after dependency graph with exact usable/VOID output IDs and proof paths.

### P0-T07 — Honest winner reporting without double-approval

**Given:** Node N durably approved A. Supported B has lower H_canon. B's original
receipt is available, and a legitimate later C spends an output created by B.
**When:** N receives B, emits an observation, serves B's original receipt and
processes C; attacker retypes the observation as an approval/fraud component.
**Then:** OwnChoice for the original slot remains A, no B approval is emitted,
observation replay fails, and C may progress on its distinct slot. Missing B proof
produces UNKNOWN. A positive control with N's two genuine conflicting approvals
must produce a verified personal proof. **Mutants:** erase A on merge; count an
observation toward14; treat the observation as fraud; block all B descendants.
**Evidence:** durable choices, typed signed bytes, receipt verification and sanctions.

### P0-T08 — Admission forgery and the actual capture boundary

**Given:** Six gateway roster variants:20 free keys;20 invalid-work tickets;20 valid
fresh tickets;20 mature-looking tickets known only from this gateway; a genuinely
qualified regional committee;20 real mature attacker identities already admitted
through the recipient's independently configured trust context. Add foreign F2F
provenance, forged old timestamps and a pending-ticket replacement case.
**When:** Verify eligibility and catalog/top20 against the recipient's real context.
**Then:** First four unqualified variants fail; valid local committee passes.
Foreign/self-asserted provenance and inherited replacement age fail. The mature,
actually admitted attacker set exposes capture: do not assert magical rejection
or f<=6 from ticket costs. Report the breached trust/fault premise. **Mutants:**
allow gateway-supplied catalog authority, signature validity alone, or N keys=N
independent humans. **Evidence:** observation provenance, work/maturity checks and
explicit admitted-capture result.
Also deliver eight old heartbeat slots in one batch: they must not count as eight
observed hours. Replay an old signed reachability response under a new view:
without a fresh challenge/valid observer context it cannot renew eligibility.

### P0-T09 — Admissibility before min-hash and mixed-mode support

**Given:** A supported Regional14 A. Candidate variants alter origin, ancestry,
root expiry, signature, network/shard/view, signer uniqueness or entire child bundle.
Other valid lower-hash B variants have one vote, partial quorum, PROVISIONAL proof
or a real Regional14 receipt. Include two provisional rivals and late valid live
proof older than 30days, plus an already expired root.
**When:** Import each variant alone; then deliver a genuine Regional14 receipt
for provisional B, collected in another admitted view whose signers had compatible
own choices and no locally excluding A evidence at issuance; rederive statuses.
Also try collecting fresh B votes from nodes already excluding B through A.
**Then:** Invalid data never participates. Hints/partials/provisional cannot displace
A. Actual class2 B competes by hash; provisional rivals compare within class1.
Promotion requires a true same-view14 certificate and may revise derived VOID.
Nodes already excluding B refuse fresh B votes; import of independently issued
authentic rival evidence is not such a fresh approval.
Live old proofs are not rejected at30days; expired roots never revive. **Mutants:**
min before validation; promote by label; combine views; resurrect pruned expiry.
**Evidence:** candidate/support table, exact winner and reasons for every variant.

### P0-T10 — Late smaller candidates and bounded proof repair

**Given:** Valid Regional14 C,B,A with `H(A)<H(B)<H(C)` on one slot and independent U.
C arrives first, B at reconnect, A after a further long delay while root remains
live. Repair transfers include omissions, duplicated/out-of-order ranges and an
interrupted cursor resume.
**When:** Perform bounded shard-direct anti-entropy, validate source/cursor scope,
complete repair and repeat A; do not use lock gossip.
**Then:** Incomplete repair cannot assert readiness; complete evidence yields
C->B->A with U unaffected and duplicate delivery idempotent. Original approvals
remain. Reconnect, a matching digest or quiet interval never enables green.
**Mutants:** freeze the first merged winner; discard live proofs after 30days;
advance a durable cursor before records commit. **Evidence:** transfer/cursor trace,
retained proof references, derived revisions and zero lock-gossip emissions.

### P0-T11 — Correlated loss, resource failure, crash and view skew

**Given:** A frozen20 with exactly7 unavailable members; another fixture with
reachable mature replacements; fixed slight catalog/reachability differences
among honest voters. Separate persistence/flood cases fill bounded queues, delay
commit, crash before/after durable acknowledgment, and restore stale own history.
**When:** Collect, attempt future-view reconstitution, reconnect, and retry the
same intent or an opposing intent after restore. Saturate background sync while
retaining declared checkout and repair budgets.
Inject observer clock intervals with overlap, then excessive uncertainty, and
replay an expired positive response after reconnect without a new challenge.
**Then:**13 responses never count as14. Reconstitution is between attempts and only
works when14 voters independently accept a view. Disagreement may honestly stall;
measure it. Full queues reject before RAM mutation; no undurable signature leaks.
Crash-after-commit retry preserves the choice; lost own history stays passive
regardless of matching digests. No timeout/resource/telemetry ban occurs. Check
independent ready scopes remain serviceable subject to actual shared resources.
Clock uncertainty and replay cannot extend a lease or authorize a fresh approval.
**Mutants:** erase choice on timeout; turn view change into signing amnesty; uncap
queues; treat observation equality as rollback recovery; globally ban slow peers.
**Evidence:** wire rejections, durable trace, queue bounds and availability timeline.

### P0-T12 — Coordinated attack scale, merchant limits and uncertain checkout

**Given:** A deterministic workload of 1000 valid independent consumed outputs,
100 coordinated owner double-spends across regions, multiple recipients and fixed
successor depths. Fix at least one unaffected sibling path per split attack.
For terminal-only test units, use single-purchase cap10 and cumulative regional
cap20 per local policy interval; these values are fixtures, not currency advice.
Include concurrent purchases6+6+6+6, one11 purchase, repeated receipts, terminal
restart, lost first response and a proposed alternate-voucher retry.
**When:** Run a long scheduled partition, accept only according to each terminal's
policy, deliver all supported conflicts and revalidate exact causal dependencies.
**Then:** Report authentic regional receipts, accepted/rejected purchases, losing
recipients, dependent output count, total revalidation/proof traffic, convergence
time, useful throughput and p95/p99 with the workload assumptions. Cap10 rejects11;
cap20 atomically admits at most three6 purchases before reset. Journal restarts/
duplicates release goods once. UNKNOWN never silently starts another payment.
No amount reaches L2, no policy changes evidence class, and no global ceiling or
real-world attack frequency follows from these counters. **Mutants:** enforce only
single-purchase cap; race cumulative counters; switch voucher on timeout; ignore
descendant loss or assume one attacked input per partition. **Evidence:** separate
blind L2 logs, terminal policy/purchase journal and exact fixture-derived damage.

## 9. Invariants, conditional arguments and acceptance gate

| Invariant | Required property / qualification | Main cases |
| --- | --- | --- |
| P0-I01 | Only independently admitted mature identities count; no proof of operator independence is inferred | T03,T08 |
| P0-I02 | One frozen view and exact payload per receipt; distinct full identities and proper threshold | T02,T03,T09 |
| P0-I03 | OwnChoice is immutable and durable before a binding response across views/crashes | T07,T11 |
| P0-I04 | Supported comparable candidates select one deterministic canonical transaction; partial data cannot take over | T04,T05,T09,T10 |
| P0-I05 | Only actual losing dependencies lose usability; split bundles are atomic | T06,T12 |
| P0-I06 | Personal sanctions require two authentic incompatible approvals; no honest merge loser is punished | T05,T07,T08 |
| P0-I07 | Finite compatible evidence converges after eventual delivery; no finite deadline under arbitrary withholding | T04,T10,T11 |
| P0-I08 | Regional-only evidence never produces FINAL_GLOBAL | All12 |
| P0-I09 | Merchant limits and purchase reconciliation remain outside blind L2; uncertain receipt is not failed payment | T12 |
| P0-I10 | Expiry, bounded parsing/persistence/repair and F2F barriers remain enforced at actual receivers | T08–T11 |

Within one fixed20-member view, any two14-voter sets intersect in at least 8.
Under the conditional at-most6 Byzantine assumption, at least 2 correct members
would need incompatible immutable approvals; the signing rule excludes that.
Different regional windows need not share those honest voters; conflicting
regional receipts remain allowed. Mature-ticket admission does not establish
the assumption. A hidden-key compromise or lost signing history can invalidate it.

Local liveness is conditional on a stable qualified20 population (or smaller
provisional population), a view accepted by enough signers, enough timely ready
responders, available causal/receipt data and fair bounded storage/transport work.
A common valid view and 14 timely ready votes can complete; P0 cannot promise either
under every F2F graph, operator refusal, eclipse or partition. Permanently lost
proofs or choices remain explicit unavailability cases. Regional autonomy removes
the predecessor14 dependency, not all possible deadlocks.

Design elaboration is delivered by this revision. **P0 is not verified/closed**
until: the12 scenarios are executable with passing positive and rejecting unsafe
mutants; compatible context and mixed-mode assumptions are exercised; production
limits are measured; and actual receiver-side QUIC/crash tests validate new network
and storage defenses. A green global mode needs its own separately justified
scheme; no absent proof is papered over with a new status name.

## 10. Integration work and evidence provenance

| Surface | Required alignment before production use |
| --- | --- |
| Shared protocol library / human-money-core | Canonical blind intent, complete bundles, ownership/ancestry, support policy, versioned approval/observation domains and one authoritative hash rule |
| Current resolver | `resolve_split_brain_with_proof` in sim-core `resolver.rs` currently uses a smallest-node attestation signature as hash entropy; signer subsets can change the hash, contrary to §2. Replace/version this behavior only in a separately implemented migration |
| L1 offline conflict import | The inspected core import path uses earliest transaction time in places; reconcile with this admitted min-hash rule, rather than assume current consumers already agree |
| Peer manager / presence | Reconcile code first-seen incubation with specified heartbeat maturity, persisted safe-time records, regional reachability cuts and 24h population continuity |
| Storage / readiness | Explicit immutable choices versus derived winners, atomic durable acknowledgment, independent admission history, same-key loss/rollback gate and retention budgets |
| Transport / gateway | Versioned view/proof payloads, typed status/observations, no mixed quorums, receiver-side admission/work caps and scoped anti-entropy |
| Wallet / terminal | Independent historical context, cryptographic receipt checks, fail-closed global guard, explicit merchant risk/purchase journal and portable custody |
| Existing specs and CEH research | Consolidate unconditional FINAL, min-hash, async-durability and handoff statements deliberately; preserve historical counterexamples and original Q-S3.3-01 |

Relevant local sources: [admission](07_admission_und_wot_buergschaften.md),
[presence](11_organische_praesenz_und_dunbar_gossip.md),
[resolver](../crates/humoco-sim-core/src/resolver.rs),
[peer manager](../crates/humoco-node/src/network/manager.rs),
[prior robustness report](DECENTRALIZED_ROBUSTNESS_RESEARCH.md),
[interview record](ARCHITECTURE_INTERVIEW_NOTES.md#758-p0-formal-contract-and-twelve-acceptance-scenarios),
and [closure work plan](CEH_SECURITY_CLOSURE_WORK_PLAN.md).
These are design inputs, not claims of freshly executed production audits.

### 10.1 Previously executed bounded analysis, unchanged

For an ideal equally split network and a sampled old committee of 20, with
`X ~ Binomial(20,0.5)`: `P(X>=14)=0.057659149`,
`P(X>=14 or X<=6)=0.115318298`, and `P(7<=X<=13)=0.884681702`.
The latter gives an expected 57,978.5 blocked committees out of 65,536.
Finite uniform N1000 split500/500 hypergeometric calculation gives approximately
0.888313073 with neither side holding old 14. These placement models do not measure
internet geography, prove independent shard failures or predict an outage from
one broken cable. The old checkout quorum itself has this partition limit.

CP-0046 also evaluated343 finite already-admitted union/min combinations and a
split sibling/descendant example. Those checks assumed fixed hashes and valid
candidates; they do not verify the expanded draft0.2 protocol, admission, signatures,
mixed-mode support or merchant policy. No new model, Rust suite, QUIC test or
performance measurement is claimed by this documentation-only elaboration.
