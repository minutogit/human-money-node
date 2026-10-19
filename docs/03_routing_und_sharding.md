# 03. Routing, Fixed Checkout Committees and Demand-Triggered Recovery

> Canonical requirements. The complementary [status and sync specification](03_statusabgleich_und_sync.md)
> defines live proof semantics. Selected requirements do not establish the still
> open membership/source-continuity proof or implemented behavior.

## 1. Shard and identity selection

There are 65,536 fixed voucher shards. The voucher's genesis determines its shard:

`Shard_ID = u16::from_be_bytes([Genesis_Hash[0], Genesis_Hash[1]])`.

Every descendant/output remains in this shard. `NodePubKey` is the permanent
Ed25519 identity; `HrwRoutingId` is its replaceable Argon2d shard ticket. HRW ranks
eligible identities by the full 256-bit `BLAKE3(HrwRoutingId || Shard_ID)` score,
with deterministic full-key tie breaking. Canonical encoding/domain definitions
belong to the shared protocol library; shorthand formulas omit no required domain.
A new ticket matures after 24 hours of verified observation, not a self-asserted
old timestamp. One active and one announced successor ticket are permitted per
identity; re-mining does not create a second vote (DEC-018).

Presence derives passively from hourly F2F heartbeats. Three consecutive missed
heartbeats exclude a peer from subsequent local HRW snapshots (DEC-056). Ticket
maturation, calendar `epoch_day`, the existing network-size stability hysteresis,
and passive presence are four different clocks. None creates daily committee terms.

## 2. Frozen checkout collection

For one checkout, freeze one canonical HRW snapshot of at most twenty distinct
full identities, including eligible self in the same ranking before truncation.
At N>=20, FINAL requires fourteen verified votes from these twenty. At N<20,
retain adaptive `Q(N) = floor(2N/3)+1` and PROVISIONAL status. The existing 24-hour
network-stability rule for FINAL does not authorize a third assurance status.
FINAL is regional/revisable under DEC-053/054, not global irreversibility.

Dispatch to all eligible members concurrently. Collection stops immediately at
quorum, when the remaining eligible members cannot reach quorum, or at the 800 ms
collection deadline. No rank21–40 substitution, sequential hedged expansion or
statistical membership shortcut is permitted. All causes of unavailable votes
share the six-member headroom: slow disk, failed transport, Byzantine withholding
and NOT_READY do not each get a separate allowance. A timeout is an uncertain
outcome; it does not free a consumed slot or roll back successful commits.

Every original approval and eligible self vote passes current responsibility,
per-shard readiness, atomic collision/own-choice checks and the exact durable
lock+immutable-own-choice commit before release. Signature computation is in RAM;
blocking redb work runs only in the bounded worker, without RAM guards held over
the acknowledgment wait. See [Spec 14 §4](14_node_persistenz_und_redb_speicher.md#4-asynchronous-write-path-and-durable-signature-release).

Recipients verify every counted Ed25519 signature, distinct full-key membership,
status and exact network/shard/root/consumed-output/target/purpose/context binding.
Bitmaps refer to this same frozen snapshot; popcount, truncated IDs, Bloom filters,
score quantiles and a gateway-supplied roster alone establish no authority.
A justified snapshot despite differing local views remains gate S2.

## 3. Reads and local feedback

**INV-0310** preserves ordinary status `read_quorum=1`: choose one member of the
current top20 using the existing randomized routing policy. Bounded read backoff
and another eligible target after failure remain client/gateway routing behavior;
this does not turn a matching record into payment clearance. Explicit payment
verification requires the fresh full quorum proof in the complementary Spec03.
The exact bounded read timeout/retry parameters remain integration work; there is
no guaranteed sub-100-ms Internet failover.

**INV-0309** is local diagnostic feedback only. A `signers_bitmask` can describe
observed collection; an unsigned or gateway-asserted absence is not first-party
fault evidence and cannot propagate failure judgments to other peers. Distinguish
actual local failures from NOT_READY, NOT_IN_SHARD, ordinary capacity refusal,
idle closure and cancellation after quorum, which are neutral. Checkout counters
cannot exclude identities from future HRW presence, expand the frozen electorate,
or suppress heartbeat/fraud gossip. Local scheduling backoff must be bounded and
recoverable. The old same-name missing-count/piggyback sanction mechanism is retired.

**INV-0308** retains bounded F2F-only gossip with the fan-out rules in Spec11.
Historical 73.1% percolation and 99.8% reach fits are informative model candidates,
not universal censorship immunity or authority/fault bounds. Transport and topology
assumptions need their own evidence; checkout failures do not throttle presence.

## 4. Demand-triggered shard recovery

A newly assigned or insufficiently recovered shard starts NOT_READY, including
an unknown/default shard. Trigger one bounded digest-pull job when the shard is
first needed. Do not eagerly scan all 65,536 assignments or queue pending payments.
Coalesce concurrent recovery triggers per shard; clients use the existing bounded
exact-payload retry policy. Unrelated ready shards continue serving.

The selected transfer skeleton is a fixed snapshot with bounded, gap-free deltas
through installation (DEC-058/059/061/085/086). Verify source identities, request
and shard/snapshot/cursor binding, all imported fields, counts/bytes/digests,
root lifetime and completeness before atomic durable installation. Retain every
live root through `root.valid_until+30s`, including locks older than24h. An empty
local index, one matching lock, a network-size median or14 newly empty replicas
agreeing on a digest cannot establish safe readiness. Original own choices are
retained independently and cannot be overwritten by imported canonical state.

Known retained data may be served by an unready or no-longer-responsible peer;
that does not make the source a qualified current witness. No binding write or
live-state quorum signature is issued before safely installed readiness. Source
continuity and authority are not supplied by an inherited old-quorum archive or
mandatory predecessor permission. Those constructions remain rejected.

A single data stream matching an authenticated digest can save bandwidth, but
matching a digest proves integrity relative to that digest, not complete history
coverage. In the8+6+6 example, eight peers know independent confirmed locks A+B,
six know only A and six only B: each lock may have14 supports while no 14 peers
share a whole-state digest. A digest-equality-only retry loop is not a proven
recovery algorithm. Exact source coverage, concurrent-write cutoff/activation and
bounded cursor/buffer contracts remain gate S3; fail closed while unjustified.

## 5. Lazy client reconciliation

Do not ingest unsolicited dead histories. Clients retain L1 ownership/causality
and submit a bounded required ancestry path to the target output when needed.
Accept the valid prefix and stop at the first invalid/conflicting step; preserve
already accepted progress. This does not require recursive L2 receipts. Shared
active state is synchronized directly; hot-path locks are never gossiped.

## 6. Invariant ownership

1. **[INV-0301] Bounded Relevant Ingestion:** No unsolicited dead-history dump; client reconciliation and justified active-state recovery have separate bounded admission.
2. **[INV-0302] Root-Shard Locality:** All descendants/outputs of one voucher root remain on its fixed genesis-derived shard.
3. **[INV-0303] No Checkout Replacement or Failure Gossip:** Freeze the electorate; local failures never authorize substitute votes or hearsay sanctions.
4. **[INV-0304] Verified Active-State Pull:** Verify current-state source qualification, integrity and coverage; no inherited historical quorum bundles. Source-continuity proof remains open.
5. **[INV-0305] Per-Shard Readiness Barrier:** A shard may vote only after complete verified durable state installation. Unknown or syncing state fails closed; unrelated ready shards remain usable.
6. **[INV-0306] Demand-Triggered Recovery:** First legitimate need triggers at most one bounded recovery job per shard; no eager sweep or payment queue. Legacy rank-invitation authorization is retired.
7. **[INV-0307] Autonomous Membership, Separate Safe Activation:** Living-mesh HRW defines prospective responsibility; verified continuity/readiness gates signatures. Legacy24h socket-uptime successor tenure is retired.

INV-0308–0310 are defined in §3. See the [registry](INVARIANT_REGISTRY.md) for
qualified legacy meanings and concrete acceptance obligations. None is an
executed security result.
