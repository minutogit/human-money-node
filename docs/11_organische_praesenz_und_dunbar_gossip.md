# 11. Organic Presence, Bounded Dunbar Gossip and Domain Isolation

> **Status:** Requirements reconciled with DEC-040/055/056/083–089. Presence is a local observation, not an authoritative global voter roll. Simulation fits and diagnostic thresholds are not security theorems. See [invariant/evidence registry](INVARIANT_REGISTRY.md).

## 1. Local knowledge and two gossip streams

A node learns presence through configured, authenticated direct F2F friends. Incoming gossip from a non-friend is discarded. Learned eligible identities may be used for separately authorized shard-direct RPC; an arbitrary endpoint is not admitted merely because it can connect. These P2P restrictions never apply to public client HTTP ingress.

Mesh gossip has exactly two streams ([INV-1006](10_p2p_wire_format_und_session_framing.md)):

1. Hourly heartbeat/presence, carrying authenticated topology and allowed clock/load observations.
2. Cryptographically verified first-party equivocation evidence with priority forwarding.

No lock gossip, receipt sampling, bad-peer rumors, general reputation feed, active presence ping storm or application leave flood is added. A lock is synchronized through bounded shard-direct digest PULL; it is not an epidemic gossip event.

## 2. Cadence, fan-out, freshness and deduplication

Each node emits a heartbeat at the specified hourly cadence. Forwarding has hop TTL 16 and Dunbar fan-out

`k(d) = min(d, ceil(sqrt(d)) + 1)`.

For `d=1`, fan-out is one; for `d=16`, five; for `d=64`, nine. Degree zero has no forwarding edge. Hop limits and sparse forwarding bound amplification, but do not guarantee global percolation for arbitrary topology or loss.

Apply bounded framing, recipient authorization, freshness and deduplication before expensive work where possible. Cryptographic verification precedes acceptance of the claimed sender, signed state or fraud. The designed heartbeat freshness window is ±60 seconds relative to the approved network-adjusted logical time, not naive unsanitized `SystemTime::now()`. Exact boundary/restart/clock behavior still needs proof and production evidence. Dropped stale/duplicate messages do not consume the honest admitted-forwarding budget; they still require separately bounded receive/parsing work.

Remember verified `(full identity, hourly slot)` observations within a bounded deduplication structure; a short hash prefix is only an index hint, never sufficient identity equality. Identical retransmissions are not a second signed decision. A claimed packet size of 64 bytes cannot include a 64-byte signature plus all header, identity, nonce and time fields; use the actual bounded wire schema in Spec 10 rather than that legacy estimate.

## 3. Local edge budgets

The existing heuristic budget for positive degree is:

`R_soft_hour = max(60, ceil(N_local * k(d) / d * 2))`.

An illustrative RED limiter uses `R_hard = 5 * R_soft` and:

| Observed edge rate | Drop probability |
| --- | --- |
| `r <= R_soft` | `0` |
| `R_soft < r <= R_hard` | `1 - R_soft/r` |
| `r > R_hard` | `1` |

The limiter needs bounded receive queues, time-based rate accounting, cheap rejection and fair treatment of distinct admitted work. The formula alone does not prove service fairness, botnet exclusion or resource safety under adversarial scheduling. Changes in a single observer's known-node count cannot establish global network size or authorization.

The older tables claimed 87.9–100% honest activation and 99.9% bot rejection/merge success. They lack a reproducible model/configuration/evidence mapping here and are not normative guarantees. Multiple independent bridges can improve connectivity, but a bribed bridge can still introduce valid work-backed identities. No theorem establishes that all bots behind it remain immature or that every real village merges within 24 hours.

### [INV-1104] First-seen newcomer pacing

Coalesce first-seen announcements by verified full identity before queuing. Use bounded per-edge queues and bounded total admission work; already known observations still obey authentication, freshness, deduplication, fan-out and edge budgets. Being known does not authorize unbounded forwarding to all friends.

The former example `50min + Uniform(0,20min)` has a one-hour mean and illustrates jittered pacing; it is not a promise of global 3–6 hour propagation. Valid time must drive waiting; local membership tests alone do not make pacing clock-independent.

The old queue-depth-4 QUIC health-check campaign is removed under DEC-055's passive-presence policy. Do not send background probes to refresh newcomers or candidate windows. Legitimate demanded RPCs retain their normal transport behavior. Pacing must survive full queues without unbounded memory, retry amplification or accidentally promoting a queued identity to a qualified committee member.

## 4. Ticket maturation, passive exclusion and shard readiness

Keep distinct state for ticket/identity admissibility, passive presence and per-shard readiness. New tickets mature only after 24 hours of valid local observation; a self-signed timestamp cannot shorten the wall. Existing newcomer admission uses at least eight valid hourly observations in that 24-hour history; this admission history is not a 24-hour committee term.

DEC-056 selects exclusion from future HRW snapshots after three consecutive missed hourly gossip heartbeats. It supersedes the old claim that offline nodes remain eligible for 21–24 hours. An in-flight request retains its frozen roster. A short RPC miss, explicit NOT_READY, normal shard idle closure, local capacity rejection or cancelled straggler does not constitute a missed hourly heartbeat and cannot cause a ban. Successful lock RPC alone does not erase missing presence history.

Exact hourly slot closing deadlines, logical-time tolerances, restart reconstruction and the safe reentry predicate remain to be consolidated and proved. Older two-heartbeat fast-reentry, 8/24 sliding-history reentry and extra flap-exception descriptions disagree; no new exception is selected here. Two observations an hour apart also do not prove two full hours of uptime. Retention is separate: dormant remote metadata follows the 60-day policy and direct-friend metadata the one-year policy in Spec 07, rather than unconditional deletion when a short observation bitmap empties.

HRW eligibility is not authorization to sign from an empty shard. Newly assigned shards remain NOT_READY until demand-triggered complete justified recovery and durable installation. Missing all old signers is not an archival failure: transfer objective active lock state, not historical quorum bundles. Matching unready empty digests do not supply the missing safety proof.

## 5. Clock and work signals

Only authenticated direct-friend observations feed the approved network-adjusted clock. A median can limit some outliers; it does not guarantee safety when the trusted input set itself is biased or its time distribution is unbounded. Do not assert automatic harmonious correction from an arbitrary influx of external heartbeats. Logical time, drift clamps, monotonicity and the allowed ±60-second acceptance envelope must be evaluated together; monotonic elapsed timers and protocol timestamps are not interchangeable.

The older sketch used a ±15-minute offset clamp and a 45-second skew warning, with ten direct-friend samples and gradual correction. Treat these as existing design parameters requiring compatibility review, not proof that NTP jumps can never cause false accusations or small villages always have ten independent observations. Private clock diagnostics inform operators and never trigger bans. No new NTP automation is authorized by this text.

Heartbeat work/difficulty summaries may support a direct-friend median, renewal headroom and time-based dampening. Earlier +5%/30-day and 2–4x surge examples require measurement and consistency with quota/ticket policies. Neither a diagnostic median nor a difficulty index is cryptographic committee authority. Optional mining respects node sovereignty.

## 6. First-party evidence and false-accusation boundaries

A permanent node sanction requires the offender's own fully verified incompatible signed statements under the exact specified proof predicate. Mere heartbeat rate, topology, missing responses, queue depth, a remote accusation or clock skew is insufficient. Never co-sanction friends.

The historical heartbeat detector proposed a same-author pair less than 50 minutes apart, bounded direct-mapped storage, a 75-minute replacement horizon and a one-hour startup wait. Array sizes varied between old texts. These are implementation sketches, not a complete anti-framing argument: distinguish exact duplicate replay from genuinely distinct incompatible messages, verify full keys/signatures/domains, account for restart and time changes, and specify proof retention. A collided/full detector can miss evidence; it cannot invent guilt. A fixed startup delay alone does not prove crash or clock safety. Preserve existing formal fraud-family work in Spec 10, with receiving-side adversarial verification required before claiming enforcement.

## 7. [INV-1105] Gossip percolation model — qualified legacy claim

The previous document described the fitted curve

`R(x) = 100 * exp(-((x / 73.1)^19))`

as an exact censorship threshold. Its coefficients depend on topology, fan-out, hop limit, scheduling and the experiment; they are not physical protocol constants or an identity ban rule. The old reachability table included paths exceeding the configured TTL and cannot certify the TTL-16 protocol without its model assumptions. No universal 73.1/74% tipping point or 50%-cartel censorship immunity is established. Keep this identifier as a qualified modelling topic, not a production guarantee; a reproducible scenario-specific evaluation remains required.

Likewise, differing local HRW candidate sets can change authority. Minimal disruption of rendezvous hashing does not prove a common top-twenty or safe membership transition. Frozen rosters prevent expansion within one checkout, not divergence across regional views. Class-first canonical merge is selected policy, not compensation for missing transfer/activation proofs.

## 8. [INV-1106] Cryptographic gossip domain separation

Every accepted heartbeat authenticates the network's canonical domain together with the complete identity, hourly/calendar context, timestamp and defined payload. Hashing uses the canonical length-prefixed domain mechanism. Mainnet/base unanchored islands and testnet have separate domains, including the existing `HUMOCO_V1_HEARTBEAT_MAINNET` and `HUMOCO_V1_HEARTBEAT_TESTNET` labels where the wire version uses them.

A valid signature in another domain is invalid locally; forwarding by a friend does not remove the receiving node's obligation to verify. Use full authenticated network context; domain separation does not authenticate an otherwise arbitrary roster or decide which network an unanchored node may safely adopt. Existing domain/manifest authorization boundaries remain explicit in Spec 08.

## 9. Evidence requirements

Real QUIC tests must distinguish friend/non-friend streams, replay versus distinct signed heartbeat fraud, wrong-domain messages, stale/future timestamps, bounded newcomer floods, queue saturation and neutral shard timeouts. Passive selection needs scenarios for three missed slots, restarted observation state and delayed reentry; exact slot/reentry rules remain open. Measurements must state topology/model/configuration instead of treating a fitted graph as a security theorem. This reconciliation executes no tests and makes no complete-wire-defense claim.
