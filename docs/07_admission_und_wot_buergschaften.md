# 07. Admission, F2F Peering and Sybil Resilience

> **Status:** Normative requirements reconciled with DEC-053–089. Admission constraints are not proof of a globally identical roster, a per-shard Byzantine bound or safe committee transition. See [invariant and evidence registry](INVARIANT_REGISTRY.md).

## 1. Permanent identity and renewable shard ticket

`NodePubKey` is the permanent Ed25519 identity for TLS and F2F friendship. `HrwRoutingId` is the renewable Argon2d-based ticket used only for HRW scoring. Renewing a ticket does not create another identity, duplicate its vote or rebuild friendship edges.

The ticket design separates public work from uniform routing output:

1. Compute public Argon2d work from `NodePubKey || Nonce || T0`, with the specified parameters (`m=64 MiB, t=3, p=1`). Validate the complete binding, work score and parameter set rather than accepting a claimed routing hash.
2. Derive the uniform routing ticket with length-prefixed `DOMAIN_HRW_ROUTING_TICKET`, identity, canonical nonce/time encoding and the work result. HRW ranks its full 256-bit output; identity tie-breaking is deterministic.

Argon2d has public inputs here; password-secret timing protection is not the motivation. No statement of maximal ASIC resistance, fixed mining hours or impossible grinding follows from that choice. Parameter compatibility, work calibration and implementation verification remain required.

### 1.1 Work floor, admission threshold and renewal ratchet

The admission design uses an immutable minimum floor and a locally derived network-work threshold:

`W_min_admission = max(W_min_floor, W_net_median >> 3)`.

A new ticket for an existing identity must satisfy
`W_new > max(W_active, W_pending)`.

This rejects equal/weaker replacement tickets; it does not mathematically eliminate targeted grinding. A single valid active ticket contributes one identity to HRW. New tickets are announced immediately but mature only after 24 hours of valid local observation. A self-signed old timestamp cannot backdate that observation. The previous active ticket may remain in use while a valid replacement matures; a newcomer has no active rank before maturation.

### 1.2 Headroom and operator feedback

The diagnostic ratio is `H = W_own / W_net_median`. The existing headroom guide is:

| Ratio | Meaning |
| --- | --- |
| `H >= 0.25` | Healthy relative margin |
| `0.16 < H < 0.25` | Low-headroom warning |
| `0.125 <= H <= 0.16` | Renewal advisable |
| `H < 0.125` | Below the relative admission threshold |

Direct F2F feedback may signal `FLAG_POW_OUTDATED`; multi-hop invalid/outdated announcements are dropped under the admission rules. Friendship remains bound to `NodePubKey`. Work admissibility is distinct from diagnostic headroom: warnings do not create bans, automatically replace software or override operator policy. Optional mining runs with bounded low-priority resources; zero downtime is not guaranteed if an old ticket loses eligibility or new assignments still need sync.

## 2. Organic F2F entry and social peering

One verified reciprocal friend edge can introduce a newcomer into the mesh. At least three independent neighbors are recommended for resilience against one censoring bridge; this is not an additional consensus-entry threshold. One edge does not guarantee worldwide propagation or safe roster authority. A bribed friend can introduce valid work-backed Sybils; edge throttling, pacing and maturation constrain but do not prove their exclusion.

Before adding a peer, the operator applies the five-finger checklist:

1. Personal acquaintance or a verified WoT relationship.
2. Plausible knowledge of physical region, outside the blind consensus state.
3. Explicit reciprocal agreement and full-key configuration.
4. Review of existing social connections and concentration risks.
5. No bought, sold, rented or collateralized friendship slots.

These are social operating rules, not remotely provable facts about a stranger's humanity or independence. Friends bear no financial liability and are not banned for another identity's offense. Every permanent node sanction needs the offender's own verified cryptographic proof. There is no staking.

Public client ingress is separate: any client may submit admitted requests. A P2P NodePubKey is public information and can never be an ingress bearer credential; ingress friend access uses random 128-bit secret tokens. Do not apply P2P peer-IP admission to public HTTP clients.

## 3. Presence, eligibility and readiness are distinct

Three mechanisms must not be conflated:

| Mechanism | What it controls | What it cannot establish |
| --- | --- | --- |
| 24-hour ticket maturation and observed admission history | Whether a new ticket can enter later HRW calculations | Committee tenure or 24-hour outage detection |
| Passive hourly F2F heartbeat presence | Locally active/non-suspended candidates | Global network membership, a ban, or shard state completeness |
| Per-shard safe recovery/readiness | Whether an eligible member may issue a countable vote for that shard | Authority from a guessed roster or unverified source |

Newcomer admission retains observed 24-hour maturity plus at least eight valid hourly observations in the 24-hour history. Ongoing liveness excludes a peer from subsequent HRW snapshots after three consecutive missed hourly heartbeats (`missing_count >= 3` / suspended). Do not wait 21–24 hours to exclude an offline member. The older two-heartbeat fast-reentry, universal sliding-history reentry and flap-exception descriptions conflict; exact restart/reentry and slot timing remain unresolved under DEC-056. None authorizes immediate signing because one RPC succeeded; reactivation still needs justified presence and shard readiness.

Short RPC timeouts and normal shard-pool idle closure do not advance the hourly presence clock. No active background ping campaign refreshes candidates. Gossip forwarding is not suppressed because someone else claims a peer is bad. Ticket readiness does not bypass local shard recovery.

### 3.1 Knowledge-count diagnostics are not authority

The earlier `NodeSyncStatus` compares local known-node count to a direct-friend median. Its hysteresis estimates were:

- Enter apparently in-sync when `N_local >= max(N_median - 2, floor(0.95 * N_median))`.
- Fall back when `N_local < min(N_median - 3, floor(0.90 * N_median))`.

These may describe diagnostic lag; equal counts can contain different identities. Neither threshold certifies a canonical roster, complete state, authorized current committee or safe activation. A global ready flag cannot substitute for shard-specific safe recovery. No telemetry warning authorizes automatic banning.

## 4. Retention and local operator control

Known dormant remote identities may be retained for 60 days rather than all being deleted after a 48-hour observation ring empties. After that retention expires, returning identities need the appropriate newcomer observations again. This metadata retention is separate from active-lock TTL.

Configured direct friendship metadata may be retained for one year of inactivity, then deactivated for explicit operator reactivation through local administration. A private diagnostic dashboard reports conditions; it is not a public control plane. Ban evidence/identity revocation state is not an expired voucher tombstone.

## 5. Departure and safe succession

A planned shutdown uses transport-native QUIC `CONNECTION_CLOSE` to direct connected peers; it creates no third global leave-gossip stream. Socket closure itself does not authorize a different checkout committee. Silent failures are handled through bounded RPC collection and passive presence; shard-direct idle close is normal.

The current request retains its frozen at-most-twenty committee. A later justified HRW snapshot may select a new member after presence changes; rank 21 cannot fill the current request's missing slot. The new member remains NOT_READY. The first admissible relevant request starts bounded per-shard recovery, not a sweep or payment queue.

Recovery must establish authenticated source/confirmation authority, all still-active root lifetimes, a coherent snapshot plus bounded concurrent deltas, per-entry validity and durable installation. Matching empty digests from unready peers do not prove continuity. Existing partial data remains serviceable to authorized peers, but does not make its source a qualified voting witness. No universal five-millisecond recovery or guaranteed preservation from any remaining nineteen copies is claimed. Safe activation/source coverage remains a proof obligation; there is no mandatory old-committee permission chain.

## 6. Invariants and explicit legacy revisions

1. **[INV-0701] Universal Argon2d admission:** Validate work and canonical identity/nonce/time binding, parameters, minimum floor and routing derivation. Fixed mining-hours claims are estimates, not invariant guarantees.
2. **[INV-0702] Social entry edge:** Gossip introduction requires a configured verified reciprocal F2F edge. One edge can suffice; it proves neither humanity nor independence of all introduced identities.
3. **[INV-0703] Observed maturation:** New tickets remain ineligible for 24 observed hours; initial admission retains the required observed heartbeat history. This is not a committee term or liveness timeout.
4. **[INV-0704] Passive reactivation:** Three consecutive missed hours suspend future selection. Reentry does not bypass safe shard recovery; its exact retained-history/restart predicate remains pending. Earlier 21–24h failure detection is superseded, while conflicting fast-reentry/flap sketches establish no completed rule.
5. **[INV-0705] Metadata retention:** Keep dormant remote entries for the 60-day policy; after a year of direct-friend inactivity require operator reactivation. These periods do not prolong active voucher locks.
6. **[INV-0706] First-party identity revocation:** Fully verified same-author incompatible signatures authorize permanent identity/ticket revocation and WoT severance. Proof verification is independent; ban enforcement retains local state. No hearsay or guilt by association.
7. **[INV-0707] Safe successor readiness:** Later HRW selection does not imply state readiness. Require demand-driven complete justified transfer and durable activation. The previous seamless/immediate successor guarantee is withdrawn.
8. **[INV-0708] Transport-native leave:** No global application leave gossip. A connection close affects transport lifecycle, not the frozen checkout roster.
9. **[INV-0709] Identity-stable ticket renewal:** Renew only the ticket under the same authenticated identity and maturation rule; preserve friendship edges. Optional mining honors operator control and bounded resource budgets.
10. **[INV-0710] Five-finger operating doctrine:** Apply the social checklist without financial deposits; do not claim it cryptographically eliminates botnets.

## 7. Evidence gates

Real QUIC scenarios must reject unauthorized shard peers and non-friend gossip, verify ticket binding/maturation and exercise neutral close/timeouts. Adversarial recovery must cover all-unready sources, missing old active locks and membership change during installation. Roster authority, adversary bounds and activation safety need explicit arguments. No such tests or proofs were executed by this documentation reconciliation.
