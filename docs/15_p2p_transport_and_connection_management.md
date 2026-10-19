# 15. P2P Transport and Connection Management

> **Status:** Canonical English transport requirements, consolidated from the
> accepted architecture interview packages DB2–DB5 and DEC-083–088.
> Requirements describe the target contract; this edit does not establish current
> implementation, measured latency or executed security evidence.

This specification covers internal node-to-node QUIC transport. Public wallet
and Point-of-Sale HTTP ingress is a separate boundary. Membership and routing
are specified in [Spec 03](03_routing_und_sharding.md), framing in
[Spec 10](10_p2p_wire_format_und_session_framing.md), persistence in
[Spec 14](14_node_persistenz_und_redb_speicher.md), and passive presence in
[Spec 11](11_organische_praesenz_und_dunbar_gossip.md).

## 1. Identity, authorization and separate connection roles

Internal P2P uses QUIC over UDP with TLS 1.3 authentication bound to the permanent
Ed25519 `NodePubKey`. The separately mined `HrwRoutingId` is used for HRW routing;
a valid connection or routing ticket alone does not establish committee authority.
Full authenticated identities must be used, not short IDs, IPs or Bloom matches.

| Connection role | Authorization | Lifecycle and permitted work |
| --- | --- | --- |
| F2F | Direct configured friendship | Persistent sessions may use transport keep-alive; heartbeat and verified equivocation-proof gossip only between direct friends. |
| Shard-direct | Peer previously learned through authorized F2F presence into `known_network_nodes` | Ephemeral bounded LRU pool, 128–256 sockets, 15-second idle timeout, no keep-alive; authorized lock/status/sync RPC. |
| Public client ingress | Free/Friends/VIP admission in Spec 13 | HTTP clients need no P2P friendship; a public node key is never an ingress secret. |

Unauthorized shard-direct peers are rejected on the internal P2P boundary;
non-friend gossip is discarded even if the sender has shard-direct permission.
Locks are never gossiped. QUIC stream separation removes stream-level ordered
blocking between different streams, but does not eliminate shared CPU, socket,
congestion or bandwidth contention.

## 2. Bounded streams and protected work budgets

Stream classes describe scheduling roles, not fixed QUIC stream numbers or new
gossip protocols. F2F mesh gossip has exactly two semantic streams: hourly
presence and verified equivocation proofs. The other classes below are direct
RPC/control work.

| Work class | Scheduling requirement | Admission and overload behavior |
| --- | --- | --- |
| Lock/status shard RPC | Protected data-plane capacity ahead of ordinary gossip/control | Bound concurrent streams, tasks, bytes, per-peer work and waiters; refuse promptly when full. |
| Snapshot/delta sync | Protected bounded background progress | Bound transfer size, chunks, concurrent shards, retries and CPU; at most one active recovery per shard. |
| Presence gossip | Lower-priority, bounded | F2F-only, hourly cadence and fan-out under Spec 11; no lock records or missing-signer accusations. |
| Equivocation evidence | Priority within a finite verification budget | Bound frames, queue and CPU even for urgent traffic; verify offender signatures before sanctions. |
| Direct connection control | Bounded | No active background shard-ping storm, gossip privilege escalation or unbounded retry loop. |

Public ingress must not consume the reserved capacity needed to serve incoming
shard RPC and advance repair. Priority is not permission to starve recovery or
bypass admission. No stream class has an unbounded queue. Exact queue/batch sizes
and scheduling parameters require measurement and receiver-side verification.

Run cheap length, type, authorization, quota and time-window checks before
expensive cryptography. Incrementally read bounded chunks; an untrusted length
must never directly determine a frame allocation. Wire parsing uses checked safe
standard-library methods under `#![forbid(unsafe_code)]`.

## 3. Frozen checkout collection and separate live-state evidence

A write request freezes one canonical HRW snapshot of at most 20 distinct
`NodePubKey` identities, including self when eligible, using full 256-bit scores
and deterministic identity tie-breaking. FINAL requires 14 verified distinct
votes from that snapshot. Collection uses an 800 ms budget; dispatch is bounded
by that committee, without rank-21 replacement or a 50 ms/25 ms hedge policy.
Fail early once the remaining eligible members cannot supply the required quorum.
After a valid quorum, cancel outstanding collection tasks neutrally.

`NOT_READY`, `NOT_IN_SHARD`, capacity refusal, cancellation after quorum, normal
idle eviction and clean connection close do not establish misconduct. Do not
count them as peer failures. All unavailable votes share the six-member headroom;
six silent members plus one unready member leave only 13 possible votes. The
budget bounds waiting, not success, disk latency or Internet delivery.

Ordinary status retains `read_quorum=1` / INV-0310. A single matching lock or a
gateway success flag is insufficient for payment release. Current live-state
clearance requires a fully verified current 14/20 proof under DEC-084. Verify
every signature, full identity, distinctness, justified current authority and
agreement on the exact request/state context. Bind the response to the network,
shard, target lock, state and a fresh recipient challenge; reject replays and
mixed contexts.

A live-state response has a distinct authenticated signature purpose from an
original write approval. It attests safely installed current state; it neither
reissues a historical write choice nor requires bundles signed by retired nodes.
Check per-shard synchronization readiness and current responsibility immediately
before every countable state signature, including self responses. Pending RAM
state cannot bypass durable installation through an idempotent or status path.
The final encoding, domain tags, authority justification and safe activation
proof remain delivery/design obligations; TLS authentication alone proves none
of them. A local frozen snapshot does not prove globally identical views or
unconditional global irreversibility (DEC-053).

## 4. Persistence and non-blocking response release

For an original binding write approval, reserve bounded persistence capacity
before RAM mutation. The RAM collision check is followed by an asynchronous
worker that atomically commits the exact lock and immutable own signing decision
in `redb`. Release the attestation, idempotent approval, response envelope or
gateway self vote only after its exact successful durable commit acknowledgment
(DEC-087, restoring DEC-029 and superseding DEC-062's early release).

Signature calculation may happen in RAM; enqueue success or a computed signature
never authorizes release. Await persistence without RAM guards or blocking disk
I/O on the request/runtime thread. Expensive CPU work uses bounded dedicated
workers. Coalesce identical in-flight operations without unbounded waiters; a
pending cache entry is not a durable vote. Bound batches by time, entries and
bytes, including under single-request load.

Timeout does not roll back an already committed lock. An unknown outcome remains
unresolved and an identical retry may observe the commit. A failed or missing
commit acknowledgment never permits a binding approval. An ordinary process
crash with intact committed storage is addressed by this ordering; actual
storage loss, rollback and failed recovery remain separate safety gates. Local
commit latency targets require measurement, not assumptions about a 1–5 ms disk.

## 5. 0-RTT, replay and lifecycle

State-changing lock requests are forbidden in QUIC 0-RTT. Other early-data
eligibility is controlled exclusively by the whitelist and validation rules in
[Spec 10](10_p2p_wire_format_und_session_framing.md). A nominal read must not
bypass state-changing admission, trigger unlimited recovery or amplify work.
No local duplicate filter makes TLS early data globally non-replayable across
restarts, sessions or replicas.

The bounded session-sequence replay window (4096 positions where specified by
Spec 10) applies within its authenticated scope. Validate that scope and sequence
bounds; duplicate/old frames cannot mutate locks or obtain a new write approval.
Recipient challenges and purpose/context verification protect live proof reuse
at a separate layer; a transport sequence is not a replacement for them.

Persistent F2F keep-alive maintains a transport session; it is not network-wide
presence evidence. HRW presence comes passively from hourly F2F heartbeats,
with suspension after three consecutive missed hourly heartbeats (DEC-056).
Request timeouts, private latency metrics and idle socket eviction must not
be substituted for those presence observations. The 24-hour ticket maturation
wall and phase-stability hysteresis are separate from presence and committee
terms. There is no daily committee baton handover.

Clean QUIC close and idle expiration release transport resources; neither
changes a frozen checkout committee nor supplies an extra vote. Graceful daemon
shutdown stops admission, drains bounded accepted persistence work within its
deadline, and closes sessions according to the lifecycle contract. No timeout
or teardown accusation is gossiped. Diagnostic observations remain private and
non-authoritative under INV-1701; bans require verified first-party evidence.

## 6. Canonical transport invariants

1. **[INV-1501] Zero 0-RTT Writes:** No state-changing lock request is accepted
   as early data; writes require the completed 1-RTT authentication boundary.
2. **[INV-1502] Data-Plane Priority:** Protect bounded shard data-plane service
   ahead of ordinary gossip/control while preserving bounded repair progress.
3. **[INV-1503] Non-Blocking Network Threads:** Expensive cryptography and disk
   work use bounded workers; network tasks do not perform blocking heavy work.
4. **[INV-1504] Transport Replay Defense:** Enforce the authenticated bounded
   sequence/replay window and early-data whitelist of Spec 10. A volatile bitmap
   does not establish universal replay immunity or replace application freshness.
5. **[INV-1505] Transport-Native Teardown:** Close/idle/error handling reclaims
   connection resources without failure gossip, checkout replacement or invented
   presence/identity sanctions.

These meanings own INV-1501–1505. Historical uses of INV-1501 for missing-count
control in Spec 18 and INV-1502 for skip-and-replace in Spec 19 are withdrawn,
not aliases authorizing those obsolete rules. Diagnostics refer to INV-1701;
checkout membership refers to Spec 03.

## 7. Required evidence (not executed by this consolidation)

| Rule/interface | Positive and adversarial scenario | Required result |
| --- | --- | --- |
| P2P authorization | Real QUIC friend, learned non-friend and unknown peer; unauthorized gossip/RPC | Correctly scoped acceptance/refusal; HTTP ingress remains independent. |
| INV-1501 / 1504 | Real QUIC early lock, replayed/old/out-of-window frames and valid allowed read | No early write or replay mutation; bounded resource use and correct read behavior. |
| INV-1502 / 1503 | Flood gossip, sync, urgent proof and public ingress while honest shard requests run | Receiver-side caps/refusal; protected service and repair progress; no unbounded CPU queue. |
| Checkout collection | 14 valid members; duplicate/out-of-snapshot votes; six silent plus one unready; cancelled stragglers | Exact membership threshold; bounded failure when impossible; no peer-failure accounting for neutral results. |
| Durable release | Process crash before commit, after commit before send, and after send; idempotent/self/status paths | No binding write signature before exact commit; committed own choice recovered; no pending-state shortcut. |
| Current live proof | Wrong purpose/target/challenge/context, stale authority, one unready signer, changed sync generation | No payment clearance from invalid/incomplete proof; readiness rechecked before countable signatures. |
| INV-1505 / lifecycle | Idle pool churn, graceful close, deadline and repeat stop signals | Bounded sockets/drain, normal cleanup neutral, no replacement votes or hearsay. |

Real QUIC tests must exercise receiving server behavior; relevant HTTP/client
verification and process-crash checks are separate requirements. No source/test
name or simulation supplies executed evidence here. Safe source continuity,
complete transfer under concurrent writes, current authority and activation
remain explicit proof gates; historical quorum archives are not a remedy.
