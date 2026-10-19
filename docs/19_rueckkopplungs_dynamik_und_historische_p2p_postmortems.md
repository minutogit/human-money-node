# 19. Feedback Dynamics and Cascade Prevention — Informative Memo

> **Status:** Informative local-control rationale. This memo is neither a new
> consensus specification nor a completed system-theoretic security proof.

Binding rules live in [Spec 03](03_routing_und_sharding.md),
[Spec 13](13_client_ingress_und_access_tiering.md),
[Spec 15](15_p2p_transport_and_connection_management.md) and
[Spec 17](17_topologie_telemetrie_und_social_defense.md). Unsupported incident
stories, universal immunity claims and rank-21 replacement rules from previous
versions are withdrawn. No historical outage attribution is needed for the
requirements below.

## 1. Positive feedback and bounded reactions

A slow peer can cause extra retries, which add work and make more peers slow.
Broadcast accusations can similarly turn one local observation into a network-
wide exclusion cascade. The design response is bounded work, backpressure and
no hearsay sanctions, not expansion of the checkout signer pool.

| Observation or pressure | Selected bounded response | Forbidden inference |
| --- | --- | --- |
| Public ingress flood | Cheap admission, token buckets and required-difficulty feedback under INV-1307 | Public clients need P2P friendship or node public keys may bypass PoW. |
| Slow/unreachable checkout member | Collect only within the frozen committee and 800 ms budget; fail when 14 become impossible | Rank 21 may replace a missing member or a timeout proves fraud. |
| `NOT_READY`, non-member/capacity refusal, fulfilled-quorum cancellation | Neutral outcome; preserve exact result semantics | Peer penalty, heartbeat miss or gossip accusation. |
| Shard takeover/restart | One bounded on-demand recovery per shard; remain unready until verified installation | An empty RAM index proves no collision. |
| Disk delay or unknown commit | Await exact durable acknowledgment, bound work, return honest unresolved/failure state | Release a write signature before commit or roll back a known commit on timeout. |
| Idle shard-direct socket or graceful close | Normal transport cleanup under INV-1505 | Presence suspension, replacement vote or identity sanction. |

Ingress pacing is INV-1307 in Spec 13. Earlier use of INV-1302 for pacing here
conflicted with its account-privacy meaning and is withdrawn. INV-1502 means
bounded data-plane priority in Spec 15, never skip-and-replace.

A checkout timeout does not recursively fan out shard-to-shard lock traffic.
This removes that particular amplification path. Bounded client retry/read follow-
up and recovery still consume resources; their composed load must be measured.
A blanket claim that every failure response creates zero extra packets or that
all workloads mathematically satisfy $\Delta\mathrm{Load}\le0$ is unsupported.

## 2. Local feedback is separate from network authority

Local direct-edge backoff controls a node's own bounded work. Observations are
not propagated as reputation, cannot change a frozen checkout committee, and
cannot independently ban identities or invalidate tickets. Private metrics and
operator dashboards are non-authoritative (INV-1701); no automatic exclusion is
derived from a latency percentile, error ratio or telemetry warning.

An illustrative local counter with penalty $a$ per failure and forgiveness $b$
per success has expected change per observation

$$E[\Delta]=a p-b(1-p).$$

For $(a,b)=(2,2)$ its drift changes sign at $p=1/2$; for $(1,2)$ it changes at
$p=2/3$. This algebra explains a local forgiveness bias, but assumes a defined
observation process. It does not prove homeostasis at a particular network
stress percentage, protect against correlated failures, or authorize a change to
presence/admission. Event rates, sampling, neutral outcomes and time-based decay
must be modeled explicitly. Quota/load EMA decay remains physical-time-based,
not accelerated by transaction frequency.

Passive presence is governed separately by hourly F2F heartbeats and three
consecutive missed heartbeats (DEC-056). Neither successful checkout replies nor
missing checkout signatures replace that process. Active background probes and
gossip about missing signers are not a cure for incomplete presence views.

## 3. First-party evidence and limits of inference

Delay, loss and silence alone do not distinguish an honest overloaded node from
an attacker. They are not cryptographic evidence. Identity penalties require the
specified first-party proof, including verification of both genuine signatures
on divergent payloads in the same equivocation scope before applying sanctions.
Proof transport and verification are themselves bounded; urgent packets cannot
obtain an unbounded queue merely by claiming fraud.

L1 retains voucher ownership and causality. L2 synchronizes active collision
state `parent_lock -> child_lock`, not historical quorum bundles of retired
signers. Current authorized ready nodes may sign a distinct challenge-bound live
state proof. A historical write signature and a current state signature have
different purposes; neither private diagnostics nor a matching single lock
substitutes for the payment consumer's verified current 14/20 proof.

Durable-before-Release (DEC-087) protects own original write choices across an
ordinary process crash with intact committed storage. It does not prove recovery
after storage loss/rollback, correct current authority, complete state transfer,
clock/seal compatibility or safe activation across changing membership. Those
remain explicit proof/design obligations; no mandatory predecessor permission or
historical signature archive is introduced as a shortcut.

## 4. Verification obligations

The relevant tests must exercise real receiving QUIC servers with peer floods,
unauthorized accusation frames, malformed evidence, slow peers, neutral
cancellation and clean/idle teardown. Confirm bounded queues/CPU and protected
shard and sync progress under public ingress pressure. HTTP/client tests must
check truthful timeout/payment outcomes; process-crash checks must verify exact
commit-before-release ordering and decision restoration.

Any simulation must state topology, adversarial placement, timing and measurement
assumptions and retain reproducible results. It cannot establish wire defenses
or replace those integration checks. No experiments, benchmarks or tests were
executed for this consolidation; the requirements are not a current-code audit.
