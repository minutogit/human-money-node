# 18. Shard Collaboration and Percolation — Informative Memo

> **Status:** Informative mathematical context. This memo creates no committee,
> presence, sanction or synchronization rule. Analytical assumptions and model
> estimates are not a project security proof or executed network evidence.

Canonical routing, passive presence and transport requirements are in
[Spec 03](03_routing_und_sharding.md), [Spec 11](11_organische_praesenz_und_dunbar_gossip.md)
and [Spec 15](15_p2p_transport_and_connection_management.md).

## 1. Expected shard workload

Let $S=65,536$ and $K=20$. For $N\ge K$ eligible identities, a uniform independent
per-shard ranking model gives

$$E[M]=\frac{SK}{N}=\frac{1,310,720}{N}.$$

Under independence across shard rankings, the chance of at least one assignment is

$$P(M\ge1)=1-\left(1-\frac{K}{N}\right)^S
\approx1-e^{-SK/N}.$$

The point $N=SK$ means **one assignment in expectation**, not an assignment for
every node: the approximation gives only $1-e^{-1}\approx63.2\%$ with at least
one assignment. Unassigned identities do not become replacement voters in an
already frozen checkout. For $N<20$, apply the distinct provisional all-shard
regime, not these $K=20$ formulas.

For a specified pair of identities, the probability of sharing a committee in
one uniform sample without replacement is $K(K-1)/(N(N-1))$. Thus the expected
number of distinct co-shard partners over independent shard samples is

$$E[U]=(N-1)\left[1-\left(1-\frac{K(K-1)}{N(N-1)}\right)^S\right].$$

These are capacity estimates under the stated distribution assumptions. Shared
responsibility is not an authorization edge, persistent socket requirement,
heartbeat observation or proof of honest membership. Real topology, correlated
eligibility changes and adversarial ticket selection require separate analysis.

## 2. Percolation estimates and their limits

Gossip reachability depends on friendship topology, bridges, fan-out, loss,
partitions, adversarial placement and observation time. A fitted survival curve
or Monte Carlo result is useful only with its exact model, seed, parameters and
reproducible evidence. An epidemic analogy does not establish a Byzantine bound.

Earlier versions quoted a 73.1% tipping point and a Weibull fit as if they proved
universal isolation resistance. Those guarantees and the associated transaction-
volume/isolation table are withdrawn. They do not prove that an honest node can
never become unreachable or dormant, nor that locally observed HRW committees
have identical membership or a shared honest intersection.

The two F2F gossip classes remain hourly presence and verified equivocation
proofs. No missing-signer bitmask or gateway report is spread to persuade other
nodes to penalize a peer. There is no network-wide "percentage informed of a
failure" that authorizes an exclusion or an extra checkout vote.

## 3. Quorum arithmetic is conditional

In one fixed 20-member set, two 14-member subsets intersect in at least
$14+14-20=8$ identities. If at most six identities in that same justified set
are Byzantine and honest identities preserve their immutable signing choices,
the intersection contains honest identities. This arithmetic is not proof that
successive or partitioned committee views share the needed state or identities.

The 800 ms collector freezes that set and counts 14 distinct verified votes.
Six non-contributions exhaust the allowance; a seventh missing vote prevents
completion. No ranks 21–40, zero-latency failover promise or throughput-based
fault-detection threshold follows from the workload formulas.

State takeover needs complete active state through `root.valid_until` plus grace,
including records older than 24 hours, with verified source continuity and safe
installation. Matching digests from replicas with the same omissions prove no
completeness. Independent confirmed locks need not produce 14 identical whole-
state digests. This memo supplies no new transfer or consensus algorithm.

## 4. Presence, diagnostics and evidence boundary

DEC-056 uses three consecutive missed **hourly F2F heartbeats** for passive
presence suspension. Checkout timeouts and cancelled stragglers are not heartbeat
misses. Automatic idle close of ephemeral shard-direct sockets is normal.
The 24-hour ticket maturation wall is a different mechanism.

Local observations may inform bounded direct-edge scheduling and private operator
diagnostics, but must not rewrite a frozen committee, suppress F2F gossip because
of shard-RPC misses or trigger identity sanctions. Diagnostic non-authority is
INV-1701 in Spec 17. INV-1501 belongs exclusively to the 0-RTT write prohibition
in Spec 15; its former missing-count meaning here is withdrawn. The historical
INV-0309 signer-bitmask cascade is withdrawn; consult Spec 03 for its qualified
local diagnostic meaning. Missing-count diagnostics do not authorize pool
expansion, presence changes or signature acceptance.

Acceptance requires real receiver-side QUIC checks for unauthorized gossip,
miss-report injection, quota flood, neutral cancellation and correct committee
counting; plus recovery/activation and client checks at their actual interfaces.
No such tests or model experiments were run for this document consolidation.
