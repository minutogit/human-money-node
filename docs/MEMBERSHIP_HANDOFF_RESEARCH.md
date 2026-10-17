# Membership and shard handoff: executable research candidate

Status: conditional design and isolated simulation, **not a binding specification,
production implementation, complete distributed proof, or an accepted answer to
Q-S3.3-01**. Interview continuation: CP-0029 / notes §7.40.

## Result and architectural boundary

Unrestricted local HRW activation after copying state is unsafe under the selected
six-Byzantine target. The executable counterexample produces two conflicting
fourteen-signature outcomes in a twenty-two-identity universe without honest
double-signing. Reliable QUIC delivery, a matching digest, social reputation and
ticket incubation do not close that race.

The candidate retains subjective discovery for finding eligible candidates. It
makes the selected shard configuration and its transition verifiable protocol
state. Gateways and payment verifiers count signatures against that state rather
than interpreting their latest local discovery cache as sufficient authority.
There is no median of every node's view and no lock gossip.

The circular phrase "the old group" is replaced by an explicit first-admission
condition followed by certified configuration history. The first condition is a
real additional premise. Existing F2F rules do **not** establish it. Without a
justified first admission or another mechanism proving compatible accepted quorums,
the original local-view rules do not yield the requested unconditional FINAL
guarantee. The simulation includes an out-of-assumptions witness of that limit.

## Initial admission from partial knowledge

This stronger research construction is our own; it is not attributed to the CUP
paper as an implemented or corrected algorithm.

For one fixed bootstrap instance, each participant supplies one immutable,
authenticated participant-detector row. Every referenced identity also needs
authentic instance participation evidence; naming arbitrary public keys is
insufficient. A local verifier receives rows from a set R and constructs U as R
plus all identities named by those rows. Its admission predicate requires:

- at least thirteen distinct authenticated row issuers;
- at most six identities in U whose rows are missing;
- valid instance-bound authentication, no substituted equivocating row and no
  unauthenticated referenced identity.

The verifier uses only its transcript, never the harness's actual participant or
fault set. The construction additionally assumes that the fixed correct
participants' effective knowledge graph remains **seven-vertex-connected** and
that the instance has at most six Byzantine eligible identities. Authentication,
partial synchrony and eventual usable communication are also required. Minimum
friend count alone does not establish this graph property. The model checks
mutual learned-identity admission for its discovery queries; it does not implement
the daemon's F2F presence gossip, TTL, incubation or resource policies.

**Completeness argument, conditional on those premises.** R contains correct
participants because its size exceeds the faulty bound. A correct participant
outside U could be reached from a correct row issuer only through missing correct
members of U: received rows contain no outgoing edge outside U. Removing those
at most six missing correct participants would disconnect the correct graph,
contradicting seven-vertex-connectivity. Thus U contains every correct participant
of this fixed instance. This is an argument about an assumed graph, not a local
test establishing that the actual network meets the assumption.

Two accepted universes can consequently differ only in Byzantine members. If h
correct participants are common and b<=6 faulty members are present, the adaptive
bootstrap quorum q=floor(2(h+b)/3)+1 is available from the correct participants and
contains strictly more than h/2 correct members when h>=13. This gives honest
intersection even across such universes. The finite arithmetic check covers
h=13..64 and b=0..6; the argument is broader than the enumeration.

Discovery is not agreement. A globally comparable bootstrap instance and durable
round state must prevent a correct identity from treating differing candidate
universes as unrelated opportunities to vote. The integrated fixtures converge
their local transcripts and then execute actual propose/prepare/commit/view-change
messages for initial populations of 20, 21 and 22. They choose the first ordinary
twenty-member shard using the existing full-score HRW selector, conservatively
import available provisional choices, enforce a virtual 24-hour stability gate,
and obtain the first fresh FINAL without Byzantine assistance. Earlier PROVISIONAL
certificates are not silently promoted to FINAL. Conflicting imported choices
remain blocked.

The model does not implement a general protocol for continuous admission during
bootstrap, heterogeneous live agreement electorates, independently joining late
observers, all provisional merge semantics or full ticket verification. These are
necessary integration/proof obligations before this becomes a complete network
bootstrap solution. In particular, the strong graph premise is not something
ordinary gossip similarity or a successful simulation can certify.

### Research-source discrepancy

[Heydari et al., extended version, Theorem 3 and Algorithm 2](https://arxiv.org/html/2405.06055v2)
prints a P3 condition counting **sources** in S1 having an outgoing edge outside
S1. Its later existence argument treats the bounded exterior Byzantine population
as if it bounded that source count. The literal predicate fails in our complete
twenty-node fixture with six silent Byzantine nodes: all fourteen available
correct rows point outside any qualifying S1, exceeding six sources. The model
enumerates available S1 candidates and reproduces this liveness discrepancy.
This is a narrow finding about the printed predicate, not a refutation of CUP or
permission to silently change the paper's algorithm.

[The 2023 Stellar/CUP paper](https://www.di.fc.ul.pt/~bessani/publications/icdcs23-stellar-cup.pdf)
is useful for the distinction between initial partial knowledge, discovery and
consensus. Its assumptions and sink abstraction do not provide a ready HuMoCo
admission implementation.

## Conditional handoff protocol

Assume the current shard configuration has been justified, contains twenty
identities and has at most six Byzantine members over the lifetime of its retained
evidence. Correct storage does not lose or roll back binding choices. For progress,
fourteen correct old members, fourteen correct successor members and their needed
state eventually remain available. An arbitrary partition has no completion SLA.

1. **Prepare data.** Obtain snapshot-bound records and subsequent contiguous
   source-local changes within background budgets. Roots authenticate a commitment;
   they do not by themselves prove full range coverage or data availability.
2. **Fence old writes.** Persist an epoch-wide admission stop, independent of any
   successor proposal. Drain admitted durable decisions or prevent them from ever
   escaping. Fix the final source state after that ordering. Restart retains the
   fence. A pre-fence durable vote may arrive later and must remain represented.
3. **Certify inclusion.** Propose a completely available, authenticated transfer
   state preserving own and inherited exclusions. An old honest node endorses it
   only after fencing and checking inclusion of its own relevant state. Fourteen
   matching endorsements form the closure certificate. Endorsements are
   non-exclusive: conservative alternatives may also be endorsed.
4. **Choose a successor.** Run separate BFT agreement over the successor roster and
   closure-certified state. The closure certificate is publicly verifiable
   proposal validity. A voter does not impose a new private inclusion condition
   inside this agreement; it retains its own immutable payment choices separately.
   Proposals, prepares, commits and view-change evidence bind their instance,
   round and exact value. The model follows the highest-prepared-value approach
   from [PBFT §4.4](https://pdos.csail.mit.edu/6.824/papers/castro-practicalbft.pdf),
   with explicit fourteen-signature thresholds for ordinary shard configurations.
5. **Install before voting.** Each successor verifies the actual payload and
   transition evidence, commits its inherited state and readiness, then may vote
   in the new configuration. Fourteen context-bound installation receipts show
   transition completion; they never authorize an uninstalled individual to vote.

The selected configuration ID must be derived from or cryptographically bind its
predecessor, shard, generation, selected roster/tickets and state commitment. The
example idealizes authentication and value identities; it has external emission
registries for signatures and immutable value bindings, not production encodings.
No new canonical protocol domain tag or wire message is specified by this report.

### Why inclusion and agreement are separate

If eight honest and six Byzantine nodes prepare a package that omits the remaining
six honest nodes' singleton records, Byzantine nodes can subsequently withhold.
Safe view change retains that prepared value. If all agreement voters must now
apply private inclusion validity, only eight honest commits remain possible.
Separating the fourteen inclusion endorsements from publicly valid agreement
allows all fourteen honest agreement voters to finish without erasing any private
immutable payment choice. The executable prepared-recovery fixture exercises this
case with a competing fresh default value.

### Preservation argument and its exact scope

Any fourteen old payment voters and fourteen closure endorsers intersect in at
least eight identities, at least two honest. Those honest inclusion endorsements
preserve the possible old certificate's exclusion effect even when its aggregate
certificate is withheld. Once eight honest closure endorsers are fenced, only
twelve old identities remain capable of producing fresh old votes, insufficient
for fourteen. New votes require installed inherited exclusions. Repeating the same
rule preserves effects over later full turnovers.

This does not reconstruct every singleton stored only by an unreachable excluded
identity. Remaining/rejoining identities retain their own exact private choices
until justified expiry and cannot erase them on installation. The simulation also
retains a monotone closed-epoch watermark, so overlapping members cannot reopen an old
write context after activation or restart.

Unresolved genuine conflicts block their slot and descendants. An authentic late
historical FINAL can resolve transferred ambiguity; timeout, raw report majority
or a lower hash cannot. A malicious owner plus a Byzantine signer can attack
availability of its conflicting slots. This is a cost of the investigated
one-payment-round candidate A, **not** an accepted A/B answer. The model uses bounded
exact candidate sets; constant-size certified BLOCKED-effect compression, root
TTL/expiry and proof retention remain unimplemented obligations.

Static faulty identities may differ across generations, provided every signing
configuration retains its six-fault bound. Later compromise of retired honest keys
is outside this model. A per-instant fault bound alone does not prevent long-range
history forgery; temporal keys or independently justified fresh checkpoints need
their own design if that threat is included.

## Run and interpret

```bash
cargo run -p humoco-sim-core --example membership_handoff_model
cargo run -p humoco-sim-core --example membership_handoff_model -- --scenario handoff --seed 1 --seed-count 128
cargo run -p humoco-sim-core --example membership_handoff_model -- --scenario bootstrap
cargo run -p humoco-sim-core --example membership_handoff_model -- --scenario lifecycle
cargo run -p humoco-sim-core --example membership_handoff_model -- --scenario capacity
cargo test -p humoco-sim-core --example membership_handoff_model
```

Agreement messages use a deterministic `(virtual time, sequence)` scheduler and
Xorshift64 seeds. Trace and failing scenario/seed are returned on failure. The
durability/installation checks are explicit scripted transitions, supplemented
by exhaustive exploration of a finite one-vote lifecycle model; they do not explore
all distributed interleavings or execute redb. Exhausting a model bound yields
INCONCLUSIVE/error, never evidence of progress. A thirteen-member available set
is an expected unavailable-quorum case. Expected unsafe variants must produce a
counterexample for their regression check to pass.

Fixtures cover baseline payment; the unsafe twenty-two-identity activation;
three complete turnovers with six fixed faulty identities in each generation;
two-A/twelve-B transfer reports; withheld and later presented certificates;
three-way partial conflicts; successful unrelated payments; closure/prepare/
view-change/installation evidence tampering; durable commit/fence/restart;
overlapping membership and stale epoch requests; split proposals; and prepared
value recovery without private-validity deadlock.

The capacity experiment offers 1,000 and 10,000 locks/s using configured useful
record service/transfer rates, bounded reservation queues, pre-copy, final drain
and installation. Its short-pause case assumes transfer faster than ingress and a
small final tail. At 10,000 ingress records/s and 5,000 transfer records/s, the
configured snapshot leaves a 125,000-record tail and roughly 25 seconds of pause.
These numbers are **virtual parameter consequences**, not measured node throughput
or expected deployment latency. Evidence bytes, cryptographic cost, disk commits,
fanout, RTT and actual Merkle/IBLT compression require measurement.

## Remaining implementation gate

Before changing the daemon: settle or explicitly adopt the initial-admission
premises, preserve the exact Q-S3.3-01 choice, define admission/transition/history
formats and resource limits, complete dynamic-bootstrap and temporal-key proofs,
normalize retained effects, then implement the protocol and adversarial real-QUIC
tests. Existing workspace tests passing does not prove these new defenses exist
on the wire. No production protocol behavior was changed here.

## Recorded validation (2026-10-16)

- `cargo test -p humoco-sim-core --example membership_handoff_model`: twelve
  tests passed, including bootstrap/initial-FINAL fixtures and the finite lifecycle
  checker.
- Handoff scenarios, seeds 1..128: 1,536 scenario executions and 4,036,608 reported
  abstract model steps completed. Fixed faulty identities include six members in
  each of three fully replaced configurations. Expected unsafe/stall cases were
  asserted as such; they are not successful safe executions.
- Bootstrap study: fourteen checks, including the conditional 20/21/22 paths,
  literal-source liveness counterexample, unknown outside identities, fabricated
  participation and disconnected communities.
- Lifecycle checker: all 34 reachable safe-model states and 56 edges; both old-vote
  and fresh-successor progress are reachable without a conflicting pair. The
  snapshot-before-drain mutant yields an explicit seven-action counterexample.
- `cargo test --workspace`: passed after allowing existing QUIC tests to bind local
  loopback sockets. The initial sandboxed attempt failed on that OS restriction.
  This workspace run preceded final isolated-model refinements; those refinements
  were covered by the example tests and all-target clippy afterward. No production
  file changed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed on the final code.
- Formatting, local links, unchanged DEC register/original question and checkpoint
  consistency are checked with the CP-0029 save. No commit or PR was created.

These checks are evidence about the stated finite model and unchanged workspace;
there is no empirical security probability, general dynamic-consensus proof,
measured server-throughput result or new real-QUIC defense claim.
