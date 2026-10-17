# Research and validate a workable decentralized HuMoCo architecture

## Mission

Act as the lead distributed-systems researcher and implementation reviewer for
HuMoCo's blind Collision Lock Registry. Find a concrete, implementable architecture
that can provide reliable FINAL payment confirmations during organic growth,
subjective discovery, repeated shard turnover and realistic network failures.

Answer the operational question: **Within exactly which defensible operating and
adversary limits does the complete system remain safe, available and stable, and
what must change for those limits to be realistic?**

Do the research and experiments. Produce a tested design and a justified verdict.
A literature list, a plan to simulate later, an assumed common committee, or another
statement that "membership is still unresolved" does not complete this task.
Never manufacture a positive result: if requirements conflict, establish the
specific conflict and develop and test the smallest workable alternative.

Communicate with the maintainer in German. Write repository artifacts in English.
Maintain vocabulary yourself; glossary preference questions are closed.

## Authorization and working method

When the maintainer asks you to execute this brief, continue autonomously through
research, candidate design, adversarial review, isolated prototype/simulation
implementation, execution and analysis. Use subagents to preserve the overall view:

- one investigates membership, initial admission and late-verifier recognition;
- one independently attacks safety, handoff and recovery arguments;
- one develops/reviews experiments and resource/performance evidence as capacity
  permits.

The lead agent owns integration, assumptions, the evidence ledger and the final
verdict. Assign disjoint files, require concrete evidence from each agent, and
reconcile disagreements. A candidate's author must not be its only reviewer.
If delegation is unavailable, record that limitation and continue useful work.

Research prototypes, simulation changes and isolated real-QUIC/process test
harnesses are in scope. Preserve existing work. Do not deploy, commit, open a PR,
rewrite binding specifications or install a new production consensus design through
this research prompt. Prepare concrete reviewable changes if later integration is
needed. Reading this brief to edit it is not an instruction to execute the research.

Resolve technical choices yourself. Ask at most one substantive question when a
real product/security tradeoff cannot be resolved from existing decisions. First
prepare the candidate, consequences and evidence so the maintainer can decide.
Do not ask permission for each search, experiment or reversible research edit.
Do not treat "continue" as selecting a previously unresolved policy option.

## Read and resume without resetting the interview

Read applicable `AGENTS.md`, then:

1. [Interview workflow](architecture_interview.md).
2. The entire current [compact state](../docs/ARCHITECTURE_INTERVIEW_STATE.md).
3. [Interview notes](../docs/ARCHITECTURE_INTERVIEW_NOTES.md): current decision,
   alternative, open-item and specification-gap registers (§2), then the sections
   referenced by the active node. Start with §7.41 and §7.40 where present; follow
   §7.37–7.38, §7.29–7.35 and §7.16 as needed.
4. [Existing research report](../docs/MEMBERSHIP_HANDOFF_RESEARCH.md).
5. [Executable research model](../crates/humoco-sim-core/examples/membership_handoff_model.rs)
   and its `membership_handoff/` support modules. Inspect their actual predicates
   and knowledge boundaries before reusing their results.
6. Relevant current specifications, daemon paths and tests. Historical audits are
   leads, not descriptions guaranteed to match today's code.

This brief was prepared after CP-0030. Always use the latest consistent checkpoint;
do not reset to that checkpoint or overwrite later work. Preserve exact question
IDs, meanings and accepted decisions. Follow the interview's notes-first,
state-second save/readback procedure throughout this work.

## Precise problem and current evidence

HuMoCo stores blind collision decisions about consumed predecessor outputs. Each
node discovers participants through F2F presence, maintains a subjective ticket
catalog and computes HRW shard candidates. Different observers can know different
eligible identities and finish local incubation at different times. Requests,
durable commits and replies continue while snapshots and membership change.

A locally frozen set of twenty identities prevents expansion within one checkout;
it does not establish compatibility with another checkout's accepted set. Valid
signatures prove who signed, not which participants a recipient should count.

The original "mature ticket, copy state, start voting from my own view" rule has a
specific unsafe schedule. Let F be six Byzantine identities and H1..H14 be honest
old members. The concrete witness is:

```text
Old committee: F + H1..H14
New committee: F + H3..H14 + X + Y
Votes for A:   F + H1..H8
Votes for B:   F + H9..H14 + X + Y
```

The honest newcomers X,Y copy the empty slot before A obtains fourteen old votes, then activate
without a justified old-write cutoff. Both outcomes reach fourteen, and only F
double-signs. Reproduce the timing rather than attributing this only to independent
networks.

The present research candidate separates durable closure/inclusion endorsements
from successor BFT agreement and durable installation. It addresses several
handoff races under justified membership. Its initial-admission candidate adds
strong connectivity, identity and fixed-instance assumptions that current F2F rules
do not establish. Its successful 20/21/22 fixtures are not a general dynamic
bootstrap or late-observer protocol.

Treat all prior favorable claims and the reported discrepancy in a CUP paper's
printed predicate as findings to independently reproduce or correct. Do not assume
the existing novel construction is preferable to an established protocol.

## Preserve the product and distinguish unselected mechanisms

Carry forward the actual DEC register; the following constraints orient research:

- Blind L2, client-held causality proofs, no monetary stake/deposits, node
  sovereignty, cheap admission checks and bounded resources.
- One organically growing network; N<20 remains PROVISIONAL. Preserve the existing
  N>=20 FINAL regime and stability requirements. Do not repeatedly ask whether
  FINAL should exist at twenty or force a permanent-network/domain preference.
- Ordinary checkout freezes at most twenty distinct full `NodePubKey` identities;
  FINAL requires fourteen. Keep the 800 ms collection budget, no rank-21 replacement
  within that request, and neutral handling of NOT_READY/quorum cancellations.
- Seek safety with up to six Byzantine identities in the relevant committee.
  This is a target conditional bound, not evidence that tickets/F2F enforce it.
- Gossip remains the prescribed F2F presence and verified equivocation streams.
  Locks are not gossiped. Shard-direct RPC requires peers learned through the
  permitted F2F mechanism; do not silently add open discovery connections.
- Durable own signing choices precede released votes; retain exact-intent retries,
  the same-key loss/rollback gate, root TTL plus grace and bounded expiry. The
  selected relaxed local latency requirement conflicts with older specification
  wording; record and reconcile that conflict without silently changing policy.
- Planned affected-shard pauses, repeated complete turnover and safe automatic
  transition progress after stabilization are selected. Permanent original signers
  and root-lifetime committee pinning are not the solution.
- Genuine unresolved conflicts may block their slot/dependents while unrelated
  work continues. Irreversible FINAL cannot be justified by later choosing a
  smaller hash and invalidating the payment after goods were released.
- Q-S3.3-01 remains unanswered. Its A investigates one payment collection round
  with retained own/inherited obligations; B investigates preparation plus an
  additional quorum-confirmed payment completion round. Preserve the exact §7.16
  wording. Compare both if needed; a simulation branch is not policy selection.
  Q-S2.2-01 was withdrawn as the next question because its old-roster premise was
  missing; its conditional recommendation is not an accepted membership rule.

If robust operation requires changing a selected constraint, identify the exact
decision and derive the necessity. Develop the alternative as a clearly labeled
proposal. Do not claim success by weakening FINAL or quietly reducing the attacker.

## Phase 1 — Convert unknowns into explicit claims

Create an evidence ledger with stable claim IDs. For each claim record its
property, assumptions, actual enforcement/evidence, counterexample, experiment and
current status: requirement, observation, hypothesis, conditional argument,
bounded-model result, implementation test or unresolved gap.

Cover at least these coupled questions:

1. **Who counts?** What exact evidence justifies the first accepted voter set,
   concurrent admissions, ticket changes, removal and later full replacement?
   What does a newly started node or independent payment recipient verify?
   A self-signed list, a network label, a hash or "the previous group" is insufficient
   without establishing its recognition. Avoid an infinite chain of assumed roots.
2. **What survives?** Preserve every possibly completed historical certificate's
   exclusion effect, inherited obligations and each reused identity's own choices,
   including missing aggregates and delayed replies. Distinguish this from the
   impossible promise of reading every inaccessible private singleton.
3. **When is transition complete?** Specify admission stop, pending durable work,
   snapshot/change boundaries, data availability, competing proposals, rounds,
   installation and individual activation. Define crash/restart and rollback.
4. **Which failures are tolerated?** Separate Byzantine, unavailable correct,
   mobile/late-compromised and resource-exhausted participants, graph cuts and
   packet/path failures. State fault scope across views and evidence lifetime.
   Investigate ticket grinding, Sybil admission and concentration across all
   65,536 shards and repeated selections. F2F reputation, a low global adversarial
   fraction or an honest past must not be treated as a proven per-shard bound.
5. **What remains live?** State the exact post-stabilization communication and
   available-state premises. Six withholding Byzantine members plus one additional
   unavailable honest member leave thirteen correct responses, not fourteen.
   Do not promise progress under that case by silently adding replacement voters.
6. **What is operationally affordable?** Bound presence catalogs, proof/history
   retention, signing metadata, synchronization, queues, CPU, memory and bandwidth
   while ordinary checkout and background recovery run concurrently.

Separate safety, availability, convergence and performance. Do not substitute one
for another. Use explicit proposed operational targets where none exist; mark
them as engineering hypotheses, justify them and report sensitivity. Do not invent
maintainer-approved SLAs or empirical failure probabilities.

## Phase 2 — Search existing solutions and scrutinize their premises

Use internet research actively. Prefer primary papers, their current versions and
errata, official specifications and maintained reference implementations. Read the
relevant proofs/algorithms, not only abstracts or secondary summaries. Record URL,
version/access date, applicable sections and the exact assumption being borrowed.

Investigate, as relevant, authenticated BFT reconfiguration and state transfer,
consensus with unknown participants, federated/personal quorum intersection,
bootstrap/weak-subjectivity and long-range protection, and bounded anti-entropy.
Compare practical implementations as well as theory. Do not transplant stake,
global membership, a permanent validator list or synchrony guarantees into HuMoCo
without explicitly accounting for them.

For each viable candidate map literature premises to actual HuMoCo mechanisms.
Classify an assumption as enforced, established outside the protocol, conditional,
unmeasured or incompatible. If a graph predicate is globally required, explain
how it is obtained or why it cannot be certified locally. A simulator checking
its own complete graph does not establish a node-verifiable operating condition.

Keep a small candidate shortlist. Prefer a known simpler construction when it
meets the requirements. Reject candidates with a concrete reason or attack trace.
If none fits, derive the minimum additional mechanism or assumption and investigate
its smallest workable realization instead of repeatedly proposing the same premise.

## Phase 3 — Specify and independently attack complete candidates

For each surviving candidate write executable state transitions and verification
predicates. Specify node/gateway/client knowledge, stable instance identifiers,
signed fields, participant/ticket eligibility, vote exclusions, round recovery,
state transfer, readiness, expiry and failure responses. Separate private signing
history from transferable effects and public proposal validity.

Give safety and progress arguments that span the entire sequence:

`organic startup -> first FINAL -> concurrent growth -> repeated handoffs ->
partition/reconnection -> restart -> independent late recipient verification`.

Address compatibility of all accepted configurations and policies. An overlap
calculation for one fixed universe is not proof across arbitrary local views or
time. A per-current-committee Byzantine fraction is not a long-range key/history
argument or a demonstrated bound on every HRW shard over many epochs.

The adversarial reviewer must seek a counterexample before accepting each claim.
In particular test the known private-inclusion/Prepared-QC deadlock, missing state,
source omission, stale context replay, backdated participation, hidden eligible
nodes, counterfeit initial configurations and forged historical membership.
Reconcile review findings in the implementation, not just in prose caveats.

## Phase 4 — Implement models that cannot hide the problem

Reuse or revise the existing Rust example where useful; build a separate model if
its abstractions cannot express the proposed solution. Inspect existing tests for
vacuity and avoid reusing their conclusion as an assumption.

Required modeling discipline:

- Deterministic scheduler, virtual time, recorded seeds/configuration, explicit
  event/state limits and replayable failure traces; minimize important failures.
- Nodes decide from received messages and durable local state. Global actual
  membership, fault identities, future events, connectivity and the safety monitor
  belong only to the harness, never to admission/activation predicates.
- Authentication primitives must be clearly bounded. A payload's repeated signer
  names are not signatures; test external provenance, distinct signers, exact
  context/value binding and fabricated nested certificates.
- Split admission, durable commit, release, fence, page/delta receipt, agreement,
  install, activation, crash and restart so relevant interleavings are possible.
  Label any remaining scripted atomic step and its untested implementation gap.
- Candidate-specific idealizations are allowed only when explicit and justified.
  Never use booleans such as `membership_decided=true` or
  `provisional_import_justified=true` as substitutes for the property under study.
- Include deliberately unsafe mutants and verify they actually fail. A protocol
  that never signs must fail progress checks. Required progress not reached before
  a bound is INCONCLUSIVE/failure, never PASS by omission.

Required scenarios include:

- 1..19 PROVISIONAL startup, 19->20->21->22, concurrent arrivals/ticket changes
  and admission while other observers retain earlier views;
- the exact unsafe two-newcomer activation trace and the two-A/twelve-B report
  case, authentic minority witnesses, three-way partial conflict and late full
  evidence over at least three generations;
- successful fresh payments before and after complete replacement of every
  original member, without relying on Byzantine cooperation or founders;
- competing proposals, genuinely prepared but uncommitted values, withheld
  commits, round recovery and preservation of private immutable choices;
- honest and malicious bridges, unequal communities, eclipse, directed discovery,
  partitions/reconnection and unknown participants; use one organically growing
  network, not only artificial unrelated domains;
- unavailable old quorums, correlated outages, cold restart, storage loss/rollback,
  operator stop, late key compromise and independently joining verifiers;
- omitted/duplicated/replayed snapshot ranges, concurrent insertion/expiry,
  noncontiguous deltas, insufficient transfer capacity and crash during install;
- Byzantine metadata floods, conflicting owner-authorized requests, quota/pool
  exhaustion and bounded-resource recovery without gossip/load cascades.

Use exhaustive small models where feasible and seeded larger experiments. Explore
20/30, 100, 1,000 and 10,000 participants as useful. Assess the million-node goal
with explicit complexity, metadata/traffic estimates and targeted scaling tests;
do not require an infeasible all-pairs model or represent one million-node catalog
as one million independently simulated nodes. Label abstractions and extrapolation.

## Phase 5 — Bridge model assumptions to real execution

Use measured service costs and isolated real-process/QUIC/storage experiments for
the selected prototype. Pure configured-rate experiments remain sensitivity models.
Tests of existing daemon behavior cannot prove a candidate absent from that daemon.
Do not change production membership behavior merely to make research tests pass.

At minimum investigate offered/accepted load around 1k and 10k locks/s, explicitly
distinguishing aggregate network load from a hot shard/replica. Measure or bound:

- useful committed throughput and end-to-end p50/p95/p99 checkout latency;
- quorum success/deadline rates, affected-slot blocking and unaffected progress;
- handoff pause, catch-up time, final tail and recovery after restored connectivity;
- transferred proof/state bytes, verification/signing and durable-commit costs;
- queue saturation, backpressure, peak memory, CPU and restart behavior.

Vary RTT/jitter, bandwidth, bursts, storage delay, topology, churn and correlated
failures. QUIC transport recovery and application idempotency are distinct; do not
assume independent loss or add blind duplicate RPCs as a default solution.
Model real heartbeat/incubation/stability and resource policies or explicitly test
their impact before extrapolating. Report hardware, software, workload, repetitions,
parameter choices and confidence limits for measurements. Do not infer a security
probability from zero failures in sampled schedules.

For network rules actually implemented in the prototype, include adversarial
wire-level tests of receiver enforcement. Identify unimplemented defenses and the
exact tests still required before production integration. Run relevant example
tests and project checks; record environmental failures separately from defects.
Do not broaden/repeat expensive tests without a concrete remaining concern.

## Iterate toward a usable result

Repeat `research -> specify -> attack -> implement -> execute -> correct -> review`
until a complete candidate meets the stated acceptance envelope or a specific
necessary requirement change is established. Do not stop because one simulation
is green, the report is long, or another round of literature search is possible.

Safety must have an explicit argument and no unresolved reproduced violation
within its declared model. Progress must be demonstrated under its stated
availability/stabilization conditions. Out-of-assumptions cases must state whether
the consequence is safe refusal, liveness loss or possible false FINAL, and whether
real nodes can detect that boundary. "Fail closed" is not a mechanism unless those
nodes can actually recognize the missing evidence.

If full requirements cannot coexist, supply the smallest concrete counterexample,
the minimum necessary change, a tested feasible alternative and its product cost.
Compare that alternative before asking one unavoidable maintainer tradeoff question.
Never silently adopt stronger trust, permanent privileged participants, a weaker
attacker or conditional finality to manufacture completion.

## Deliverables and completion gate

Maintain a focused report at `docs/DECENTRALIZED_ROBUSTNESS_RESEARCH.md`, or continue
an already existing matching report rather than duplicating it. Keep historical
results distinguishable. Include:

1. A direct verdict, explained to the maintainer in German: supported within a
   precise envelope, incomplete, or requirements incompatible; identify decisive
   evidence and residual risk. The saved report itself remains English.
2. Claim/evidence and assumption/enforcement tables, actual source references,
   candidate comparisons and independently reproduced attack traces.
3. The exact proposed protocol, end-to-end verification/knowledge boundaries,
   safety/progress arguments, costs and justified deviations from current design.
4. Executable models/prototypes, mutation/progress tests, reproducible commands,
   compact machine-readable results where useful and measured-versus-assumed data.
5. A bottleneck/failure envelope and actionable steps needed for production,
   including wire defenses, migration, client verification, resource sizing and
   any policy decision that genuinely remains.

An isolated conditional model is an intermediate result. The main question stays
open until its extra premises have a defensible realization or the necessary
requirements change is made explicit with the tested alternative. A prototype's
success is not a claim that the current daemon is ready for payment deployment.

Save progress after material findings and before ending any turn: notes first,
compact state second, same next checkpoint, then read back and validate links,
IDs, original question meanings and statuses. Keep one active research leaf and
concrete next actions; do not mark requirements decided by inference. Preserve the
interview tree and exact Q-S3.3-01 meanings. Tool/context/runtime limits are not
scientific completion: leave runnable artifacts and a precise continuation cursor.

Start by stating the actual current blocker and the first falsifiable claim you
will investigate. Then execute the research; do not finish with a plan alone.
