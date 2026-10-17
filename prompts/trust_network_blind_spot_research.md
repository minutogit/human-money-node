# Find the missing link in HuMoCo's recursively trusted operator network

## Mission and the maintainer's actual premise

Investigate HuMoCo as a socially admitted, recursively maintained network of
operators. An operator adds peers whose operators they believe will run the
intended code unchanged, operate reliably and exercise the same care in selecting
their own friends. Their friends do likewise. Treat this as a substantive design
premise to understand and use, rather than replacing it with anonymous arbitrary
public-key enrollment.

Find whether a small overlooked property, an existing mechanism used incorrectly,
or a minimal missing rule connects this social trust to safe counted votes.
Determine **whether, under which practical operating conditions, and through which
actual mechanisms the complete blind Collision Lock Registry can provide reliable
irreversible FINAL payments**. Seek the simplest workable construction first.
Neither a positive conclusion nor a negative one is predetermined.

The desired result is a tested, implementable explanation of the whole system:
human admission -> discovery -> counted voting -> payment -> member/state/key
succession -> independent recipient verification -> recovery. A reassuring story,
a literature list, another unexplained "membership is unresolved", or a model
that succeeds only after supplying the answer as an oracle is insufficient.

Communicate with the maintainer in German. Repository artifacts remain English.

## Invocation, authority and limits

**Preparing, reading for editing, or linking this prompt does not execute it.**
The prior investigation was explicitly stopped. A later explicit request to read
and execute this prompt authorizes this focused investigation to resume. Then
work autonomously through source inspection, primary-source internet research,
candidate design, adversarial models, isolated prototypes, execution and review.

Preserve existing uncommitted work. Research-only scripts/examples and isolated
QUIC/storage/process harnesses are authorized. Do not deploy, commit, open a PR,
rewrite binding specifications or install a new production consensus/admission
scheme under this research assignment. Prepare concrete reviewable proposals.
Do not contact operators or collect private social data without explicit authority.

Use subagents with disjoint file ownership:

1. Trust/model fidelity: reconstruct human admission, code behavior and prior
   counterexample admissibility.
2. Independent challenger: seek failures of proposed trust/eligibility/continuity
   rules and independently review their implementation.
3. Experiments: model topology/resources and bridge surviving assumptions to real
   process, QUIC and durable storage execution as appropriate.

The lead integrates findings and resolves disagreements. A candidate's author
must not be its only reviewer. If delegation is unavailable, record the limit.
Ask at most one substantive unresolved product question after examining existing
decisions and preparing concrete consequences; do not re-ask the clarified trust
intent or outsource technical research to the maintainer.

## Resume from the latest interview, not from an old conclusion

Read applicable `AGENTS.md`, then:

1. [Interview workflow](architecture_interview.md) and the entire latest
   [compact state](../docs/ARCHITECTURE_INTERVIEW_STATE.md).
2. [Interview notes](../docs/ARCHITECTURE_INTERVIEW_NOTES.md): current decision,
   alternative, open-item and gap registers, then §7.47/7.46 and newer relevant
   records. Follow §7.44/7.40 and exact §7.16 when needed. Use the latest consistent
   checkpoint; this prompt was prepared after CP-0036.
3. [Trust/model audit](../docs/research/robustness_trust_blind_spot.md),
   [finite audit script](../docs/research/robustness_trust_audit.py) and its results.
4. [Robustness report](../docs/DECENTRALIZED_ROBUSTNESS_RESEARCH.md),
   [membership study](../docs/research/robustness_membership.md),
   [independent review](../docs/research/robustness_safety_review.md),
   [execution evidence](../docs/research/robustness_experiments.md) and relevant
   actual predicates in the existing research examples.
5. Specs 01, 07, 11, 15 and relevant current code: configured friend keys, manual
   friend registration, gossip learning, ticket maturation, committee selection,
   client verification, durable vote release, readiness and state transfer.

The [broader research brief](decentralized_robustness_research.md) supplies useful
protocol/experiment disciplines. This assignment's focus is the clarified social
trust premise; do not merely repeat the broader report's conclusions. Preserve
historical results, scope qualifications and all question meanings.

Q-S2.1-TRUST-01 is answered at the intent level: trust includes intended code,
reliable operation and recursively careful friend selection. This is operator
belief and a meaningful social filter; it is not a proof that nobody becomes
malicious, compromised or mistaken. No executable endorsement rule was selected.
Q-S3.3-01 remains unanswered with its original one-versus-two payment-round
meanings. Q-S2.2-01 remains withdrawn as the next question.

## 1. Audit the premises before adding a protocol

Build a small traceable table for each relevant property:

`human intention -> specification -> actual operator action -> local evidence ->
code predicate -> model predicate -> claimed system property`.

Classify each item as existing enforced rule, human operating assumption,
measurable hypothesis, unmeasured premise, implementation omission, or proposed
change. Distinguish these meanings of trust:

- I know this operator and have authenticated this NodePubKey.
- I expect their machine to run the intended correct code reliably.
- I accept an admission assertion they make about another operator.
- I authorize that introduced identity to contribute to a particular FINAL quorum.

Inspect the actual five-finger admission checklist and its community-diversity
requirement. Reconcile it with "one friend suffices for worldwide activation".
Identify what an honest operator actually checks, what others receive, and how
one operator controlling several machines is treated. Do not invent a selected
one-human/one-node restriction or equate twenty keys with twenty independent
operators. A graph of apparent endorsements is not evidence of human independence.

Check whether configured friend keys, recipient-selected gateways, authenticated
admission paths or existing root/causality evidence already provide part of the
recognition basis previously called missing. Identify their exact scope. Personal
local anchors need not automatically produce compatible global authority. Do
not introduce a new central checkpoint as a default assumption; derive necessity
if an additional anchor is required.

A software version hash, signed promise or knowledge of a person does not prove
runtime behavior, absence of bugs, configuration correctness or future key
custody. Conversely, do not dismiss social admission merely because it is not
cryptographic attestation. Specify the external operating premise honestly and
test what it actually buys.

## 2. Re-evaluate each counterexample against real admission

For each prior failure, record the first action at which an honest participant
would violate a specific existing rule, the information available to them and
the actual rejection/stop predicate. Otherwise retain the counterexample.

At minimum replay:

- The 39-identity organic bridge witness: two locally known twenty-member groups
  certify conflicting values with one shared Byzantine bridge. The finite audit
  gives every identity at least nineteen reciprocal friends; minimum degree alone
  does not refute it. The actual human diversity check remains to model.
- The exact 22-identity copy-before-A/two-newcomer activation race with six
  Byzantine identities and no honest double-signing.
- The all-honest weak-handoff mutant with eight newcomers copying empty state
  before old A votes. Trust and correct transfer ordering are separate questions.
- Counterfeit first membership, hidden eligible nodes, colluding introducers,
  graph cuts, delayed discovery, equal-sized different catalogs, and late recipients.
- Minority/hidden certificate preservation, competing prepared transitions,
  complete turnover, restart/rollback and late compromise of retired keys.

Distinguish an actually invalid social-admission trace from an allowed but unlikely
trace and from a trace outside an explicitly adopted fault envelope. "A friend
would never do that" requires either a stated model boundary or an operative
defense; the existing six-Byzantine target may not silently become zero.
Hearsay or shared acquaintances never establish fraud or authorize automatic bans.

## 3. Search for the smallest missing connection

Use a short candidate ladder:

1. **Existing mechanism:** can a correct interpretation, missing verification,
   existing signed field or repaired ordering close the gap without a new subsystem?
2. **Minimal explicit trust rule:** if needed, investigate scoped authenticated
   admission assertions, bounded delegation/influence or a verifiable eligibility
   condition carried through the existing F2F mechanisms. Define exactly whose
   evidence counts and why colluding keys cannot manufacture authority.
3. **Established broader alternative:** compare federated/personal quorum systems,
   socially constrained admission and recognized-group reconfiguration only when
   their assumptions genuinely fit. Explain why a smaller candidate fails before
   recommending architectural replacement.

Research primary papers, current official specifications and maintained reference
implementations actively. Relevant leads include SCP/FBA, Byzantine quorum systems,
social-network Sybil defenses such as SybilGuard/SybilLimit/SybilRank, and dynamic
authenticated reconfiguration. Record version/date, sections and exact premises.
Do not borrow a rapid-mixing graph, bounded attack edges, a trusted seed, honest
quorum intersection, global graph visibility, admission authority, secure erasure
or an honest-operator fraction without showing its realization/classification.

For each survivor specify identity/operator scope, introducer authority, exact
signed context, admission/revocation, local validation, learned-peer restrictions,
initial and late-recipient recognition, bounded state and costs. Explain how it
interacts with HRW rather than silently changing what fourteen counted votes mean.
Signed friendship metadata may expose social relationships; assess that cost
before assuming a public global trust graph.

## 4. Preserve the actual product

- Blind L2, no amounts/accounts/real names required by consensus, client custody,
  no financial deposits/staking and sovereign operators.
- One organically growing network; N<20 PROVISIONAL, existing N>=20 FINAL and
  stability policy. Frozen at-most-twenty distinct NodePubKeys, fourteen votes,
  800 ms collection, all-member dispatch and neutral NOT_READY/cancellations.
- Six Byzantine identities remains the conditional target; derive how social
  admission affects influence, rather than assuming a global fraction implies
  every one of 65,536 committees meets it across repeated selections/grinding.
- F2F presence and verified-fraud gossip only; locks are not gossiped. Direct
  shard RPC requires identities learned through the allowed mechanism.
- Durable exact own choices before released votes, conservative inherited effects,
  safe old-write cutoff, durable individual install, rollback/loss gate, root TTL
  plus grace, bounded expiry and full eventual replacement of founders.
- No financial liability or automatic guilt for an introducer, hearsay sanctions,
  telemetry-driven bans or forced software updates. A suspected loss of confidence
  is not cryptographic fraud. Any membership exclusion/change needs its own safe
  continuity rule; do not silently make revocation a new arbitrary roster switch.
- Planned affected-shard pauses and safe automatic progress after stabilization;
  no irreversible FINAL revoked later by choosing a lower hash.

Six withholding Byzantine nodes plus one unavailable correct member supply only
thirteen correct responses. Respect that availability limit. Honest operation,
correct software, shared information and preserved state are different premises.
The selected durable-before-vote/relaxed local latency direction conflicts with
older <5 ms specification wording; record it without rewriting binding rules.

Changes to selected constraints must be labeled and justified as proposals. Do not
reopen glossary questions, freeze root committees for their entire lifetime or
require permanent founders to manufacture a simple solution.

## 5. Execute models that represent the human process and failure boundary

Reconstruct startup and growth from named operator actions, not just random key
insertion. Separate operator identity from device/key, a friendship from received
proof of that friendship, and social evaluation from automatic machine actions.
Use explicit traceable abstractions for human checks; do not treat a harness
truth label such as `independent_human=true` as evidence available to nodes.

Include honest communities, uneven degrees, weak bridges, independent alternate
paths, clique-like collusion, operator mistakes, several nodes per operator,
later machine compromise, software/configuration mistakes, churn and correlated
regional/hosting failures. Human acquaintance may correlate failures as well as
constrain entry. Friendship is not automatically transitive honesty or independent
random sampling. Evaluate discovery/fan-out/TTL/incubation/stability policies, not
only reachability in the harness's complete graph.

Use deterministic virtual-time scheduling, seeds, explicit bounds, replayable
events and minimized important failures. Model admission, evidence receipt,
durable commit, vote release, fence, transfer, agreement, install, activation,
crash/restart separately. Nodes use received/local durable state; global faults,
actual human independence and connectivity remain harness-only observations.
Use real signature verification for proposed authentication predicates or an
explicit ideal-authentication boundary with fabricated-nested-proof tests.

Require both safety and useful progress. Include deliberately unsafe mutants
without the proposed missing rule and verify they fail. Then add the minimal rule
and test the same schedules plus successful 1..19->20->21->22 growth, ordinary
fresh payments, conflicts, at least three complete turnovers, partition healing,
restart and independently joining recipients. A never-signing rule or uncompleted
bounded run is failure/inconclusive, not success by omission.

Measure sensitivity at 20/30, 100, 1000 and 10000 operators where useful; assess the
million-node goal with actual bounded catalog/proof tests and complexity, not an
infeasible all-pairs simulation. Social mistake/compromise/topology parameters are
engineering hypotheses unless supported by actual cited data. Do not invent field
observations or multiply independent-fault probabilities for correlated humans.
Distinguish a conditional safety proof, measured service reliability, a statistical
risk estimate and merely sampled schedules. Zero sampled failures proves none of
the unstated social assumptions.

## 6. Test the complete practical chain

Reuse existing measured service costs within their exact scope. For a surviving
new mechanism, test its actual implementation with isolated real QUIC/process/
durable storage experiments. Verify receiver rejection of forged/replayed/
over-budget admission evidence, missing transfer/install proof and exhaustion of
delegation/verification/queue budgets. Follow the project's mandatory adversarial
wire-test rule for implemented network defenses; list absent defenses explicitly.

Exercise ordinary checkout and recovery/admission concurrently. At offered 1k and
10k locks/s distinguish network aggregate from a hot shard/replica; measure useful
commits, success/deadline rates, p50/p95/p99, pause/tail/catch-up, evidence bytes,
CPU/memory, backpressure and restart. Vary relevant network/storage/churn conditions
and report hardware, repeats and confidence limits. An application sleep is not
a measured lossy/jittered WAN; a configured rate is not measured throughput; a
graceful reopen is not a power-cut/rollback experiment. Existing green daemon
tests do not prove a new trust protocol absent from that daemon.

## Verdict, deliverables and stop condition

Iterate `premise audit -> smallest candidate -> independent challenge -> execute
-> correct -> measure -> review`. Continue until there is a concrete tested
operating envelope or a specific necessary change with a tested alternative.
Do not finish at "more trust needed", a new architectural name or another plan.

Maintain `docs/TRUST_NETWORK_BLIND_SPOT_RESEARCH.md` with:

1. A direct verdict: robust under stated realized conditions, conditionally viable
   with named missing implementation/field evidence, or incompatible requirements.
2. The actual missing puzzle piece, if found: its exact rule, where existing
   semantics/code/model lost it, before/after failure trace and working execution.
   If no simple piece exists, explain the smallest surviving alternative and cost.
3. Trust/intention/spec/code/model evidence table with stable T-claim IDs; actual
   source versions and admissibility review of every decisive prior counterexample.
4. Complete node/recipient knowledge, safety and progress argument, temporal and
   per-shard adversary boundary, resource bounds, operator burden and privacy cost.
5. Runnable artifacts, seeds/commands/raw results, mutant/progress tests,
   independent review corrections and measured-versus-assumed evidence.
6. A practical operating contract: what operators must really check/do; which
   conditions machines enforce; what users see when evidence/quorum is missing;
   what cannot be detected locally; and exact remaining production/field tests.

Practical robustness may rely on explicit human operating assumptions. Evaluate
whether they are understandable, achievable, maintainable through churn and
compromise, and supported by evidence. Do not describe a global graph/fault
property as locally checked if it is not. A laboratory model cannot establish
how reliably real people vet friends; missing field evidence remains a precisely
scoped gap, not a fabricated success or automatic rejection of social trust.

An unresolved conflicting-FINAL execution inside the declared envelope rules out
a positive safety verdict, even if sampled normal operation looks excellent.
Outside the envelope, distinguish safe refusal, lost availability and possible
false FINAL, including whether actual nodes can detect the missing condition.

Answer the maintainer briefly in German: what works, why, necessary changes,
residual risk and the single most useful next action. Never claim the current
daemon is payment-ready solely because a conditional prototype passes.

Save interview progress after material findings and before ending: notes first,
compact state second, matching next checkpoint, then read back IDs/links/statuses.
Keep one active focus, original question meanings and concrete continuation steps.
Maintain historical research as historical; no positive or negative conclusion
may silently acquire stronger premises. If execution is interrupted, leave runnable
artifacts and a precise continuation cursor rather than calling it completed.
