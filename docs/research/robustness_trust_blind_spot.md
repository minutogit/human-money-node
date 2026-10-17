# Trust-semantics and model-fidelity audit

Date: 2026-10-16. Follow-up to CP-0034. Research clarification, no selected
mechanism or production change. The maintainer emphasizes that actual growth is
socially vetted, rather than arbitrary key arrival, and suspects an omitted premise.

## First finding

The most promising blind spot is the exact meaning and propagation of a friendship.
The specification contains a substantive human admission procedure. Existing
research does not simulate people carrying out that procedure. The daemon's
examined committee selector uses learned mature identities, rather than a portable
proof that a particular human admission procedure established voting eligibility.
An intended human premise, a signed assertion and an enforceable quorum rule are
different objects; the missing connection must be investigated before selecting
a replacement consensus architecture.

The prior negative result applies to the formalized local-activation rules and
declared fault/scheduling assumptions. It is not a demonstration that every
possible socially constrained HuMoCo admission procedure fails. A new intended
social rule must either be present in existing requirements or be labeled as a
proposed change; it cannot simply be assumed to invalidate a counterexample.

## Concrete specification/code/model comparison

| ID | Source fact | What it establishes | Missing or ambiguous meaning |
| --- | --- | --- | --- |
| TR-01 | [Spec 07 §2](../07_admission_und_wot_buergschaften.md): one direct friend suffices for worldwide activation; multiple friends are resilience | Admission is socially attached, not anonymous open enrollment | Scope of what a friend endorses; limits on how much voting influence one operator/edge may introduce |
| TR-02 | [Spec 07 §2.1](../07_admission_und_wot_buergschaften.md): personal acquaintance, location, reciprocity, diverse existing friends and no sale | Human checks are explicitly required | Operational test for sufficient independent community diversity; evidence held by other nodes and late recipients |
| TR-03 | [Configured keys and register_f2f_friend](../../crates/humoco-node/src/network/manager.rs): explicit local friend identity | A real locally authenticated starting trust choice already exists | Does this authorize only transport, a node's answers or bounded delegation to further operators? No shared global root follows automatically |
| TR-04 | [shard_committee](../../crates/humoco-node/src/network/manager.rs): local learned/mature/non-banned identities enter HRW selection | Local known-participant selection | No checked human-vetting receipt or approved delegation rule in this examined path |
| TR-05 | Research bridge fixture uses exact key sets and selective discovery | Demonstrates an allowed weak-rule schedule and an honest-intersection gap | Does not model an operator performing the qualitative diversity checklist; intended social compliance must be checked separately |
| TR-06 | Immutable choices/cutoff concern time and storage | Honest actors can follow inadequate transition rules | Social honesty alone does not order snapshot, pending old commit and activation |

The examined path is not a complete whole-repository audit of every social check.
No claim that social admission has zero value follows. No hearsay bans, transitive
guilt, financial deposits or automatic sanctions on an endorser are proposed.

## Narrow executable checks

Run:

```sh
python3 docs/research/robustness_trust_audit.py
```

[Script](robustness_trust_audit.py) and [results/source hash](robustness_trust_audit.json).
Deterministic finite set/graph/local-choice checks, no random sampling, real QUIC,
human validation, cryptographic certificates or general protocol proof.

1. **Many reciprocal friends do not imply robust honest interconnection.**
   In the 39-identity bridge fixture every identity has at least nineteen mutual
   friends. Distinct human operators/personal acquaintance can be supplied as
   fixture premises; no bot population is needed. Removing the one malicious
   bridge disconnects the correct graph into two nineteen-member communities.
   Two fourteen-member quorums share only that bridge. Minimum friend count,
   reciprocal edges and equal local size twenty do not exclude this schedule.
   This does not establish that the full intended diversity check accepts it.
2. **Trust/honesty and handoff ordering are independent questions.**
   In an explicitly unsafe copy-before-cutoff variant, twenty old members and a
   twenty-member successor with eight newcomers produce disjoint fourteen-voter
   sets A and B, with zero Byzantine actors and zero honest double-signers.
   Newcomers copy the empty slot before old A choices, then activate without
   importing/fencing the subsequent changes. This is a counterexample to that
   weak handoff rule, not to the certified closure alternative. It does not model
   all continuous admission timers or all social interactions.

Both expected unsafe outcomes are asserted. Passing the audit means they were
reproduced under those exact premises, not that a new social defense was proved.

## How to find and validate the missing premise

1. Reconstruct an actual startup/growth story using named human operators and
   their real actions: acquaintance checks, operator versus node count, duplicate
   machines, reciprocal approvals, existing-community checks and recipient setup.
2. For every old attack trace, identify the first action at which an honest actor
   would violate a specific admission/trust rule. A violation must name the rule
   and the information actually available to that actor. Do not ban the schedule
   just because it is considered unlikely or because the harness sees a cut.
3. Separate three assertions: "I know this person", "I rely on this node's
   answers", and "I authorize this operator to introduce further counted voters".
   Determine which is already intended, how far it propagates, and whether the
   assertion is local human trust, transferable signed evidence or a new proposal.
4. Add the smallest exact predicate that represents the identified existing rule.
   Replay the bridge and newcomer attacks, plus a successful ordinary growth/
   full-turnover trace. A rule that prevents all participation fails progress.
5. Independently try honest community separation, compromised acquainted friends,
   multiple nodes per operator, colluding introducers, delayed approvals and
   restart. Test genuine diversity rather than counts of mutually vouching keys.
6. Keep timing/storage/key lifecycle separate. A better social admission bound
   cannot silently prove durable acknowledgments, complete transfer or old-key
   erasure. Record which risks each new premise actually removes.

Candidate hypothesis only: existing operator-approved friend identities and
explicitly scoped admission endorsements may supply some recognition currently
treated as missing. This might reduce additional machinery. No complete safe
endorsement/delegation protocol, independent-operator bound or global honest-quorum
intersection has yet been established from the existing five-finger checklist.
Do not select a new central checkpoint, a fixed validator list or a different
consensus engine before resolving this semantic question.

Clarification **Q-S2.1-TRUST-01** asks which exact promise the maintainer intends
for an F2F friendship and what an honest operator must check before admission.
It is an interpretation question, not a policy A/B selection. It does not change
the unanswered original Q-S3.3-01 or the withdrawn Q-S2.2-01.
