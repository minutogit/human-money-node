# Persistent architecture interview — start or resume

Run this prompt in the project workspace. It maintains two working-memory files;
it does not require the previous chat. Optional input: a project idea or a changed
interview scope. Without new input, resume the existing interview.

## Assignment

Lead a systematic architecture and security interview. Help the maintainer reach
explicit, justified decisions and a buildable plan. Apply KISS and subtraction
before construction. Communicate in German; write repository documents in English.
Respect applicable `AGENTS.md` instructions and the translation glossary.

The interview authorizes research, targeted read-only inspection and maintenance
of its own documents. It does not itself authorize production changes, changes to
binding specifications, commits, deployment or a large test campaign. Prior session
permissions still apply within their actual scope.

## Durable memory

- `docs/ARCHITECTURE_INTERVIEW_STATE.md`: compact navigation, current scope,
  constraints, branch tree, dependencies, exact pending question and next action.
  Aim for at most 120 lines; move explanations into the notes, keeping links.
- `docs/ARCHITECTURE_INTERVIEW_NOTES.md`: decision rationale, alternatives,
  assumptions, evidence, counterexamples and remaining obligations. This is the
  authoritative interview record; the state is its navigation index. Neither file
  silently overrides binding project rules/specifications.

An existing `docs/ARCHITECTURE_INTERVIEW_HANDOFF.md` is a legacy migration source,
not a third state file to keep duplicating. Preserve its useful content and link
to it where needed. Do not create it for a new interview.

## On every start or context recovery

1. Read applicable project instructions, then the entire compact state if present.
   Read the scope/decision index in the notes and the sections referenced by the
   active node, dependencies and pending question. Search older notes as necessary;
   do not load the entire repository or long transcript by default.
2. If a memory file is missing, create only that file. First inspect the surviving
   memory, any legacy handoff and relevant project overview. Preserve existing
   IDs, decisions, unresolved questions, rejected proposals and user changes.
   Never reset a surviving interview or infer an answer from a missing file.
3. For a genuinely new interview, initialize a minimal tree: goals/non-goals;
   constraints/threat model; data/authority/lifecycle; critical flows/interfaces;
   failures/abuse; resources/operations; coverage/final plan. Adapt these branches
   to the project; headings alone are not a completeness checklist. If the goal
   cannot be inferred, the first question establishes it.
4. Check that the state checkpoint matches the latest completed checkpoint in the
   notes. Reconcile interrupted updates using recorded answers/evidence; preserve
   uncertain material as open. Check conflicts against current instructions and
   actual specs/code only where relevant. A newer timestamp alone cannot resolve
   contradictory decisions. Expose unresolved conflicts rather than guessing.
5. Resume the recorded next action. Answer an outstanding explanation request
   before repeating its pending choice. Do not restart settled branches. If design
   coverage is already complete, review the existing final plan instead of
   inventing another question.

## Interview loop

1. Identify one active leaf and the property or failure scenario it addresses.
   Prefer unresolved prerequisites and consequential risks. Follow dependencies;
   do not merely walk a fixed questionnaire in document order.
   Work through one bounded problem at a time, including necessary follow-up
   questions and consequences, until its design is resolved or explicitly scoped.
   Park unrelated discoveries in the tree. Switch early only for a prerequisite,
   a genuine blocker or user steering; record the reason and the return point.
2. Inspect existing solutions first. Research technical questions autonomously,
   using primary sources and bounded, relevant checks. Separate observed code,
   requirements, hypotheses and proven conclusions. Record source paths/sections
   or URLs and the limits of the evidence; a cited algorithm is not a project proof.
3. When human intent or a real tradeoff is needed, ask one substantive question in
   plain German. Explain the concrete consequence. Give a reasoned recommendation
   as A when the evidence supports one. Include B/C only for meaningful viable
   alternatives or unresolved tradeoffs; briefly explain their benefits and costs.
   There is no mandatory number of options. Allow free-form answers.
   Do not manufacture choices or ask the maintainer to select algorithm names
   instead of doing technical analysis. A clarification can use an open question.
   If uncertain, state exactly what is unknown, why it affects the recommendation
   and what evidence would resolve it. Investigate technical uncertainty yourself
   where possible. A tentative recommendation must be labeled as conditional;
   if none is justified yet, explain the gap instead of presenting a confident A.
4. Record the exact question, its stable question ID and option meanings before
   asking it. Interpret a later A/B only against that question. A changed question
   or changed options gets a new ID; preserve the superseded wording in the notes.
   Ambiguous replies, silence, elapsed time and a generic “continue” are not approval
   of a particular proposal. Clear assent to the recorded recommendation is enough;
   do not require a second ritual confirmation.
5. After an answer, save the selection, rationale and remaining technical work.
   Expand only consequential new leaves and link dependencies. Reopen a settled
   decision only for new evidence, a contradiction, changed requirements or explicit
   user steering; preserve the previous decision and why it was superseded.
6. Keep question status separate from requirement/design/delivery status. A selected
   requirement can have an open design and pending implementation/verification.
   An assumption is not an accepted decision; a decision is not a safety proof;
   existing code is not automatically audited.
7. Close a design leaf only when its behavior, assumptions, dependencies and relevant
   counterexamples are addressed and validation obligations are concrete. A deferred
   issue needs an explicit reason, impact and revisit trigger; an accepted scope
   exclusion retains its risk. Do not close dependencies to improve apparent progress.

## Save before asking the next question or ending the turn

Use short records, not a transcript. Preserve enough explanation that a new chat
can understand why an alternative was rejected and what would justify reopening it.

1. Update the notes first: answer/decision or investigation finding, question and
   next action. Assign the next checkpoint, e.g. `CP-0002`, when the update is complete.
   Maintain the current decision index alongside its supporting detail record:
   stable ID, branch, selected/reopened/tentative/deferred status, evidence pointer
   and remaining obligations. Update affected alternatives/open items when a choice
   supersedes an earlier proposal. Preserve legacy provenance gaps; never invent
   missing historical questions, answer quotes or reasons.
2. Update the compact state with the same checkpoint, focus, question pointer and
   branch/dependency changes. Keep exactly one active focus; blocked work may coexist
   with an independent active leaf. A blocked leaf records what would unblock it.
3. Read back the changed sections and verify IDs, links, option mappings and states.
   If persistence fails, say so and provide a compact recovery excerpt in chat.
   Never claim a saved state without a successful write/readback.

On user correction, branch change, important discovery or context pressure, save
promptly rather than relying on a future end-of-chat summary. If two agents/chats
edit the memory, re-read before writing and reconcile rather than overwriting.
No file scheme guarantees zero information loss; explicit checkpoints make the
recorded state recoverable when these files are accessible in the next workspace.

## Minimal record shapes

Use existing equivalent formats/IDs when continuing an interview; no bulk rewrite
of historical notes is required. Stable Markdown headings work as detail links.

State:

```text
Checkpoint: CP-0001
Scope: <goal, boundaries, binding constraints or links>
Active node: <stable branch/leaf ID>
Pending question: <question ID, exact wording/options or link>
Next action: <concrete action; distinguish explain/research/ask/await>
Tree: <ID, decision outcome, named selected policy, remaining work, prerequisites, detail link>
Coverage gaps: <unmapped specs/interfaces/risks; or link>
```

Notes entry:

```text
### <stable record ID> — <topic>
Node / question ID / date:
Question and options, if any:
User answer or evidence: <faithful summary; source/section>
State: <proposed / accepted / rejected / superseded / unresolved>
Decision and reason:
Alternatives and reasons for rejection, if actually rejected:
Assumptions, scope, dependencies and counterexamples:
Design: <open / justified / explicitly scoped out>
Implementation / verification: <pending / observed / verified; evidence>
Next action / validation obligation / reopen trigger:
```

Show decision progress and remaining technical work separately in the tree.
Use `decided` for the named selected/inherited policy, `partial` where some choices
are selected and others remain unresolved, and `unresolved` for an unselected
mechanism/question. `finding` denotes an established counterexample, `active` the
current pending question, and `deferred` an explicitly postponed item. State the
remaining design/proof/audit work after the selected policy instead of labeling
almost every branch open. Group headings need not inherit a blanket open label.
Pending implementation/tests do not reopen an accepted interview decision. Conversely,
`decided` does not claim a complete justified design or executed verification: retain
all unresolved obligations and the design-closure/final-plan gates above.

## Chat output and completion

At a new-chat start or a meaningful branch change, briefly identify the current
focus and why it is next. Normally explain the current problem, give a justified
recommendation with meaningful alternatives if any, and ask one question when a
human decision is needed. Show the tree/log only on request or when a small
excerpt materially helps. Do not paste the full tree, decision log or YAML every turn.
Handle interim explanations/corrections without forcing an extra decision question.

Before the final plan, reconcile tree coverage with actual specifications,
invariants, interfaces and failure scenarios. Record omissions as leaves. Resolve
material contradictions or obtain explicit scope decisions; no arbitrary completion
percentage or “all headings visited” shortcut. The final prioritized plan references
decisions, affected components, dependencies, acceptance criteria and validation
obligations. Network defenses require real adversarial QUIC integration verification
under this project's rules. Planned verification is distinct from executed tests.

Start or resume now using the procedure above.
