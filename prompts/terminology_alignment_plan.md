# Terminology alignment — executable review and editing plan

Status: reusable execution plan. The initial execution and the 2026-10-16 continuation
are recorded in [the alignment report](../docs/TERMINOLOGY_ALIGNMENT_REPORT.md);
naming is settled under interview DEC-049–052; substantive conflicts remain open.

## Objective and invocation

Review and align terminology across `docs/TRANSLATION_GLOSSARY.md`, current project
documentation/specifications and source-code comments. Readers should understand
the same concept when the same term appears and recognize distinct concepts when
their names differ. Preserve the bilingual policy: German maintainer communication;
English repository prose and comments, with German headwords in the dictionary.

When the maintainer explicitly asks to execute this plan, perform the investigation
and justified editorial changes through completion. Merely preparing or reading the
plan as context does not mean its audit has been executed. No commits, publication
or production-behavior changes are included. Do not invoke the master audit orchestrator.

## Scope and boundaries

Inspect:

- Applicable `AGENTS.md` files, root documentation, `docs/TRANSLATION_GLOSSARY.md`,
  numbered specifications and current operational/client guides.
- Rust module docs, Rustdoc (`//!`, `///`), ordinary comments, documented examples
  and terminology in test descriptions under `crates/`.
- Relevant declarations, validators, call sites, DTOs and tests as evidence of what
  a comment describes. Distinguish static inspection from executed verification.
- Maintained prompts as a secondary surface so they do not reintroduce old meanings.
- Interview decision/status records for accepted requirements, proposed names and
  unresolved architecture questions. These records are not binding specifications.

Preserve executable logic, public/private identifiers, field names, serialization,
wire tags, HTTP responses, config keys, logs and runtime strings. Record suggested
identifier/interface migrations separately if terminology would benefit from them.
Do not change dependencies, algorithms, quorum thresholds, timing, storage semantics,
authority rules or defenses through an editorial change.

Treat historical reports, archived documents, quoted examples and chronological
interview records as historical evidence. Inventory them separately; do not rewrite
their old statements to make proposals appear retrospectively approved. Add a short
current-status pointer only where useful and authorized. Do not edit project rules
or remove normative obligations to match code or glossary wording.

## 1. Establish the starting point

1. Read applicable instructions and inspect `git status --short`. Preserve existing
   edits; do not reset or stage unrelated work. Re-read files before editing if
   another chat/agent may have changed them.
2. Read the entire glossary, including original mappings, G-IDs, naming-review
   paragraphs and TERM-01–13. Read the compact interview state, current decision
   register and only the detail sections relevant to disputed terms.
3. Build an explicit file inventory using `rg --files` and targeted searches.
   Include current untracked documentation relevant to this task. Record ignored,
   generated, vendored, historical, external or inaccessible material separately.
4. Start or resume `docs/TERMINOLOGY_ALIGNMENT_REPORT.md`. Preserve earlier findings
   and use stable finding IDs. Record the inspected Git revision and local-change
   context; a revision alone does not identify uncommitted inputs.

Do not create another competing dictionary. The glossary remains the shared
vocabulary reference; the report tracks evidence, edits and remaining decisions.

## 2. Review the dictionary before imposing names

Cover both the original mapping table and all G-001–066 entries, plus any additions
made after this plan. Give each reviewed concept a status in the report:

| Status | Meaning | Permitted action |
| --- | --- | --- |
| Established | Existing applicable terminology or an explicitly selected name. | Align equivalent uses when meaning and project rules remain unchanged. |
| Editorial naming | A preferred label or alias needing clearer wording. | Select and align it autonomously under DEC-052; record the change without asking a glossary preference question. |
| Ambiguous | One word covers different objects or a definition conflates them. | Separate the meanings and qualify occurrences using established descriptive language. |
| Substantive conflict | Requirements, implementation or safety claims disagree. | Document evidence and impact; leave the policy choice open while completing unaffected editorial work. |

For each concept, establish the German headword, English preferred term, allowed
aliases, plain definition, exclusions, relevant code identifiers, evidence and status.
Reuse existing G-IDs; add IDs only for genuinely distinct concepts. Do not erase an
old meaning or change an ID to hide a semantic revision. Update glossary explanations
where justified, distinguishing editorial names from unresolved protocol meanings explicitly.

Settled naming examples (DEC-049–052):

- G-014: “Eltern-Lock” / parent lock for the predecessor record;
  “Vorgängerausgabe” / predecessor output for the specific consumed output.
- G-021: “Lock-Signatur” / request authorization signature for the client's
  individual signature; “Freigabenachweis” / client authorization evidence for
  the disclosed key, its checked predecessor-output binding and valid signature.
  Genesis remains a separate case; no new proof format follows from the name.
- G-049: “Shard-Zusammenfassung” / shard digest for compact comparison information.
  Distinguish it from full state, a single checksum and node-quorum evidence.

The maintainer explicitly removed glossary approval gates. Apply and refine names
independently; do not turn spelling, aliases or term selection into interview
questions. This does not approve unresolved payment, authority or recovery rules.

## 3. Find and classify occurrences in context

Search German and English spellings, aliases, abbreviations and associated code
identifiers. Start with glossary words and expand searches from actual occurrences.
Examples of useful initial groups:

```bash
rg -n -i 'certificate|attestation|partial.?sig|quorum|zertifikat|bestätigung' docs crates
rg -n -i 'parent_lock|parent.?lock|vorgänger|eltern|spend.?slot' docs crates
rg -n -i 'digest|snapshot|sync|synchron|ready|readiness|handoff|cutoff' docs crates
rg -n -i 'persist|durab|commit|reserv|pending|final|void' docs crates
rg -n -i 'node.?id|nodepubkey|hrwroutingid|friend|f2f|tier|gossip' docs crates
```

Searches identify candidates. Read surrounding prose, signatures, validators and
call sites before deciding what an occurrence means. Common words such as “lock,”
“signature,” “proof,” “reservation” and “snapshot” legitimately have multiple uses.
Review relevant prose/comment blocks beyond initial keyword hits; keyword search
alone does not establish semantic coverage. Avoid blanket replacements.

Record findings using this shape:

| Field | Required content |
| --- | --- |
| Finding / concept | Stable `TA-xxx` ID and glossary G-ID or original mapping. |
| Location | Exact file and current line/section; include relevant symbol where useful. |
| Current meaning | Term in context, actor, object and claim being made. |
| Evidence | Applicable rule/spec, observed declaration/validator/call site, interview status. |
| Classification | Consistent, editorial drift, ambiguous, substantive conflict or historical alias. |
| Proposed action | Specific wording or glossary clarification; explain why meaning is preserved. |
| Outcome | Applied and checked, already consistent, proposed, unresolved or excluded with reason. |

Prioritize these distinctions:

1. Client authorization signature versus node attestation versus quorum certificate
   versus TLS certificate; distinguish full Ed25519 signatures from threshold shares.
2. Parent lock versus consumed output; lock record versus voucher/history/proof path.
3. Shard versus committee versus quorum; candidate ranking versus authorized membership;
   full identity versus short ID versus routing ticket.
4. Local acceptance versus queue admission versus durable commit versus emitted vote
   versus verified quorum; status observation versus recipient acceptance evidence.
5. Digest versus state snapshot versus committee snapshot; copied data versus justified
   completeness, old-write closure, successor installation and signing readiness.
6. Client ingress versus internal P2P; client friend secret versus node friendship;
   F2F gossip versus shard-direct RPC; temporary refusal versus identity ban.
7. Root expiry versus physical purge; protocol time versus OS time; per-attempt vote
   collection budget versus local processing and full checkout latency.

## 4. Resolve wording without hiding design conflicts

Use applicable instructions/specifications to identify required behavior, code to
identify observed behavior and interview records to identify selected future directions.
No one source makes every statement in another source correct. The glossary records
meaning; it cannot authorize an otherwise unselected protocol change.

Apply clear spelling, alias, actor/object and definition corrections. In English
comments, keep exact Rust identifiers in backticks and explain their conceptual role
if their historical names are misleading. Do not rename symbols to imitate a German
headword. Use explicit qualifiers instead of adding new unnecessary jargon.

For a factual comment correction, inspect the actual relevant path. If code differs
from a requirement, do not rewrite the requirement or describe the defect as intended.
Record the mismatch and keep observed behavior separate from required behavior.
Preserve normative words such as MUST/MAY and all guarantees/conditions unless an
already authorized decision specifically justifies a substantive revision.

Known conflicts to track rather than settle by synonym replacement include FINAL
versus VOID, durable-before-vote versus existing asynchronous-response descriptions,
unconditional merge claims, binary status policy versus High Assurance references,
and unresolved membership/handoff authority. Reuse TERM-01–13 and interview GAP/OPEN
IDs where applicable. New conflicts get evidence and an explicit next action.

Batch independent editorial fixes by concept across current specifications and
comments. Update glossary source pointers alongside them. Complete unambiguous work
while substantive architecture choices remain open. Only consequential protocol
tradeoffs may need maintainer intent; editorial naming does not. Preserve the
architecture interview cursor and do not re-ask settled policy.

## 5. Verify the actual change

- Review every diff hunk: it must be vocabulary/explanation only within this scope.
  Inspect comment examples and Rustdoc code fences carefully; they can affect doctests.
- Run `git diff --check`; check modified Markdown links, anchors, G-IDs and report
  references. Include changed untracked files in manual/content checks too.
- Re-run relevant searches for replaced aliases and inspect all remaining hits.
  Keep a ledger of intentional historical/API aliases and unresolved meanings.
  Zero search hits is not a substitute for contextual review.
- Re-read updated spec passages and the corresponding comments together. Check that
  the same term names the same object and preserves its required conditions.
- No new behavioral test suite is required for ordinary prose/comment edits. If a
  Rustdoc example changes, run the relevant documentation tests when feasible and
  report any limitation. If an intended change requires runtime/protocol behavior,
  leave it as a separate implementation task with appropriate tests, including real
  adversarial QUIC verification for network defenses under project instructions.
- Do not run unrelated audits, reformat the workspace or launch a large test campaign
  solely for wording changes. Never claim the workspace is green without running it.

## 6. Completion and handoff

Keep `docs/TERMINOLOGY_ALIGNMENT_REPORT.md` compact enough to navigate and include:

1. Inspected scope/file coverage, exclusions with reasons and uninspected dependencies.
2. Reviewed glossary concepts with status, evidence and any recommended naming choice.
3. Applied changes with finding IDs and locations; intentional unchanged aliases.
4. Unresolved semantic/design conflicts and concrete decisions or implementation work
   needed to resolve them. Preserve the pending architecture interview question.
5. Checks actually run and their results/limits; separate static inspection from tests.
6. Exact next action if work remains; on resume, reconcile current files with the report.

Completion requires every inventoried current spec and relevant source-comment area
to be accounted for, every glossary concept to have a review outcome, and each finding
to be fixed, justified as intentional or explicitly unresolved. Do not claim complete
language uniformity while material semantic conflicts or unreviewed editorial surfaces remain.

Report the result in German: what was aligned, which decisions remain, what was
checked and where the report is saved. Creating the report or finding consistent
vocabulary does not establish implementation correctness, cryptographic safety or
completion of the architecture interview.
