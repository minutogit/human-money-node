# Architecture Interview — Compact State

Updated: 2026-10-15 (Europe/Berlin). Checkpoint: **CP-0011**.
Mode: maintainer-directed glossary detour; architecture implementation/final plan pending.
Goal: justified decisions and a buildable plan under explicit assumptions, preserving KISS.
Workflow: [start/resume prompt](../prompts/architecture_interview.md).
Rhythm: finish one bounded problem; justified A, useful alternatives only, explicit uncertainty.
Details: [notes](ARCHITECTURE_INTERVIEW_NOTES.md); [legacy handoff](ARCHITECTURE_INTERVIEW_HANDOFF.md).
The notes hold decision evidence; this file indexes it. Binding specs are not changed here.
Register: [48 decisions with status/provenance](ARCHITECTURE_INTERVIEW_NOTES.md#21-current-decision-register-and-provenance),
[alternatives](ARCHITECTURE_INTERVIEW_NOTES.md#22-alternatives-refinements-and-superseded-proposals),
[open items](ARCHITECTURE_INTERVIEW_NOTES.md#23-open-design-and-decision-inventory) and
[record/spec gaps](ARCHITECTURE_INTERVIEW_NOTES.md#24-record-gaps-and-pending-specification-consolidation).

## Resume cursor

- Active leaf: **K3**, dictionary review/alignment; details **7.22 / GLOSSARY-002**.
- Next action: execute [alignment plan](../prompts/terminology_alignment_plan.md)
  when requested, or continue glossary review; proposed names remain unselected.
  Repository-wide alignment follows review; it has not been performed.
- Parked question Q-S3.3-01: A retain one-round 14-vote payment confirmation and carry
  justified binding obligations through handoff (recommendation), or B investigate
  separate preparation/completion payment rounds with explicit safe cutoff rules.
- Answer: **not selected**. Glossary detour does not select payment semantics.
- Read first: notes **7.21–7.22**, alignment plan, glossary **3–5**; return to **7.17 / S3.3**
  after the detour. S2 remains unresolved; S4 progress/round recovery follows handoff work.
- After S3.3: investigate closure/inclusion and successor installation, then S4 recovery;
  keep S2 membership justification explicit. Return to C4/S5, K2/C1 and N/O by dependencies.

## Constraints and settled requirements to retain

- German conversation; English repository documents. Apply `AGENTS.md` and glossary.
- Blind Collision Lock Registry; client custody; no staking/deposits or hearsay bans.
- Preserve 14/20, frozen at-most-20 distinct identities and 800 ms collection budget.
  The interview selects durable signing-before-response and removes a rigid local
  5 ms target; this is a pending consolidation conflict with existing project rules,
  not authorization to silently rewrite specs or production behavior.
- N >= 20 FINAL policy and one organically growing network are reaffirmed. Do not
  re-ask threshold/anchor choices; subjective-view/membership safety remains open.
- Up to six Byzantine identities is a conditional design target, not an enforced bound.
- Repeated safe full committee turnover and automatic progress after communication
  stabilizes are selected requirements; no handoff algorithm/history scheme is approved.
- Keep immutable durable own-choice storage, same-key loss/rollback safety gate,
  bounded drain/expiry, private operator boundary and small shared protocol library.
- Do not infer approval of ranks 21–23 as voters, FINAL revocation, a separate reservation
  subsystem, a certificate-return round or unconditional lower-hash FINAL takeover.
- Current selections/limits: notes **2** (DEC-001–048). Legacy handoff supplies context.
- DEC-006 follows selected library DEC-038; DEC-039's fixed-context mechanism was reopened.
  DEC-028 remains deferred; DEC-043's hourly parameter is tentative. No new protocol choice.

## Branch tree

Decision outcome and remaining work are separate. `decided` means the named policy is
selected/inherited; `partial` means some choices are selected and others unresolved.
`unresolved` marks an unselected mechanism; `finding` marks an established counterexample.
`active` is the pending question. None of these labels claims implementation/test completion.
Keep stable IDs; design/proof gaps remain until resolved or explicitly scoped.

```text
HuMoCo architecture/security interview [in progress; prior decisions retained]
├── K — Scope and integration
│   ├── K1 [decided] Blind service / custody / KISS; remaining: scope consolidation
│   ├── K2 [decided] Shared protocol library; remaining: exact formats / integration
│   └── K3 [active] Dictionary draft and alignment plan saved; review/audit pending
├── C — Checkout and client evidence
│   ├── C1 [decided] Valid-prefix causal-path batches; remaining: output/wire details; K2
│   ├── C2 [decided] Frozen 14/20 / 800 ms / all-member dispatch; safety proof: S1–S3
│   ├── C3 [decided] Direct idempotent submission / exact-intent retry; bounds/fields pending
│   └── C4 [partial] Recipient chooses sources; safe read acceptance unresolved; S2/S3/S5
├── S — Consensus and membership
│   ├── S1 [partial] Coordinated attacker / six-Byzantine target; bound/time model unresolved
│   ├── S2 [unresolved] Justified participants despite subjective HRW views
│   │   ├── S2.1 [unresolved] Initial participant justification; needs S1
│   │   └── S2.2 [unresolved] Compatible membership/certificates over time
│   ├── S3 [partial] Pause / full turnover chosen; safe handoff unresolved; S2/O1/N3
│   │   ├── S3.1 [finding] Raw-majority copy insufficient; not a replacement algorithm
│   │   ├── S3.2 [finding] Copy alone insufficient; safe old-write cutoff unresolved
│   │   └── S3.3 [partial; parked] One-round/carrying vs two-round choice; Q-S3.3-01
│   ├── S4 [decided] Automatic safe progress after stabilization; round/recovery design pending
│   ├── S5 [partial] Support gate / unresolved-slot policy chosen; FINAL/merge rules unresolved
│   └── S6 [decided] Ticket lifecycle / fresh identity / first-party fraud; wire/domain audit pending
├── N — P2P and resources
│   ├── N1 [decided] F2F barrier / learned shard peers / idle-first eviction; enforcement audit pending
│   ├── N2 [decided] Protect shard/sync budgets / refuse full active capacity; sizing/fairness pending
│   ├── N3 [partial] Recovery signing gate chosen; partial-set recovery proof unresolved; S3/O2
│   └── N4 [decided] PoW / quota / bounded parsing defenses required; coverage/wire audit pending
├── O — Durability and operation
│   ├── O1 [decided] Durable vote / immutable redb choice table; exact semantics/ack paths pending
│   ├── O2 [partial] Automatic safe resume / loss gate chosen; rollback recovery unresolved
│   ├── O3 [decided] Root TTL+grace / bounded expiry; safe choice retention/time details pending
│   ├── O4 [decided] Bounded graceful shutdown; drain/signals/measured deadline pending
│   ├── O5 [decided] systemd-first / private local admin / operator veto; enforcement audit pending
│   └── O6 [decided] Bounded metric history / direct diagnostics; aggregation details pending
└── F1 [pending] Coverage / contradictions / final plan; needs resolved/scoped design
```

Branch detail: legacy handoff **Root branches and current design state** and
**Active subtree: resume S2–S4**; these sections also preserve withdrawn policy questions.
S3.1/S3.2 retain established counterexamples; their replacement design remains to establish.

## Evidence and coverage gaps

- Notes **2** indexes selections, alternatives and OPEN-01–15/GAP-01–06;
  early legacy-only records lack original Q/A/rationale. **7.3** records core/node inspection.
- Legacy handoff indexes seven abstract counterexamples; these are not real-wire tests.
- Full spec/invariant/interface-to-branch coverage is still missing; F1 must establish it.
- Latest-context verification, temporal corruption, partial conflicts and safe cleanup
  remain obligations; an algorithm name or completed download cannot close them.
- Glossary additions are a review draft; existing mappings and protocol decisions remain.
- No production code/specs, Rust/QUIC tests, commits or PRs changed in this detour.
- Latest durable checkpoint: notes **9**, **CP-0011**; restart checks remain in **CP-0001**.
