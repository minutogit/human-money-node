# Architecture Interview — Compact State

Updated: 2026-10-17 (Europe/Berlin). Checkpoint: **CP-0043**.
Mode: cross-interview risk assessment complete (§7.54); broad trust research remains stopped.
Goal: justified decisions and a buildable plan under explicit assumptions, preserving KISS.
Workflow: [start/resume prompt](../prompts/architecture_interview.md).
Rhythm: finish one bounded problem; justified A, useful alternatives only, explicit uncertainty.
Details: [notes](ARCHITECTURE_INTERVIEW_NOTES.md); [legacy handoff](ARCHITECTURE_INTERVIEW_HANDOFF.md).
The notes hold decision evidence; this file indexes it. Editorial audit: [report](TERMINOLOGY_ALIGNMENT_REPORT.md).
Register: [52 decisions with status/provenance](ARCHITECTURE_INTERVIEW_NOTES.md#21-current-decision-register-and-provenance),
[alternatives](ARCHITECTURE_INTERVIEW_NOTES.md#22-alternatives-refinements-and-superseded-proposals),
[open items](ARCHITECTURE_INTERVIEW_NOTES.md#23-open-design-and-decision-inventory) and
[record/spec gaps](ARCHITECTURE_INTERVIEW_NOTES.md#24-record-gaps-and-pending-specification-consolidation).

## Resume cursor

- Saved focus: **S2.1**, recursive operator trust; investigation stopped, **7.47**.
- K3 names/editorial screening complete: **DEC-049–052**, report **§8**.
  No more glossary questions; maintain vocabulary autonomously and refine as needed.
- **Q-S2.1-TRUST-01** answered at intent level (**7.47**); no executable policy selected.
- **Q-S2.2-01** unanswered, withdrawn as next question (**7.37**);
  exact proposal preserved in **7.36**. Its "previous group" prerequisite is unresolved.
  Do not repeat the conditional transition sketch as if it establishes its own authority.
- Parked **Q-S3.3-01**, unchanged/unanswered, exact A/B in **7.16** (one vs two payment rounds).
- Investigation ended at maintainer request. Future execution prompt prepared (**7.48**):
  [trust-network blind-spot research](../prompts/trust_network_blind_spot_research.md); invoke explicitly.
  Operator belief is not a proved fault bound; no architecture/protocol change selected.
- Interjection **7.33**: QUIC already retries stream data; no blind triple-RPC policy selected.
  DEC-027/009/042 retained; application retry/duplicate accounting stays OPEN-07/08.
- Read first: risk assessment **7.54**, CEH v1.4 review **7.53**, [current plan](CERTIFIED_EPOCH_HANDOFF_PLAN.md).
  CEH v1.5 adds a 30-day late-receipt cutoff: unapproved continuity tradeoff, not a cache-only change.
  Membership/handoff is central; fault/key/rollback/client/availability gates remain. No adoption.
- Return: S2.2 / **7.35**, then S3.3 / **7.34**, S4 recovery, C4/S5, K2/C1 and N/O.

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
- Current selections/limits: notes **2** (DEC-001–052). Legacy handoff supplies context.
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
│   └── K3 [decided] Vocabulary/alignment complete; autonomous maintenance; protocol gaps tracked
├── C — Checkout and client evidence
│   ├── C1 [decided] Valid-prefix causal-path batches; remaining: output/wire details; K2
│   ├── C2 [decided] Frozen 14/20 / 800 ms / all-member dispatch; safety proof: S1–S3
│   ├── C3 [decided] Direct idempotent submission / exact-intent retry; bounds/fields pending
│   └── C4 [partial] Recipient chooses sources; safe read acceptance unresolved; S2/S3/S5
├── S — Consensus and membership
│   ├── S1 [partial] Coordinated attacker / six-Byzantine target; bound/time model unresolved
│   ├── S2 [unresolved] Justified participants despite subjective HRW views
│   │   ├── S2.1 [active] Audit intended human trust vs counted membership; §7.46 / §7.44
│   │   └── S2.2 [unresolved] Local-view robustness; Q-S2.2-01 withdrawn as next question
│   ├── S3 [partial] Pause / full turnover chosen; safe handoff unresolved; S2/O1/N3
│   │   ├── S3.1 [finding] Raw-majority copy insufficient; not a replacement algorithm
│   │   ├── S3.2 [finding] Copy alone insufficient; safe old-write cutoff unresolved
│   │   └── S3.3 [unresolved] Conditional handoff model run; Q-S3.3-01 parked; §7.40 / §7.34
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
- Notes **7.44** / robustness report: incompatible local first-FINAL, tested recognized alternative;
  trust/key/resource limits and exact production gaps; contracts **7.29–7.34** retained.
- Glossary naming/alignment complete (DEC-049–052); report §8 retains protocol conflicts.
- Current specs/source comments were clarified; runtime behavior/interfaces are unchanged.
- Original handoff: 1,536 runs; composition: 128 seeds / 3,072 checks; real QUIC costs measured.
  Workspace: 504 pass / 11 ignored; strict clippy pass; candidate remains research, no production edit.
- Latest durable checkpoint: notes **9**, **CP-0043**; restart checks remain in **CP-0001**.
