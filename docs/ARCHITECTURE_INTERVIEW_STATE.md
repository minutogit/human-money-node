# Architecture Interview — Compact State

Updated: 2026-10-18 (Europe/Berlin). Checkpoint: **CP-0058**.
Mode: DEC-062 restores RAM-first attestation/entry-only freshness; prior durability ordering superseded (§7.69).
Workflow: [start/resume prompt](../prompts/architecture_interview.md); always present A/B proposals (WF-004).
Details: [notes](ARCHITECTURE_INTERVIEW_NOTES.md); [legacy handoff](ARCHITECTURE_INTERVIEW_HANDOFF.md).
Register: [62 decisions with status/provenance](ARCHITECTURE_INTERVIEW_NOTES.md#21-current-decision-register-and-provenance),
[alternatives](ARCHITECTURE_INTERVIEW_NOTES.md#22-alternatives-refinements-and-superseded-proposals),
[open items](ARCHITECTURE_INTERVIEW_NOTES.md#23-open-design-and-decision-inventory) and
[record/spec gaps](ARCHITECTURE_INTERVIEW_NOTES.md#24-record-gaps-and-pending-specification-consolidation).

## Resume cursor
- Active focus: **O1.1** issued-but-unflushed own choices versus safe same-key restart; **§7.69**.
- **Q-S3-FRESH-COMMIT-01 withdrawn**: neither A nor B. **DEC-062** selects RAM attestation before async flush, ingress-only freshness and fixed nominal seal; no question pending.
- **Q-S3-LATE-BUCKET-01 withdrawn**: neither A nor B; DEC-061 direct historical sync/projection retained.
- **DEC-059/061**: fixed closed-window state + bounded open tail; no extra correction/version subsystem. Wallet-bound public T_0 is distinct from encrypted_timestamp.
- **Q-S3-RECOVERY-BASIS-01** answered **A / DEC-058**: quorum-backed verified digest-pull; source-coverage proof remains open.
- **Q-S3-STATELOSS-01** answered **A / DEC-057**: restart/loss requires P2P digest-pull gate; no recoverable state means blocked affected scope.
- **Q-S2.1-PRESENCE-01** answered: **DEC-056**, three consecutive missed hourly gossip heartbeats; exact timing/enforcement pending. Old A/B superseded.
- **Q-S2.1-TRUST-01** answered at intent level (**7.47**); no executable policy selected.
- **Q-S2.2-01** unanswered, withdrawn as next question (**7.37**);
  exact proposal preserved in **7.36**; its old-group premise belongs to the former candidate.
  DEC-053 removes mandatory predecessor permission; do not repeat the old question.
- Parked **Q-S3.3-01**, unchanged/unanswered, exact A/B in **7.16** (one vs two payment rounds).
- Broad trust investigation stays stopped; passive-presence reconciliation is bounded interview work:
  [trust-network blind-spot research](../prompts/trust_network_blind_spot_research.md); invoke explicitly.
  Operator belief is not a fault bound; DEC-053 selects the direction, with implementation pending.
- **DEC-060 / §7.66** now selects exact-payload/T_0 conditional three-send retries, refining DEC-027.
  §7.33 remains historical; QUIC/correlated-loss limits, 800ms/cancellation, quotas and bounded background work still require composition.
- Read first: DEC-053/054 **7.57–7.58**, [P0 draft0.2](PARTITION_RESILIENT_REGISTRY_P0.md), [results](P0_SIMULATION_RESULTS.md), [work plan v0.4](CEH_SECURITY_CLOSURE_WORK_PLAN.md).
  Next: derive volatile-choice/restart evidence under unchanged DEC-032 gate; return to strict seal timing and source/full-root coverage.

## Constraints and settled requirements to retain
- German conversation; English repository documents. Apply `AGENTS.md` and glossary.
- Blind Collision Lock Registry; client custody; no staking/deposits or hearsay bans.
- Preserve 14/20, frozen at-most-20 distinct identities and 800ms collection.
  **DEC-062**: reservation-first RAM acceptance, <5ms attestation, bounded async flush;
  do not wait for disk commit or recheck freshness before response. DEC-029 and
  pre-response durability clauses of DEC-033/034 are superseded; P0/model consolidation pending.
- N >= 20 retains 14/20 regional receipts; DEC-053 permits later conflict revision.
  DEC-054 guards admission/merchant risk; global proof schemes empty, so baseline green is unavailable.
- Up to six Byzantine identities is a per-view conditional target, not a global-view bound.
- Repeated safe full committee turnover and automatic progress after communication
  stabilizes are selected; no old-quorum permission. Restart readiness requires justified P2P repair (DEC-057); source completeness remains open.
- Keep immutable own choices with async persistence and same-key loss/rollback safety gate,
  bounded drain/expiry, private operator boundary and small shared protocol library.
- Do not infer checkout pool expansion, a separate reservation subsystem, an extra
  payment round or unsupported one-node lower-hash takeover from DEC-053.
- Current selections/limits: notes **2** (DEC-001–062), including superseded timing policy. Legacy handoff supplies context.
- DEC-006 follows selected library DEC-038; DEC-039's fixed-context mechanism was reopened.
  DEC-028 remains deferred; DEC-043's hourly parameter is tentative. P0 timing/support rules are candidates.

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
│   │   └── K1.1 [decided] Regional availability/revocable acceptance; DEC-053/054; global proof reserved
│   ├── K2 [decided] Shared protocol library; remaining: exact formats / integration
│   └── K3 [decided] Vocabulary/alignment complete; autonomous maintenance; protocol gaps tracked
├── C — Checkout and client evidence
│   ├── C1 [decided] Valid-prefix causal-path batches; remaining: output/wire details; K2
│   ├── C2 [decided] Frozen 14/20 / 800 ms / all-member dispatch; safety proof: S1–S3
│   ├── C3 [decided] Exact-payload conditional three-send / DEC-060; resource/freshness composition pending
│   └── C4 [partial] Recipient chooses sources; safe read acceptance unresolved; S2/S3/S5
├── S — Consensus and membership
│   ├── S1 [partial] Coordinated attacker / six-Byzantine target; bound/time model unresolved
│   ├── S2 [unresolved] Justified participants despite subjective HRW views
│   │   ├── S2.1 [unresolved] Admission/trust prerequisite; broad trust research stopped (§7.47)
│   │   │   └── S2.1a [decided] Three consecutive missed heartbeats; DEC-056; timing/enforcement pending
│   │   └── S2.2 [decided] Regional contract; historical T01–T12 12/12 pass; passive-profile revalidation pending
│   ├── S3 [partial] Full turnover chosen; regional readiness / repair under DEC-053 pending
│   │   ├── S3.1 [finding] Raw-majority copy insufficient; not a replacement algorithm
│   │   ├── S3.2 [finding] Copy alone insufficient; safe old-write cutoff unresolved
│   │   ├── S3.3 [unresolved] Conditional handoff model run; Q-S3.3-01 parked; §7.40 / §7.34
│   │   └── S3.4 [decided] No empty-state recovery; mandatory P2P sync gate; DEC-057
│   │       └── S3.4a [partial] Quorum verified digest-pull selected; source coverage unproved; DEC-058
│   │           ├── S3.4a.1 [decided] Snapshot+bounded deltas / DEC-059; exact buffer/cursor contract pending
│   │           ├── S3.4a.2 [decided] Direct sync/projection; no extra corrections/versions; DEC-061
│   │           ├── S3.4a.3 [partial] Wallet T_0 selected; concurrent code alignment unverified; §7.68
│   │           └── S3.4a.4 [decided] Entry-only freshness / RAM-first / nominal fixed seal; DEC-062; timing proof pending
│   ├── S4 [decided] Automatic local progress after stabilization; activation/recovery design pending
│   ├── S5 [partial] Revocable regional receipts; support/merge/fraud contract drafted; tests pending
│   └── S6 [decided] Ticket lifecycle / fresh identity / first-party fraud; wire/domain audit pending
├── N — P2P and resources
│   ├── N1 [decided] F2F barrier / learned shard peers / idle-first eviction; enforcement audit pending
│   ├── N2 [decided] Protect shard/sync budgets / refuse full active capacity; sizing/fairness pending
│   ├── N3 [partial] Restart FLAG_NOT_READY gate chosen; source/partial-set proof unresolved; S3/O2
│   └── N4 [decided] PoW / quota / bounded parsing defenses required; coverage/wire audit pending
├── O — Durability and operation
│   ├── O1 [decided] RAM-first attestation + async immutable choices; DEC-062; durability proof reopened
│   │   └── O1.1 [active] Unflushed issued-choice loss / same-key recovery evidence; §7.69
│   ├── O2 [partial] Automatic safe resume / loss gate chosen; rollback recovery unresolved
│   ├── O3 [decided] Root TTL+grace / bounded expiry; safe choice retention/time details pending
│   ├── O4 [decided] Bounded graceful shutdown; drain/signals/measured deadline pending
│   ├── O5 [decided] systemd-first / private local admin / operator veto; enforcement audit pending
│   └── O6 [decided] Bounded metric history / direct diagnostics; aggregation details pending
└── F1 [pending] Coverage / contradictions / final plan; needs resolved/scoped design
```

Branch detail: legacy handoff **Root branches and current design state** / **Active subtree: resume S2–S4** retains withdrawn questions.

## Evidence and coverage gaps
- Notes **2** indexes selections, alternatives and OPEN-01–15/GAP-01–06;
  early legacy-only records lack original Q/A/rationale. **7.3** records core/node inspection.
- Full spec/invariant/interface-to-branch coverage is still missing; F1 must establish it.
- Prior **7.44** results concern irreversible global acceptance; DEC-053 changes that target.
  Keep their witnesses/limits as references; new regional admission/merge properties need verification.
- Current other-chat edits add created_at_ms/hash/bucket preference; legacy/zero/envelope fallbacks remain unverified (§7.68). Do not repeat field-absent claim.
- Historical runs/QUIC/check evidence retained in notes; no new executions or delivery claims in this continuation.
- DEC-055/056 require passive-profile integration; P0 probe tests do not verify three-miss enforcement.
- DEC-057 audit: daemon no-peer paths mark ready; current QUIC tests manually flip flag; source coverage unproven.
- Latest durable checkpoint: notes **9**, **CP-0058**; prior durable-vote model does not verify RAM-first crash safety.
