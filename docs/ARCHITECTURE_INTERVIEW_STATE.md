# Architecture Interview — Compact State

Updated: 2026-10-19 (Europe/Berlin). Checkpoint: **CP-0072**.
Mode: DEC-074 preserves bounded drain across repeated stop signals; deadline-enforcement owner pending (§7.83).
Workflow: [start/resume prompt](../prompts/architecture_interview.md); always present A/B proposals (WF-004).
Details: [notes](ARCHITECTURE_INTERVIEW_NOTES.md); [legacy handoff](ARCHITECTURE_INTERVIEW_HANDOFF.md).
Register: [74 decisions with status/provenance](ARCHITECTURE_INTERVIEW_NOTES.md#21-current-decision-register-and-provenance),
[alternatives](ARCHITECTURE_INTERVIEW_NOTES.md#22-alternatives-refinements-and-superseded-proposals),
[open items](ARCHITECTURE_INTERVIEW_NOTES.md#23-open-design-and-decision-inventory) and
[record/spec gaps](ARCHITECTURE_INTERVIEW_NOTES.md#24-record-gaps-and-pending-specification-consolidation).

## Resume cursor
- Active focus: **O4.2**, pending **Q-O4-DEADLINE-OWNER-01**, exact A/B **§7.83**.
- A = node deadline plus longer outer supervisor limit (recommended); B = supervisor-only limit, explicit standalone-run responsibility. Await answer.
- **Q-O4-SECOND-SIGNAL-01 answered A / DEC-074**: repeated SIGTERM/SIGINT neither shorten nor reset/extend original drain; OS SIGKILL remains force-stop.
- **Q-C3-ALTERNATE-PAYMENT-01 answered A / DEC-073**: strictly client-only no automatic substitute; partial multi-voucher purchase/tender choice stays outside node.
- **Q-C2-POS-RECEIPT-DURABILITY-01 corrected A / DEC-072**: durable L1 voucher/purchase before release; no completed-checkout certificate archive/back-fill.
- **Q-C3-WALLET-SEND-DURABILITY-01 answered A / DEC-071**: durable original wallet intent/pending-output before first dispatch; WAL/SQLite examples only.
- **DEC-070**: node own approvals/context until root TTL+30s; no shorter timer. DEC-072 does not require merchants to archive/retrieve completed-checkout bundles.
- **DEC-069**: bounded original-approval recovery for still-uncertain checkout; no new votes. Completed-checkout archive duty removed by DEC-072; current read proof remains open.
- **Q-C3-UNCERTAIN-FOLLOWUP-01 answered A / DEC-068**: bounded automatic growing-backoff reads; example5 attempts not frozen; no guaranteed resolution.
- **Q-C2-CONFLICT-VETO-01 answered A / DEC-067**: valid14/20 completes despite weaker authenticated collisions; no minority veto.
- **Q-S5-MIXED-SUPPORT-01 answered A / DEC-064**: FINAL/Regional14 > PROVISIONAL > partials; min-hash within highest confirmed class; no sanction for honest losers.
- **Q-O1-CRASH-RESUME-01 answered A / DEC-063**: DEC-032 unrestricted. Finite bucket quarantine proposed; proof against later fresh conflicting spends remains O1.1.
- **Q-S3-FRESH-COMMIT-01 withdrawn**: neither A nor B. **DEC-062** selects RAM attestation before async flush, ingress-only freshness and fixed nominal seal; no renewed choice on that policy.
- **Q-S3-LATE-BUCKET-01 withdrawn**, neither A/B: DEC-059/061 fixed closed windows+bounded open tail, direct sync/projection, no added correction/version system; public wallet T_0 differs from encrypted_timestamp.
- **DEC-057/058**: restart/loss P2P gate with quorum-backed verified digest-pull; no recoverable state means blocked scope; source-coverage proof open.
- **Q-S2.1-PRESENCE-01** answered: **DEC-056**, three consecutive missed hourly gossip heartbeats; exact timing/enforcement pending. Old A/B superseded.
- **Q-S2.1-TRUST-01** intent answered (**7.47**), policy unselected. **Q-S2.2-01** unanswered/withdrawn (**7.37**, wording **7.36**); DEC-053 removes old-group permission.
- Parked **Q-S3.3-01**, unchanged/unanswered, exact A/B in **7.16** (one vs two payment rounds).
- Broad trust research stays stopped; [separate prompt](../prompts/trust_network_blind_spot_research.md) requires explicit invocation. Operator belief is not a fault bound.
- **DEC-060 / §7.66**: exact-payload/T_0 conditional three-send refines DEC-027; §7.33 historical. QUIC/correlated loss,800ms/cancellation,quotas/background bounds require composition.
- Read first: DEC-053/054 **7.57–7.58**, [P0 draft0.2](PARTITION_RESILIENT_REGISTRY_P0.md), [results](P0_SIMULATION_RESULTS.md), [work plan v0.4](CEH_SECURITY_CLOSURE_WORK_PLAN.md).
  Next: ask §7.83 deadline-owner A/B; derive daemon/supervisor contract and O4/F1 checks, then current-read evidence/C4. Status possession is not14/20 proof. O1.1 recovery proof remains mandatory before readiness claims.

## Constraints and settled requirements to retain
- German conversation; English repository documents. Apply `AGENTS.md` and glossary.
- Blind Collision Lock Registry; client custody; no staking/deposits or hearsay bans.
- Preserve frozen<=20/14 votes/800ms; **DEC-062** reservation-first RAM acceptance, <5ms attestation, bounded async flush;
  no disk wait or post-gate freshness recheck. DEC-029/033/034 response ordering superseded; P0/model consolidation pending.
- N>=20 retains14/20 regional receipts with possible revision (DEC-053); DEC-054 admission/merchant guardrails; no justified global-proof scheme.
- Up to six Byzantine identities is a per-view conditional target, not a global-view bound.
- Safe full turnover/automatic progress after stabilization selected; no old-quorum permission. Restart requires justified P2P repair (DEC-057); source completeness open.
- Keep immutable own choices, async persistence, same-key loss gate, bounded drain/expiry, private operator boundary and shared protocol library.
- DEC-053 does not imply expanded checkout pools, a reservation subsystem, extra payment round or unsupported one-node takeover.
- Current selections/limits: notes **2** (DEC-001–074), including superseded timing policy. Legacy handoff supplies context.
- DEC-006 follows DEC-038; DEC-039 reopened; DEC-028 deferred; DEC-043 hourly tentative. P0 timing/support rules remain candidates.

## Branch tree
Decision and delivery differ: `decided` names a selected policy; `partial` has selected and unresolved choices.
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
│   │   └── C1.1 [decided] Inline compact signed evidence in409; DEC-066; exact envelope/verification pending
│   ├── C2 [decided] Frozen 14/20 / 800 ms / all-member dispatch; safety proof: S1–S3
│   │   ├── C2.1 [decided] No weaker collision veto vs valid14/20; DEC-067; collector/wire verification pending
│   │   └── C2.2 [decided] Durable L1 voucher/purchase before release; no post-completion certificate duty; DEC-072
│   ├── C3 [decided] Exact-payload conditional three-send / DEC-060; resource/freshness composition pending
│   │   ├── C3.1 [decided] Bounded automatic read follow-up / backoff; DEC-068; parameters/read proof pending
│   │   ├── C3.2 [decided] Wallet durable intent/pending-output before first send; DEC-071; client crash tests pending
│   │   └── C3.3 [decided] Client-only no auto substitute; partial-purchase/tender outside node; DEC-073
│   └── C4 [partial] Recipient chooses sources; safe read acceptance unresolved; S2/S3/S5
│       ├── C4.1 [decided] Bounded recovery for unresolved checkout; DEC-069/072; no completed-certificate archive duty
│       └── C4.2 [partial] Retrieval skeleton derived; context/storage/wire integration pending; §7.77–7.78
│           └── C4.2a [decided] Own original approvals/context until root TTL+30s; DEC-070; layout/purge verification pending
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
│   ├── S5 [partial] Revocable regional receipts; support/merge/fraud proof and wire delivery pending
│   │   ├── S5.1 [decided] Strict class priority then min-hash; DEC-064; integration/proof pending
│   │   └── S5.2 [decided] Minimal live evidence/own choices, no losing-tree archive; DEC-065; exact proof set pending
│   └── S6 [decided] Ticket lifecycle / fresh identity / first-party fraud; wire/domain audit pending
├── N — P2P and resources
│   ├── N1 [decided] F2F barrier / learned shard peers / idle-first eviction; enforcement audit pending
│   ├── N2 [decided] Protect shard/sync budgets / refuse full active capacity; sizing/fairness pending
│   ├── N3 [partial] Restart FLAG_NOT_READY gate chosen; source/partial-set proof unresolved; S3/O2
│   └── N4 [decided] PoW / quota / bounded parsing defenses required; coverage/wire audit pending
├── O — Durability and operation
│   ├── O1 [decided] RAM-first attestation + async immutable choices; DEC-062; durability proof reopened
│   │   └── O1.1 [unresolved] DEC-032 retained; finite quarantine proof vs fresh later spend open; §7.71
│   ├── O2 [partial] Automatic safe resume / loss gate chosen; rollback recovery unresolved
│   ├── O3 [decided] Root TTL+grace / bounded expiry; safe choice retention/time details pending
│   ├── O4 [decided] Bounded graceful shutdown; drain/measured deadline pending
│   │   ├── O4.1 [decided] Repeated ordinary signals preserve original deadline/drain; DEC-074; lifecycle tests pending
│   │   └── O4.2 [active] Internal node deadline+supervisor margin vs supervisor-only; Q-O4-DEADLINE-OWNER-01
│   ├── O5 [decided] systemd-first / private local admin / operator veto; enforcement audit pending
│   └── O6 [decided] Bounded metric history / direct diagnostics; aggregation details pending
└── F1 [partial] 22 numbered families mapped (§7.78); exact invariant/interface/scenario coverage and final plan pending
```

## Evidence and coverage gaps
- Notes **2** indexes selections, alternatives and OPEN-01–15/GAP-01–06; early legacy-only records lack original Q/A/rationale. **7.3** records core/node inspection.
- F1 initial map:22 numbered families/24 files,113 distinct mentioned invariant IDs; definitions/interfaces/scenarios/test evidence still unmapped (§7.78).
- **7.44** witnesses concern old global finality; DEC-053 regional proof pending. Concurrent created_at_ms/hash/bucket edits require fresh audit; do not repeat field-absent claim (§7.68).
- DEC-055/056 require passive-profile integration; P0 probe tests do not verify three-miss enforcement.
- DEC-057 audit: no-peer ready paths/manual QUIC readiness flags; source coverage unproven. DEC-069 audit: stored-original vote retrieval not established (§7.77).
- Latest durable checkpoint: notes **9**, **CP-0072**. O1.1 return trigger: concrete recovery model / any proposed activation / final plan.
