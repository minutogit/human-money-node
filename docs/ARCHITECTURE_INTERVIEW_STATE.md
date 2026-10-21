# Architecture Interview — Compact State

Updated: 2026-10-21 (Europe/Berlin). Latest interview checkpoint: **CP-0095**; subsequent read-only audit and implementation handoff add no decision ID.
Mode: implementation incomplete; full-plan audit reconciled against newer code. Use the [complete implementation handoff](ARCHITECTURE_IMPLEMENTATION_HANDOFF_PLAN.md) for current findings, dependencies and acceptance; G1–G5 remain unclosed.
Workflow: [start/resume prompt](../prompts/architecture_interview.md); important choices: two options+recommendation; short derived batches require sign-off (WF-006).
Agent workflow: maintainer confirmation before every further agent assignment, including reassignment. Use the [handoff protocol](ARCHITECTURE_IMPLEMENTATION_HANDOFF_PLAN.md#9-human-questions-and-agent-start-protocol); the older six-assignment estimate is historical, not a fixed current queue.
Details: [notes](ARCHITECTURE_INTERVIEW_NOTES.md); [legacy handoff](ARCHITECTURE_INTERVIEW_HANDOFF.md).
Register: [89 decisions with status/provenance](ARCHITECTURE_INTERVIEW_NOTES.md#21-current-decision-register-and-provenance),
[alternatives](ARCHITECTURE_INTERVIEW_NOTES.md#22-alternatives-refinements-and-superseded-proposals),
[open items](ARCHITECTURE_INTERVIEW_NOTES.md#23-open-design-and-decision-inventory) and
[record/spec gaps](ARCHITECTURE_INTERVIEW_NOTES.md#24-record-gaps-and-pending-specification-consolidation).

## Resume cursor
- Active cursor: **implementation in progress**, user authorized production/test changes, subagents and final commit. See [execution record](ARCHITECTURE_IMPLEMENTATION_PROGRESS.md). Maintainer confirmed network-size-only FINAL hysteresis and mandatory readiness per signing shard after an initial automatic approval-review rejection. No pending approval question. No new decision ID.
- **DEC-083** withdraws Q-C4-ACTIVE-PROOF-CONTINUITY-01, neither A/B: no old-quorum archive; old signers leaving alone cannot make synchronized state unconfirmed.
- **DEC-085 / §7.99**: Q-S3-RECOVERY-TRIGGER-01 answered A; on-demand recovery, no proactive assignment sweep or payment queue.14 timely valid votes still required; NOT_READY consumes existing six-member headroom.
- **DEC-084 / §7.97**: DB2 five-item summary / DB2-01–08 accepted in full. C4.3b requirements selected; authority/coverage/crash proof and implementation remain pending.
- **DEC-086 / §7.100**: DB3-01–05 accepted in full. Block2 requirements selected; source/activation proof and tests pending. User requests block3; no claim of measured zero latency impact.
- **DEC-088 / §7.104**: DB4-01–05 accepted; block4 requirements selected, measurements/implementation pending. User requests block5; bounded batching does not guarantee physical commit latency.
- **DEC-069/070/083**: retain own signing-safety records through rootTTL+30s; bounded exceptional original-approval retrieval is not required when current live quorum answers. No inherited bundle/client archive duty or new spend votes.
- **DEC-087 / §7.102**: restore atomic durable lock+own-choice commit before binding signature release/self vote. Q-O1-ROOT-RISK-MARKER-01 withdrawn, neither A/B; no markers, ordinary-crash quarantine or identity abandonment. Actual storage loss/rollback remains separate.
- **DEC-062 partially superseded by DEC-087**: early signature release/no commit wait removed; entry-only wallet freshness, reservation-first RAM processing and nominal fixed seal retained. Old Q-S3-FRESH-COMMIT-01 stays withdrawn.
- **Q-S3-LATE-BUCKET-01 withdrawn**, neither A/B: DEC-059/061 fixed closed windows+bounded open tail, direct sync/projection, no added correction/version system; public wallet T_0 differs from encrypted_timestamp.
- **DEC-057/058**: restart/loss P2P gate with quorum-backed verified digest-pull; no recoverable state means blocked scope; source-coverage proof open.
- **Q-S2.1-PRESENCE-01** answered: **DEC-056**, three consecutive missed hourly gossip heartbeats; exact timing/enforcement pending. Old A/B superseded.
- **Q-S2.1-TRUST-01** intent answered (**7.47**), policy unselected. **Q-S2.2-01** unanswered/withdrawn (**7.37**, wording **7.36**); DEC-053 removes old-group permission.
- Parked **Q-S3.3-01**, unchanged/unanswered, exact A/B in **7.16** (one vs two payment rounds).
- Broad trust research stays stopped; [separate prompt](../prompts/trust_network_blind_spot_research.md) requires explicit invocation. Operator belief is not a fault bound.
- **DEC-060 / §7.66**: exact-payload/T_0 conditional three-send refines DEC-027; §7.33 historical. QUIC/correlated loss,800ms/cancellation,quotas/background bounds require composition.
- Read first: DEC-053/054 **7.57–7.58**, [P0 draft0.2](PARTITION_RESILIENT_REGISTRY_P0.md), [results](P0_SIMULATION_RESULTS.md), [work plan v0.4](CEH_SECURITY_CLOSURE_WORK_PLAN.md).
  Next on implementation request: follow plan W0/W1 and C1–C5 milestones; A14 tests accompany each fix, A10 privacy independently. Full activation needs G1–G5; no settled questions, new payment round or archive prerequisite.

## Constraints and settled requirements to retain
- German conversation; English repository documents. Apply `AGENTS.md` and glossary.
- Blind Collision Lock Registry; client custody; no staking/deposits or hearsay bans.
- Preserve frozen<=20/14 votes/800ms; **DEC-087** reserve-first RAM processing, bounded worker, atomic durable lock+own-choice commit then signature release;
  await exact acknowledgment without RAM guards. No blocking handler I/O or renewed wallet-freshness gate;1–5ms storage unmeasured. No historical quorum archive.
- N>=20 retains14/20 regional receipts with possible revision (DEC-053); DEC-054 admission/merchant guardrails; no justified global-proof scheme.
- Up to six Byzantine identities is a per-view conditional target, not a global-view bound.
- Safe full turnover/automatic progress after stabilization selected; no old-quorum permission. Restart requires justified P2P repair (DEC-057); source completeness open.
- Keep immutable own choices, async persistence, same-key loss gate, bounded drain/expiry, private operator boundary and shared protocol library.
- DEC-053 does not imply expanded checkout pools, a reservation subsystem, extra payment round or unsupported one-node takeover.
- Current selections/limits: notes **2** (DEC-001–089), including restored durability ordering. Legacy handoff supplies context.
- DEC-006 follows DEC-038; DEC-039 reopened; DEC-028 deferred; DEC-043 hourly tentative. P0 timing/support rules remain candidates.

## Branch tree
Decision and delivery differ: `decided` names a selected policy; `partial` has selected and unresolved choices.
`unresolved` marks an unselected mechanism; `finding` marks an established counterexample.
`active` is the current focus; pending human questions, if any, are in the cursor. No label claims implementation/test completion.
```text
HuMoCo architecture/security interview [in progress; prior decisions retained]
├── K — Scope and integration
│   ├── K1 [decided] Blind service / custody / KISS; documentary scope reconciled; proof/delivery gaps retained
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
│       ├── C4.1 [decided] Bounded unresolved recovery DEC-069/083; current live quorum need not retrieve old approvals
│       ├── C4.2 [partial] Retrieval skeleton derived; context/storage/wire integration pending; §7.77–7.78
│       │   └── C4.2a [decided] Own original approvals/context until root TTL+30s; DEC-070; layout/purge verification pending
│       └── C4.3/3a/3b/3c [decided] Current live proof/no archive DEC-080/081/083/084; DB2 accepted; authority/readiness proof+delivery pending
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
│   │       └── S3.4a [partial; G2 proof retained] Quorum verified digest-pull selected; source coverage unproved; DEC-058/§7.107
│   │           ├── S3.4a.1 [decided] Snapshot+bounded deltas / DEC-059; exact buffer/cursor contract pending
│   │           ├── S3.4a.2 [decided] Direct sync/projection; no extra corrections/versions; DEC-061
│   │           ├── S3.4a.3 [partial] Wallet T_0 selected; concurrent code alignment unverified; §7.68
│   │           ├── S3.4a.4 [decided] Entry-only freshness/fixed seal DEC-062 retained; durable release DEC-087; timing proof pending
│   │           └── S3.4a.5/5a [decided] Demand trigger+bounded recovery DEC-085/086; DB3 accepted; source/activation proof+delivery pending
│   ├── S4 [decided] Automatic local progress after stabilization; activation/recovery design pending
│   ├── S5 [partial] Revocable regional receipts; support/merge/fraud proof and wire delivery pending
│   │   ├── S5.1 [decided] Strict class priority then min-hash; DEC-064; integration/proof pending
│   │   └── S5.2 [decided] Minimal live evidence/own choices, no losing-tree archive; DEC-065; exact proof set pending
│   └── S6 [decided] Ticket lifecycle / fresh identity / first-party fraud; wire/domain audit pending
├── N — P2P and resources
│   ├── N1 [decided] F2F barrier / learned shard peers / idle-first eviction; enforcement audit pending
│   ├── N2/N2.1 [decided] Protect shard/sync budgets+DB4 DEC-088; bounded batching/wait/coalescing; sizing/implementation/wire proof pending
│   ├── N3 [partial] Restart FLAG_NOT_READY gate chosen; source/partial-set proof unresolved; S3/O2
│   └── N4 [decided] PoW / quota / bounded parsing defenses required; coverage/wire audit pending
├── O — Durability and operation
│   ├── O1 [decided] Atomic durable lock+own choice before release DEC-087; worker/ack integration+verification pending
│   │   └── O1.1/1.1.1 [decided] Ordinary process-crash window closed by ordering; no root markers/quarantine; actual crash/wire proof pending
│   ├── O2 [partial] Automatic safe resume / loss gate chosen; rollback recovery unresolved
│   ├── O3 [decided] Root TTL+grace / bounded expiry; safe choice retention/time details pending
│   ├── O4 [decided] Bounded graceful shutdown; drain/measured deadline pending
│   │   ├── O4.1 [decided] Repeated ordinary signals preserve original deadline/drain; DEC-074; lifecycle tests pending
│   │   ├── O4.2 [decided] Internal deadline+longer supervisor fallback; DEC-075; process teardown/measurement pending
│   │   └── O4.3 [decided] Default CLI waits for clean stop/process exit/DB release; DEC-076; result/lifecycle tests pending
│   ├── O5 [decided] systemd-first / private local admin / operator veto; enforcement audit pending
│   │   └── O5.1/2/2a [decided] Private metrics/public discovery/client-only cache fallback DEC-077–079; delivery pending
│   └── O6 [decided] Bounded metric history / direct diagnostics; aggregation details pending
└── F1 [partial] Documentary reconciliation complete §7.107; final justified buildable design depends on G1–G5
    └── F1.1 [complete] DEC-089 consolidation+registry; F1.2/3 [complete]89-decision audit+15-package detailed source-linked plan §7.108–7.109
```

## Evidence and coverage gaps
- Notes **2** indexes selections, alternatives and OPEN-01–15/GAP-01–07; early legacy-only records lack original Q/A/rationale. **7.3** records historical core/node inspection.
- F1 §7.107: [result](ARCHITECTURE_CONSOLIDATION.md), [registry](INVARIANT_REGISTRY.md):115 owned definitions/topics+2 undefined retired references. G1 authority/G2 coverage+activation/G3 merge/G4 clocks+reentry/G5 actual loss remain; counts are not proof.
- **7.44** witnesses concern old global finality; DEC-053 regional proof pending. Concurrent created_at_ms/hash/bucket edits require fresh audit; do not repeat field-absent claim (§7.68).
- DEC-055/056 require passive-profile integration; P0 probe tests do not verify three-miss enforcement.
- §7.108 audit at node51347f6 + proto7d3dea7 + dirty HMCb9bbdf7: productive verifier, pending-ack/own-choice, READY/transfer, class/presence, privacy/stop gaps. Host wallet/PoS unverified; no runtime tests executed.
- Latest checkpoint: **CP-0095 / §7.110**; 89 decisions. Production changes in node/proto/core; targeted evidence and full-suite failures recorded separately. Final integration/commit pending; unrelated user edits preserved.
