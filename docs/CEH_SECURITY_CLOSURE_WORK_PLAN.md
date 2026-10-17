# Registry security and operational closure work plan

Date: 2026-10-17 (Europe/Berlin). Version: 0.4.
Status: P0 active under DEC-053; subsequent implementation packages pending.
Revision history: v0.1 planned CEH closure; v0.2 reopened its necessity;
v0.3 applies the maintainer's partition-resilience decision; v0.4 records the
approved P0 guardrails and formal draft0.2 / twelve fully specified scenarios.

## 1. Current direction

The maintainer selected regional availability, current-mesh committee formation
without predecessor-quorum permission, and deterministic conflict reconciliation.
Q-K1-FINALITY-01 is answered B; do not repeat that choice. The normative P0 draft is
[PARTITION_RESILIENT_REGISTRY_P0.md](PARTITION_RESILIENT_REGISTRY_P0.md).
The strict [CEH proposal](CERTIFIED_EPOCH_HANDOFF_PLAN.md) is a historical/alternative
candidate, not the required activation architecture.

A qualified regional receipt can later lose against a valid competing branch.
Keep that consequence visible in protocol/client semantics. No global irreversible
uniqueness or 99.999% availability is promised. Preserve blind service, client
custody, root expiry plus 30 s, durable own choices, first-party-only sanctions,
F2F discovery and shard-direct lock/sync transport.

Maintain fixed<=20 identities per collection, fourteen votes for the N>=20 mode,
adaptive N<20 PROVISIONAL quorums and the 800 ms collection budget. A regional view
may be reconstituted between attempts without old 14 signatures. Running attempts
never expand or combine different voter pools. Ticket/stability and local readiness
conditions remain explicit; the new authority rule is not arbitrary roster acceptance.
Original Q-S3.3-01 keeps its original meanings and remains parked; assess its
applicability to the selected architecture without silently selecting a payment round.

## 2. Active P0 and what has already been done

P0 draft0.2 now specifies candidate admission/view/receipt predicates, independent
catalog context, conservative maturity, bounded reachability profile, local mode
transitions, durable choices, support ordering and complete-bundle merge. Separate
approval/observation domains protect honest losers. All twelve scenarios have
Given/When/Then, unsafe mutants and required evidence; execution remains pending.
DEC-054 records the maintainer's admission, anti-framing and merchant guardrails.

`GlobalProofSchemes={}` in the regional-only baseline: green FINAL(Global) remains
reserved until a separately justified global proof scheme exists. Regional14 stays
blue even after quiet gossip/reconnect. Ticket costs/incubation/F2F do not establish
a per-view fault bound. Amounts, exposure budgets and uncertain-payment purchase
reconciliation stay in the terminal/wallet, outside blind L2.

Completed earlier analysis remains the CP-0046 balanced-partition quorum arithmetic,
343 finite union/min cases and sibling/descendant example. These do not verify the
expanded contract. Current resolver signer-dependent hash entropy, L1 earliest-time
imports and presence/storage/verifier differences require versioned integration.

Next: encode and execute P0-T01..T12 and their negative controls using existing
research fixtures, with authentic crypto and node-local information. Regional
conflicting receipts in R-01/R-02 are allowed outcomes followed by correct merge;
global irreversible receipt production is not the new oracle. Exercise exact
historical context, clock/lease expiry, view skew, mixed support and honest merge
continuation. Then compose P1–P3 interfaces and receiver-side QUIC/crash defenses.
P0 documentation elaboration is delivered; design verification and production
qualification remain open. The reference profile is not production tuning.

## 3. Remaining package order

| Package | Deliverable under DEC-053 | Dependency / exit gate |
| --- | --- | --- |
| P0 — Regional authority and merge | Formal draft0.2, eligibility/trust basis and execution of the12 specified scenarios | Active; no predecessor-quorum dependency; no arbitrary attacker roster; honest merge and explicit risk semantics |
| P1 — Portable proof and retained evidence | Owner/causal proof, regional view/receipt context, backup/ownership transfer, expiry and pruning | P0; authentic old receipts remain verifiable within live root lifetime without a mandatory global CEH chain; no automatic preference over a smaller admissible rival |
| P2 — Signing-key lifecycle | Identity/view key binding, copy/backup/retirement threat model and required protection | P0/P1; zeroize alone does not prove forward security or erase all copies; no hidden historical-key assumption |
| P3 — Durable state and recovery | Atomic own-choice/effect commit, durable reply acknowledgment, safe restart and separate canonical state | P0/P2; crash/restore cannot silently authorize conflicting own approval; unresolved own-history loss remains behind a signing gate |
| P4 — Composed adversarial model | Membership changes, partitions, delayed evidence, split trees, modes and recovery together | P0–P3 contracts; no forged acceptance; deterministic eventual convergence under stated evidence/delivery premises; no false fraud bans |
| P5 — Shared verifier and receiver integration | Canonical protocol library, complete client checks, actual QUIC/storage enforcement | P4; malicious wire/crash tests for every defense in crates/humoco-node/tests/; all consumers use the same acceptance semantics |
| P6 — Availability and payment workflow | Measured regional throughput/repair, bounded retry comparison, wallet/merchant reconciliation | P5 for deployment claims;20/20,80/20,90/10 and correlated failures; no silent second payment after uncertain first outcome |
| P7 — Full coverage and readiness verdict | OPEN/GAP/spec/invariant map and scoped supported operating envelope | P0–P6; retained assumptions, receiver risk and unavailable cases disclosed; pilot/rollout are separate decisions |

P1/P2/P3 contract work may proceed in parallel after P0 interfaces stabilize;
one integrating owner prevents incompatible proof/key/storage definitions.
Use independent reviewers for admission, merge/fraud and the composed model.
Reuse the existing handoff/HRW/transfer fixtures where useful; do not preserve a
predecessor-consensus dependency merely because it exists in an old module.

## 4. Required evidence and non-negotiable boundaries

- Never treat a receipt as a guarantee that no competing region accepted a spend.
  Display and version status semantics accordingly; N<20 is still PROVISIONAL.
- Validate actual owner authorization, parent/output/child-list/root binding,
  signer uniqueness and recipient-trusted membership context before counting votes.
- A normal LOCK_APPROVAL remains immutable across views. Canonical status changes
  use explicit different semantics and cannot be replayed to frame or pay twice.
- Before emitting a binding vote, obtain successful durable commit acknowledgment.
  Keep queue reservation, bounded async batch persistence and no RAM lock across I/O.
- Crash, stale backup and cloned signer are different recovery cases. A new identity
  neither recovers the lost signer nor erases its old obligations.
- Do not turn local timeouts into global bans. Ordinary regional view changes are
  not fraud sanctions. Keep the existing two F2F gossip streams.
- Exact retry delays, more-than95% packet-loss recovery, sub-millisecond voucher
  fallback and automatic one-shard isolation are not established facts.
- A lost first response may hide a completed payment. Voucher switching needs
  wallet/merchant purchase-level reconciliation outside the blind registry.
- Client history, active exclusions, proof-generation state, caches and metadata
  have separate storage budgets. Never discard a live obligation for a cache target.
- Process-kill tests do not emulate all power-loss/storage-rollback behavior.
  Prove/measure the selected scope and expose undetectable-copy assumptions.
- All new network defenses require real receiver-side QUIC integration tests;
  model success alone does not establish production protection.

## 5. Outcome tracking

For each package retain its contract revision, source hashes, owner, tests/commands,
actual results, open predicates and next action. Preserve the decision register and
original question wording. Only a consequential new product tradeoff warrants a
maintainer question; execute technical analysis autonomously.

Complete the coverage audit before declaring a final master plan. Reconcile old
unconditional-FINAL, FINAL/VOID, min-hash and CEH activation wording deliberately,
rather than let different implementations expose contradictory promises.

Current work is documentation, independent review and bounded arithmetic only.
Existing source changes from other workspace activity are not attributed to this
plan, audited here, or reverted. No deployment, commit or production edit is included.

## 6. References

- [Interview notes](ARCHITECTURE_INTERVIEW_NOTES.md), especially §7.55–7.58,
  DEC-053/054 and CP-0047; [compact state](ARCHITECTURE_INTERVIEW_STATE.md).
- [P0 contract and evidence](PARTITION_RESILIENT_REGISTRY_P0.md).
- [Earlier robustness report](DECENTRALIZED_ROBUSTNESS_RESEARCH.md) and
  [handoff research](MEMBERSHIP_HANDOFF_RESEARCH.md): their negative results concern
  the former irreversible-global-acceptance target; they remain valid in that scope.
- [redb v2.6.3](https://github.com/cberner/redb/blob/v2.6.3/src/transactions.rs):
  successful Immediate commit is the checked persistence boundary, not enqueue.
- [zeroize1.9.0](https://docs.rs/zeroize/1.9.0/zeroize/):
  memory hygiene with explicit limits, not proof that every copy disappeared.
- [RFC9000 §13.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-13.3):
  reliable stream retransmission is already a transport function.
