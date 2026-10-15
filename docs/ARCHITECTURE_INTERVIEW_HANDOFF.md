# Architecture Interview — Continuation Handoff

> Navigation update (2026-10-15): use [ARCHITECTURE_INTERVIEW_STATE.md](ARCHITECTURE_INTERVIEW_STATE.md)
> as the compact live cursor and [the start/resume prompt](../prompts/architecture_interview.md)
> for the ongoing workflow. This handoff is preserved as migration context; its
> former instructions to maintain a second map are superseded by that workflow.
> Historical continuation statements below must be checked against the live cursor
> and detailed notes. No pending protocol choice was answered by this update.

Updated: 2026-10-15 (Europe/Berlin). Current at the maintainer's explicit request to move the discussion into a new chat.

Status: architecture interview and targeted research. This is not a binding protocol specification, finished security proof or final implementation plan.

## Read first and resume

1. Read `AGENTS.md`, including the German user / English code-and-documentation policy.
2. Read [ARCHITECTURE_INTERVIEW_STATE.md](ARCHITECTURE_INTERVIEW_STATE.md) for the live cursor.
3. Consult [ARCHITECTURE_INTERVIEW_NOTES.md](ARCHITECTURE_INTERVIEW_NOTES.md), section 2, for current DEC-001–048 status, provenance, alternatives and open items. Follow its evidence pointers into the historical sections; do not treat old pending proposals or this legacy summary as newer decisions.

Workspace: `/home/basti/Coding/humoco/human-money-node`.
Sibling domain core: `/home/basti/Coding/humoco/human-money-core` (read-only inspection so far).
The maintainer owns both projects and permits coordinated breaking changes.

**Exact continuation point:** investigate the smallest safe committee/state handoff that preserves subjective local views and progresses automatically after communication stabilizes with the relevant honest quorum available. This automatic-progress requirement was the last selected option A. Approximately hourly candidate checks are a tentative starting parameter; they neither force a transition nor confer signing authority.

**Current pending decision (notes 7.14 / S3.3):** the maintainer requests continued
A-recommendation/B-alternative decisions to complete the interview. Resume the
unanswered section 7.5 tradeoff: A retain one-round 14-vote payment confirmation
and preserve justified safety-relevant binding choices through handoff (recommended),
or B investigate separate preparation/completion payment rounds with safe cutoff rules.
No answer yet. This does not close membership justification or authorize implementation.

Latest clarification request (notes 7.15): the maintainer asks why missing returned
aggregate certificates matter when locks already exist at their signers and can be
reconciled. Explain that they need not matter if those existing binding lock records
are retained/transferred. The concern was hypothetical filtering/incomplete copy,
not an asserted disappearance or a requirement for another reservation subsystem.
Then explain the final old-write cutoff/delta condition. No A/B answer is inferred.

**Latest maintainer clarification (notes 7.13):** FINAL from the established N >= 20
regime is already selected; retain 14/20 and existing stability requirements. Normal
adoption grows one global network through existing users, and clients choose globally
connected providers. Spontaneously separate twenty-node networks are considered
unlikely in this operating model, without a measured probability. Do not repeat the
permanent-network/anchor or FINAL-versus-revocation A/B questions. No anchor/history
mechanism or FINAL revocation was approved; investigate handoff inside one growing
network, with unresolved membership assumptions explicitly retained.

The latest assistant recommendation is to first assess established round-based BFT agreement, such as the Tendermint/CometBFT pattern, only for per-shard handoff decisions. Preliminary votes, finalizing phases, proposer rotation and evidence-based round changes can address competing partial proposals. Payment lock choices remain separate and immutable. This is a research direction, not a selected library, approved protocol or implementation request.

**Critical scope condition still unresolved:** ordinary round-based agreement needs a justified authenticated participant set for each instance. Arbitrary local HRW top twenties do not automatically satisfy its assumptions. Do not present this as solved, impose a globally identical ranking, or silently assume that the maintainer accepted an explicit committee-history mechanism. Initial membership/authority and safe inclusion/closure of prior lock obligations are the next foundations to establish. Compare dynamic Byzantine lattice agreement if useful; both families require verifiable quorum assumptions and neither is ordinary replica synchronization.

## Assignment and interaction

- Continue as lead architect/security reviewer; do not restart the interview.
- Always explain to the user in German; write repository documentation/code in English.
- Ask one substantive decision question at a time. When a choice is needed, A is the reasoned recommendation, B a viable alternative where useful. Explain concrete consequences simply.
- Use engineering judgment for technical investigation. Do not repeatedly ask the user to choose algorithm names or reapprove settled requirements.
- Apply KISS: additional machinery must demonstrate a concrete benefit. Preserve useful existing work.
- Do not implement protocol changes, run a large implementation/test campaign, commit, deploy or open a PR merely because the interview continues.
- Produce the final prioritized implementation/consolidation plan only after material obligations are resolved or explicitly scoped by agreement.

Discussion order: KISS boundaries; checkout/core; consensus/attacks; P2P/scaling; operations/resilience. Operations directions have been discussed, but the interview returned to unresolved consensus/membership dependencies. Several earlier topics still require proofs, actual integration inspection or measurements.

## Mandatory decision-tree workflow

The maintainer explicitly clarified the assignment after requesting this handoff:
this is a systematic, branching architecture/security interview intended to make the
project defensible under an explicit threat model, not a sequence of unrelated A/B
preferences. Continue the decision tree, preserve prior decisions, expose missing
assumptions and follow unresolved dependencies to their conclusions. "Watertight" is
the engineering objective, not a claim of unconditional security or an exhaustive audit.

Use the following procedure throughout the continuation:

1. Identify the active branch and its prerequisites using the IDs below. Start at
   S2–S4, not at the beginning of the interview.
2. State the concrete property or failure scenario. Inspect existing code/specification
   and relevant primary sources before adding machinery. Apply the KISS filter.
3. If a maintainer preference or changed requirement is needed, ask one clear question
   with recommended A and a viable B where useful. Technical investigation does not
   require repeated preference questions. Explicitly mark rejected alternatives.
4. Record the answer, rationale, assumptions, dependencies, known counterexamples and
   verification obligations in the detailed notes; update this map when its state changes.
5. Separate **requirement selected**, **design specified/justified**, **implemented** and
   **verified**. A letter answer selects a requirement/direction; it is not a proof or
   evidence that production code enforces it. Existing code is not automatically audited.
6. Close a design leaf only when its behavior/assumptions are unambiguous, relevant
   counterexamples and dependencies are addressed, and validation obligations are
   concrete; otherwise keep it open. An explicitly accepted scope limitation can close
   a policy question, but retain its consequence and do not describe the excluded risk
   as solved. Reopen a settled leaf only for new evidence, contradiction or user steering.
7. At branch changes, briefly identify what was settled and what remains next. Before
   the final plan, audit coverage across all root branches, actual specs/invariants and
   core/node interfaces. Do not infer completeness from the five topic headings alone.

No complete specification/invariant-to-branch coverage inventory has yet been made.
Creating/checking that inventory is part of the remaining work. Newly found gaps get
explicit leaves; never silently omit them to finish the interview. Later implementation
and test completion are separate gates from interview/design completion.

### Root branches and current design state

This is the current working map, not a claim that all possible leaves are known.
"Selected; open details" means policy is agreed but the design branch is not closed.
Delivery/verification of the newly selected changes remains pending throughout.

| Branch | Property / decision area | Current state |
| --- | --- | --- |
| K1 | Blind service, client custody, scope, KISS boundaries | Main directions selected; check consolidated scope against code/specs |
| K2 | Shared core/node types, canonical encodings and crypto boundary | Shared-library direction selected; exact signed formats and full integration open |
| C1 | Origin, output/parent binding, ancestry/splits and batch acceptance | Valid-prefix causal-path policy selected; domain/wire enforcement audit open |
| C2 | Checkout committee, 14/20, 800 ms, dispatch and cancellation | Target policy selected; depends on S1–S3 for membership safety |
| C3 | Timeout, idempotency, retries and payment completion feedback | Main policy selected; exact bounds/fields and consumer behavior open |
| C4 | Read/status evidence and safe recipient acceptance | Open; preserve hidden-query/multiple-witness proposal |
| S1 | Adversary, Sybil/ticket assumptions, temporal corruption, fault bounds | Six-Byzantine target selected; derivation/enforcement/time scope open |
| S2 | Initial/continuing participant justification with subjective views | Active foundational open branch |
| S3 | Closed state transfer, old/late votes and safe successor activation | Active open branch; bare sync/majority counterexamples established |
| S4 | Competing transitions, round recovery and eventual progress | Automatic progress selected; actual mechanism/proof open |
| S5 | Islands, merges, PROVISIONAL/FINAL/VOID and conflict reconciliation | Support gate/unresolved-slot policy selected; full consistency open |
| S6 | Ticket replacement, identity lifecycle, verified fraud and local observations | Main policies selected; full wire/domain evidence verification open |
| N1 | F2F discovery barrier, shard-direct authorization and session lifecycle | Invariants given; complete implementation/wire audit pending |
| N2 | Gateway/shard/sync budgets, pool/stream limits and fairness | Role priorities/refusal policy selected; sizing/measurements open |
| N3 | Recovery across partial replica sets, missed delivery and readiness | Open; whole-shard digest counterexample established; feeds S3/O2 |
| N4 | Ingress/P2P abuse limits, PoW/quota integrity and bounded parsing | Repository defenses exist; complete coverage/adversarial-wire audit pending |
| O1 | Durable vote acknowledgement, atomic own-choice storage and queue integrity | Main durability/layout policy selected; exact semantics/enforcement open |
| O2 | Restart, disk loss, stale backup, rollback detection and safe same-key resume | Safety gate selected; recovery evidence/mechanism open |
| O3 | Trusted time, root expiry, signing-state retention and bounded pruning | Main expiry policy selected; safe timing/retention details open |
| O4 | Graceful shutdown/drain, signals and deployment limits | Main policy selected; joining/durability/deadline validation open |
| O5 | Private admin/dashboard, control socket, deployment and operator veto | Main boundary/deployment policies selected; enforcement audit open |
| O6 | Bounded operational telemetry and direct reliability observations | Main diagnostic policies selected; exact bounded implementation open |
| F1 | Cross-branch coverage, contradictions, prioritized final plan and validation matrix | Pending; do not finalize while substantive obligations are silently open |

### Active subtree: resume S2–S4

- S2.1: What initially justifies the participant set, and what must a joining node or
  gateway verify? Open; neither arbitrary self-declaration nor an unknown global map
  is an acceptable assumed answer.
- S2.1a: The maintainer clarifies one organically connected global network as the
  normal model; startup/deliberate islands are exceptions (notes section 7.12).
  The prior common-anchor/independent-domain A/B was not selected. Do not force a
  permanent-network product choice or infer approval of a bootstrap/history scheme.
  Transient incompatible views within one intended network remain an open safety issue.
- S5.1a: Withdraw the repeated A/B as the next policy question (notes 7.13).
  The maintainer reaffirms N >= 20 FINAL under the intended one-global-network
  operating model. No FINAL revocation was selected. Technical consistency with
  partition/merge rules remains to establish without re-asking the threshold policy.
- S2.2: How can differing local HRW views remain safe across certificates/time? Open.
  Extra querying through rank twenty-three is not approved extra voting authority.
- S3.1: Is a current raw-majority copy sufficient? Refuted by the eight-A/twelve-B
  example despite an older fourteen-A certificate.
- S3.2: Is an otherwise complete one-time copy sufficient? Refuted by old writes
  racing newcomer activation. Specify a safe cutoff and inherited obligations.
- S3.3: How are prior individual votes/client-held late certificates included, and how
  do successors verify/install the resulting state? Active pending A/B (notes 7.14):
  one-round payments with carried justified obligations versus redesigned two-round
  completion. Neither selected. Reservations are not FINAL; bare Byzantine conflicting
  votes must not automatically invalidate a proven FINAL.
- S4.1: Are immutable one-successor endorsements alone sufficient for progress?
  Refuted by the thirteen-X/seven-Y stall.
- S4.2: Must progress resume automatically after communication stabilizes with an
  available honest quorum? Selected A: yes, with stated conditions.
- S4.3: Can a narrowly scoped established round protocol satisfy S2/S3/S4 together?
  Investigation direction, not selected/proved algorithm. Compare dynamic lattice
  agreement if needed, retaining its assumptions and costs.

After this subtree, return to C4/S5, K2/C1 integration and remaining N/O obligations;
choose the next leaf by dependencies and security consequence, not merely document order.
An approved algorithm name cannot close S2/S3, and a closed policy leaf does not close
the implementation or verification gate.

## Progress and work performed

Roughly 60–70% of the interview's topic areas have been discussed as a coarse coverage estimate. This is not a percentage of fully proved decisions, implemented changes or production readiness. The hardest remaining safety dependencies are substantial, so remaining effort cannot be inferred from that percentage.

Completed in this interview: requirement decisions, targeted read-only node/core inspection, primary-source research and small abstract JavaScript set/event counterexamples. Changes are limited to this file and the detailed interview notes. No production code changes, Rust/unit/QUIC test runs, commits or PRs occurred. Existing repository code predates this interview and its readiness claims are not audit evidence.

Both interview documents are untracked working files in this checkout. Preserve them. The detailed notes retain the historical reasoning and withdrawn proposals; this handoff intentionally consolidates the former chronological handoff.

## Settled directions — do not re-ask

### Scope, clients and checkout

- Blind Collision Lock Registry; client custody of causality proofs; no account/amount/currency logic, monetary staking or deposits. Any compatible application may use ingress.
- Preserve useful diagnostic/dashboard work outside the consensus core. Aggregate metrics: minute resolution for 24 hours and hourly for one year; no expired-lock retention or tombstones.
- A small shared Rust protocol/types/canonical-encoding/basic-crypto library for core and node is selected, without wallet/application dependencies. Exact packaging remains engineering work; remove obsolete paths after checking actual uses.
- Keep the 14/20 checkout target and at most twenty distinct full NodePubKeys per frozen attempt; self may count where eligible. No lower-rank vote replacement was originally selected. The later ranks-21–23 suggestion reopens discussion but does not approve expanding eligibility.
- The 800 ms limit is per gateway signature-collection attempt. Fast quorum/impossibility exits; quorum cancellation is neutral. End-to-end latency needs measurement; no deadline guarantees Internet completion.
- Every admitted checkout attempts all remote committee members concurrently, once per member at application level. No extra checkout-specific offline suppression/probes. Shared transport backoff still needs review. Future suppression must justify its measured benefit.
- Direct idempotent payment submission; no free-slot preflight. Timeout is unknown, not rollback or permission for a replacement spend. Preserve the exact signed intent for bounded retries. Do not release goods as finally paid without verified completion evidence.
- Bounded causal-path reconciliation batches for one target, including relevant split/output proofs. Accept the valid prefix, stop at the first invalid/conflicting step and retain prior progress.
- Free/Friends/VIP have identical proof requirements; priority and provider reputation are not cryptographic evidence.
- Allow a coordinated malicious payer, gateway and controlled nodes. Recipient-selected sources help but do not establish source independence or justified membership.

### Identity, evidence and membership requirements

- NodePubKey is identity; one active and one pending shard ticket per key. Replacement pending work must exceed both active and pending work and restart 24-hour incubation. New identity requires fresh friendship and maturity; IP continuity confers neither.
- Network-size observations from multiple recipient-selected sources may be cached. Strong disagreement remains unresolved; do not average it into false certainty.
- Ban only on verified first-party cryptographic fraud. Local reliability observations are useful diagnostics; distinguish valid answers, NOT_READY and deadline misses. Exclude unsent and quorum-cancelled work. No hearsay gossip, guilt propagation or automatic reputation-based exclusion.
- NOT_READY supplies no vote, like a timeout for quorum attainment, without proving deceit. No new checkout suppression follows from diagnostics.
- Safety target: tolerate up to six Byzantine identities in the relevant twenty-member model. This is conditional; WoT/Argon2 do not prove that bound. Temporal corruption scope remains open.
- Valid vouchers must survive repeated safe handoffs until no original signer remains, including growth from thirty to thousands of nodes. Root-lifetime pinning is rejected: vouchers can last up to ten years; seven permanent departures would leave only thirteen voters.
- Planned affected-shard write pauses are allowed, aiming for a few seconds in normal conditions with useful PoS feedback. Other shards continue. No short-pause guarantee under partitions.
- Client retains/retries its exact intent during handoff; no additional newcomer request queue.
- Batch routine changes. Tentatively check candidates about hourly, only attempting a transition if relevant changes exist. Do not shorten incubation, activate from a timer or turn local timeouts into membership exclusions. Verified fraud handling is not delayed to a maintenance window.
- Latest A: handoffs must make safe automatic progress after communication stabilizes and a suitable honest quorum remains available, including competing proposals. Permanent 13-for-X/7-for-Y stalls are not an acceptable final design. This does not promise recovery after abrupt permanent old-quorum loss.
- A singleton conflicting lower-hash lock cannot displace confirmed state. Require justified authenticated support; one transport source can carry many signatures. If evidence remains insufficient, leave the affected slot/descendants unresolved; unrelated branches continue. Do not restore unconditional min(H_canon) takeover.

### Resources, persistence and operation

- Protect inbound shard work from locally originated gateway load. Checkout and bounded, non-starving background sync have separate resource budgets. Exact capacities/fairness need measurement.
- Reclaim idle shard-direct connections first; do not abort active RPCs solely for eviction. Refuse new work promptly at full active capacity without an extra queue. Idle close and capacity refusal are neutral. F2F persistent connections remain separate from shard-direct sessions.
- Gate affected signing after state loss/new shard assignment until safe recovery is justified. A completed download or matching digest alone is insufficient.
- Persist the exact binding signing choice before releasing a vote. Use an immutable table in existing redb and atomic lock/choice durable commits through bounded asynchronous batching, with actual commit acknowledgement. No rigid local five-millisecond requirement; retain the separate 800 ms collection budget.
- Persistent commit failure disables dependent signing, retaining diagnosis/admin and NOT_READY. Reads must not promote undurable RAM state. Resume automatically only after durable storage and relevant signing/state safety recover; respect operator veto.
- Lost/rolled-back earlier choices can be absent from peer-confirmed state. Withhold affected same-identity votes until safety is established; ordinary sync and a fresh identity do not automatically solve this.
- Bounded graceful drain with honest reporting; bounded automatic expiry cleanup using verified root TTL plus 30-second grace. Safe choice-retention rules/time protection remain open; no permanent tombstones.
- Linux systemd-first deployment, retaining Docker/Compose. Dedicated private local operator endpoint with protected control-socket authority and SSH forwarding; retain useful admin functions.

## Established counterexamples and limits

See detailed notes for full sets/assumptions. These are logical counterexamples, not empirical attack rates or real-wire tests.

1. **Different top twenties:** two 14-vote quorums in identical twenty-member sets overlap in at least eight. If the committees share nineteen members, at least seven; if eighteen, at least six. At f=6, two membership differences can leave only Byzantine common signers. Per-step one-member replacement does not bound cumulative lifetime drift.
2. **Raw majority can reverse FINAL:** eight honest vote A, six honest vote B, six Byzantine vote both but later return B. A has fourteen signatures, yet querying all twenty returns eight A/twelve B. Current majority is not historical quorum acceptance.
3. **Complete copy does not close writes:** old C=M1..M6+H1..H14; new D=M1..M6+H3..H14+N1+N2. Newcomers copy unanimous empty state. Then old M1..M6+H1..H8 certify A; new M1..M6+H9..H14+N1+N2 certify B. Only the six bad double-sign. A safe cutoff is needed even if copy-time state was genuinely complete.
4. **Fourteen from twenty-three:** two fourteen-vote sets can share only five Byzantine identities, with nine disjoint honest voters each. Extra queries for evidence are different from counting extra signers. Fifteen-of-twenty-three only fixes a static intersection bound for one shared pool, not varying local lists/churn.
5. **Per-lock quorum is not whole-shard digest agreement:** eight replicas hold independent locks A+B, six only A, six only B. Both locks may have fourteen votes; no whole-state digest has fourteen matching copies. Recovery must handle partial sets rather than discard either valid independent lock.
6. **One-successor endorsements alone can stall:** thirteen endorse X, seven Y; neither gets fourteen. Timer-based forgetting is unsafe. Preliminary rounds and proof-based recovery need design.
7. **Own signing-history loss:** an earlier individual vote may never reach quorum or any recovering peer. Confirmed-state sync does not prove the old identity can safely sign a conflicting candidate.

## Critical open obligations and next work

1. **Minimal handoff and justified participants:** assess narrow round-based agreement without imposing a global ranking. Establish the initial accepted context/participant rule; explain how a newcomer/gateway verifies applicable membership. A valid stale history prefix does not prove the latest head. HRW eligibility, ticket maturity, candidate admission and the new-set fault assumptions remain open.
2. **Preserve past/future obligations:** specify old-write closure, late/client-held certificates, exact own/inherited choices, snapshot completeness, availability, successor installation and activation. No ordinary majority or arbitrary single digest establishes these. A reservation is not FINAL. Carrying all partial choices versus adding a payment completion round is still an unanswered earlier design choice; do not force it prematurely.
3. **Progress and time/key model:** safely recover competing/abandoned transitions; no commitment erasure after timeout. Distinguish immutable payment votes from permitted handoff-round votes. Define temporal corruption/retired-key assumptions, slow-client behavior, proof retention and recovery after old-quorum loss. Neither a BFT engine nor forward-secure signatures alone solves everything.
4. **Read/payment acceptance:** preserve the maintainer's proposal to query multiple recipient-selected nodes without revealing the expected full lock, avoiding historical per-lock certificate storage. Authentic owner data or possession does not prove quorum finality; a colluding owner can pre-share conflicting data and honest laggards can return unconfirmed branches. No probabilistic acceptance budget is selected. Reconcile FINAL irreversibility versus FINAL-to-VOID/merge claims.
5. **Core integration:** fully audit actual wallet/PoS consumers, canonical signature/slot/owner/output binding, ancestry/splits, root TTL, wire types, batch/retry semantics and certificate verification. Shared crypto/type code alone does not prove authority.
6. **Recovery, storage and P2P implementation detail:** durable acknowledgement through all signing paths, rollback/total-disk-loss detection, safe readiness across partial sets, bounded cleanup/drain, local admin boundary, QUIC lifecycle/admission/fairness and measured pool/stream/concurrency budgets.
7. **Consolidation and verification:** after the design is resolved/scoped, produce the prioritized final plan, then implement with shared vectors, adversarial real-QUIC tests and appropriate repository checks. No full plan or implementation yet.

## Targeted code findings — verify before changing

- `network/manager.rs::shard_committee` computes local known/mature/non-banned write membership and freezes it per checkout, without certified handoff context. It does not use the separate two-hour freshness/local-suspension filter of `active_hrw_nodes`; do not conflate these views.
- Spec 11 contains DORMANT/deletion timings and rank-21 promotion wording inconsistent with parts of the newer policy/code; consolidate later.
- `api/routes.rs` already spawns supplied committee candidates, but `transport::connect_peer` can sleep under shared reconnect backoff. NOT_READY is grouped with neutral NotInShard in collection; selected diagnostics need distinction.
- `storage/engine.rs` HMC ingress reserves/enqueues `PutHmcLock`, mutates RAM and returns without per-entry durable acknowledgement; transport then signs. Existing batching is 100 operations/50 ms, not a proven maximum loss window. Immutable own-choice storage/acknowledgement is unimplemented.
- `daemon.rs` readiness uses matching dominant digests/completed pulls; this does not establish restored own signing history. Periodic sync is sixty seconds with topology-triggered five-second debounce.
- `api/dto.rs` still has a signer bitmap alongside full signatures. The spec's four-byte gateway-to-shard callback was not found in inspected production paths; do not assert historical removal. Heartbeat observations are unrelated ingress evidence.
- Sibling `human-money-core/src/services/l2_gateway.rs` quorum plausibility uses short IDs/statistics without individual attestation verification on the inspected ConfirmFinal path. Core DTO lacks node's full NodePubKey; the application maps local/provisional/final outcomes to Confirmed. These are inspection findings, not an executed exploit/full audit.
- Current HMC reconciliation is locally all-or-nothing rather than selected valid-prefix behavior. PartitionSync can replace owner-valid state by lower hash without the selected support gate.
- Current dashboard/admin shares public HTTP routing with token checks; dedicated private boundary is unimplemented. Unix socket chmod errors are ignored. Graceful handler joining/durable drain is not proved. Deployment templates have thirty-second stop allowances, unvalidated.
- Shared inspected QUIC config has fifteen-second idle and five-second keep-alive; tier-specific behavior needs verification. The proposed 128–256 session pool is unmeasured. At N=5,000, uniform HRW gives about 262 owned shards/3,153 distinct co-shard peers per node, not that many simultaneously open connections.

## Primary references already researched

- [CometBFT consensus rounds](https://github.com/cometbft/cometbft/blob/main/spec/consensus/consensus.md), [signing rules](https://github.com/cometbft/cometbft/blob/main/spec/consensus/signing.md), and [durable signing state](https://github.com/cometbft/cometbft/blob/main/privval/file.go).
- [PBFT sections 4.3–4.4](https://pdos.csail.mit.edu/6.824/papers/castro-practicalbft.pdf): certified checkpoints and prepared evidence; fixed-member view change is not complete dynamic membership.
- [Sui Lutris sections 4.2–4.3](https://docs.sui.io/paper/sui-lutris.pdf): staged handoff and checkpoint closure, but different finality, consensus and stake assumptions. Do not import rollback/epoch lock resets into HuMoCo's current one-round payments.
- [Kuznetsov/Tonkikh DISC 2020](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.DISC.2020.27), especially sections 3.4–3.6/4.2 and Algorithm 1: comparable certified histories, dynamic Byzantine lattice agreement, protected transfer and installation. Not an ordinary sync algorithm; no globally identical current view, but explicit quorum assumptions remain.
- [Stellar section 4.1](https://stellar.org/papers/stellar-consensus-protocol.pdf): locally chosen trust still needs honest quorum intersection.
- [etcd learners](https://etcd.io/docs/v3.7/learning/design-learner/): useful non-voter preparation pattern, crash-only assumptions.
- [EIP-3076](https://eips.ethereum.org/EIPS/eip-3076), Teku and Lighthouse: signing protection/clone detection comparisons, not arbitrary-slot history restoration.
- SybilGuard, Douceur, BFT-SMaRt, Sui state verification and HTTP 503/Retry-After references are preserved with qualifications in the detailed notes.

Use primary sources for deeper research. Do not claim the cited protocols prove HuMoCo's unresolved assumptions or automatically authorize their machinery.
