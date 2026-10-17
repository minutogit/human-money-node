# Membership, bootstrap and late-recipient recognition

Research continuation of CP-0031, 2026-10-16. This document proposes no accepted
policy or production change. Main result: the current local-activation policy has
no defensible universal first-FINAL recognition rule on arbitrary subjective F2F
views. A small workable recognition alternative requires an explicit externally
authenticated checkpoint and certified admission; its full-system dependencies
remain separately visible. No answer to Q-S3.3-01 is inferred.

## Independent source checks

Primary sources accessed on 2026-10-16:

- **CUP:** [Heydari, Vassantlal and Bessani, arXiv:2405.06055v2](https://arxiv.org/html/2405.06055v2),
  2 July 2024; §II-A, §II-C, Theorem 3/P3, Algorithm 2, Appendix IX-B.
  The latest arXiv history still lists v2. Its model fixes participants, makes
  identities Sybil-resistant, assumes static faults, reliable authenticated
  communication and partial synchrony. The required correct knowledge graph has a
  unique suitable sink; F2F alone supplies no such guarantee. P3 counts **source
  vertices** with exterior neighbors. In a complete twenty-node graph with six
  silent faulty nodes, received rows are fourteen correct vertices. Every possible
  S1 with at least thirteen received vertices has thirteen or fourteen sources
  pointing to silent vertices, exceeding six. Algorithm 2 therefore cannot finish.
  The printed proof's choice of correct sink members as S1 does not satisfy its
  P3 in this fixture. This reproduces the narrow liveness discrepancy; it does
  not refute all CUP results, nor justify silently replacing sources by targets.
  There are fifteen qualifying subsets (fourteen thirteen-element sets and the
  fourteen-element set). Both HTML statement and algorithm were read directly.
- **Practical dynamic storage:** [Kuznetsov and Tonkikh, DISC 2020](https://drops.dagstuhl.de/storage/00lipics/lipics-vol179-disc2020/LIPIcs.DISC.2020.27/LIPIcs.DISC.2020.27.pdf),
  §2 “I still work here”, §3.3 forward-secure signatures, §3.4 verifiable inputs,
  §3.5 reconfigurable objects, §4.2 confirmation/state transfer. Old configurations
  are neutralized through key evolution/erasure. Input configuration validity is
  a supplied predicate, not a discovered Sybil or first-recognition solution.
  Reconfiguration liveness assumes sufficiently stable periods; the formal model
  restricts verifiable updates. Its lattice semantics do not directly implement
  an irrevocable, exclusive collision decision. Useful components: certified
  input validation, key lifecycle, confirmation against slow-reader attacks and
  bounded update admission. Their full protocol is not implemented here.
- **Maintained light-client practice:** [CometBFT verification specification](https://github.com/cometbft/cometbft/blob/main/spec/light-client/verification/README.md),
  “Failure Model”, “Correctness”, initial-header assumption. Verification starts
  from a trusted header and retains temporal correctness assumptions throughout a
  trusting period. This is a clear practical recognition contract. Neither stake
  nor its validator selection is transplanted. HuMoCo has no demonstrated
  equivalent trusting period or source for its first trusted checkpoint.
- **Federated alternative:** [Stellar SCP paper](https://stellar.org/papers/stellar-consensus-protocol.pdf),
  §4.1 and §9 Theorem 13, plus [current validator configuration guide](https://developers.stellar.org/docs/validators/admin-guide/configuring).
  Safety needs correct-quorum intersection, including relevant configuration
  eras. Operators choose trusted organizations and quorum configuration.
  This realizes personal trust operationally, but does not make arbitrary local
  HRW top-twenty lists intersect. Adopting SCP would change accepted counting,
  admission and recipient trust semantics substantially. It is not a smaller
  replacement for the investigated recognized 14/20 configuration chain.

Source version distinction: the storage citation above is the conference paper;
a [2022 journal version](https://doi.org/10.1007/s00446-022-00421-1) exists. No claim
of implementing the journal algorithms or finding author-confirmed errata is made.

## Concrete necessity: one growing network, one malicious bridge

Start with one node B. Nineteen honest nodes L1..L19 grow organically through B's
F2F community; nineteen other honest nodes R1..R19 do likewise. B forwards valid
presence within each community and conceals the other side. All identities use
the same advertised network instance. They wait every required 24-hour maturity
and stability timer. The receiving servers only use learned identities; no open
connection or lock gossip is required for the attack.

Left local committee: `{B,L1..L19}`. Right local committee: `{B,R1..R19}`.
The owner authorizes conflicting locks A and Z for the same parent. A gets
`{B,L1..L13}`; Z gets `{B,R1..R13}`. Both have fourteen genuine signatures.
Only B signs both. Each relevant committee contains **one**, not seven, Byzantine
identities. Neither honest committee knows the other exists. An eventual honest
friendship path or released delayed presence reconnects this same organically
grown thirty-nine-node network; that cannot undo goods already released on FINAL.

Until decision, each side sees precisely the authenticated transcript of a
legitimate twenty-node execution in which it is the whole network. Any rule that
must eventually allow its first local FINAL in that execution also allows it here.
A larger wait can be exceeded before stabilization; silence contains no proof of
absence. This is an indistinguishability argument for these allowed graph and
availability conditions, not an impossibility theorem for CUP under its stronger
premises. A malicious bridge can also be replaced by discovery delays before GST
if the model permits such early decisions. The existing twenty-two-identity
copy-before-write witness independently demonstrates the later activation race.

A fresh receiver with no accepted external state cannot distinguish a genuine
self-signed twenty-member genesis from a counterfeit twenty-member genesis.
Every signature in either can be genuine. A label, timestamp, common genesis
formula or proof that the keys exist cannot privilege the intended group. Random
queries only help after assuming a non-eclipsed sampling population and an
adversarial identity/resource bound. No such mechanism is established here.

## Smallest explicit operational recognition alternative

This is a **proposal requiring product approval**, not an accepted common initial
roster premise and not a complete new consensus implementation. It preserves
blind records, no financial deposit, operator veto, twenty payment voters and
fourteen signatures. It changes who is eligible: local F2F discovery proposes
candidates, while a recognized, certified configuration determines counted votes.

### Cold bootstrap with actual bytes and authority

1. A new installation starts with no accepted FINAL authority. Ordinary discovery
   and N<20 PROVISIONAL behavior may run, but cannot manufacture authority merely
   by reaching twenty locally known keys.
2. Its operator/merchant obtains an onboarding manifest through an existing
   authenticated channel: in-person QR from its own established installation,
   authenticated administrator provisioning, or a signed application bundle whose
   publisher the operator explicitly trusts. That publisher/channel is a trust
   source, not decentralized evidence. An arbitrary QR or majority of anonymous
   gateways is insufficient. No new permanent founder signing role is required.
3. The manifest fixes exact canonical bytes: protocol version, network instance,
   checkpoint digest, per-shard configuration commitments, generation, twenty
   distinct NodePubKeys and the directly committed epoch signing public keys,
   inherited-state commitment, acceptance-policy identifier and a freshness bound.
   A whole-network manifest can commit the 65,536 shard roots in a Merkle root;
   a receiver requests only its shard and verifies the inclusion path.
4. The operator's configuration stores the approved digest atomically. Matching
   textual network names are insufficient. Counterparties claiming a different
   root need an authenticated reconciliation; they cannot silently merge FINAL.
   This is the explicit additional common-recognition mechanism. There is no
   theorem that arbitrary independently selected checkpoints refer to one network.
5. On a completely new real network, the initial bootstrap manifest must be
   authenticated by this same operational setup procedure. The operator chooses
   the exact accepted first group, with the <=6 faulty premise explicit. Absence
   of an established operator channel means no reliable first FINAL. This is a
   product cost, not an omitted automatic protocol step.

A reference configuration shape is `{instance, checkpoint_digest, shard_root,
policy_id, expires_at, max_links}`. Never download a replacement digest from the
same untrusted peers whose claimed authority it is meant to validate. Existing
installations can advance through valid certified history; new/cold installations
need an authentic starting manifest. Existing operator sovereignty does not
require automatic software or trust-anchor updates.

### Concurrent growth, old observers and complete turnover

Only an accepted predecessor may authorize its successor. A proposed successor
binds predecessor digest, shard, increasing generation, all member identities,
actual matured ticket claims/eligibility cutoff, successor epoch keys, inherited
state and policy version. New arrivals first become candidates through existing
permitted F2F presence. Learning or maturing them confers no vote in an old
configuration and no authority to self-form a separate successor. Canonical HRW
runs on the **certified candidate catalog/cutoff**, not on every receiver's live
cache. Authenticated omissions cannot be solved by pretending the catalog is
complete; a bounded admission protocol must define how known requests obtain
inclusion/progress. Withholding affects admission fairness/liveness; divergent
self-selected catalogs cannot be counted as concurrent authoritative committees.

Old nodes fence/drain, establish publicly valid inclusion evidence and BFT-decide
one successor; installed successors alone vote. The separate handoff model supplies
conditional tests of those steps. Admission certificates bind fourteen distinct
predecessor epoch keys to the exact successor. Competing discoveries share the
same predecessor decision slot. A stale observer can validate a descendant but
cannot re-open fenced predecessors. Every original participant may leave through
repeated certified turnover; none is an eternally privileged validator.

This adds a real membership control plane, potentially per shard, with durable
state, versioned catalog commitments, rate limits and inclusion policy. It is
not present in the daemon and not proved by signature verification alone.

### Temporal adversary and recovery

There are two defensible variants, both additional assumptions:

- **Lifetime-bound variant:** at most six of each configuration's signing secrets
  ever become adversarial while its certificates can affect accepted live roots.
  Retiring validators does not release that bound. This is simple but a demanding
  long-lived operational assumption.
- **Key-evolution variant:** predecessor authority commits independent ephemeral
  keys directly; old secret material is irrecoverably erased after its last
  required closure/agreement signatures, before the decisive retirement receipt
  counts. Persist fence, successor/readiness and key lifecycle in crash-safe order.
  A crash in the erasure/receipt interval sacrifices availability rather than
  re-opening an old epoch. At least eight honest retired keys become unavailable,
  leaving at most twelve possible new old signatures. Correct state transfer is
  still separately required. NodePubKey identity remains stable, but its permanent
  secret cannot re-delegate a replacement historical epoch key. Seeds derived from
  the permanent identity, recoverable encrypted backups and disk rollback defeat
  this mechanism. The proposal has no audited erasure implementation or FSS proof.

A per-current-time <=6 bound does not imply either variant. The real-signature
experiment deliberately recovers fourteen retired fixture epoch secrets: they
forge an alternate history which even the pinned old root accepts. Domain tags
and instance IDs do not detect genuine signatures created after compromise.

Fresh checkpoints bound the old history that a newly onboarded recipient accepts;
they do not repair false FINAL already accepted by an online recipient. A fresh
manifest cannot safely authorize arbitrary previously hidden old certificates.
It must commit inherited exclusion effects; claims predating the retained history
need a matching committed effect/proof or a separately justified historical chain.
Do not drop effects of live voucher roots merely because an epoch is old.

Freshness is an explicit external operating condition. A new receiver's
P2pClock derived only from eclipsing neighbors proves no age bound. An onboarding
manifest can carry an authenticated time interval; persisted monotonic elapsed
time advances that interval while running. Cold restart with lost trusted time
requires renewed provisioning. Wall-clock dates alone are not anti-replay proofs.
The prototype's `trusted_now` is an input representing this missing deployment
mechanism, not a claim that its local clock was independently proved.

Example engineering policy only: maximum 64 certified links between a retained
manifest and current configuration, plus an externally justified refresh horizon
(e.g. 24 hours). Reaching either limit causes an observable missing-proof refusal
and requests re-provisioning. These constants are not maintainer-selected SLAs or
proof that keys stay safe for 24 hours. A permanent trusted root without such
refresh needs unbounded retained lineage or an additional succinct-history proof
mechanism. No such mechanism is assumed silently.

## Executable evidence and deliberate limits

Artifact: [`robustness_admission.rs`](../../crates/humoco-sim-core/examples/robustness_admission.rs).
No new dependency; real `ed25519-dalek` strict verification, deterministic fixture
secrets, length-prefixed research-only BLAKE3 domains. Pure verification reads
only the anchor, supplied configurations and signatures; it never reads a harness
fault map or actual global membership. Initial root recognition explicitly checks
operator-pinned bytes. Tests include:

- Genuine fourteen-signature certificates in two thirty-nine-node local views,
  with exactly one shared signer; a pinned root rejects the alternate universe.
- Counterfeit first group with genuine public keys; the unanchored mutant accepts
  it, the anchored verifier refuses it.
- Four complete roster replacements, each certified by fourteen honest previous
  members without the six withholding participants; a late verifier checks links.
- Mutated state, cross-shard replay, repeated signers, thirteen signatures, omitted
  predecessor, expired anchor and proof length overflow all rejected.
- Permanent identity secrets cannot replace already committed epoch keys.
  Fourteen recovered old epoch secrets **can** produce an accepted forged branch;
  the unsafe outcome is required for this test to succeed.
- Two competing admissions sharing one predecessor: durable sign-once exclusions
  prevent two quorums with six Byzantine double-signers. All honest voters see one
  proposal first in this fixture; this is **not** BFT recovery or progress proof.
- All fifteen available S1 candidates in the complete-twenty/six-silent CUP fixture
  fail the literal source-boundary P3.

The standalone signature predicates do not prove admission fairness, actual erasure,
ticket maturity, network discovery, clock trust,
Byzantine concentration, the first honest roster's identity composition, or BFT
round recovery. A fourteen-key certificate merely authenticates predecessor
approval; honest signing validity and durable transition logic remain required.
No public wire protocol was added, so no QUIC enforcement is claimed.

Executed commands:

```sh
cargo run -p humoco-sim-core --example robustness_admission
cargo test -p humoco-sim-core --example robustness_admission
cargo clippy -p humoco-sim-core --example robustness_admission -- -D warnings
```

Final predicate run: **44 checks**, one standalone predicate regression test passed, focused strict
clippy passed. The subsequent composed campaign is recorded below. Counts include expected unsafe mutants, not successful safe-network
executions. There is no probability estimate or performance result.

## Costs and claim ledger

One member record is 64 bytes for identity and epoch public keys. Twenty need
1,280 bytes. A link with fourteen `(identity, signature)` entries needs 1,344 bytes
plus its roughly 1,394-byte configuration: about 2.7 KiB/link before envelope,
tickets, actual closure/install/BFT certificates and state proofs. Sixty-four links
need about 171 KiB and 896 Ed25519 verifications. A 16-level binary Merkle path for
one of 65,536 shard commitments costs 512 hash bytes. A full 65,536-roster map
without deduplication needs 80 MiB merely for those public-key pairs. Catalogs,
evidence retention and proof exchange are additional. These are byte arithmetic,
not runtime measurements; production budgets must count all omitted evidence.

| ID | Property | Evidence / status | Remaining premise or consequence |
| --- | --- | --- | --- |
| MEM-01 | Local first-FINAL activation is unsafe | 39-node bridge indistinguishability trace; real local certificate predicates | One growing network, only one faulty identity; no metadata convergence repair |
| MEM-02 | Printed CUP P3 has silent-row liveness discrepancy | Direct v2 source/algorithm read; exhaustive 15-subset predicate check | Narrow result; no repaired CUP protocol claimed |
| MEM-03 | Exact external root rejects counterfeit genesis | Real Ed25519 counterexample and anchored predicate test | Authentic onboarding is an explicit proposed trust/product change |
| MEM-04 | Repeated full replacement needs no permanent founders | Four real-signature configuration-link replacements | Signature-chain recognition only; conditional handoff dependencies remain |
| MEM-05 | Current fault bounds do not stop historical forgery | Real fourteen-retired-key alternate branch accepted | Lifetime compromise bound or audited key erasure plus trusted refresh required |
| MEM-06 | Local F2F graph cannot certify unknown excluded population | Identical local transcripts with hidden bridge community | CUP requires external graph/identity premises; none currently enforced |
| MEM-07 | Bounded late recognition has operational cost | Explicit 64-link/expiry refusal and arithmetic | Refresh authority/time/data availability required; values proposed only |

Disposition: retain the current negative whole-system verdict. The proposed
recognition mechanism has concrete inspectable predicates, successful conditional
recognition/turnover checks and decisive unsafe mutants. It makes the necessary
trust/admission cost visible rather than claiming to remove it mathematically.
Before production: approve the recognition policy; realize authenticated
provisioning and freshness; specify admission fairness, tickets and policy hashes;
implement/review the separately justified handoff, temporal keys and rollback;
then add malicious real-QUIC receiver tests and end-to-end load validation.

Independent review: the safety agent inspected the real-signature verifier and
confirmed the direct epoch-key binding, identity-key rejection and deliberately
successful recovered-key forgery. It required the limits above: signatures alone
prove no closure/installation or ticket eligibility; the sign-once fixture has no
split-vote recovery; erasure must occur after last required old signatures and
before decisive retirement, with recoverable backups counted as un-erased.


## Composed scheduled agreement -> signed history -> late payment verification

The lead requested a stronger composition than independently successful signature
and handoff fixtures. The model now additively exports concrete transition and
payment outputs through `RecognitionTrace`. `Lab::handoff` retains its ordinary
behavior; a new optional competing-proposal path exposes the existing scheduled
BFT to two different valid successor rosters. A Byzantine leader sends split
13/7 proposals in view zero, neither produces a decision, and the actual seeded
scheduler plus normal view changes must decide a package. The exporter reads the
**decided** package's exact state and next roster, actual closure endorsers,
actual commit voters and individually emitted post-install receipts.

`composition(seed)` in the admission example then performs a cryptographic
refinement of those outputs. It signs only identities present in each concrete
emission set. The root digest comes from explicit operator configuration. Every
successor configuration binds the actual previous digest, roster, generation,
installed-effect digest and fixed fixture epoch-key mapping. Separate genuine
Ed25519 domains authenticate inclusion/closure, decided successor and durable
installation. Actual transferred effect data accompanies its digest. Payment
signatures are created **only** for model `Replica.vote` emitters, bound to exact
configuration, slot and value; the receiver also verifies that those emitters
have the exported individual installation receipts.

Each composed execution requires an initial honest-only payment, three complete
roster replacements with split-proposal recovery, preservation of the first
payment's exclusion effect, and fresh honest-only payment success after every
replacement. Fourteen honest responses are required; six Byzantine participants
in each generation remain offline. A late receiver calls the pure
`verify_payment_from_anchor(anchor, root, proofs, payment, trusted_now)` entry
point for each of the four actual payments. That function checks the exact pinned
root, expiry and ancestry bound, validates every supplied closure/state/commit/
installation proof, and resolves the payment's configuration only from that
verified history. The producer's expected configuration, model trace, fault map
and emission registries are not arguments to the receiver.
Missing/changed state, substituted roster, missing closure, missing installation,
mutated payment value and out-of-ancestry payment context must be rejected through
this same entry point. Additional negative checks present a genuine payment with
its last ancestry link omitted, reorder predecessors, exceed the link bound, and
expire the anchor. An individual-installation mutant keeps a genuinely signed
fourteen-member installation quorum but replaces one payment signer's receipt
with a Byzantine member's receipt: transition verification succeeds, while the
recipient refuses the payment whose individual receipt is missing. No failed
progress check is counted as success.

This is stronger executable evidence about **composition**, not a new wire
implementation. BFT messages still use the existing ideal-authentication scheduler;
the emitted decisions are converted to real signatures after execution. It is
not a scheduler of real cryptographic network processing. The original fence,
drain and install steps retain their scripted atomic boundaries. The wrapper
must not be described as proving every crash interleaving, actual redb durability,
actual signature emission timing, erasure or network receiver enforcement.

The initial trusted manifest supplies recognition; the model does not infer its
honesty from its own global monitor. The declared lifetime-static six-key bound
is an external operating premise, not a locally measurable fact. Candidate
rosters/keys are deterministic fixtures standing for admitted, eligible identities;
full F2F presence, ticket mining/maturation, admission fairness, 24-hour timers,
clock trust, large-catalog policy and network resource enforcement remain
unimplemented in this composed example. The proposed authenticated onboarding
procedure realizes *which bytes an operator accepts*, not a proof that unknown
keys obey a fault bound.

Recorded composed campaign:

```sh
cargo run --release -p humoco-sim-core --example robustness_admission -- --seed-count 128
cargo test --release -p humoco-sim-core --example robustness_admission
cargo clippy -p humoco-sim-core --example robustness_admission --example membership_handoff_model -- -D warnings
```

Seeds **1..128** passed: **1,000,960 scheduled model events**, **3,072 composed
checks** (24 per seed), three complete turnovers and four actual honest-only payments per seed.
The separate unsafe/recognition predicates contribute **44** checks. Compact
machine-readable per-seed output, assumptions and source hashes are in
[`robustness_admission_results.json`](robustness_admission_results.json).
The original twelve example tests passed after the additive audit/factoring
change; the composed example's fourteen tests (those twelve plus two new tests)
passed in release mode. Focused strict clippy passed for both examples. Release
mode changes runtime only, not the model's virtual scheduler or pass criteria.
Identical event counts across seeds do not imply identical event order. These
finite scheduled executions establish no empirical failure probability.
