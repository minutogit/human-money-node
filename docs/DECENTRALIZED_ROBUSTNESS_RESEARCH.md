# Decentralized robustness research

Research date: 2026-10-16, Europe/Berlin. Starting checkpoint CP-0031.
**Verdict: the unrestricted architecture is unsafe; its automatic local first-FINAL
rule and irreversible global payment acceptance cannot both hold over the allowed
discovery cuts.** This is a reproduced counterexample, not just missing proof.
The smallest investigated alternative adds authenticated recipient onboarding and
certified membership transitions. It is tested under an explicit retained-key
fault envelope; it does not establish an unconstrained permissionless deployment.
No production protocol, binding specification, selected decision or Q-S3.3-01
answer is changed by this report.

The decisive new witness needs only **one Byzantine bridge**, thirty-nine
identities in one organically growing network, and genuine signatures in both
locally plausible twenty-member committees. The earlier two-newcomer race is also
independently reproduced. Ticket maturity, reliable QUIC, matching snapshots and
later min-hash convergence do not prevent goods being released against both FINALs.

Additional conclusions are independent: six withholding Byzantine members leave
exactly fourteen correct responses, so one extra correct outage stops 14/20; a
small global attacker fraction does not enforce a six-identity bound in every
one of 65,536 shards; and ordinary retired signing keys can forge history after
later compromise. Measured 1k/s hot-replica service is feasible in a short local
probe, while stable 10k/s hot-replica service was not demonstrated.

## Evidence ledger

| ID | Property and assumptions | Actual evidence / status | Failure or enforcement boundary |
| --- | --- | --- | --- |
| R-01 | Compatible initial and late recognition | **Reproduced violation**: one-bridge 39-node views and authentic counterfeit root; real Ed25519 verifier rejects wrong configured digest | An externally authenticated manifest is an explicit proposed recognition mechanism. Self-signature proves no intended authority. |
| R-02 | Local mature-ticket/copy activation preserves FINAL | **Reproduced violation**: exact 22-node timing, 14 A and 14 B, only six double-voters | No old-write cutoff; initial copy really was complete. |
| R-03 | Closure preserves every possibly completed old QC, given recognized C20 and <=6 faults over its evidence lifetime | **Conditional argument + finite enumeration**: all 38,760 closure quorums against a symmetry-fixed historical QC, >=2 honest witnesses | Endorsers must actually fence/drain and verify own/inherited inclusion in the same available payload. A signed hash alone is insufficient. |
| R-04 | Competing transitions recover after stabilization | **Scheduled bounded model**: split proposals, genuinely prepared carryover, public closure validity; private-validity mutant stalls at eight honest commits | Requires relevant honest quorums/state and fair eventually timely communication; no arbitrary partition deadline. |
| R-05 | Historical authority survives late compromise | **Reproduced violation** with fourteen recovered retired secrets and genuine alternate signatures | Lifetime retained-key bound is explicit in the tested alternative. Forward-secure/erasure branch remains a proposal. |
| R-06 | Availability under withholding and correct outages | **Arithmetic + real-QUIC test**: fourteen responders succeed, thirteen time out | Sufficient timely responders >=14; no lower-rank replacements. Lost old quorum also blocks transition. |
| R-07 | Per-shard six-fault bound follows from ticket/F2F admission | **Not enforced**; exact hypergeometric sensitivity, all-shard actual HRW census and ideal valid-ticket grinding experiment | Global fraction, social reputation, 24h delay and one active ticket are not a per-shard adversary proof. |
| R-08 | Presence establishes complete timely discovery | **Counterexamples**: connected TTL-limited chain/rings, withheld bridge and different honest first-observation times | Full fan-out/perfect delivery is an optimistic upper bound; adding RED cannot repair hop-unreachability. |
| R-09 | Source range verification and safe installation | **Implementation-predicate tests** with real Ed25519: omitted/repeated/noncontiguous/corrupted records, stale context, oversize, crash | Source authenticity is not distributed inclusion. Independent review found and fixed cursor-after-crash empty reinstall; atomic persistence remains abstract. |
| R-10 | Durable throughput/resource affordability | **Measured** real QUIC/Ed25519/redb Immediate, bounded receiver queue, 1k/10k offered load, three repeats and storage perturbation | One local host, mostly one hot replica; no full-quorum high-load or handoff-performance measurement. |
| R-11 | Replacement without founders and late-payment recognition | **Conditional bounded composition**, described below; existing three-generation scenarios preserved | Recognized root, static retained-key bound, ideal BFT authentication and scripted durability remain explicit. |
| R-12 | Candidate defenses exist in current daemon | **False / implementation gap** from current source inspection | Existing green wire tests do not implement certified admission, durable own-choice acknowledgments or handoff. |

Status vocabulary: requirement, observation, conditional argument, bounded-model
result and implementation test are distinct. A deliberate unsafe mutant passing
its regression means the expected attack occurred. There is no empirical security
probability derived from zero failures in scheduled tests.

## Decisive counterexamples and the necessary change

**One-network bootstrap:** grow from bridge B into nineteen honest L identities
and nineteen honest R identities. B supplies each side its own valid presence and
hides the other side. After all maturity/stability timers, left sees
`{B,L1..L19}`, right sees `{B,R1..R19}`. An authorized malicious owner obtains A
from `B+L1..L13` and conflicting Z from `B+R1..R13`. Each local certificate has
fourteen real signatures; only B double-signs. The physical network is connected
and organically grown. Releasing delayed cross-community presence later cannot
restore irreversible payment safety. Until acceptance each local transcript is
indistinguishable from a permitted standalone twenty-node execution. Thus any
rule promising first FINAL from those transcripts also accepts this execution.
This is a conditional indistinguishability argument for the permitted cuts, not
a claim that unknown-participant consensus is impossible under every model.

**Concurrent newcomer activation:** old roster `F+H1..H14`, new roster
`F+H3..H14+X+Y`. X,Y copy the empty slot; old `F+H1..H8` then sign A; X,Y activate;
new `F+H9..H14+X+Y` sign B. Both reach fourteen and no honest identity double-signs.
Waiting for one request to freeze a local roster does not prevent another request
from freezing the incompatible roster. The adversarial review prints this timing.

**Necessary functional change:** counted voters need a recognition basis that
excludes both apparently valid electorates; copying data is a separate obligation.
The smallest investigated realization is an authenticated checkpoint plus a
certified transition control plane. A stronger externally established admission/
connectivity/resource premise is another possible class, but present F2F rules
do not establish it. A hash, median catalog size or longer timeout supplies none
of these premises. The report does not claim that checkpoint trust is uniquely
necessary; compatible accepted quorums and an initial recognition basis are.

The precise changed mechanism is **local discovery/maturity no longer confers
counted voting membership**. DEC-047/048's one-network and N>=20 regime, fourteen
checkout votes, at-most-twenty request members, 800 ms collection and sovereign
operator configuration remain. Authenticated onboarding/certified admission is
**unselected additional trust/policy**, not an inferred interview decision.

## Candidate comparison and source verification

Primary sources accessed 2026-10-16. Detailed independent reads, sections and
versions are in [membership research](research/robustness_membership.md) and
[safety review](research/robustness_safety_review.md).

| Candidate | Borrowed premise / actual fit | Disposition |
| --- | --- | --- |
| Local HRW + copy + 24h | Subjective discovery, no certified configuration | Rejected by both witnesses above. |
| [CUP, Heydari et al., arXiv 2405.06055v2, §II/Theorem 3/Algorithm 2](https://arxiv.org/html/2405.06055v2) | Fixed Sybil-resistant participants, authenticated communication, partial synchrony and a suitable unique knowledge-graph sink | Not supplied by F2F; independently reproduces literal P3 source-count discrepancy on all fifteen available >=13-row subsets of complete20/six-silent. No silent correction or general refutation. |
| [SCP, §4.1](https://stellar.org/papers/stellar-consensus-protocol.pdf) | Personally chosen quorums still require honest intersection | Operational trust is explicit, but different counting/onboarding semantics make this larger than recognized 14/20 transitions. |
| [PBFT, §4.2–4.4](https://www.usenix.org/legacy/publications/library/proceedings/osdi99/full_papers/castro/castro_html/node4.html) | Known roster; prepared evidence and view change | Prefer this established agreement pattern for infrequent recognized-roster transitions. It supplies neither unknown initial membership nor the inclusion validity predicate. |
| [Vertical Paxos, MSR-TR-2009-63, §2/4](https://www.microsoft.com/en-us/research/wp-content/uploads/2009/05/podc09v6.pdf) | Auxiliary configuration master and crash-fault quorum model | Useful state-transfer ordering comparison, incompatible as an unexplained Byzantine membership solution. |
| [Kuznetsov/Tonkikh, arXiv 2005.13499v2 §2/3.5, Algorithms 1/3/5, Appendix C](https://arxiv.org/html/2005.13499v2) | Given initial configuration; certified inputs; forward-secure keys; available active configuration combinations; reliable global history dissemination | Established broader reconfiguration alternative. Its communication/admission machinery is larger and not automatically compatible with two allowed F2F gossip streams or ordinary one-round collision finality. |
| [CometBFT light-client specification, failure model/initial-header assumption](https://github.com/cometbft/cometbft/blob/main/spec/light-client/verification/README.md) | Authentic trusted header and temporal trust interval | Maintained implementation comparison for explicit recipient onboarding; no stake/validator policy imported. |
| [Douceur, IPTPS 2002, §2–3](https://www.microsoft.com/en-us/research/wp-content/uploads/2002/01/IPTPS2002.pdf) | Independent identities require explicit identification/resource premises | Explains why public keys and a Web-of-Trust do not alone establish distinct operators. This research does not derive a universal impossibility for resource-bounded permissionless designs. |

The CUP v2 printed P3 counts vertices inside S1 with outgoing exterior neighbors.
Fourteen available complete-graph rows each name six silent vertices. Every
qualifying S1 has at least thirteen exterior-pointing sources, exceeding six;
the printed existence argument's exterior population bound is different. This
narrow discrepancy is a counterexample to the literal tested predicate only.

## Smallest investigated conditional design and knowledge boundary

This is proposed **candidate A**, preserving the original one-collection-round
payment interface. Q-S3.3-01 remains unanswered. Candidate B would add preparation
and a quorum-confirmed completion round; that can change incomplete-payment
semantics but does not remove bootstrap, cutoff or historical-key requirements.
No extra payment round is silently selected as a cure.

1. **Real onboarding:** an operator approves exact canonical checkpoint bytes
   through its own authenticated provisioning, an in-person transfer from an
   established installation or an explicitly trusted signed application bundle.
   The installation persists the digest/policy. A sender-provided anonymous QR or
   peer self-description cannot authorize itself. Fresh installations without
   such evidence retain PROVISIONAL/unknown-authority status. First launch of a
   brand-new network needs the same explicit setup of its first twenty-member
   configuration, after the selected ticket/stability prerequisites. No founder
   must remain online or keep a permanent special signing role.
2. **Certified membership:** bind instance, shard, generation, predecessor, policy,
   exact roster, ticket/candidate cutoff, epoch public keys and inherited state.
   Run HRW over a certified admitted catalog/cutoff; local presence proposes
   candidates. A newly mature hidden ticket cannot create a parallel authoritative
   committee. Discovery retains the F2F barrier and learned-peer shard RPC rule.
   This introduces actual admission/control-plane state and admission fairness
   obligations. The small signature example implements a subset of these fields;
   full ticket/catalog/policy encodings remain specified integration work.
3. **Payment:** a ready member accepts only the recognized context, authentic
   origin/root validity and owner-authorized exact intent; it reserves bounded
   persistence capacity, checks immutable own/inherited exclusions and releases
   its vote only after acknowledged durable choice commit. The vote binds context,
   parent/output, value and root validity. The gateway freezes <=20 identities,
   dispatches all once, exits at fourteen or impossibility/800 ms and treats
   NOT_READY/cancellation as neutral. No synchronous I/O while holding RAM locks.
4. **Close:** persist an old-epoch fence; drain admitted work or make sure no
   uncaptured vote can escape; export complete available own/inherited effects.
   Fourteen nonexclusive endorsements attest inclusion in the **same** available
   state. A possible old QC intersects these endorsers in at least two honest
   witnesses. Eight honest fences leave at most twelve fresh old voters. Delayed
   pre-fence replies remain meaningful and their effects survive.
5. **Agree:** a separate PBFT-style instance selects exactly one successor/state,
   with authentic prepared/view-change carryover. Public validity is closure
   evidence, not a new private-inclusion veto by every agreement voter. Otherwise
   eight honest prepared supporters can get stuck after six Byzantine commits
   disappear. Every identity retains its private immutable choices separately.
6. **Install:** verify contextual range-complete source transfer, final contiguous
   deltas and distributed inclusion evidence; durably install inherited effects
   and readiness before each individual new vote. Fourteen installation receipts
   establish completion but never activate an uninstalled individual. Restart
   retains fences/own choices; loss/rollback remains behind the selected safety
   gate. No blanket “sync finished” flag proves these obligations.
7. **Recipients:** verify their configured anchor, exact predecessor chain and
   transition/state/install certificates, then fourteen distinct signatures in
   the relevant recognized payment context. Stale local discovery cannot re-open
   old epochs. A legitimate old QC can remain valid for its live root; it does
   not justify a fresh conflicting successor. Single-node status/absence and a
   matching digest are not FINAL payment proofs.
8. **Lifetime/security:** the executed alternative assumes <=6 adversarial signing
   identities per historical configuration throughout retained evidence use.
   Stable NodePubKey identity does not authorize replacement of a directly bound
   historical epoch key. Later compromise of fourteen retired secrets really
   forges history. Audited forward-secure keys/irrecoverable erasure is a larger
   unimplemented alternative; deletion must follow final old agreement work and
   precede released retirement acknowledgment. Backup/VM snapshots count as keys.
9. **Bounds:** cap parsed proof size/depth before cryptography, cap background
   state/verification queues and retain a separate protected checkout budget.
   The recognition prototype rejects >64 links and expired anchors, with trusted
   time supplied externally; these are proposed engineering limits. Refresh needs
   a newly authenticated checkpoint and trusted time after cold loss. It may not
   discard live root obligations merely to bound history. Root TTL+30s remains
   the deletion boundary; full cryptographic expiry/pruning is not implemented in
   the new examples. The existing bounded exact conflict sets can block affected
   slots while unrelated fresh payments continue; constant-size BLOCKED-effect
   normalization is a remaining production design task.

**Safety argument:** induction starts at an authentic recognized configuration
with the fault/key premise. One fixed committee's fourteen-vote sets intersect in
eight, including at least two correct signers under f<=6. Immutable choices exclude
two outcomes. Closure preserves every potentially completed QC's exclusion by the
same intersection argument, even if its aggregate is hidden. Publicly valid BFT
selects one installed successor, inheriting those effects. Apply inductively over
complete roster replacements; private choices of reused identities are never
erased. This argument depends on actual inclusion, durable fences/install and
historical key security. The code tests finite schedules/refinement predicates,
not a mechanized general proof of the whole implementation.

**Progress argument and price:** after a sufficiently long stable interval,
fourteen correct current and successor members with required state, mutually
learned authorized paths, fair bounded resource access and eventually timely
communication can close, agree, install and complete fresh payments. Competing
proposals recover through rounds. Correct infinite withholding of an operator's
permission or missing state violates that progress premise. Genuine conflicting
owner intents may block their slot as DEC-023 permits. The extra product cost is
authenticated onboarding/refresh, a membership control plane, planned pauses,
historical key custody and refusal when evidence/availability is missing.

## Operating and adversary envelope

| Condition | Classification and actual realization | Outside consequence / locally detectable? |
| --- | --- | --- |
| Same authentic recognition basis for counterparties | Established outside protocol by proposed operator provisioning; no arbitrary-source majority | Counterfeit/incompatible roots can yield false FINAL if accepted. A pinned verifier detects digest mismatch, cannot prove its provisioning source honest. |
| <=6 signing identities Byzantine over each retained configuration's evidence lifetime | Conditional security budget; tickets/F2F do not enforce or measure it | Possible false FINAL/history after sufficient compromise; nodes cannot generally detect selective attackers before evidence appears. |
| >=14 timely valid responses in fixed C20 | Enforced deadline/counting in candidate; real-QUIC smoke verifies count boundary | Safe timeout/uncertain outcome, not free slot. Six withholding + one correct outage cannot progress. |
| Available old closure/agreement quorum and inherited state | Conditional liveness/data-availability premise | No safe emergency local rank replacement; affected shard may remain stopped until quorum/state returns. |
| No undetected own-choice rollback | Required storage/recovery contract; selected policy, absent complete production implementation | Same-key rollback can equivocate. A known loss disables signing; an invisible rollback is not magically detected by redb. |
| Finite/batched candidate changes with stable completion window | Proposed bounded admission through learned peers; hourly cadence alone grants no authority | Continuous churn/censorship may prevent progress; no unconditional pause SLA. |
| Budgeted state/crypto/bandwidth service exceeds admitted demand | Local queue reservations and transfer caps are observable | Capacity refusal is locally detectable and safe; enough honest capacity must exist for liveness. |
| Safe origin expiry and sufficiently trustworthy time | Existing policy; detailed candidate retention implementation pending | Early deletion can lose exclusion; late deletion wastes resources. Eclipsed neighbors cannot establish external checkpoint freshness. |

For n voters, q signatures, b possible equivocators and a additional unavailable
correct members, require `2q-n>b` for honest intersection and `q<=n-b-a` for
worst-case progress. With n20/q14/b6, a must be zero. Reducing q to13 admits an
intersection of exactly six Byzantine voters. If simultaneous six-Byzantine safety
and one extra correct outage must be guaranteed, **n21/q14 is the smallest
arithmetic alternative**: `2*14-21=7>6`, `21-6-1=14`. It violates the selected
at-most-twenty rule and is only a derived proposal, never silently installed.

## Executed models, source-transfer review and scaling

- [Original model](../crates/humoco-sim-core/examples/membership_handoff_model.rs):
  seeded virtual-time BFT, three turnovers, minority/late/three-way evidence,
  prepared recovery, lifecycle enumeration and configured-rate capacity model.
  Fresh original tests/results are recorded below; historical CP-0029 counts
  remain historical until rerun.
- [Independent attacks](../crates/humoco-sim-core/examples/robustness_attacks.rs):
  exact 22 timing, 38,760 closure quorums, private-validity stall, three scripted
  turnovers and genuine Ed25519 provenance/retired-key attacks.
- [Recognition/composition](../crates/humoco-sim-core/examples/robustness_admission.rs):
  configured-root verification, authentic counterfeit/bridge universes, four
  signature-chain replacements, CUP predicate and deliberate long-range mutant;
  additive model audit connects executed BFT/state/install outputs to real signed
  certificates and late-recipient payment verification. Details/counts below.
- [Envelope/source transfer](../crates/humoco-sim-core/examples/robustness_envelope.rs):
  actual full production HRW scores, all 65,536 shards, exact finite-population
  sensitivity, ideal valid-ticket grinding, one million-entry scan, graph cuts,
  real Ed25519 source seals and bounded contiguous records/install predicates.
  [JSONL results](research/robustness_envelope.jsonl),
  [parameters/source hashes](research/robustness_envelope_metadata.json).
- [Real execution](../crates/humoco-node/examples/robustness_probe.rs): bounded
  isolated QUIC/redb service, adversarial receiver cases and 20-endpoint quorum
  smoke. [Full experiment report](research/robustness_experiments.md).

Independent review found a concrete source-transfer defect in the new research
example: `page -> complete -> install -> crash -> complete -> install` could reuse
an old verified cursor/root after clearing volatile staging, install empty state
and permit a conflict. The fix resets cursor and hash-chain root together with
staging after crash; complete/install fail until a fresh full transfer. The
regression checks the previous installed exclusion remains. A second agent read
the fix and confirmed its exact scope. This did not alter production code.
The source tests also deliberately accept an authentically re-signed omitted
source stream: only distributed inclusion endorsements can establish that it is
the right transfer. Source cryptography alone cannot detect honest-state omission.

**Concentration:** exact hypergeometric results assume a fixed non-adaptive uniform
twenty-member subset. At 1000 nodes/100 attackers, `P[X>=7]=0.0021111` and
`P[X>=8]=0.0003468` per shard. At one million/5% attackers, expected shards with
>=7 attackers is about 2.224 of 65,536. Expected counts need no shard-independence
assumption; they are not the probability of any failure. Seven exceeds the target
six; eight specifically permits splitting 14/20 votes with all eight equivocators
and disjoint six-honest halves. Per-shard/epoch union bounds must account for all
repeated selections; no sampled zero gives a security probability.

The actual score census found 25 shards with >=7 attackers at N=100/10 bad,
and 131 with >=7 (including 13 with >=8) at N=1000/100 bad. These are
reproducible deterministic fixtures, not estimated deployment probabilities.

Actual HRW census uses deterministic research tickets and exact production
`hrw_score_32`, not Argon2-verified eligibility. Ideal grinding with eight attacker
identities versus 1000 fixed honest tickets puts 0/2/8/8 attackers in target
shard 17's top twenty with 1/16/256/4096 usable independent candidate tickets each.
This measures selection leverage **per usable valid trial**, not mining cost or
a demonstrated bypass of W_new monotonicity. Argon2 work, the work ratchet and
24h wait make trials costly/delayed but establish no finite adversary budget by
themselves. A feasible production envelope must supply that budget or an explicit
admission/diversity mechanism; authentic random selection alone still needs an
adequate committee-size/risk analysis.

**Discovery:** perfect all-edge delivery on a 36-node chain reaches only 17 identities
from one end at TTL 16; rings of 100/1000/10000 reach33. These are topology counterexamples,
not predictions of a measured social network. Repeated hourly origin heartbeats
reset TTL and cannot cross a permanently too-long path. Lower fan-out, RED and
Byzantine dropping only weaken this optimistic reach. Local first-seen at hours 0
and 6 yields opposite maturity at hour 25 despite the same ticket. The existing
globally seven-connected static bootstrap construction is therefore not locally
certified by these policies.

## Measured execution and resource costs

Hardware/software/workload, repetitions and limitations are recorded in the
[experiment report](research/robustness_experiments.md). Host: Ryzen 7 7730U,
NVMe-backed btrfs, Rust 1.94.1, Quinn loopback, release opt3/LTO off/16 codegen units.
No thermal/power isolation. Each request is 152 application bytes with real owner
signature; a successful reply 65 bytes. Queue 64, max batch 32, 1ms batching,
Immediate redb durability before signed response. These are short synthetic cost
measurements, **not a production-node or candidate end-to-end benchmark**.

| Workload, three 3s repeats | Useful observed commits/s | Successful-trip p99 range | Main observation |
| --- | --- | --- | --- |
| Hot replica, offered1k/s | 998.7–999.1 | 5.01–6.77ms | 9000/9000 observed useful completions |
| Hot replica, offered10k/s | 2908–5552 | 40.7–118.4ms | 38,390/90,000 useful; full receiver queue, refusals and some client/transport losses |
| +25ms storage delay/batch, offered1k/s | 993.1–995.2 | 30.0–72.5ms | 8986/9000 useful, 14 capacity refusals |
| +25ms storage delay/batch, offered10k/s | 949.6–1116.2 | 84.6–143.6ms | 9539/90,000 useful; 80,461 receiver capacity refusals |

Successful-trip percentiles exclude rejected/timed-out work. Exact p50/p95/p99,
CPU and peak RSS are in raw JSONL/time files. Baseline microbench median signing
15.56us, verification28.04us; redb Immediate single commit0.738ms (200 samples).
The 20-endpoint/20-key/20-database low-load smoke gets 5/5 with 20 and 14 responders,
0/5 with 13 (about 802 ms including timer/scheduling). This has no high-load quorum
or candidate handoff, membership, RTT/jitter, packet loss or bandwidth proof.
A 50 ms application sleep tests in-flight residency only. Graceful reopen retains
acknowledged choices; no power-cut, killed-process rollback or key-loss recovery
was tested. No measured pause/catch-up/recovery SLA is claimed.

At network-wide rate L and uniform assignments, expected replica rate/node is
`20L/N`; a hot shard imposes L on **each** of twenty replicas. At L=10k/s and 144B
per retained choice, raw replicated data is 2.49 TB/day network-wide, or 124.4 GB/day
on each hot replica, before signatures/index/redb amplification. A 30-day live
retention multiplies these figures by 30. The configured transfer model's
10k/s ingress versus5k/s transfer case leaves 125k records and roughly 25 s pause;
that is a virtual sensitivity, not a measured handoff.

One million compact synthetic catalog rows actually allocate 96 MB before maps,
authentic tickets/proofs and history; the separate actual-HRW scan uses a 32 MB
ticket-only floor. A full bare twenty-key map for 65,536 shards is 40 MiB; adding
epoch keys doubles it. An admitted million-node population yields 1.31 assigned
shards/node on average. Full catalog renewal each hour already costs at least
26.7 kB/s/node for 96-byte rows, 44.4 kB/s for 160-byte signed rows, before fan-out and
duplicates; this is not established by the spec's 25 KB/s claim. One heartbeat
signature alone consumes 64 B, so the current serialized fields exceed a 64 B packet.
These floors quantify a conflict, not an invented production heartbeat redesign.

## Validation, exact gaps and delivery gate

Executed results (final recipient-boundary checks are separately recorded in
[composition results](research/robustness_admission_results.json)):

- Original handoff campaign rerun after additive model audit: seeds1..128,
  1,536 executions, 4,036,608 abstract steps; explicit unsafe/stall expectations.
  [Result manifest](research/robustness_handoff_results.json). Original twelve
  example tests passed after factoring.
- Composed recognized handoff/payment campaign:128 seeds,1,000,960 scheduled
  events,3,072 checks (24 per seed), three full replacements and four honest-only
  payments per seed;44 additional recognition/unsafe predicate checks. All14
  example tests passed on the final receiver implementation. The pure recipient
  function accepts only its anchor, supplied history/payment and trusted time;
  it independently checks every closure/state/commit/install proof and resolves
  the payment roster from that history. The missing-individual-install-receipt
  mutant is rejected even with fourteen otherwise valid install receipts.
- Independent attacks: five tests; 38,760 closure subsets; deliberate unsafe
  activation/private-validity/history mutants reproduced.
- Source envelope: three tests, 18 transfer-predicate checks; actual score census
  for all 65,536 shards at N=100 and N=1000; one million ticket-only catalog scan.
  Its final independent source/crash tests passed.
- Workspace: 504 passed, 0 failed, 11 pre-existing ignored tests across 65 result
  groups. Examples run separately as above. Strict
  `cargo clippy --workspace --all-targets -- -D warnings` passed.
  [Check summary](research/robustness_workspace_checks_summary.txt).
- Environment: normal sandbox prohibits UDP socket creation (EPERM). Local QUIC
  probes and existing workspace wire tests passed using approved socket
  escalation; this is an environment boundary, not a protocol defect.
- `cargo fmt --all -- --check` finds extensive existing source-format differences.
  No workspace-wide reformat was applied. New isolated files were formatted
  and checked locally; preservation is more important than unrelated churn.

The reproducible commands are:

```sh
cargo test -p humoco-sim-core --example membership_handoff_model
cargo run -p humoco-sim-core --example membership_handoff_model -- --scenario handoff --seed 1 --seed-count 128
cargo test -p humoco-sim-core --example robustness_attacks
cargo run -p humoco-sim-core --example robustness_admission
cargo test -p humoco-sim-core --example robustness_admission
cargo test -p humoco-sim-core --example robustness_envelope
CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
  cargo run -p humoco-sim-core --example robustness_envelope --release -- all
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The probe's real-wire cases enforce malformed size/context, corrupt signature,
authorized conflict, exact retry and bounded queue refusal at its receiver.
They do not test absent candidate membership/fence/closure/install/retirement/
quota/F2F protections. Before integration those require malicious QUIC tests in
`crates/humoco-node/tests/`, including nested forged certificates, gap/replay,
concurrent capacity/flood fairness, durable/fence/install crash points, rollback,
root expiry and multi-generation late evidence. No production security defense
is declared complete solely from an in-memory model.

| Required scenario family | Current evidence | Remaining exact limitation |
| --- | --- | --- |
| 1..19, first20,21,22 | Existing provisional gate and fixed-instance20/21/22 fixtures; organic39-node negative witness | Continuous automatic globally complete bootstrap is refuted under arbitrary cuts; authenticated setup is an explicit replacement mechanism |
| Concurrent roster changes, conflicts, missing aggregates, >=3 generations | Original scheduled model plus independent attacks and cryptographic refinement | Ticket admission/fairness and all distributed interleavings not exhaustively verified |
| Competing/prepared/withheld transition rounds | Scheduled BFT recovery; public-validity versus private-veto mutant | Ideal message authentication; not an encoded real QUIC BFT implementation |
| Bridges/eclipse/directed discovery/partitions | One-bridge witness, TTL upper-bound fixtures, conditional stabilization | No measured global graph/failure distribution or universal availability |
| Old quorum loss/restart/stop/rollback/late compromise | Quorum arithmetic/wire smoke, finite local lifecycle, graceful reopen and long-range mutant | No actual abrupt process/storage-loss/rollback/key-erasure deployment experiment |
| Snapshot omission/duplicate/replay/deltas/crash/expiry | Real-signature bounded source verifier, crash defect fixed; existing concurrent/live-pagination model | Full Merkle/range protocol, concurrent per-root expiry and candidate durability remain unimplemented |
| Floods/quota/pools/background recovery | Queue saturation and receiver refusals measured; fixed source proof caps | No complete Byzantine metadata/quota/F2F-pool defense or fairness test in new candidate |
| 1k/10k and million-node goal | Real hot-replica and low-load quorum costs; one million catalog rows and all-shard score census | No multi-host candidate handoff/checkout concurrent performance, no statistical deployment SLA |

These gaps bound implementation readiness. They do not weaken the decisive
negative result: one valid conflicting-FINAL execution suffices to reject the
original universal safety claim. The tested conditional alternative makes the
minimum recognition and fault-custody costs explicit instead of silently adopting
them. Production work needs a deliberate onboarding/admission policy, shared
canonical client verification library, durable own-choice/fence/install paths,+resource admission, retained-effect/TTL design, adversarial wire coverage and
controlled multi-host sizing. DEC-029's relaxed local processing target conflicts
with old <5 ms specification wording; consolidation is still required, no binding
document was rewritten. No deploy, commit or PR is part of this research.

### Current daemon evidence and concrete implementation order

These are current bounded source observations, not inherited audit claims:

| Path | Observed mechanism | Required delta before this candidate can count as implemented |
| --- | --- | --- |
| [`network/manager.rs::shard_committee`](../crates/humoco-node/src/network/manager.rs) | Clones local known/peer maps; eligibility uses local maturity; calculates twenty from that view | Recognized configuration/candidate-cutoff evidence; versioned verified committee cache; no million-row clone/scan per checkout |
| [`api/routes.rs` quorum collection](../crates/humoco-node/src/api/routes.rs) | Frozen write committee, 800 ms bound, fast quorum/impossibility exits and neutral readiness handling | Count against certified context and return independently verifiable client proof; keep current dispatch semantics |
| [`storage/engine.rs::FlushOp::PutHmcLock`](../crates/humoco-node/src/storage/engine.rs) | Queue reservation and asynchronous batch; this operation has no per-entry durable acknowledgment | DEC-029/033 atomic own-choice/lock commit and successful commit acknowledgment before vote release |
| [`network/transport.rs` LockVerifyRequest](../crates/humoco-node/src/network/transport.rs) | Readiness checked at entry; later awaited ingress and signed reply | Per-shard durable fence/drain ordering, authentic transition context and individual installation gate |
| [`daemon.rs::run_shard_digest_pull_sync`](../crates/humoco-node/src/daemon.rs) | Pull convergence/readiness logic | Snapshot/range/delta plus closure/inclusion proof, own-choice rollback safety and durable install; digest convergence alone is insufficient |
| [`network/framing.rs::HeartbeatWirePayload`](../crates/humoco-node/src/network/framing.rs) | Public key, address, times/counters, signature, ticket and optional evidence | Size/CPU/retention accounting from real encoding; F2F transport remains discovery, never a membership oracle |

First obtain an explicit recognition/admission policy; its cost is now concrete.
Then specify the small shared client/node proof library and retained-effect/time
formats. Implement bounded atomic choice/fence/install paths and receiver-side
wire tests before enabling counted transitions. Keep candidate discovery,
telemetry and operator decisions outside automatic fraud punishment. A lost old
quorum must remain an honest unavailable state, never authorize an emergency
unsafe successor. Migration has no deployed compatibility obligation (DEC-004),
but PROVISIONAL records must be conservatively imported or left unresolved;
they may not be silently promoted to FINAL.

Resource sizing should cache recognized twenty-member proofs at checkout, reserve
separate bounded transfer/verification work, and update admitted catalog rankings
incrementally between certified generations. The measured 149 ms favorable
million-ticket single-shard scan already consumes too much of an 800 ms request
budget when repeated under contention; naively rebuilding all 65,536 rankings
takes about 2.7 CPU-hours, before map/proof overhead. These observations justify
removing full-catalog scanning from request processing, but do not prove a future
incremental implementation's throughput. Its cache/proof invalidation, bounded
admission and fairness need actual tests.

## Subsequent trust-premise audit (CP-0035)

The maintainer emphasizes the intended human-vetted growth process.
[The follow-up audit](research/robustness_trust_blind_spot.md) compares Spec07's
personal/diversity checks, one-friend activation and the current selection path.
The counterexamples above apply to the precise formalized activation/fault rules;
they do not simulate humans enforcing an as-yet-unformalized community-diversity
rule. Existing operator-approved friend keys may supply more of the intended
recognition basis than an entirely new anchor. That is a hypothesis to formalize
and test, not a retraction of the reproduced schedules or acceptance of stronger
assumptions. No replacement architecture is selected before resolving this gap.

## Work ownership and continuation

Three agents independently investigated membership, adversarial safety and real
execution. The lead reconciled claims, source inspection, envelope experiments
and interview preservation. Candidate author was not its only reviewer; the
transfer-crash failure was fixed following independent reproduction and readback.
Existing uncommitted work is preserved. Q-S3.3-01 stays unanswered with exact
original meanings. The only active interview leaf remains S2.1, now at the
concrete recognition-policy consequence, with a runnable tested proposal rather
than another circular assumption about “the old group.”

Final review boundary: the safety agent independently reviewed the initial
recognition predicates and attacked the handoff; the lead's subsequent composition
review required a single pure anchored-recipient verification entry point, then
reviewed its implementation/mutants. The execution agent independently checked
the corrected transfer-crash path. No author-only acceptance or whole-system
production proof is inferred from this division of work.
