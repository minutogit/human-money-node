# Independent adversarial safety review

Date: 2026-10-16 (Europe/Berlin). Baseline interview: CP-0031; decisions and
Q-S3.3-01 are unchanged. Research artifacts only; no production protocol edits.

## Verdict

The unrestricted copy/mature/activate rule is unsafe. The conditional
closure/inclusion + successor agreement + durable installation construction
survives the reproduced attacks under a recognized configuration, static fault
identities over the evidence lifetime, complete inclusion endorsements and
nonrollback storage. This is not an end-to-end deployment approval: initial
recognition, temporal key security, resource enforcement and wire execution are
additional gates. A current-committee-only six-fault bound is insufficient.

The reviewed membership alternative uses an explicitly operator-authenticated
current checkpoint, predecessor-certified exact epoch signing keys, bounded
recognition history and a trusted freshness input. It is a concrete proposal
changing onboarding trust; it is not inferred as accepted policy. Neither a
permanent identity signature nor a self-signed roster substitutes for that
recognition. The predicates demonstrate this distinction with actual Ed25519.

## Evidence ledger

| ID | Property / status | Evidence | Boundary / counterexample |
| --- | --- | --- | --- |
| SAF-01 | Unsafe local activation: reproduced violation | `exact_twenty_two_trace`; exact 14/14 witness below | Zero honest node equivocation; therefore fraud bans cannot prevent initial false FINAL |
| SAF-02 | Historical exclusion preservation: finite arithmetic result | Every one of 38,760 fourteen-member closure sets intersects a fixed historical fourteen-voter set in at least two honest nodes | Same justified twenty-member universe and at most six faulty identities over evidence lifetime |
| SAF-03 | Old-write cutoff: conditional argument | At least eight honest closure endorsers fence; at most twelve old identities can subsequently sign | Pending durable decisions and released replies must serialize before fence/report; abstract method alone is not a storage implementation |
| SAF-04 | Private-inclusion liveness mutant: reproduced | Eight honest prepared-value supporters versus fourteen required with six Byzantine commits withheld | Applying every agreement participant's private inclusion as public validity deadlocks an otherwise valid carried value |
| SAF-05 | Minority/inherited conflict retention: scripted bounded result | Two-A/twelve-B report set keeps both effects through three complete replacements; affected slot blocks; fresh slots progress | No claim of recovering every inaccessible singleton; full late-QC resolution is separately exercised in existing model |
| SAF-06 | Provenance/context: implementation predicate test | Real Ed25519 verifies authentic baseline and rejects changed payload, changed epoch, duplicate signer and unknown signer | Not QUIC; key generation deterministic fixtures only |
| SAF-07 | Recipient recognition: reproduced unsafe mutant | Real signatures from fourteen members of a fabricated self-created roster pass its own quorum predicate | Recognized exact roster rejects them; sig validity is not an admission rule |
| SAF-08 | Long-range old key attack: reproduced unsafe mutant | Fourteen retained/late-compromised retired ordinary signing keys sign changed old state successfully | Current new committee may have zero Byzantine nodes; epoch label alone provides no erasure |
| SAF-09 | Complete replacement without founders: conditional checks | Three disjoint abstract generations; separately membership example verifies four real-signature configuration links | Transfer/consensus and membership predicate are separate artifacts, not an integrated complete-system proof |
| SAF-10 | Operational availability: arithmetic limit | Six withholding Byzantine plus one unavailable correct member provide thirteen responses | No fourteen-vote progress; replacement must itself obtain old closure/agreement quorum |

## Independently reproduced timing attack

Use F=0..5, H1=6 through H14=19, X=20, Y=21.

```
old roster = F + H1..H14
new roster = F + H3..H14 + X + Y
t0 X,Y receive an empty, complete snapshot; no A choice yet exists.
t1 F + H1..H8 durably sign A; gateway can assemble fourteen signatures.
t2 X,Y activate based on maturity/copy, without an old-write cutoff.
t3 F + H9..H14 + X + Y durably sign B; another gateway assembles fourteen.
```

Both rosters have twenty identities; each contains six Byzantine nodes. The only
double-voters are F. This is one growing network with two newcomers, not merely a
merge of unrelated domains. Deterministic min-hash repair cannot undo the goods
already released against both claimed irreversible confirmations.

Closure removes this schedule only when the historical roster is justified. A
fourteen-endorser closure intersects the prospective fourteen-vote A certificate
in eight identities, including at least two honest inclusion witnesses. Complete
inclusion cannot omit A even if the gateway alone holds its aggregate. At least
eight honest fences leave at most twelve old identities able to issue new old
votes. Repeat the inherited exclusion at every handoff.

The existing `membership_handoff/model.rs` was inspected directly. `package`
fences only actual reporters, unions received effects and requests inclusion
endorsements. `valid_package` checks external closure-emission provenance and
immutable exact value binding. `valid_prepared` and `chosen` check emitted
prepare/change provenance and highest-prepared carryover. `present_certificate`
delivers historical evidence explicitly; the monitor alone does not inform
replicas. These are appropriate abstractions, but their registries model ideal
authentication, and fence/install remain scripted atomic steps. They are not
proofs that the daemon implements the corresponding storage/wire rules.

## Prepared-value deadlock and required validity boundary

A valid closure package P carries {A}, endorsed by F plus H1..H8. H9..H14 have
authentic additional private effects omitted from P. Eight honest nodes prepare
P after six Byzantine prepares; the Byzantine nodes withhold commits. A later
new-view certificate carries that prepared P. If H9..H14 now require P to include
their private effects before any agreement vote, only eight correct commits are
possible. Replacing P with a local preferred union also violates the agreement's
prepared-value rule.

Public validity instead checks the authentic closure certificate and carried
prepared proof; all fourteen correct agreement participants can commit P. Each
participant retains private immutable payment choices separately. The independent
test checks this count and retention boundary; the existing `prepared-recovery`
scenario supplies the scheduled propose/prepare/commit/new-view execution. The
independent count is not presented as another full BFT implementation.

## Candidate challenge and review outcome

The membership author's `robustness_admission.rs` was independently read.
`Configuration::id` binds instance, shard, generation, predecessor, state and the
ordered identity/epoch-key pairs. `link_valid` uses the exact predecessor's bound
epoch keys, distinct identities and fourteen signatures. A permanent NodePubKey
cannot re-delegate an old epoch key. Real changed-state/shard, missing-link,
duplicate and identity-key mutants are rejected. Deliberately retained fourteen
old epoch secrets successfully forge an alternate link; the example does not hide
that failure. The external anchor digest rejects a counterfeit root.

The following challenges were sent directly to the author and lead:

1. Erasure must follow the final required old agreement signature, and precede
   the released retirement acknowledgment. Erasing the same old epoch keys before
   closure/agreement votes are complete prevents prepare/commit/view-change
   recovery. A possible ordering is fence/closure, BFT successor commitment,
   release retirement proof only after durable key deletion, then successor
   installation/activation. An acknowledgment may be pre-signed but must not escape
   before deletion; exact crash persistence remains a production proof obligation.
2. Epoch secrets must not be derivable from permanent identity secrets. Retained
   backups, VM snapshots and rollback copies count as extractable old secrets.
   A label saying “erased” or an epoch number does not establish erasure.
3. Fourteen retirement acknowledgments imply at least eight genuine deletions
   only within the six-fault temporal assumption, leaving at most twelve keys.
   This must be integrated with preserved obligations, not replace state transfer.
4. `trusted_now` and checkpoint authenticity come from outside the peer transcript.
   An eclipsed new node's subjective P2P median clock cannot by itself justify
   checkpoint freshness. Expiry bounds recognition cost; it does not authenticate
   the next checkpoint. Refresh must continue through the authenticated channel.
5. `link_valid` alone does not check closure, key deletion, ticket eligibility,
   mature HRW selection, installation or state availability. Its four-turnover
   signature-chain fixture is a recognition-predicate result. Its sign-once
   competing-admission check schedules every honest node to see the left proposal
   first; it is not proof of recovery from an 8/6 honest split.

No violation was found in those exact signature predicates. The remaining gates
prevent treating them as a complete executable decentralized payment design.

## Existing alternatives and borrowed premises

Primary sources accessed 2026-10-16; these observations are independent of the
existing report's favorable descriptions.

| Candidate / source | Relevant algorithm and premise | Fit and reason |
| --- | --- | --- |
| [Castro/Liskov PBFT, OSDI 1999, §4.2–4.4](https://www.usenix.org/legacy/publications/library/proceedings/osdi99/full_papers/castro/castro_html/node4.html) | Three phases, context-bound prepared proof, new-view carries highest prepared request; stable checkpoint proof bounds log retention | Suitable known agreement machinery once roster is recognized; it does not supply unknown-participant admission or justify replacing old voters |
| [Vertical Paxos, MSR-TR-2009-63, §2/4](https://www.microsoft.com/en-us/research/wp-content/uploads/2009/05/podc09v6.pdf) | Configuration master chooses acceptors/leader; variant II activates after state transfer; read/write quorums intersect | The transfer-before-activation pattern is useful. Crash-tolerant Paxos intersection and auxiliary master cannot silently stand in for Byzantine HuMoCo membership |
| [Kuznetsov/Tonkikh, DISC 2020, §2–4 and Algorithm 1](https://drops.dagstuhl.de/storage/00lipics/lipics-vol179-disc2020/LIPIcs.DISC.2020.27/LIPIcs.DISC.2020.27.pdf), [journal version, Distributed Computing 35 (2022), 477–502](https://doi.org/10.1007/s00446-022-00421-1) | Configuration lattice/access predicates; active candidate quorums available; forward-secure keys; state transfer; globally reliable history broadcast; confirmation stage prevents slow-reader attack | Established broader solution to reconfiguration and retired-key attacks. Not a drop-in: it requires larger communication/verification machinery and assumptions absent from the allowed two F2F gossip streams and unknown initial recognition |
| [Castro/Liskov proactive recovery, OSDI 2000](https://static.usenix.org/events/osdi2000/castro/castro_html/index.html) | Byzantine fault bound applies across a vulnerability window; refresh, authenticated transfer and recovery mechanisms matter | Supports explicit temporal adversary bounds. A currently honest roster and long-lived signing identities do not imply safe historical evidence |

The DISC source's key-update argument is particularly relevant: superseded keys
must cease to authorize fresh historical statements. Its broader framework also
assumes certified admissible configuration inputs and sufficient stabilization.
Importing only its key-update intuition while claiming its complete theorem would
be invalid. Full reconfigurable lattice agreement is larger than using an already
recognized roster with standard BFT for infrequent transitions.

## Minimum feasible proposal and remaining product cost

Within the present mechanisms, subjective F2F transcripts plus valid signatures
do not establish a unique first accepted electorate for an independent recipient.
Hidden participants and delayed bridges preserve indistinguishable local views;
waiting a fixed incubation period does not prove absence. A solution needs an
additional authenticated recognition mechanism or enforceable global admission
premise. This does not prove that operator pinning is the only possible design.

The smallest investigated realization is explicit current-checkpoint onboarding,
standard BFT agreement over admitted successor configurations, closure/inclusion
handoffs, predecessor-bound independently generated epoch keys and checked
retirement/install gates. It preserves blind L2, no deposits, at most twenty
checkout voters and fourteen signatures, unrelated-slot progress and eventual
full founder replacement. It costs an authenticated onboarding/refresh dependency,
planned affected-shard pauses, a real temporal key-custody condition and fail-closed
behavior when checkpoint/proof bounds or old quorum availability are absent.
It does not establish that HRW/Sybil policy keeps every one of 65,536 committees
below seven Byzantine identities, or that physical storage reliably erases secrets.

## Executed commands and scope

```
cargo test -p humoco-sim-core --example robustness_attacks
cargo run -p humoco-sim-core --example robustness_attacks
cargo clippy -p humoco-sim-core --example robustness_attacks -- -D warnings
```

All passed: five tests; five scenario families; all 38,760 closure subsets;
three abstract complete replacements; actual Ed25519 provenance checks. The CLI
prints the exact unsafe trace and a compact JSON summary. Fixed schedules need
no random seed. The closure enumeration is exhaustive only over fourteen-member
subsets against one symmetry-fixed historical quorum/fault arrangement. The
remaining cases are scripted regressions, not exhaustive distributed schedules.

Important failures are asserted as expected mutant behavior: unsafe activation,
private-validity deadlock, self-created-roster acceptance and retained retired-key
forgery. Passing the suite means those attacks were reproduced, not prevented by
the current daemon. These tests implement no receiver defense and therefore make
no wire-enforcement claim. Before integration, actual QUIC rejection tests must
cover forged/nested membership certificates, stale contexts, incomplete transfer,
retirement/install crashes, oversize proof floods and storage rollback gates.
