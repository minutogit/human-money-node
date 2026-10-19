# 03. Current Live Proof, Status Queries and Active-State Sync

> Canonical complementary requirements to [routing/committee Spec03](03_routing_und_sharding.md).
> Decisions DEC-080–086 and LRC-002 (§7.93 interview notes). This contract replaces
> historical original-quorum archival premises; implementation/proof gates remain explicit.

## 1. L1 custody and two signature purposes

The L1 voucher/deed contains ownership, transactions and causality. L2 retains the
active collision map `parent_lock -> child_lock` with authenticated root lifetime
and the fields needed to validate the exact consumed output and successor. An
original write approval authorizes one immutable identity/slot decision. Before
it escapes the node or counts as self vote, the exact lock+own choice is atomically
durably committed (DEC-087; [Spec14 §4](14_node_persistenz_und_redb_speicher.md#4-asynchronous-write-path-and-durable-signature-release)).

A live-state response freshly attests safely installed current state under a
separate signed purpose. It is not a recreated original write approval. A node
that originally approved A may lawfully report B after a justified canonical
merge; different signature purposes/state contexts are not automatically
incompatible choices or equivocation. Keep immutable own signing decisions and
original own approval/context through rootTTL+30s independently of shared state.

## 2. Cheap ordinary lookup and payment clearance

Ordinary status stays `read_quorum=1` under INV-0310. Found/Matching/ConfirmLocal
and a gateway envelope alone do not mean paid. A recipient authorizes release only
after actually verifying a fresh current14/20 proof (or the existing explicitly
PROVISIONAL adaptive mode), plus the relevant L1 transaction and durable local
purchase/voucher storage. Do not silently choose an additional payment round;
Q-S3.3-01 remains parked.

For the FINAL live proof, the verifier must:

1. Obtain a justified current frozen top20 snapshot and verify fourteen distinct
   full `NodePubKey` identities belonging to it; duplicates, truncated IDs and
   unauthorized members add no votes. A caller-chosen roster is insufficient.
2. Verify every actual Ed25519 signature over canonical length-prefixed domain,
   signature purpose, network, committee context, shard, root, consumed output,
   exact target lock and declared state/status. Shared protocol encoding must bind
   all semantics; signing only a found flag or a floating payload hash is insufficient.
3. Bind the response to the recipient's fresh unpredictable challenge and exact
   request, enforce the permitted freshness/lifetime, and consume it for that
   checkout context. A proof for another challenge/output/network cannot be reused.
   Exact challenge size/expiry/encoding remain shared-interface integration work.
4. Count only current responsible signers whose affected shard passes safe sync
   readiness immediately before signing. A partially installed/pending state cannot
   sign absence, non-conflict or a countable positive state. Ordinary read diagnostics
   may describe uncertainty honestly; they must not bypass the quorum-signing gate.
5. Verify the complete mathematical evidence at the consumer, including signatures
   and membership rather than trusting a gateway's `verified` flag or matching record.

No disk write per ordinary read or new write-choice per live response is required.
The safely durably installed state is its read basis; a pending RAM-only insertion
must not acquire countable approval through a status/self path. Current authority
and safe synchronization are premises to justify, not consequences of nonce use.

## 3. Transfer without historical signature bundles

Synchronize canonical active state, not historical896-byte quorum signature
bundles. The digest must canonically bind all semantically relevant record fields
(including root identity/lifetime) with domain separation, deterministic ordering,
and explicit snapshot/cursor bounds. Exact final shared encoding remains K2;
legacy formulas omitting signed lifetime are not the complete schema.

Demand-triggered snapshot+bounded-delta pull and per-shard readiness follow the
routing specification. Verify source qualification, integrity, full live lifetime
coverage and installation before signing. Knowing partial data may permit bounded
peer service, never a current quorum vote. The selected skeleton does not yet prove
complete coverage across arbitrary turnover or safe concurrent activation.

## 4. No departed-signer dependency

Currently qualified synchronized nodes sign current live state with their own
keys. A transferred lock is not unresolved merely because original signers retired.
Neither nodes nor downstream clients must archive old quorum bundles through
successive generations. Exceptional retrieval of an uncertain attempt's original
own approvals is bounded and distinct; it is not a mandatory prerequisite when a
valid current live quorum answers. The merchant receipt is ephemeral after completed
checkout and is not recursively inserted into the L1 ProofChain.

These requirements add no new global finality guarantee, predecessor veto,
root-risk marker, ordinary-crash quarantine or new assurance tier. See the
[consolidation result and proof gates](ARCHITECTURE_CONSOLIDATION.md).
