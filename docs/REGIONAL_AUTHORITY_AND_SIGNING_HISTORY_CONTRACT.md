# Regional authority and reachable signing-history loss detection

Date: 2026-10-23. Execution clarification: the maintainer selected A for both
regional recipient configuration (G1) and achievable local loss detection (G5).
This refines implementation premises; it does not close G2/G3/G4 or complete a
purchase/release transaction. No TPM, notary, pre-signing network round, external
coordinator, historical quorum archive or additional gossip stream is introduced.

## Recipient authority: authenticated subjective regional sources

The recipient explicitly persists `RegionalMeshPolicy` in its private wallet
profile through `AppService::configure_regional_mesh_authority`. The managed
wallet transaction authenticates the password, reloads current state and commits
before configuration succeeds. This policy is absent from public profile exports
and signed voucher data. Missing configuration rejects authority verification.
A receipt cannot install or replace the policy.

The policy specifies network (`u8`: mainnet0/testnet1) and1–8 distinct pinned
Ed25519 observation-source identities. These are observation sources, not an
assertion that the sources or committee have a cryptographically established
Byzantine bound. The recipient delegates their subjective ticket/presence
observations to these explicitly configured sources. A source must apply actual
observed ticket incubation, work verification, passive presence and identity bans
before publishing qualified identities. Signatures authenticate these observations;
they do not prove their truth or eliminate eclipse attacks and operator mistakes.
The at-most-six Byzantine committee assumption remains explicitly conditional.

`GET /v1/operator/regional-mesh-view` exports the node's qualified view only on
the private operator router, behind its existing loopback/Host/Origin boundary.
Public ingress does not register this route. No endpoint addresses, topology edges,
metrics, monetary data or purchase IDs occur in the signed view. Export refuses
an unhealthy signing history or a view exceeding4096 qualified identities; it
never truncates silently. Larger-region export requires further bounded protocol
work, not a claim that omission is safe.

The canonical `HUMOCO_V1_REGIONAL_MESH_VIEW` digest concatenates:

1. Domain length as `u8`, then domain bytes.
2. `version:u8 = 1`, `network:u8`, source public key32.
3. `issued_at_ms:u64 LE`, `valid_until_ms:u64 LE`.
4. Member count`u32 LE`, followed by each identity32 + active HRW ticket32.

Members are sorted strictly by full public key. Duplicates, invalid keys, excess
members, invalid network/version or lifetime outside(0,60000]ms reject before
source signature verification. At verification, issue time must not be in the
future and expiry must be strictly greater than the backend's verification time.
Source/time failure remains an unverified observation, never a peer fraud sanction.
Clock correctness remains a G4 premise; this introduces no OS clock on Node
consensus paths. The client backend currently supplies its local verification time.

Proto verifies one distinct view for **every configured source**, recomputes
production HRW (`BLAKE3(ticket32 || shard_u16_LE)`, descending full256-bit scores,
ascending public-key tie-break), and requires twenty members and the exact same
ordered top20 from every source. Missing sources, signatures, freshness or agreement
reject. No averaging, invented confidence, lower threshold or rank21 substitution
is allowed. This format deliberately preserves existing HRW bytes.

The registered App verification command bounds incoming view JSON to4MiB and
loads authority from the Core wallet policy, rather than accepting the proof's
committee as its own justification. View transport remains untrusted: it may
carry authentic source signatures but cannot configure trust. The separate
configuration IPC requires a password and bounds policy JSON to4096bytes.

This integration still returns an observation with automatic release disabled.
Recipient-created durable challenges, operation lookup, L1/purchase commit and
idempotent release remain Z08. Automatic source refresh, endpoint configuration,
provider credential isolation and UI configuration remain client integration work;
the new service must not be described as a completed network/payment workflow.

## G5: local generation and detectable history inconsistency

`signing_commit_state` retains one constant-size record: generation, active own
choice count, XOR commitment over canonical slot/value hashes, and a permanent
local corruption latch. This is not a per-lock tombstone or a journal archive.
Root-bound own choices and their indexes continue to expire at rootTTL+30s.

Each new original choice or class approval and each actual own-choice deletion
advances generation with checked arithmetic in **the same redb transaction** as
the choice/index change. A retained exact retry does not advance generation.
Each changed choice stores the generation that installed its current version.
Fingerprint leaves use length-prefixed `HUMOCO_V1_OWN_CHOICE_STORAGE`, followed by
slot length`u64 LE`/bytes and JSON-value length`u64 LE`/bytes. XOR is an order-independent
integrity accumulator, not a quorum/support or omission-coverage proof.

Original approvals still commit with `Durability::Immediate` before ACK/release.
Startup streams own choices, reconstructs count/fingerprint, checks row generation
against the commit-state generation and requires the expected rootTTL index entry.
A mismatch or malformed record latches `FAIL_CLOSED_CORRUPT` durably. The daemon
can expose diagnostics while `DualTierEngine::is_signing_healthy` refuses signing.
Irrecoverably truncated/unreadable redb files fail database opening before a node
can sign; this is not automatically recoverable by copying peer canonical state.

Legacy histories lacking this metadata are measured once on migration. This does
not retroactively prove their earlier completeness. Missing metadata alongside
already generation-tagged rows is corruption. A complete replacement of metadata
and choices by a consistent old directory is the explicitly excluded case below.

The existing heartbeat gains an optional nested `SigningCheckpoint`. It binds:
length-prefixed `HUMOCO_V1_SIGNING_CHECKPOINT`, network`u8`, full node public key32,
generation`u64 LE`, fingerprint32, signed with that node's Ed25519 key. It is not
an approval or a quorum proof. The existing full heartbeat encoding without the
extension still decodes without discarding its ticket/incubation fields.

A checkpoint is emitted from committed storage by a blocking background read;
it adds no checkout disk read and no pre-signing network request. The real F2F
QUIC receiver checks the nested signature against **its own** identity and network.
A greater own generation, or a different commitment at the same generation,
proves inconsistency and atomically latches local signing health before durable
latch persistence. Storage writes run in a blocking worker. Readiness is invalidated;
queued original choices are refused by the same persistent gate, and ACK waiters
check health again before handing back binding approvals. Foreign, forged or
cross-network checkpoints have no authority to trigger this latch.

The latch is local diagnosis, not an automatic network fraud ban. Genuine
incompatible original Ed25519 approvals remain subject to the existing
`HUMOCO_V1_EQUIVOCATION` sanctions. Canonical state copied from peers cannot clear
or reconstruct lost private own choices. Same-key resumption requires intact,
consistent own signing history, not just a matching public shard digest.

A consistent operator backup copies commit metadata, own choices and TTL indexes
from the same read transaction. A corrupt latch remains corrupt on backup/restore.
An intact process crash preserves committed decisions and needs no quarantine.

**Guarantee boundary:** if the entire directory (key, database, generation and
commitment) is silently restored offline, local software cannot distinguish it
from the earlier intact directory. No detection is promised without independently
available contradictory self-signatures. Heartbeat availability or later network
fraud detection cannot retroactively prevent an earlier conflicting release.
The identity and its database must be operated as one node; copied concurrent
instances and maliciously rewritten consistent local state remain outside this
local integrity guarantee. No external trust anchor is added.

## Executed interface evidence and remaining work

- Storage tests: intact reopen, retained retry, TTL deletion, consistent backup,
  missing own-choice row and persistent corruption latch.
- Real QUIC: forged signature, foreign identity, wrong network, identical checkpoint,
  and actual later checkpoint from a newer database versus an older backup; checks
  engine health, readiness, lack of network ban and corrupt-backup persistence.
- Real private/public HTTP: source signature, actual HRW selector equality,
  immature-ticket exclusion, foreign Origin rejection and public route absence.
- Core wallet: incorrect password refusal, durable policy, restart, source signature
  refusal, committee mismatch, and valid authority remaining insufficient for release.

These are scoped G1/G5 implementation assertions. G2 source-complete transfer,
G3 authenticated support inheritance, G4 clock composition and complete E/V/final
acceptance remain required. Final command results and working-tree hashes belong
in the execution record; old green logs are not relabeled as current evidence.
