# System Architecture and Runtime Completeness Audit

Date: 2026-10-13. Audited source revision: `d7829c70bfa4bf4c320c5ac794516d6809af2d0e`.

## Assessment and verification boundary

**The current implementation is not ready for a production deployment with irreversible FINAL claims.** The transport and persistence mechanisms exist, but several security guarantees fail at their interfaces. This is not a finding that the daemon is merely a simulator: HTTP ingress, authenticated QUIC, envelopes, shard requests, attestations, asynchronous redb writes, pruning, and background synchronization are real implementations.

Scope: specifications 00–20, the simulation core, production daemon, relevant integration tests, and a read-only check of the adjacent human-money-core client interface. No production source was changed. Findings below are source-level call-path analysis and, for quorum intersection, a mathematical counterexample. They are **not newly reproduced adversarial wire exploits**. Existing tests were executed; their success must not be treated as verification of the new findings.

- `cargo test --workspace`: **497 passed, 0 failed, 11 ignored**, exit 0. The first sandboxed attempt failed on prohibited loopback binds; the subsequent permitted run completed successfully.
- `cargo clippy --workspace --all-targets -- -D warnings`: exit 0.
- The ignored tests include long-running simulations. No worldwide 100-daemon load experiment was performed.
- `tests/phase11_wire_level_adversarial_tests.rs:889` creates 100 PeerManager entries for HRW mathematics and then two actual QUIC endpoints for a digest spot check. It is not a 100-daemon stress test.

Priority P0 means consensus safety or irreversible state-loss release blocker; P1 means a material security, availability, or contractual completeness defect. Both require resolution before the corresponding production promise can be made.

## 1. Top system breaks

### A01 — P0: FINAL quorum membership expands to 40 while the threshold remains 14

**Specification:** Spec 03 §§2.1 and 3.1 and Spec 06 promise 14/20 BFT finality with successor ranks. Spec 03:68–77 itself permits a K=40 horizon without supplying a safe committee-transition proof.

**Code:** `api/routes.rs:1150` retains the quorum threshold, `:1171` truncates candidates to 40, and `:955–966` fans in all remaining candidates after 300 ms. `network/transport.rs:494–495` accepts local ranks up to 40 immediately. Attestations can be FINAL under the network-wide stability gate (`:845–858`). Background shard recovery filters responsibility to the Top-20 (`daemon.rs:960–966`); successors have no mandatory per-shard recovery gate before voting. The certificate verifier has no committee epoch or state-transfer commitment. The bitmap is advisory and covers only 32 ranks (`routes.rs:637–642`).

**Impact:** In a fixed 20-member committee, two 14-vote quorums intersect in at least eight members. In a 40-member voter universe, two 14-vote sets can be disjoint: `max(0, 2*14 - 40) = 0`. Two gateways with different reachable candidates can collect conflicting FINAL certificates without any honest node signing twice. Later min(H_canon) convergence does not repair the already broken finality promise. Raising the count alone is not a substitute for defining the fault model and membership transition.

**Required component:** A single authenticated committee definition per shard and voting epoch, plus safe successor activation with verified state transfer and a quorum-intersection argument across transitions. Until then, successor votes must not confer irreversible FINAL status. A real QUIC test must attempt concurrent conflicting certificates under asymmetric reachability.

### A02 — P0: Sync readiness is not a verified convergence certificate

**Specification:** Spec 03 INV-0304/0305 and digest-pull §5 require confirmed state and stream digest verification before RAM commit and readiness.

**Code:** `daemon.rs:843` selects bootstrap mode for an empty node even in a large network. Connect/page errors are skipped (`:849–885`), insertion results are ignored (`:898–908`), and readiness is set unconditionally (`:924–927`). In the dominant-digest path, records are committed as pages arrive (`:1187–1197`); successful page receipt becomes `shard_pull_ok` (`:1212–1214`). The received state is not recomputed against D* before `:1222–1226` enables voting. A stalled cursor also breaks the loop without necessarily failing the pull.

**Impact:** A restarted or joining node can attest with incomplete state. A peer selected from the digest majority can return a different stream, or queue backpressure can silently omit records, while the node still declares itself synchronized. New shard responsibility can contain entirely unknown locks because the scan starts from local records, registered active shards and shard zero (`:933–958`).

**Required component:** Shard-specific readiness and a bounded staging/commit mechanism binding the complete stream to the selected digest or verified certificates. Propagate all insertion failures. Discover and recover newly acquired shards even when their local state is empty. Empty-node recovery in a large network must retain its BFT barrier.

### A03 — P0: The first prune trusts an unverified host-clock bootstrap

**Specification:** Spec 07 and Spec 12/14 prohibit unverified OS time from destroying valid state.

**Code:** Initial disk recovery correctly uses `SimTime(0)` (`daemon.rs:128–130`). However, `NetworkClock::new` initializes both its epoch and monotonic floor from SystemTime (`network/clock.rs:60–74`). The prune ticker starts with anchor zero (`daemon.rs:390`), so its time-corroboration check is skipped on the first tick (`:400`). The engine does the same (`storage/engine.rs:1977–1996`), then deletes RAM and disk records (`:1998–2009`). No established-clock readiness gate precedes deletion.

**Impact:** Restart with an OS clock one year ahead can load valid records and then delete them after the first 30-second ticker interval. Calling the value `net_time_ms` does not make its initial host epoch corroborated. The monotonic floor additionally prevents ordinary negative-offset correction from simply stepping back.

**Required component:** Explicit confidence/readiness for destructive time decisions, including the initial tick and cold-start epoch, with a documented offline-node policy. Verify restart under large positive and negative host-clock offsets over a real daemon lifecycle.

### A04 — P1: Unknown voucher roots are inferred from successor-supplied TTLs

**Specification:** Rule 10 and Spec 12 INV-1202 require the signed genesis root to define immutable expiry and storage-time accounting.

**Code:** `storage/engine.rs:70` treats any entry carrying `deletable_at` as genesis, regardless of its tag. The window gate at `:92` runs only if a root is already known. An unknown voucher can therefore acquire a root from a successor. The actual shard path passes the verified request into this insertion (`network/transport.rs:828–831`). New genesis entries also skip this engine window gate. The envelope footprint is computed from its independently supplied `root_valid_until` (`transport.rs:633–640`), while storage derives TTL from the request entry. HTTP forwarding deliberately accepts provisional client TTLs or a ten-minute default (`routes.rs:1711–1742`).

**Impact:** The receiving shard cannot reliably prove that charged Byte-Years equal the actual retention obligation. A signed envelope and a signed client entry can still disagree about the authoritative root. Unknown-origin successors and unsupported retention periods can enter the registry despite the core window helper being correct.

**Required component:** One validated root context, derived from a genuine genesis anchor or client proof, used identically for routing, TTL, envelope verification, charging and persistence. Check new roots as well as known roots; reject an unknown-origin successor unless a valid origin proof is supplied.

### A05 — P1: Cold gateways and shards disagree about the canonical voucher shard

**Specification:** Spec 03 INV-0302 and Spec 06 require every branch of a voucher to remain on its genesis shard; gateways must support client rotation without owning the voucher state.

**Code:** Genesis uses `H(base58(transaction_hash))` (`routes.rs:1771–1773`). A single successor without local root knowledge falls back to `H(ds_tag)` (`:1775–1781`). The remote read fallback instead uses `H(voucher_id)` (`:1481–1485`). The shard independently uses the known genesis anchor, attached genesis proof, or `H(voucher_id)` (`transport.rs:428–483`). `fetch_remote_voucher_root` only queries local redb (`routes.rs:571–584`). Partial chain routing similarly derives a shard from the first supplied hop (`:2332–2338`).

**Impact:** A wallet rotating to a fresh gateway can encounter false UnknownVoucher, wrong shard targets, failed attestation verification, or missing quorums. A complete chain containing genesis takes a better path, but does not make the single-successor path correct. The current API test for shard stability uses an already populated local gateway.

**Required component:** A canonical shard anchor carried in the validated root context, or an authenticated bounded resolution mechanism. Test a voucher initialized through gateway A and queried/spent through empty gateway B, including branches and partial offline chains.

### A06 — P1: Peer-provided read timestamps can reset both quota registers

**Specification:** Spec 09/10 and the local-time policy require recipient-enforced budgets and authenticated declarations.

**Code:** The StatusQuery handler permits null payload key/signature and then uses the authenticated TLS identity (`transport.rs:935–942`). There is no equivalent of the write path's 30-second timestamp gate. Its quota epoch is taken from the sender timestamp (`:1047`); `quota.rs:558–561` clears both read and write daily registers when the supplied day advances. Independently, P2P budgets use only the first two NodePubKey bytes (`ingress/tier.rs:482`, `:504`).

**Impact:** An already authorized peer can cause repeated resets of shard-side budgets and poison the epoch anchor. Known-peer authorization limits access but does not protect the shard against an abusive member. Different real keys sharing a 16-bit prefix also share quota state, allowing interference with another node's budget.

**Required component:** Derive the accounting day from recipient network time, authenticate all supported read forms, validate freshness, and index peer accounting by full NodePubKey. Verify on real QUIC that read requests cannot advance another peer's accounting day or reset write usage.

### A07 — P1: Live envelope evidence selects a checker for fields that were discarded

**Specification:** Spec 10's signed ingress sequence/counter/EMA guarantees and Spec 09's cross-shard whale brake.

**Code:** Live writes construct `IngressEnvelopeEvidence::new_v2` with a nonzero day/sequence (`transport.rs:645`). That constructor sets legacy cumulative counters and `lock_hash` to zero (`fraud.rs:233–242`). `verify_ingress_counter_conflict` nevertheless selects its legacy branch whenever day/sequence is nonzero (`:786–792`), comparing those zeroed fields (`:804–827`) instead of the V2 operation/EMA fields. The wire payload has counters, but this evidence conversion does not preserve them.

**Impact:** Signature verification can be valid while the advertised sequence-fork and under-declaration detection does not operate for actual contemporary write envelopes. A recipient still has its own local daily counter, so this is not a claim that shard-side accounting is wholly absent. It is a loss of the intended cross-recipient enforcement and attributable fraud proof.

**Required component:** An explicit evidence version with one matching signed preimage and checker. Preserve and authenticate the fields actually checked; define replay/idempotency, legitimate physical decay and cross-day behavior consistently. Wire tests must use nonzero current-day V2 envelopes.

### A08 — P1: Successor shard equivocation evidence reconstructs the wrong signed shard

**Specification:** Spec 02/10 require two genuine signatures to prove equivocation and revoke the node identity/ticket/F2F edges.

**Code:** Live attestations sign the canonical voucher genesis shard (`routes.rs:500–530`, `transport.rs:850–859`). First-party evidence verification derives the shard from the current parent hash (`transport.rs:158`). The evidence attestation type does not preserve the signed shard context. Existing wire slashing tests use a shard derived from that parent, avoiding the successor-voucher mismatch.

**Impact:** Real double signing on a successor whose parent hash differs from the genesis shard can fail proof verification. The ban and WoT severance implementations exist, but this proof cannot reach them correctly.

**Required component:** Retain the signed shard/network/status/committee context in evidence and reconstruct the exact live preimage. Test actual successor attestations with distinct genesis and current-parent shard IDs, plus anti-framing negative cases.

### A09 — P1: Public ingress lacks the promised cost ordering and VIP resource isolation

**Specification:** Spec 13 INV-1301 and Rule 9 require cheap filters before asymmetric work and isolated VIP capacity.

**Code:** A single lock performs Ed25519 verification at `routes.rs:1636–1644`; PoW/tier evaluation starts at `:1928–1940`. Invalid requests receive another server signature. The idempotent path fans out before tier/PoW evaluation (`:1793–1842`). All tiers ultimately share the router and persistence channel; no reserved 70–80% CPU/bandwidth admission path implements the Spec 13 promise. Public `/v1/sync` performs synchronous full database reads and clones RAM maps before truncation (`routes.rs:347–401`), without the read-quota gate used by `/v1/status`; the HMC append is outside the first 10,000-entry truncation.

**Impact:** Public request work and repeated sync scans consume resources shared with VIP checkout. The existence of friend/VIP credential classification does not establish an SLA under flood. Repeating an already known valid request can amplify HTTP traffic into multiple shard RPCs without passing tier admission.

**Required component:** Cheap admission before crypto and fanout, bounded concurrency/resource reservation per tier, bounded sync enumeration and read admission before database scanning. Validate VIP latency while actual public requests saturate the same daemon.

### A10 — P1: Asynchronous persistence can permanently discard accepted work

**Specification:** Spec 14 and Rule 10 require bounded reservation, reliable flush and graceful drain.

**Code:** Reservation before RAM mutation is implemented (`engine.rs:753`). But `commit_batch` relinquishes its batch into a blocking task; after retry exhaustion the failure is only logged/counts updated (`:1698–1721`, `:1890–1892`). Evidence/ban enqueue failures are discarded (`:518–526`, `:551–559`, `:801–807`). QUIC stream handlers are detached tasks (`transport.rs:2178`, `:2277`) and are not joined before the flush drain. The drain stops on temporary queue emptiness (`engine.rs:1763`) rather than proving all producers have stopped.

**Impact:** After disk failure, accepted collision records may remain only in RAM indefinitely and disappear on restart. Persisted bans/evidence can be lost under queue pressure. Shutdown has a producer/drain race; that race has not been reproduced in this audit. The ordinary asynchronous acknowledgment window alone is not the defect: permanent discard after error and incomplete producer shutdown are.

**Required component:** Retain failed batches or fail closed under a defined recovery policy. Reserve evidence/ban persistence coherently. Stop admission, join in-flight mutations, then close and drain producers before final disk close. Add injected disk-error, full-queue evidence, and in-flight shutdown tests.

### A11 — P1: Admission, phase transition and hot-path performance do not share the claimed invariants

**Specification:** Spec 01/07/08/11 require mature presence and stable phase transitions; Spec 12 requires a lock-free first-seen index.

**Code:** `active_nodes_count` includes all non-suspended direct peer identities before filtering immature known nodes (`manager.rs:2116–2140`). `mature_network_size` does likewise (`:2158–2180`), while `active_hrw_nodes` applies a different filter (`:1954–1957`). `KnownNodeInfo::is_immature` uses elapsed time, not the core's hourly presence bitmap. Production indices are global `Arc<tokio::sync::RwLock<...>>` (`engine.rs:413–414`), backed by HashMaps, not atomic CAS maps. Chain insertion holds the global HMC write lock and clones the entire root map (`:961`, `:1040`). Pruning calls synchronous redb writes from the async method (`:2008`); the HMC TTL query scans all active index entries (`db.rs:215–219`). The idempotent latency path records a hard-coded one microsecond (`routes.rs:1844`).

**Impact:** Different runtime views disagree about eligible N and HRW participants, so the existing 24-hour gate does not by itself prove mature membership. Concurrent checkout serializes behind one index writer; chain cost grows with the total voucher-root population. Database pruning can block a Tokio worker. No deadlock or remote-input-triggered daemon panic was demonstrated; the concrete findings are inconsistent state views, blocking work, and unproven latency claims.

**Required component:** One full-key eligibility snapshot and actual presence admission model, reused by all phase/HRW consumers. Implement the required concurrent index or explicitly revise the invariant with measured limits. Remove full-root cloning from per-request work, use bounded TTL ranges and blocking workers, and report measured latency.

## 2. End-to-end chain and seven pillars

| Station | Actual runtime | Boundary that fails |
|---|---|---|
| HTTP 8080 | Real HMC handlers and tier controller | Admission order, idempotent fanout, shared VIP resources, root inference |
| QUIC 9090 | Real Quinn/TLS identities and signed envelope payloads | Canonical routing and evidence-version conversion |
| Shard guard | Learned-peer authorization, local budgets and backpressure | Sender-controlled read epoch, 16-bit quota keys, root mismatch |
| RAM/attestation | Real collision check and Ed25519 signing | Global write lock, unknown-root gate, unsafe successor voting |
| Quorum return | Real parallel signatures, early abort, count gate | 14-vote threshold over 40 candidates and incomplete response validation |
| redb/TTL | Real asynchronous batches, recovery and background prune | Discard on persistent errors, drain race and unverified first prune |

No complete pillar is wholly absent; no complete pillar earns production-ready status under the binding guarantees.

| Pillar | Specification | sim-core | humoco-node runtime | Verdict |
|---|---|---|---|---|
| Ingress and client tiering | 09/13 | Byte-Years, thermometer, quotas, PoW helpers | Credentials and dynamic PoW implemented; isolation/cost ordering/root consistency incomplete | Incomplete |
| P2P wire and envelope | 10/15 | Header, domains, evidence models | Real TLS/QUIC, limits, barriers and signed envelopes; read epoch and V2 evidence gaps | Incomplete |
| HRW routing and quorum | 01/03/06 | Ranking/quorum functions and client verifier models | Live fanout and successor candidates; canonical routing and FINAL intersection broken | Incomplete; P0 |
| RAM and redb | 12/14 | Index/window/prune algorithms; HashMap rather than CAS | Real reservation/batching/recovery/pruning; clock and persistence error barriers incomplete | Incomplete; P0 |
| Fraud proofs and slashing | 02/10 | Proof/checker models | Verification, bans and severance exist; live V2 and successor evidence mismatches | Incomplete |
| F2F gossip and clock | 07/11 | Presence, edge/load and clock models | Genuine signed heartbeat/F2F barrier/median clock; full presence admission and trusted initial epoch incomplete | Incomplete |
| Sync and mesh merge | 03/08 | Digests, majority clustering and canonical resolver | Real pull, min(H_canon) reconciliation, merge thermometer reseed and moratorium; verified convergence barrier missing | Incomplete; P0 |

### Specific questions resolved

- **Envelope:** Exists on QUIC, including epoch/sequence and EMA declarations. Counter/evidence semantics are broken at conversion; absence is the wrong diagnosis.
- **Ranks 21–40:** Are queried and allowed to attest. Safe activation/state transfer and membership transition are missing.
- **TTL pruning:** Runs every 30 seconds in production for RAM and redb. It is not a phantom; its initial-clock safety and HMC scan cost are defective.
- **Phase transition:** The 24-hour stability mechanism exists. Eligibility/presence/readiness conditions are incomplete and inconsistent. The core's full presence/sync-state model is not fully integrated.
- **Merge thermometer:** Both rings are reseeded (`quota.rs:471–473`), and the daemon activates a 24-hour penalty moratorium (`daemon.rs:287–292`). It derives read seeding from write median and discards the independently returned read median, so write/read calibration remains an integration concern. This is not an entirely absent merge path.
- **Lazy shard:** Invalid attestations, ordinary failures and implausible quota responses feed local failure accounting (`routes.rs:995`, `:1056`, `:1107`). Quorum-triggered aborts are excluded, correctly. NOT_IN_SHARD/PEER_SUSPENDED responses are skipped without corroborating the peer's actual responsibility (`:1015–1018`), leaving a refusal path outside the useful-work penalty. Ordinary laziness must remain a local routing/malus issue, not cryptographic network-wide slashing.
- **Free rider:** Local useful-work accounting and suspension exist; the implementation does not prove that every gateway reliably recovers and serves its shard obligations. A complete economic no-free-riding claim is unsupported, especially with A02/A11.

### Additional drift and verification gaps

1. `verify_peer_attestation` verifies against the parent contained in the response, but takes no expected-parent argument (`routes.rs:685–809`). Collision responses are deserialized and influence HTTP 409 without verifying the supplied first-party entry signature (`:1019–1028`). Default remote status routing similarly trusts decoded payloads and can synthesize a Verified entry with zero client signature (`:1544–1558`). Bind replies to the requested parent and verify their actual evidence.
2. `/v1/status` attempts one remote candidate and retains the local unknown verdict on failure. It implements neither the specified fast failover nor local failure accounting for that path (`:1487–1562`). The timeout wraps the request after connect and is 1,000 ms, not the 100 ms read failover promised by Spec 03.
3. `verify_chain_causality` verifies each hop and timestamp/voucher consistency, but does not validate a predecessor link or split-output proof (`engine.rs:922–939`). DAG support needs verifiable branch ancestry rather than treating arbitrary different tags as sufficient causality. This is a Spec 06 completeness gap, not a recommendation to store wallet history.
4. A rejected single-lock insertion bypasses the certificate gate and defaults to HTTP 200 (`routes.rs:2135–2164`); the chain handler has explicit 400/429 rejection mapping. Full-queue single-lock backpressure therefore violates transport semantics even though the JSON verdict says Rejected.
5. Core light-client Bloom/order-statistic functions exist (`client_flow.rs:179` onward), but no production API exports the specified three-seed membership filters. The statistical threshold is not an authenticated exact committee proof. The fixed filter has m=16,384 bits and k=8: at 10,000 identities its approximate membership false-positive probability is `(1-exp(-8*10000/16384))^8 ≈ 0.94`. This mathematical estimate contradicts treating membership as essentially unforgeable. Quantile selection and signature verification do not by themselves establish authorized membership. Adjacent human-money-core's `verify_quorum_plausibility` uses 16-bit IDs/order statistics without Ed25519 batch verification; this is an interface observation, not a full audit of that repository.
6. Spec 04's fixed-size zero-copy types differ from runtime String/Vec/bincode/JSON storage. Spec 16 still references receipt gossip/Argon2id ingress that conflict with the binding two-stream/BLAKE3 model. Spec 20's dashboard/dual-role descriptions also lag AGENTS.md. The HIGH_ASSURANCE tier in Spec 00 is not represented by the runtime certificate's 0/1 status. These should be reconciled rather than automatically implemented as new features.
7. Framing has real size caps, incremental reads, timeouts, and connection/stream semaphores. Fraud forwarding has deduplication/echo protection. No evidence supports claiming all P2P allocations are unbounded or every unwrap is remotely exploitable. Public sync scans, per-request root clones, and shared capacity are the supported stress concerns.
8. `NetworkClock::fast_reseed_on_merge` (`network/clock.rs:126`) has no production caller; its other occurrence is a test. Live merge handling reseeds the thermometer, not the clock. The ordinary median clamp remains bounded to 15 minutes, leaving large inter-island clock offsets without the advertised live re-anchor path.
9. Sync mode derives `total_known` from established sync peer addresses (`daemon.rs:819–827`), not the eligible network size. A large-network node with a small connection pool can therefore use full bootstrap sync. `ActiveSyncRequest` contains cursor/limit rather than a shard selector, so even the nominal shard-repair path downloads peer-wide state; this undermines the claimed storage/network scaling.

## 3. Prioritized closure plan

1. **Resolve FINAL membership safety (A01).** Specify committee epochs, membership evidence and safe successor handover before changing implementation. Acceptance: no two conflicting FINAL certificates under asymmetric reachability without the required cryptographic fault threshold.
2. **Close destructive-time bootstrap (A03).** Explicit confidence gate and cold-start/offline policy. Acceptance: extreme host-clock offsets do not purge still-valid persisted locks.
3. **Make sync prove convergence (A02).** Shard-scoped recovery barrier, validated complete streams and propagated insertion results; include new responsibility with no local records. Acceptance: faulty/truncated streams, missing pages and queue saturation never enable voting.
4. **Unify voucher root context (A04/A05).** One signed genesis anchor for immutable TTL, canonical shard and exact storage-time charge, including fresh gateways and partial chains. Acceptance: originless successor rejection and successful A-to-B gateway rotation over QUIC.
5. **Repair accounting/envelope boundaries (A06/A07).** Recipient epoch, full-key quota state, explicit versioned evidence and consistent signed fields. Acceptance: reads cannot reset writes; live nonzero-epoch contradictions are correctly proved while legitimate decay/reordering are not falsely slashed.
6. **Fix proof and response context (A08 and additional gap 1).** Retain exact signed domain/shard/status/committee context; validate request-parent bindings and collision/read evidence. Acceptance: genuine successor equivocation causes durable identity/ticket/F2F revocation; forged evidence causes none.
7. **Make accepted persistence reliable (A10).** Retain failed batches/fail closed, coherent proof+ban capacity, tracked producer shutdown then drain. Acceptance: injected commit failure and SIGTERM during active streams produce no silently discarded accepted state.
8. **Implement admission and workload isolation (A09/A11).** Cheap filters first, bounded public sync, measured shared-resource limits and real VIP reservation; eliminate whole-root cloning and synchronous async-worker prune writes. Correct rejected single-lock HTTP codes.
9. **Unify eligibility and local participation (A11).** Common mature/presence/ban/suspension view for N, HRW and phase gates; verify refusal responsibility locally without hearsay slashing. Preserve no-penalty quorum abort and ordinary idle close behavior.
10. **Reconcile specs and client contract.** Remove contradictory legacy promises; specify verifiable committee membership and interoperable certificates. Run wallet-to-node tests with the actual human-money-core verifier rather than only the copied DTOs.
11. **Execute the production qualification matrix.** Real daemons at 1, 19, 20, 40 and 100 nodes; matured phase transitions without readiness overrides; cold gateway rotation; partition/merge; lazy/lying peers; disk faults/restart; VIP under public read/write flood. Record latency percentiles, RSS, queue occupancy, bandwidth and reconnect rates with explicit pass/fail thresholds. Existing green workspace tests remain necessary, not sufficient.

