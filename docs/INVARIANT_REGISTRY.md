# Invariant Registry and Per-Rule Acceptance Map

Date: 2026-10-20. Basis: DEC-089 / DB5-01–05. This is the canonical ownership
and acceptance index for the numbered corpus, not an executed test report.

## Authority, scope and evidence status

There are 25 numbered physical files in 22 families (00–20,99). The two03 files
are complementary; English15/16 are canonical and the German filenames redirect.
18/19 are informative analysis; their models confer no consensus authority.
The corpus mentions117 distinct IDs: **115 owned definitions/topics** below and
**two undefined retired references** (1101/1102). New0404 and1307 disambiguate existing
obligations; these counts are lexical traceability, not a coverage percentage.

Each row links the canonical meaning, affected enforcement boundary and a concrete
scenario with expected outcome. All rows have **selected/documented requirement**
status; their complete implementation and executed verification are **not audited
by this consolidation**. Rows with G1–G5 explicitly depend on the corresponding
[open proof gates](ARCHITECTURE_CONSOLIDATION.md#remaining-proof-gates); other rows
still require their stated premise and evidence. None is marked passed.

Boundary codes: **M** deterministic model/math/shared rule; **Q** actual receiving
QUIC server/collector; **H** actual HTTP/auth/listener; **C** shared protocol/L1
consumer/recipient verifier; **P** actual daemon/worker/storage/crash; **O** private
operator/process lifecycle. Network defenses require Q even where M/H also appear.
A row using M alone may require later integration coverage once its wire effect is
specified. Positive controls accompany every rejection case. Record exact revision,
command/environment, observed wire/state effects and result artifact before claiming
execution, following [Spec16](16_chaos_testing_and_simulation.md).

## Explicit legacy mappings and retired meanings

| Historical use | Current owner or disposition |
| --- | --- |
| Spec04 INV-1402 meant1024-byte evidence bound | **INV-0404** in Spec04 owns size; **INV-1402** in Spec14 owns durable fraud retention. No ambiguous alias. |
| Spec19 INV-1302 meant sender pacing | **INV-1307** in Spec13 owns pacing/protected budgets; **INV-1302** owns private local account tagging only. |
| Spec18 INV-1501 meant missing-count dampening | **INV-1501** in Spec15 owns0RTT-write refusal; local diagnostic feedback refers to **INV-0309/1701**, with no remote-failure sanctions. |
| Spec19 INV-1502 meant skip-and-rank21-replace | Retired behavior; **INV-1502** in Spec15 owns protected bounded data-plane priority. No replacement-vote successor alias. |
| INV-0304/0305 old per-record old certificate/global sync flag | Current verified live-state pull and per-shard readiness; neither requires inherited original-quorum bundles. |
| INV-0306/0307 old three-invitation/rank/24h-socket tenure | Retired authorization/tenure; current owners define demand recovery and safe autonomous activation. |
| INV-0309 missing-signer/piggyback penalties | Local bounded diagnostics only; neutral outcomes and passive heartbeat presence remain distinct. |
| INV-0202 absolute irreversible VOID / INV-0804 bare min-hash | Current class-aware admissibility/expiry rules; new valid higher-class support cannot be ignored. Exact S5 composition remains open. |
| INV-0604 previous L2 quorum-chain requirement | Withdrawn; owner/root/consumed-output causality follows L1, current live proof follows Spec03. |
| INV-0805 bitmap-only finality | Replaced by complete actual signature/full-key/current-context verification. |
| INV-1101 / INV-1102 | No definition recovered in the reviewed corpus. Retired undefined legacy references, **not aliases and not newly invented rules**. Former references in Spec05 now cite actual bounded-pacing/domain/gossip owners where applicable. |
| INV-1202 used as time-source citation in AGENTS | Corrected citation:1202 is atomic collision insertion; time follows Spec07/11 and explicit G4. |
| German15/16 duplicate rules | Stable paths redirect to authoritative English definitions; no independent language-specific policy. |

Other strengthened/retired historical guarantee wording is documented beside its
current rule (notably0501/0503/0509,0704/0707,1105,1601–05,1703). Stable IDs do not
preserve superseded claims. Consult DEC-053–089 and the [interview register](ARCHITECTURE_INTERVIEW_NOTES.md#21-current-decision-register-and-provenance).

## Owned rules and concrete acceptance scenarios

| ID | Canonical definition/topic | Boundary | Positive/adversarial scenario and required outcome |
| --- | --- | --- | --- |
| <a id="inv-0101"></a>INV-0101 | [Keyless Root](01_organischer_netzstart_und_topologie.md) | M | Two nodes derive the same configured genesis; no privileged signing key can change it. |
| <a id="inv-0102"></a>INV-0102 | [Symmetric Handshake](01_organischer_netzstart_und_topologie.md) | Q | N=1 and N=10000 use the same authenticated handshake; only eligibility/mode differs. |
| <a id="inv-0103"></a>INV-0103 | [Strict F2F Gossip Peering](01_organischer_netzstart_und_topologie.md) | Q | Friend gossip succeeds; learned non-friend gossip is discarded, without granting friendship from discovery. |
| <a id="inv-0104"></a>INV-0104 | [Authorized Co-Shard Connections](01_organischer_netzstart_und_topologie.md) | Q | Learned gateway RPC succeeds without a vote; unknown peer is refused and nonmember votes do not count. |
| <a id="inv-0105"></a>INV-0105 | [Throttling via F2F Edges & PoW](01_organischer_netzstart_und_topologie.md) | M/Q | Invalid work/ticket admission is rejected; valid admission is not counted as proof of <=6 Byzantine members. |
| <a id="inv-0106"></a>INV-0106 | [Bounded Bootstrap Discovery Exception](01_organischer_netzstart_und_topologie.md) | H/Q | Public directory returns advertised HTTP gateways only; discovery grants neither gossip nor voting authority. |
| <a id="inv-0201"></a>INV-0201 | [Atomic Original Choice](02_lock_zustandsautomat_und_konflikte.md) | Q/P | Concurrent incompatible same-output writes yield at most one original own choice; identical pending retries share it. |
| <a id="inv-0202"></a>INV-0202 | [No Unsupported Resurrection](02_lock_zustandsautomat_und_konflikte.md) | M/C | An unsupported low-hash loser stays unusable; valid higher-class new evidence is handled explicitly; expired roots never revive. |
| <a id="inv-0203"></a>INV-0203 | [Verified Incompatible Self-Proof](02_lock_zustandsautomat_und_konflikte.md) | Q/C | Genuine same-slot original double-signing sanctions its author; wrong purpose/key/network and lawful live reports do not. |
| <a id="inv-0204"></a>INV-0204 | [Physical Root Expiry](02_lock_zustandsautomat_und_konflikte.md) | P/Q | Long-lived root locks/choices survive until rootTTL+30s, then purge; grace never permits a late spend. |
| <a id="inv-0205"></a>INV-0205 | [Neutral Evidence-Backed Conflict](02_lock_zustandsautomat_und_konflikte.md) | Q/C | Valid conflict evidence is neutral; weak competing evidence cannot veto valid14/20. |
| <a id="inv-0206"></a>INV-0206 | [Exact Idempotent Promotion](02_lock_zustandsautomat_und_konflikte.md) | Q/H/C | Identical-content promotion obtains the required current quorum without TTL extension; network-size growth alone does not promote. |
| <a id="inv-0301"></a>INV-0301 | [Bounded Relevant Ingestion](03_routing_und_sharding.md) | Q/H | Unsolicited dead-history dump is refused; bounded relevant ancestry and authorized active pull remain possible. |
| <a id="inv-0302"></a>INV-0302 | [Root-Shard Locality](03_routing_und_sharding.md) | M/Q | Both split descendants derive the genesis shard; caller-chosen cross-shard routing cannot move their consumed slots. |
| <a id="inv-0303"></a>INV-0303 | [No Checkout Replacement or Failure Gossip](03_routing_und_sharding.md) | Q | 13/20 plus rank21 fails FINAL; cancellation/timeout creates no replacement vote or remote-failure gossip. |
| <a id="inv-0304"></a>INV-0304 | [Verified Active-State Pull](03_routing_und_sharding.md) | Q/P/M | Valid source-bound snapshot/deltas install; omitted live locks or14 empty unready sources cannot establish completeness (G2). |
| <a id="inv-0305"></a>INV-0305 | [Per-Shard Readiness Barrier](03_routing_und_sharding.md) | Q/P | Partially installed shard refuses write/live votes; independent ready shard continues; default unknown shard is NOT_READY. |
| <a id="inv-0306"></a>INV-0306 | [Demand-Triggered Recovery](03_routing_und_sharding.md) | Q | First legitimate demand starts one bounded shard job; concurrent demand coalesces without a payment queue or eager65536 sweep. |
| <a id="inv-0307"></a>INV-0307 | [Autonomous Membership, Separate Safe Activation](03_routing_und_sharding.md) | M/Q | New prospective HRW member cannot sign until safe activation; socket uptime or three invitations grants no authority (G1/G2). |
| <a id="inv-0308"></a>INV-0308 | [Bounded gossip; qualified percolation model](03_routing_und_sharding.md) | M/Q | Bound fan-out/TTL on declared topology; a fitted reach curve is never accepted as unconditional censorship proof. |
| <a id="inv-0309"></a>INV-0309 | [Local diagnostic feedback only](03_routing_und_sharding.md) | Q/O | Forged missing-signer bitmap changes no membership/ban; NOT_READY/capacity/cancel/idle remain neutral. |
| <a id="inv-0310"></a>INV-0310 | [One-source ordinary read routing](03_routing_und_sharding.md) | Q/H/C | Ordinary status queries one eligible peer; matching reply alone never releases payment; explicit clearance verifies14/20. |
| <a id="inv-0401"></a>INV-0401 | [Fixed Legacy Record and Bounded Envelopes](04_datenstrukturen_und_rust_typen.md) | Q/H/C | Count16 locators/64 locks boundaries and aggregate bytes/work are checked; legacy144 bytes is not the size of every DTO. |
| <a id="inv-0402"></a>INV-0402 | [Blind Economic Domain](04_datenstrukturen_und_rust_typen.md) | C/P | Collision DTO needs full keys/output IDs but no amount/currency/name; reject unexpected economic-domain dependency. |
| <a id="inv-0403"></a>INV-0403 | [Canonical Purpose Separation](04_datenstrukturen_und_rust_typen.md) | Q/C | Valid canonical purpose/context verifies; changed network/state/target/nonce or signature rejects; no bitmap-only success. |
| <a id="inv-0404"></a>INV-0404 | [Bounded Fraud Evidence](04_datenstrukturen_und_rust_typen.md) | Q/C | 1024-byte evidence-packet bound and checked aggregate envelope reject oversized/truncated/overflowing inputs before allocation. |
| <a id="inv-0501"></a>INV-0501 | [First-party fraud sanctions](05_spieltheorie_und_angriffsmatrix.md) | M/Q/C | Verified genuine incompatible originals sanction only the author; forged reporters/innocent losing signers remain unsanctioned. |
| <a id="inv-0502"></a>INV-0502 | [Conditional censorship tolerance](05_spieltheorie_und_angriffsmatrix.md) | M/Q | Exactly14 timely valid contributors succeed;13 plus withheld/unready extras fail without pool expansion. |
| <a id="inv-0503"></a>INV-0503 | [Bounded edge saturation](05_spieltheorie_und_angriffsmatrix.md) | M/Q | Newcomer/edge flood stays within bounded admission work on declared topology; no universal bot-exclusion claim. |
| <a id="inv-0504"></a>INV-0504 | [Asymmetric ingress brake](05_spieltheorie_und_angriffsmatrix.md) | H/Q | Insufficient work returns bounded429 feedback before asymmetric work; ingress flood does not consume protected shard/sync capacity. |
| <a id="inv-0505"></a>INV-0505 | [No garbage-history replication](05_spieltheorie_und_angriffsmatrix.md) | Q/H | Reject garbage history; permit required bounded active-state recovery and valid-prefix client reconciliation. |
| <a id="inv-0506"></a>INV-0506 | [Safe replay idempotency](05_spieltheorie_und_angriffsmatrix.md) | Q/P | Identical retries preserve exact durable decision; conflicting retries do not release an incompatible approval. |
| <a id="inv-0507"></a>INV-0507 | [Binary bootstrap rule](05_spieltheorie_und_angriffsmatrix.md) | M/Q/C | N19 uses13/19 PROVISIONAL; stableN20 requires14/20 FINAL; a partial FINAL cannot downgrade itself. |
| <a id="inv-0508"></a>INV-0508 | [No collateral client sanction](05_spieltheorie_und_angriffsmatrix.md) | H/Q | One abusive credential/session is limited without banning an innocent client sharing its CGNAT address. |
| <a id="inv-0509"></a>INV-0509 | [Heartbeat anti-flood safety](05_spieltheorie_und_angriffsmatrix.md) | Q | Identical replay consumes bounded receive work without duplicate forwarding/sanction; distinct claimed fraud needs its proof predicate. |
| <a id="inv-0601"></a>INV-0601 | [Bounded active-state retention](06_dumb_server_smart_client_flow.md) | P/C | Keep active exclusions/own choices to rootTTL+30s; completed client checkout requires no recursive L2 receipt archive. |
| <a id="inv-0602"></a>INV-0602 | [Atomic First-Seen](06_dumb_server_smart_client_flow.md) | Q/P | Queue-full refusal leaves RAM untouched; concurrent writes and pending duplicates cannot bypass atomic durable acknowledgment. |
| <a id="inv-0603"></a>INV-0603 | [Recipient safety](06_dumb_server_smart_client_flow.md) | H/C | Recipient with valid L1 and verified current quorum releases only after durable local purchase/voucher storage; gateway boolean fails. |
| <a id="inv-0604"></a>INV-0604 | [Authenticated causality](06_dumb_server_smart_client_flow.md) | H/C | Genesis is exclusively a `voucher_roots` anchor, never a lock. The unchanged L1 SST tag `Hash(prev_hash || sender_ephemeral_pub)` binds independent receiver/change outputs through a separately signed versioned output proof. Wrong predecessor/split-output/root authorization rejects; a valid L1 causal path needs no previous L2 quorum bundle. |
| <a id="inv-0605"></a>INV-0605 | [Exact quorum verification](06_dumb_server_smart_client_flow.md) | Q/H/C | Valid14 distinct current full keys succeed; invalid signature, duplicate, wrong context or unjustified supplied roster fails. |
| <a id="inv-0701"></a>INV-0701 | [Universal Argon2d admission](07_admission_und_wot_buergschaften.md) | M/Q | Validate canonical Argon2d identity/nonce/time work; malformed parameters, invalid ticket and immature successor cannot rank. |
| <a id="inv-0702"></a>INV-0702 | [Social entry edge](07_admission_und_wot_buergschaften.md) | Q/M | Configured reciprocal F2F edge permits gossip introduction; alleged human identity or one edge does not prove fault bounds. |
| <a id="inv-0703"></a>INV-0703 | [Observed maturation](07_admission_und_wot_buergschaften.md) | M/Q | A newly observed ticket with self-claimed old time stays immature; observed24h/admission history are checked. |
| <a id="inv-0704"></a>INV-0704 | [Passive reactivation](07_admission_und_wot_buergschaften.md) | M/Q | Three missed hourly slots exclude future selection; restart/reentry cannot skip recovery; exact boundaries remain G4. |
| <a id="inv-0705"></a>INV-0705 | [Metadata retention](07_admission_und_wot_buergschaften.md) | P/O | Dormant remote metadata follows60-day policy and direct-friend annual reactivation, without deleting still-live root locks. |
| <a id="inv-0706"></a>INV-0706 | [First-party identity revocation](07_admission_und_wot_buergschaften.md) | Q/C | Full first-party fraud revokes identity/ticket/edges; accusation, topology and timeout do not. |
| <a id="inv-0707"></a>INV-0707 | [Safe successor readiness](07_admission_und_wot_buergschaften.md) | Q/P | New HRW responsibility triggers safe demand recovery; imported bytes alone do not authorize signatures. |
| <a id="inv-0708"></a>INV-0708 | [Transport-native leave](07_admission_und_wot_buergschaften.md) | Q | Ordinary transport close reclaims resources without new leave gossip or in-flight electorate replacement. |
| <a id="inv-0709"></a>INV-0709 | [Identity-stable ticket renewal](07_admission_und_wot_buergschaften.md) | M/Q | Same-key stronger successor follows monotonic work and24h wall; key replacement inherits no friendship or maturity. |
| <a id="inv-0710"></a>INV-0710 | [Five-finger operating doctrine](07_admission_und_wot_buergschaften.md) | M/O | Social operating checklist requires no financial deposit; topology compliance is not a mathematical Sybil bound. |
| <a id="inv-0801"></a>INV-0801 | [Bounded shard size](08_topologie_dynamik_und_netz_merge.md) | M/Q | Committee includes eligible self in<=20 total; N<20 covers all shards subject to readiness; duplicates do not add seats. |
| <a id="inv-0802"></a>INV-0802 | [Binary status eligibility](08_topologie_dynamik_und_netz_merge.md) | M/C | Binary mode/stability plus real quorum required; no third tier, global irreversibility or timer-only promotion. |
| <a id="inv-0803"></a>INV-0803 | [Controlled replication](08_topologie_dynamik_und_netz_merge.md) | Q/P | Authorized active pull succeeds with complete durable installation; unsolicited history/lock gossip remains refused. |
| <a id="inv-0804"></a>INV-0804 | [Admissible class-first resolution](08_topologie_dynamik_und_netz_merge.md) | M/Q/C | Higher valid class beats lower even with larger hash; equal highest class resolves min-hash; class0 cannot seize confirmed state. |
| <a id="inv-0805"></a>INV-0805 | [Verified quorum, not bitmap self-proof](08_topologie_dynamik_und_netz_merge.md) | Q/C | 14 verified full-key members succeed; count_ones>=14 with forged/unauthorized signatures fails. |
| <a id="inv-0806"></a>INV-0806 | [Domain compatibility](08_topologie_dynamik_und_netz_merge.md) | M/Q | Wrong authenticated network domain stays isolated; founding manifest alone cannot authenticate current roster/adoption (G1). |
| <a id="inv-0901"></a>INV-0901 | [Byte-Years accounting unit](09_netzwerk_thermometer_und_dynamische_quotas.md) | M/Q/P | Known root lifetime determines byte-time charge; supplied shorter/longer successor TTL cannot evade/extend accounting. |
| <a id="inv-0902"></a>INV-0902 | [Hard floor baseline ($960.000\,\text{BJ/day}$)](09_netzwerk_thermometer_und_dynamische_quotas.md) | M/Q | Computed write baseline never falls below960000 Byte-Years/day; test boundary and overflow-safe arithmetic. |
| <a id="inv-0903"></a>INV-0903 | [28-day median smoothing](09_netzwerk_thermometer_und_dynamische_quotas.md) | M/Q | 28 day slots replace/roll over deterministically; high event count cannot accelerate physical-time decay. |
| <a id="inv-0904"></a>INV-0904 | [24h daily budget](09_netzwerk_thermometer_und_dynamische_quotas.md) | M/Q | Day rollover resets scoped budget correctly; epoch_day never changes committee tenure/authority. |
| <a id="inv-0905"></a>INV-0905 | [Whale cap](09_netzwerk_thermometer_und_dynamische_quotas.md) | M/Q | K<=5 cap applies at/beyond boundary; retries/overflow do not exceed the admitted ceiling. |
| <a id="inv-0906"></a>INV-0906 | [Local enforcement](09_netzwerk_thermometer_und_dynamische_quotas.md) | Q/H | Over-quota receiving shard returns specified refusal/drop without state pollution, global blame or presence malus. |
| <a id="inv-0907"></a>INV-0907 | [Seed initialization for new nodes](09_netzwerk_thermometer_und_dynamische_quotas.md) | M/Q | Cold start fills28 slots using bounded eligible peer observations and floor; seed is not authoritative membership. |
| <a id="inv-0908"></a>INV-0908 | [Fast re-seed on network merges](09_netzwerk_thermometer_und_dynamische_quotas.md) | M/Q | Declared abrupt growth re-seeds once under the documented rule; observer disagreement never authorizes a ban. |
| <a id="inv-0909"></a>INV-0909 | [Three-zone local diagnostics](09_netzwerk_thermometer_und_dynamische_quotas.md) | Q/O | Below75%,75–125%,above125% change only local diagnosis/backoff, never guilt, presence or committee. |
| <a id="inv-0910"></a>INV-0910 | [Read hard floor ($50.000\,\text{reads/day}$)](09_netzwerk_thermometer_und_dynamische_quotas.md) | M/H/Q | Computed read floor stays50000/day while physical capacity refusals remain honest; reads reserve no write queue. |
| <a id="inv-0911"></a>INV-0911 | [28-day read median smoothing](09_netzwerk_thermometer_und_dynamische_quotas.md) | M/Q | Separate read28-day ring handles rollover and scraping without corrupting write budget or event-driven decay. |
| <a id="inv-0912"></a>INV-0912 | [Read Whale Brake ($K \le 5{,}0$)](09_netzwerk_thermometer_und_dynamische_quotas.md) | M/Q | Read multiplier capped at5 with checked counters; flood cannot consume protected write/sync service. |
| <a id="inv-0913"></a>INV-0913 | [Pre-filter quota check for read CPU](09_netzwerk_thermometer_und_dynamische_quotas.md) | Q/H | Exhausted read credit rejects before lookup/signature work; receiving QUIC enforces it independently of HTTP. |
| <a id="inv-1001"></a>INV-1001 | [Fixed Encoded Header](10_p2p_wire_format_und_session_framing.md) | Q/C | Exactly32 checked little-endian header bytes decode; short/oversized/overflow lengths fail without unsafe casts. |
| <a id="inv-1002"></a>INV-1002 | [Magic Constant](10_p2p_wire_format_und_session_framing.md) | Q | HUMO magic passes; changed magic is rejected before payload/crypto work. |
| <a id="inv-1003"></a>INV-1003 | [Complete Canonical Domain Binding](10_p2p_wire_format_und_session_framing.md) | Q/C | Correct registered domain verifies; changed class/network/request/purpose invalidates signatures. |
| <a id="inv-1004"></a>INV-1004 | [No Early-Data Mutation](10_p2p_wire_format_und_session_framing.md) | Q | Resumed read may serve bounded data;0RTT lock/fraud mutation receives explicit early-data-write refusal. |
| <a id="inv-1005"></a>INV-1005 | [Receiver-Enforced Accounting](10_p2p_wire_format_und_session_framing.md) | Q | Authenticated over-quota sender is refused at shard even when gateway filtering is bypassed. |
| <a id="inv-1006"></a>INV-1006 | [Two F2F Gossip Streams](10_p2p_wire_format_und_session_framing.md) | Q | Only friend presence and verified fraud are gossiped; lock/sync payload is not forwarded epidemically. |
| <a id="inv-1007"></a>INV-1007 | [Authenticated Ingress Context](10_p2p_wire_format_und_session_framing.md) | Q/C | Identical signed envelope/reordering is legal; genuine same-context incompatible originals need both signatures before sanction. |
| <a id="inv-1008"></a>INV-1008 | [Bounded Local Reciprocity](10_p2p_wire_format_und_session_framing.md) | Q/O | Local backoff on actual failure leaves neutral outcomes, passive presence and frozen membership untouched. |
| <a id="inv-1009"></a>INV-1009 | [Read-Only Replay-Safe Pull](10_p2p_wire_format_und_session_framing.md) | Q/P | Replayed pull request serves bounded read-only data; it neither installs state nor changes readiness/own choices. |
| <a id="inv-1104"></a>INV-1104 | [First-seen newcomer pacing](11_organische_praesenz_und_dunbar_gossip.md) | Q/M | Concurrent first-seen flood coalesces full identities within bounded queues; known peers gain no unlimited forwarding. |
| <a id="inv-1105"></a>INV-1105 | [Gossip percolation model — qualified legacy claim](11_organische_praesenz_und_dunbar_gossip.md) | M/Q | Reproduce a topology-specific reach experiment with stated TTL/fan-out; fitted73.1% is never a universal pass criterion. |
| <a id="inv-1106"></a>INV-1106 | [Cryptographic gossip domain separation](11_organische_praesenz_und_dunbar_gossip.md) | Q/C | Correct network heartbeat verifies; cross-domain relay from even a friend fails local verification. |
| <a id="inv-1201"></a>INV-1201 | [RAM Processing, Durable Signature Release](12_lock_storage_und_ram_index.md) | Q/P | Slow worker delays original release; exact successful acknowledgment permits it with no RAM guard held across await. |
| <a id="inv-1202"></a>INV-1202 | [Atomic First-Seen on `parent_lock`](12_lock_storage_und_ram_index.md) | M/Q/P | Concurrent same-parent conflicting inserts have one atomic winner; queue reservation precedes mutation. |
| <a id="inv-1203"></a>INV-1203 | [Deterministic Eviction via Root Expiry](12_lock_storage_und_ram_index.md) | P/Q | Live root older than24h remains; rootTTL+30s physically purges both locks and own choices without tombstones. |
| <a id="inv-1204"></a>INV-1204 | [Space-Time Accounting](12_lock_storage_und_ram_index.md) | M/P | Declared footprint/time charge is checked against measured layout;144/192/224 estimates cannot silently omit safety metadata. |
| <a id="inv-1205"></a>INV-1205 | [Durable Idempotency](12_lock_storage_und_ram_index.md) | Q/P | Pending duplicate waits within bounds; committed duplicate returns exact own decision; sync cannot invent its missing original approval. |
| <a id="inv-1206"></a>INV-1206 | [Ingress Time Window](12_lock_storage_und_ram_index.md) | M/Q | Reject invalid minimum lead/root-bound expiry; entry freshness is not rechecked as a new wallet gate after commit (G4). |
| <a id="inv-1301"></a>INV-1301 | [Bounded VIP isolation](13_client_ingress_und_access_tiering.md) | H/Q | Anonymous flood reaches bounded refusal while reserved admitted service progresses under stated workload; no universal SLA assertion. |
| <a id="inv-1302"></a>INV-1302 | [Private local account tagging](13_client_ingress_und_access_tiering.md) | H/P | Hashed random-secret tags authorize their tier; public NodePubKey or exposed account tag is not a bearer secret. |
| <a id="inv-1303"></a>INV-1303 | [Stateless Free-tier work](13_client_ingress_und_access_tiering.md) | H/Q | Puzzle recomputes from canonical slot/parent/nonce without issued_challenges or mandatory used-solution memory. |
| <a id="inv-1304"></a>INV-1304 | [Asymmetric work barrier](13_client_ingress_und_access_tiering.md) | M/H | Known correct work succeeds and insufficient work fails with bounded verification; measure rather than assert submicrosecond total cost. |
| <a id="inv-1305"></a>INV-1305 | [Autonomous emergency brake](13_client_ingress_und_access_tiering.md) | H/O | Local emergency difficulty returns429/X-Required-Difficulty consistently without global election or identity ban. |
| <a id="inv-1306"></a>INV-1306 | [Scoped reciprocal service](13_client_ingress_und_access_tiering.md) | Q/H | Internal service pacing and client token authentication stay distinct; node peering never grants public-client PoW exemption. |
| <a id="inv-1307"></a>INV-1307 | [Bounded sender pacing and protected internal budgets](13_client_ingress_und_access_tiering.md) | Q/H/P | Public/read/retry saturation cannot exhaust separately reserved bounded shard/sync budgets; outgoing work and waiters remain capped. |
| <a id="inv-1401"></a>INV-1401 | [Asynchronous I/O, Durable-before-Release](14_node_persistenz_und_redb_speicher.md) | Q/P | Precommit wire observation sees no binding vote; postcommit exact acknowledgment permits release without runtime blocking. |
| <a id="inv-1402"></a>INV-1402 | [Non-Losability of Slashing Proofs](14_node_persistenz_und_redb_speicher.md) | P/Q | Validated fraud persists before its only RAM copy drops; failed persistence reports/gates honestly rather than losing evidence. |
| <a id="inv-1403"></a>INV-1403 | [Pure-Rust Persistence](14_node_persistenz_und_redb_speicher.md) | M/P | Dependency/build inspection confirms permitted pure-Rust storage integration; document-level assertion is insufficient. |
| <a id="inv-1404"></a>INV-1404 | [Deterministic Restart](14_node_persistenz_und_redb_speicher.md) | P/Q | Real daemon crash after durable commit restores exact own decision and affected-shard readiness gate; empty reset never signs. |
| <a id="inv-1405"></a>INV-1405 | [Atomic Lock and Own-Choice Commit](14_node_persistenz_und_redb_speicher.md) | P/Q | Inject crash at transaction edges; lock and immutable choice recover together, never one released without the other. |
| <a id="inv-1406"></a>INV-1406 | [No Release Through Pending Paths](14_node_persistenz_und_redb_speicher.md) | Q/H/P | Pending RAM, duplicate, status and self-vote paths all fail to release countable evidence before the same durability gate. |
| <a id="inv-1501"></a>INV-1501 | [Zero 0-RTT Writes](15_p2p_transport_and_connection_management.md) | Q | 0RTT read is bounded;0RTT write is rejected by receiving shard regardless of resumption/client behavior. |
| <a id="inv-1502"></a>INV-1502 | [Data-Plane Priority](15_p2p_transport_and_connection_management.md) | Q/H | Bounded ingress/CPU flood preserves reserved shard/sync work; priority labels with a saturated shared queue are insufficient. |
| <a id="inv-1503"></a>INV-1503 | [Non-Blocking Network Threads](15_p2p_transport_and_connection_management.md) | Q/P | Slow disk/asymmetric verification does not block network runtime or retain RAM guards; bounded worker pressure rejects promptly. |
| <a id="inv-1504"></a>INV-1504 | [Transport Replay Defense](15_p2p_transport_and_connection_management.md) | Q/C | Wrong session/sequence/purpose/request replay fails; legal multiplexing/reordering/identical retries do not falsely slash. |
| <a id="inv-1505"></a>INV-1505 | [Transport-Native Teardown](15_p2p_transport_and_connection_management.md) | Q/P | LRU/15s shard idle and quorum cancellation reclaim bounded sessions without peer malus; F2F stays persistent. |
| <a id="inv-1601"></a>INV-1601 | [Conditional regional partition healing](16_chaos_testing_and_simulation.md) | M/Q/C | Partition/turnover schedules converge only on same admissible support; class-first ordering and conditional premises are recorded. |
| <a id="inv-1602"></a>INV-1602 | [Verified first-party fraud, without framing](16_chaos_testing_and_simulation.md) | M/Q/C | Genuine same-slot original equivocation sanctions; wrong keys/context/forged reports and honest merged live reports do not. |
| <a id="inv-1603"></a>INV-1603 | [Admission defenses under explicit adversary assumptions](16_chaos_testing_and_simulation.md) | M/Q/H | Admission/bridge/grinding attacks obey declared bounds; no simulated operator trust substitutes for justified electorate. |
| <a id="inv-1604"></a>INV-1604 | [Bounded resources and measured service isolation](16_chaos_testing_and_simulation.md) | M/Q/H/P | Public+read+sync floods and disk stalls respect explicit bounds; measure isolation/timing under declared hardware/load. |
| <a id="inv-1605"></a>INV-1605 | [Complete, justified state transfer before readiness](16_chaos_testing_and_simulation.md) | M/Q/P | 8+6+6 and agreeing empty new sources cannot establish completeness; automatic recovery installs or remains NOT_READY (G2). |
| <a id="inv-1701"></a>INV-1701 | [Non-authoritative telemetry](17_topologie_telemetrie_und_social_defense.md) | H/O/Q | Private diagnostic warning never bans/slashes or authorizes electorate change; every public alias denies diagnostic access. |
| <a id="inv-1702"></a>INV-1702 | [Legitimate multiple-node operation](17_topologie_telemetrie_und_social_defense.md) | M/Q | Multiple admitted nodes of one operator remain permitted; edge count alone grants no security/Byzantine-bound proof. |
| <a id="inv-1703"></a>INV-1703 | [Local revocation and passive presence](17_topologie_telemetrie_und_social_defense.md) | M/Q | Human edge removal affects that edge; three missed hourly slots govern future selection, not arbitrary8–24h claims. |
| <a id="inv-1704"></a>INV-1704 | [Private ingress transparency](17_topologie_telemetrie_und_social_defense.md) | H/O | Authorized operator sees bounded neighbor-load diagnostics; public aliases/subroutes reveal none and emit no blame gossip. |
| <a id="inv-1705"></a>INV-1705 | [Private shard-service transparency](17_topologie_telemetrie_und_social_defense.md) | H/O/P | Private self-diagnostics separate collision/commit/ack delay; poor I/O never licenses early signatures. |

## Accepted contracts without a dedicated new invariant ID

No mass renumbering is required to trace these selected obligations. Their decision
IDs and interfaces remain authoritative alongside the owned rules above.

| Contract | Decisions/owners | Concrete required observation |
| --- | --- | --- |
| Fresh live-state proof versus original write approval | DEC-080–084; Spec03 status,0403,0605,1406 | Recipient challenge succeeds once in its exact target/network/purpose; old nonce or purpose transplant cannot release payment. Lawful canonicalB report after own-choiceA is not fraud. |
| Frozen<=20/14/800ms | DEC-008/026/080/084; Spec03 routing,0502,0805 |14 valid authorized distinct keys succeed;13 plus rank21 fails; collector exits at quorum/impossibility/deadline; all unavailable causes share six headroom. |
| No old-quorum archive | DEC-070/072/083; Spec03,0601,1405 | Full signer turnover alone does not invalidate a safely transferred active lock. Current live quorum clearance needs no departed original signatures; own choices remain durable. |
| Bounded durable worker operation | DEC-087/088; Spec14 §4.1,1307,1401–06 | Single-load batch seals by bounded age; retry flood coalesces bounded waiters; a late commit survives deadline with no rollback or early signature. |
| Wallet/purchase safety and retry | DEC-060/068/071–073; Spec06 | Wallet intent precedes first send; merchant durably stores L1 voucher/purchase before release. Retry preserves exact payload/T0; no automatic alternative tender; post-window recovery is read-only. |
| Real stop completion | DEC-074–076; Spec20,1604 | Repeated stop preserves original drain deadline; CLI success requires independently observed process exit and DB reopen, not accepted stop RPC. |
| Private diagnostic surface | DEC-077; Spec17/20 | Every metrics/dashboard/topology alias/subroute/listener denies public access; authorized operator can inspect bounded diagnostics without any automatic sanction. |
| Public discovery and client cache | DEC-078/079; Spec01/20 | Directory exposes only explicitly advertised HTTP gateways without private tokens/topology. Stale-address fallback is bounded client logic, never server-side cache-fallback policy. |

## Audit/delivery record template

For each ID/contract record: requirement/decision; canonical version; algorithm
and assumptions or linked counterexample; actual inspected source revision and
call path; test positive/negative inputs; expected wire result and state effects;
executed command/environment; observed result/artifact and limitations. Keep these
four statuses independent: selected, justified design, implemented, executed.
This document supplies the requirement/scenario mapping only. Existing test names
in Spec16 are inspection candidates; concurrent source edits have no coverage
status here. Material open proof gates block unconditional acceptance even if a
narrow test passes.
