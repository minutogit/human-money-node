# 🗣️ HuMoCo Bilingual Translation Glossary & Domain Dictionary (DE ↔ EN)

> **Purpose:** This document is the authoritative bilingual reference for developers, operators, and AI agents.  
> **Rule:** The human maintainer communicates in German; all codebase identifiers, commits, issues, pull requests, and public documentation are in idiomatic English.

> **Review draft added 2026-10-15:** Sections 1–2 retain the existing terminology
> rules. [Section 3](#3-basic-concepts--review-draft) adds proposed definitions for
> shared understanding; these additions await maintainer review. They do not select
> protocol mechanisms or override specifications. [Section 4](#4-ambiguities-to-review)
> records ambiguities to settle before repository-wide terminology alignment.

Use this file as the shared dictionary rather than creating a second competing
glossary. German headwords support conversation; English terms and definitions
support repository documentation. Code identifiers remain unchanged during review.

---

## 🧭 1. Canonical Domain Mapping Table (Kanonische Begriffs-Tabelle)

| German (Deutscher Begriff) | Canonical English Term | Context & Technical Semantics (Bedeutung) | Forbidden / False Friends (Verboten) |
|---|---|---|---|
| **Sperrregister** | **Collision Lock Registry** | Asynchronous, history-stateless collision registry for double-spend prevention (`parent_lock -> child_lock`; clients custody history, registry holds live collision locks). | *lock register, blocking registry* |
| **Gutschein-Wurzel** | **Voucher Root / Root Anchor** | Origin lock (`root.valid_until`) anchoring TTL for all subsequent child locks. | *voucher tree, coupon origin* |
| **Kassenpfad / Hot-Path** | **PoS Hot-Path / Checkout Path** | In-memory collision check ($< 1\,\mu\text{s}$) with latency SLA $< 5\,\text{ms}$. | *register path, cashbox flow* |
| **Dorf-Merge** | **Village Merge / Local Mesh Merge** | Deterministic convergence of small isolated clusters ($N=1\dots19$) into global mesh via $\min(H_{\text{canon}})$. | *village fusion, rural merge* |
| **Community-Mesh / Insel-Netz** | **Community Mesh / Island Network** | Autonomous sub-quorum mesh ($N = 1\dots19$) operating on adaptive provisional quorums $Q(N) = \lfloor \frac{2}{3} N \rfloor + 1$ (Status `PROVISIONAL` 🟡, all nodes validate all 65,536 shards). | *village mode, local cluster* |
| **Weltnetz-Föderation** | **World Network / Federated Sharding** | Full BFT consensus ($N \ge 20$) with fixed 14/20 quorum (Status `FINAL` 🟢) and dynamic HRW sharding. | *global chain, world cluster* |
| **Knoten-Souveränität** | **Node Sovereignty** | Node operators maintain absolute veto power; zero background auto-updates. | *node dominance, node power* |
| **First-Party Evidence** | **First-Party Evidence Doctrine** | Ban and slashing only on undisputed cryptographic self-proof (`EquivocationProof`). | *own evidence, first hand proof* |
| **Hörensagen-Verbot** | **Anti-Hearsay Principle** | Ban on network gossip about "bad peers"; prevents death spirals. | *hearsay prohibition* |
| **Todes-Spirale** | **Cascading Death Spiral** | Feedback cascade of mutual bans, retries, and traffic blow-ups ($\Delta \text{Load} \le 0$). | *deadly spiral* |
| **Keine Kautionen / Staking** | **Zero Financial Deposits / No Staking** | No economic staking or deposit slashing; penalties are purely identity- and reputation-based. | *deposit slashing, bond loss* |
| **Reputationsvernichtung** | **Identity Revocation & WoT Severance** | Permanent ban of `NodePubKey`, invalidation of `HrwRoutingId` shard ticket, severing of all F2F edges. | *reputation destruction* |
| **Netzwerk-Thermometer** | **Network Thermometer** | Decentralized median load feedback adjusting PoW difficulty dynamically. | *network heat meter* |
| **Byte-Jahre** | **Byte-Years (Storage-Time Product)** | Accounting unit for storage reservation: $144\,\text{Bytes} \times \text{TTL}$. | *byte years product* |
| **5x Wal-Bremse** | **5x Whale Brake** | Exponential rate dampener against abusive burst volume. | *whale break, whale dampener* |
| **Subtraktion vor Konstruktion** | **Subtraction before Construction** | Core design doctrine: Perfection is achieved when nothing more can be removed. | *subtraction before building* |
| **Zustandslosigkeit** | **Stateless Verification** | Nodes do not store full transaction histories; clients carry proof chains. | *statelessness without proof* |
| **Schmarotzer / Trittbrettfahrer** | **Free-Riders / Free-Riding** | Peers consuming network bandwidth without reciprocating by signing shard attestations or serving shard RPC requests. | *parasites, hitchhikers* |
| **Inkubationswand (24h)** | **24h Shard Ticket Incubation Wall** | Mined Argon2d shard tickets mature for 24h before participating in HRW scoring. | *incubation barrier* |
| **Besen-Topologie** | **Broom Topology** | Single-bridge botnet fan-in structure where many malicious nodes route through a single bridge. | *broom network* |
| **Bürgschaft / WoT-Bürgschaft** | **Voucher Endorsement / Admission Sponsor** | Web-of-Trust vouching for new node admission into the mesh. | *deposit guarantee, bail* |
| **Kausalitätskette** | **Causality ProofChain** | Client-side sequence of cryptographic locks proving origin and lineage. | *causality string* |
| **Verdichtetes Digest** | **Compact Shard Digest** | Lightweight bitset/hash summary of lock state for efficient pull sync. | *compressed summary* |
| **Vorrang-Kontingent** | **Priority / VIP Quota Tier** | High-priority ingress queue allocated via Byte-Year quota tokens for merchants. | *priority contingent* |

---

## 🤖 2. Directives for AI Agents & LLMs (Instruktionen für KI-Agenten)

When interacting with this codebase:

1. **Bilingual Sensitivity:**
   - When the user communicates in German (e.g. *"Prüfe den Kassenpfad und die Wal-Bremse"*), resolve the German terms to the canonical Rust implementations (`ingress::tier`, `storage::RamIndex`).
   - Answer the user in natural, clear **German**.
   - Write all code, Rustdoc comments (`///`), git commits, and public markdown files in idiomatic **English**.
2. **Invariant: Zero Financial Deposits:**
   - Never introduce "deposits", "staking", "collateral", or "slashing of funds". HuMoCo Layer 2 is a blind collision register without balances or accounts.
3. **Preserve Code Identifiers:**
   - Never translate code symbols (`WireHeader`, `LockRecord`, `CURRENT_PROTOCOL_VERSION`, `min_compat_ver`).
4. **Preserve Math & Diagrams:**
   - Keep LaTeX blocks ($\min(H_{\text{canon}})$) and Mermaid syntax intact.

---

## 3. Basic concepts — review draft

Each G-ID identifies one proposed meaning for review. An entry defines vocabulary,
not a new requirement or an implementation guarantee. “Interview direction” means
a recorded requirement/design direction whose implementation or proof may be pending.
Sources below identify the inspected basis; discrepancies are retained in section 4.

### 3.1 Participants and roles

| ID | German headword | English term | Meaning and boundary |
| --- | --- | --- | --- |
| G-001 | Client | Client | Software using public ingress, such as a wallet or merchant terminal. A client is a protocol role, not a P2P node identity. |
| G-002 | Wallet | Wallet | Client software that holds keys and voucher history and prepares signed requests. Custody of money and full history belongs on the client side. |
| G-003 | Kassenterminal | Point-of-Sale terminal / PoS terminal | Merchant-side client involved in checkout and recipient verification. “PoS” here means Point of Sale; HuMoCo L2 has no Proof of Stake. |
| G-004 | Knoten | Node | A running HuMoCo daemon with a cryptographic node identity. One process may perform gateway and shard-service roles. |
| G-005 | Gateway | Gateway | Public client-facing role that checks ingress admission, routes requests and collects shard replies. Its own assertion is not a substitute for verifiable shard evidence. Gateway and shard service are distinct roles even when co-located. |
| G-006 | Shard-Mitglied | Shard committee member | A node whose vote is eligible in the applicable committee. Learning about a node, opening a connection or copying shard data does not by itself establish voting eligibility. |
| G-007 | Knotenidentität | Node identity / `NodePubKey` | Full Ed25519 public key used as the identity anchor for node authentication, friendship and vote attribution. An IP address, short `node_id` or routing ticket is not this identity. |
| G-008 | Betreiber | Node operator | Human or organization administering a node, retaining stop/configuration authority. A node public key does not by itself identify a real person. |

Basis: `AGENTS.md` §§1–3; [Spec 00](00_architektur_und_mental_model.md) §2;
[Spec 06](06_dumb_server_smart_client_flow.md) §1;
[`AttestationDto`](../crates/humoco-node/src/api/dto.rs).

### 3.2 Voucher, locks and causality

| ID | German headword | English term | Meaning and boundary |
| --- | --- | --- | --- |
| G-009 | Gutschein | Voucher | Client-custodied Layer-1 value/history object. L2 records collision constraints without knowing its amount, currency, accounts or real-world owner. |
| G-010 | Gutschein-Wurzel | Voucher Root / Root Anchor | The voucher's genesis anchor. Its authenticated `root.valid_until` bounds the lifetime of successor locks. This is distinct from the genesis of the node network. |
| G-011 | Ursprungssperre | Origin lock / Genesis lock | Initial L2 lock for a root, establishing the origin case for later locks. “Genesis certificate” needs qualification: root-origin evidence and node quorum evidence have different meanings. Exact shared formats remain under design. |
| G-012 | Lock / Sperreintrag | Collision lock / Lock entry | A cryptographic registry entry binding a consumed predecessor/output to a successor. It prevents another conflicting use of the same spend slot. A lock is not the entire voucher or payment history. |
| G-013 | Lock-Datensatz | Lock record | The stored representation of a lock and associated fields. `LockRecord`, `L2LockEntry` and `StoredLock` occur in different models/layers; the term does not imply identical layouts, signatures or evidentiary strength. |
| G-014 | Eltern-Lock / Vorgängerbezug | Parent lock / Parent reference | The predecessor lock and reference to the predecessor/output being consumed. “Eltern-Lock” is a proposed German name from maintainer review. Distinguish the parent record from its specific spend slot: a split can create independent outputs of the same parent. `parent_lock` remains the code term; exact split/output binding is still a protocol-design obligation. |
| G-015 | Nachfolger / Ausgabe | Successor / Output | A result that a later lock can consume. A split can create distinct outputs; spending independent outputs is not itself a collision. |
| G-016 | Lock-Kennung | Lock identifier / `lock_id` | Identifier of a particular lock. Same parent plus same lock identity is an idempotent retry; same spend slot plus a different incompatible lock is a collision. Do not assume every historical `t_id` or hash field has the same encoding. |
| G-017 | Kausalitätsnachweis | Causality proof | Evidence that a lock is authorized by the required predecessor/output and root. A valid signature on an unrelated record does not establish the required ancestry. |
| G-018 | Kausalitätskette | Causality ProofChain | Client-held evidence along the required ancestry path. A full voucher can branch; one target's proof path need not include unrelated sibling branches. This is distinct from node membership/transition history. |
| G-019 | Kollision | Collision / Conflicting spend | Two incompatible locks consume the same spend slot. Repeating an identical lock is not a collision. A collision alone is not proof that a shard node double-signed. |
| G-020 | Idempotenz | Idempotency | Repeating the same signed operation preserves its identity and effect. Retry does not authorize a replacement spend, undo a previous lock or imply that a previous timeout meant failure. |

Basis: `AGENTS.md` rules 3 and 10; Specs [00](00_architektur_und_mental_model.md) §§1–3,
[06](06_dumb_server_smart_client_flow.md) §§3/7;
[`types.rs`](../crates/humoco-sim-core/src/types.rs) (`LockRecord`);
[`hmc.rs`](../crates/humoco-node/src/api/hmc.rs) (`L2LockEntry`);
interview DEC-005/009/013/014 and OPEN-06.

### 3.3 Signatures, votes and certificates

| ID | German headword | English term | Meaning and boundary |
| --- | --- | --- | --- |
| G-021 | Antragstellersignatur | Request authorization signature | Signature authorizing the client's proposed lock under its relevant spending key. The spending client prepares it before gateway forwarding; forwarding is not the act this term names. Inspected HMC fields are `layer2_signature` and `sender_ephemeral_pub`, checked by `verify_l2_lock_signature`. Distinguish client authorization from gateway transport authentication, ingress `auth_signature`, and a shard node's vote. It does not establish registry quorum acceptance. |
| G-022 | Knotenbestätigung / Stimme | Node attestation / Vote | One node's signed approval of a specific lock in the applicable signing context. `Attestation` and `AttestationDto` are existing representations. One valid vote does not establish a quorum. |
| G-023 | Bindende Signierentscheidung | Binding signing decision | A node's safety-relevant choice that constrains later conflicting signing. Interview DEC-029/033 requires durable storage before releasing its binding vote. This is distinct from a client's intent or a temporary queue-capacity reservation. |
| G-024 | Quorum | Quorum | Required support from distinct eligible committee identities. FINAL uses 14 of the frozen 20-member committee; provisional operation uses `floor(2N/3) + 1` for `N < 20`. Duplicate signatures do not add identities. |
| G-025 | Komitee / zuständige Knotengruppe | Shard committee | The set of eligible voting identities for the relevant shard/operation. “Twenty” describes the full FINAL committee; “fourteen” describes sufficient votes, not a separately chosen permanent committee. |
| G-026 | Komitee-Snapshot | Committee snapshot | A frozen list of eligible identities/tickets for one checkout attempt. Freezing makes that attempt's signer set fixed; it does not itself authenticate the list or prove safe changes over time. |
| G-027 | Quorum-Nachweis / Quorum-Zertifikat | Quorum certificate | Collected valid node attestations meeting the threshold for the same lock and applicable context, checked against justified membership. `QuorumCertificate` / `QuorumCertificateDto` are existing names. This is a bundle of node confirmations; exact canonical formats and transition authority remain under review. |
| G-028 | Signierkontext | Signing context | The domain and fields that determine what a signature approves, such as network, shard, spend slot, lock and status. Exact fields and binding rules must be checked per message; this definition does not claim that every existing type binds them all. |
| G-029 | TLS-Zertifikat | TLS certificate | Transport-authentication object used in establishing a secured connection. It is distinct from G-027: authenticating a connection does not establish payment quorum acceptance. |

Basis: Specs [03](03_routing_und_sharding.md) §2.1,
[06](06_dumb_server_smart_client_flow.md) §6,
[15](15_p2p_transport_and_connection_management.md);
[`client_flow.rs`](../crates/humoco-sim-core/src/client_flow.rs) (`QuorumCertificate`);
[`dto.rs`](../crates/humoco-node/src/api/dto.rs);
interview DEC-029/033 and §7.17.

Naming review for G-021 (2026-10-15; no selection yet): the maintainer proposes
“Lock-Signatur” and points to the wider authorization evidence: reveal the public
key matching the predecessor output's key commitment and provide the corresponding
request signature. These are different evidence components. Disclosure of a public
key alone does not prove control of its private key; the valid signature supplies
that part. This describes the intended authorization relationship, not a newly
audited claim that all current paths enforce every predecessor/output check.

Candidates for the signature itself: **Lock-Signatur**, **Freigabesignatur**.
Candidates for the combined authorization evidence: **Freigabenachweis**,
**Berechtigungsnachweis**, **Lock-Autorisierung**. Proposed naming distinction:
“Lock-Signatur” for the individual signature and “Freigabenachweis” for the combined
evidence. Neither name implies quorum acceptance or that every lock-validity check
has passed. Exact proof packaging and canonical fields remain open; no new proof
object or wire message is selected merely by discussing vocabulary.

### 3.4 Outcomes, readiness and uncertainty

| ID | German headword | English term | Meaning and boundary |
| --- | --- | --- | --- |
| G-030 | Lokal angenommen | Locally accepted | One node accepted a lock under its local checks. State whether it is only in RAM, durably committed or already accompanied by a vote. Local acceptance alone does not establish payment finality. |
| G-031 | Ausstehend | Pending | An operation has not established the required completion evidence. Use the subject explicitly: client request, local disk write and quorum collection can each be pending independently. |
| G-032 | Vorläufig bestätigt | `PROVISIONAL` | Confirmation under the adaptive sub-20-node quorum regime. It must remain distinguishable from FINAL; merge/conflict semantics are still under interview review. |
| G-033 | Final bestätigt | `FINAL` | Confirmation under the retained N >= 20 / 14-of-20 policy and stability requirements. It is not equivalent to a local record or an HTTP success code. Membership continuity and FINAL-versus-VOID semantics remain unresolved; the label alone proves neither. |
| G-034 | Ungültiger Konfliktzweig | `VOID` | Status used for a losing/neutralized branch. The conditions permitting that result, especially for previously FINAL evidence, remain a consolidation issue; the glossary does not approve revocation. |
| G-035 | Abgelaufen | Expired | The authenticated root validity has ended; new use is rejected. Expiry is distinct from physical deletion after the grace period. |
| G-036 | Nicht signierbereit | Not ready / `NOT_READY` | The node supplies no write vote for the affected scope because signing readiness is not established. The response does not prove fraud or that the spend slot is free. |
| G-037 | Ausgang unbekannt / Zeitüberschreitung | Unknown outcome / Timeout | The caller lacks a conclusive result by its deadline. Other nodes may already have accepted/signed the lock. A timeout is not a collision proof, rollback or proof of non-execution. |
| G-038 | Statusauskunft | Status response | A report about the queried state/evidence. A single node's answer is not automatically a quorum proof. Read routing and the recipient's safe payment-acceptance rule are distinct questions. |

Basis: `AGENTS.md`; [Spec 02](02_lock_zustandsautomat_und_konflikte.md) §§1–2;
[`LockStatus`](../crates/humoco-sim-core/src/types.rs);
interview DEC-009/022/023/026/030/048 and GAP-03/04.

### 3.5 Shards, discovery and network boundaries

| ID | German headword | English term | Meaning and boundary |
| --- | --- | --- | --- |
| G-039 | Shard | Shard | One of 65,536 logical registry partitions. A voucher's shard is rooted in its genesis identifier. The shard is the partition; its committee is the currently applicable group serving it. |
| G-040 | HRW-Rangfolge | Highest Random Weight ranking / HRW ranking | Deterministic ordering of eligible candidates for a shard from their routing tickets. Different candidate knowledge can produce different local lists; computing a rank does not settle transition authority. |
| G-041 | Shard-Ticket | Shard ticket / `HrwRoutingId` | Replaceable Argon2d-derived routing input bound to `NodePubKey`. It has work and incubation rules. It is distinct from permanent identity and from short-lived client ingress PoW. |
| G-042 | Lokale Netzsicht | Local network view | What one node has learned about identities, tickets, presence and transitions. “Known,” “mature,” “reachable,” “ready” and “eligible” describe different properties. |
| G-043 | P2P-Freund | F2F friend | Explicitly trusted node identity on a direct friendship edge. Heartbeat and fraud-proof gossip follow these edges. This is distinct from a client friend token. |
| G-044 | Bekanntes Netzmitglied | Known network node | A node identity learned through the permitted discovery path and managed for shard-direct authorization. Being known does not by itself grant committee membership. |
| G-045 | Gossip | F2F gossip | Forwarding of presence heartbeats and verified equivocation evidence along F2F edges. Lock creation/replication is not an additional gossip stream. |
| G-046 | Direkter Shard-Aufruf | Shard-direct RPC | Request/response communication with learned peers for lock verification and synchronization. It is distinct from both public client ingress and F2F gossip. |
| G-047 | Client-Freundestoken | Client friend token | Random 128-bit secret (`f2f_<hex>`) for the public Friends ingress tier. The similar `f2f_` spelling does not make it a node friendship or a public-key credential. |

Basis: `AGENTS.md` §§1–3 and rule 7; Specs [03](03_routing_und_sharding.md),
[11](11_organische_praesenz_und_dunbar_gossip.md),
[13](13_client_ingress_und_access_tiering.md),
[15](15_p2p_transport_and_connection_management.md).

### 3.6 Data takeover, transitions and recovery

These entries describe the current interview problem. No complete handoff algorithm,
handoff certificate format or permanent committee-history construction is selected.

| ID | German headword | English term | Meaning and boundary |
| --- | --- | --- | --- |
| G-048 | Datenabgleich | Synchronization / Sync | Finding and transferring relevant missing or differing state. Completing a transfer does not alone prove completeness, old-write closure or signing readiness. Qualify client ancestry sync versus replica state sync. |
| G-049 | Shard-Zusammenfassung (proposed) / Shard-Digest | Shard digest | Compact summary used to detect/locate state differences. “Shard-Zusammenfassung” is the proposed clearer German name, pending review. It is not the full shard state; the exact digest representation may contain hashes or other summary structures, so “checksum” alone is too narrow. A matching digest is not by itself a payment certificate or proof that every prior binding vote was recovered. |
| G-050 | Zustands-Snapshot | State snapshot | A captured set of records at a particular point. Distinguish this from G-026's member list. Later writes can require additional transfer. |
| G-051 | Shard-Übergabe | Shard handoff / State transfer and cutover | Moving service responsibility while preserving relevant live collision constraints and earlier binding effects. Includes justified old-write closure, state installation and safe successor activation; exact mechanism remains open. |
| G-052 | Abschluss alter Schreibvorgänge | Old-write closure / Cutoff | A justified boundary after which the old writing scope cannot issue fresh incompatible votes. A wall-clock timer or completed initial download does not establish this boundary. |
| G-053 | Letzte Änderungen / Nachträge | Final deltas | Relevant changes accepted after the initial copy and before justified closure. They must be accounted for before successor signing; exact inclusion/completeness evidence remains open. |
| G-054 | Signierfreigabe | Signing activation / Readiness | Permission to issue binding votes once applicable membership, recovery and storage conditions are justified. Connectivity, ticket maturity and downloaded bytes do not individually establish it. |
| G-055 | Wiederherstellung | Recovery | Re-establishing the state and safety conditions needed after restart, loss or reassignment. Restoring registry records and safely resuming the same signing identity are separate obligations. |

Basis: interview DEC-026/031/032/041/045/046, §§7.5–7.10/7.17;
[notes](ARCHITECTURE_INTERVIEW_NOTES.md). Existing sync interfaces are described in
[Spec 03](03_routing_und_sharding.md); they are not a proof of the proposed handoff.

### 3.7 Storage, admission and time

| ID | German headword | English term | Meaning and boundary |
| --- | --- | --- | --- |
| G-056 | RAM-Index | RAM index / `RamIndex` | In-memory collision lookup and mutation structure. A RAM entry does not alone prove survival across a crash or power loss. |
| G-057 | Warteschlangenreservierung | Persistence queue reservation | Capacity secured in the bounded asynchronous write queue before RAM mutation (`try_reserve`). This is backpressure admission, not a committed write, a vote or a spend reservation. |
| G-058 | Dauerhaft gespeichert | Durably committed | Persistence has confirmed the required database commit under the selected durability contract. Enqueued and RAM-resident are weaker states. Exact durability/failure semantics remain to be specified. |
| G-059 | Commit-Bestätigung | Durable commit acknowledgement | Result from persistence confirming the relevant commit. Interview direction requires this before releasing the binding vote; it is distinct from that vote and from the quorum certificate. |
| G-060 | Rücksetzen des Speicherstands | Storage rollback | Restoring an older state that may omit signing choices already released under the same identity. It is distinct from an ordinary restart with intact durable state. |
| G-061 | Restgültigkeit / Gültigkeitsgrenze | TTL / Valid-until bound | Time-limited validity anchored in the authenticated Voucher Root. The 30-second purge grace does not extend spending validity. Temporary queue/session timeouts are different lifetimes. |
| G-062 | Protokollzeit | Protocol time / `P2pClock` / `SimTime` | Time used under the project's peer-derived/simulated clock rules for validity and protocol decisions. Unsanitized local OS time must not silently replace this authority. |

Basis: `AGENTS.md` rules 1/2/10; Specs [12](12_lock_storage_und_ram_index.md),
[14](14_node_persistenz_und_redb_speicher.md); interview DEC-029–035 and GAP-02.

### 3.8 Misbehavior and evidence

| ID | German headword | English term | Meaning and boundary |
| --- | --- | --- | --- |
| G-063 | Doppelausgabe | Double-spend | Incompatible consumption of the same spend slot. An attempted double-spend by a voucher holder is distinct from double-signing by a shard node. Name the actor/key when discussing consequences. |
| G-064 | Knoten-Doppelsignatur | Node equivocation | Incompatible statements genuinely signed by the same node identity for the same relevant slot/context. Valid signatures and the incompatibility conditions must be checked before sanctions. |
| G-065 | Doppelsignaturnachweis | Equivocation proof | Verifiable first-party evidence containing the offender's incompatible signatures. A timeout, different local state, peer complaint or ordinary collision is not sufficient. |
| G-066 | Knotensperre | Node identity ban | Cryptographic identity-level exclusion following verified applicable fraud evidence, with ticket invalidation and WoT severance. Distinct from local connection refusal/backoff, ingress rate limiting and diagnostic reliability measurements. No financial deposit is involved. |

Basis: `AGENTS.md` rules 7/8 and §3; [Spec 10](10_p2p_wire_format_und_session_framing.md)
§5; interview DEC-016/019/040 and OPEN-05.

## 4. Ambiguities to review

This is a review agenda from targeted reading, not a completed repository-wide audit.
Existing section-1 mappings and binding specifications remain unchanged for this draft.

| ID | Wording to check | Proposed clarification / unresolved point |
| --- | --- | --- |
| TERM-01 | “Certificate,” “proof,” “confirmation,” “signature” | Always identify the object: client authorization, one node attestation, collected quorum evidence, root-origin evidence, handoff evidence or TLS certificate. A transport signature and a payment quorum establish different properties. |
| TERM-02 | “Accepted,” “verified,” “confirmed,” “stored” | State the scope and evidence: local RAM acceptance, durable commit, individual vote or verified quorum. Existing HTTP/DTO names cannot be renamed or treated as equivalent without interface review. |
| TERM-03 | “Shard,” “quorum,” “committee,” “top twenty” | Separate logical partition, eligible member set, required support and candidate ranking. Fixed checkout membership does not settle dynamic transition authority. |
| TERM-04 | “Synced,” “complete,” “active,” “ready” | Name the property: transfer finished, justified state recovered, ticket mature, present/reachable or permitted to sign. Define verifiable takeover acceptance criteria during handoff design. |
| TERM-05 | “Reservation,” “lock,” “promise” | Separate queue capacity, collision constraint and durable binding signing choice. No separate reservation service has been selected. |
| TERM-06 | “Genesis,” “root,” “epoch,” “snapshot” | Distinguish voucher genesis from network genesis, heartbeat time slots from possible transition instances, and committee snapshots from state snapshots. No new epoch/history protocol is adopted by these words. |
| TERM-07 | “NodeID,” “ticket,” “friend,” “tier” | Use full `NodePubKey` for identity, `HrwRoutingId` for routing; distinguish node friendship from secret client tokens. Qualify public ingress tiers versus internal P2P roles. |
| TERM-08 | “Partial signature,” “aggregate certificate” | Current inspected certificate structs hold collections of individual Ed25519 attestations. Avoid implying threshold-signature shares or one cryptographically aggregated signature. Inspect actual consumers before changing identifiers. |
| TERM-09 | “Stateless,” “blind,” “no history” | L2 is blind to monetary/application semantics and does not custody full client history. It still holds live collision state and requires signing-safety state. Section 1's unqualified “stateless” wording needs review. |
| TERM-10 | “FINAL,” “irreversible,” “VOID,” “merge” | Specs 00/02 describe both irreversibility and FINAL-to-VOID paths; interview DEC-022/023 requires justified support. Reconcile the substantive policy before terminology alignment; wording alone cannot settle this conflict. |
| TERM-11 | “Hot path,” “latency,” “persisted” | Separate RAM lookup, local processing, durable vote release, 800 ms vote collection and end-to-end checkout. Existing section-1 latency wording and selected DEC-029 durability direction require deliberate consolidation. |
| TERM-12 | “Free-rider,” “forwarding locks,” “village merge” | Section 1 mentions lock forwarding and small-mesh merge wording. Qualify shard-direct data transfer versus prohibited lock gossip and verify island bounds against current rules before editing that mapping. |
| TERM-13 | “High Assurance” | Spec 00 retains a third tier while `LockStatus` documents intentional omission and project instructions require a binary regime. Do not introduce it as an accepted status; reconcile the existing sources. |

## 5. Review and adoption sequence

1. **Draft (this change):** add definitions and boundaries to the existing dictionary;
   retain current mappings and mark unresolved meanings explicitly.
2. **Maintainer review (next step):** review small coherent groups, correct German
   headwords and definitions, and record accepted entries and remaining questions.
   A vocabulary decision cannot silently decide an unresolved protocol rule.
3. **Repository alignment (after review):** compare approved meanings against project
   instructions, specifications, interview records, code comments, APIs and tests.
   Separate wording-only inconsistencies from conflicting behavior/requirements;
   handle public identifiers and formats through deliberate compatibility decisions.

Preserve historical interview records as history; add corrections/supersession pointers
where needed rather than making old proposals appear to have used the new vocabulary.
No repository-wide alignment or production-code change has been performed in this draft.
