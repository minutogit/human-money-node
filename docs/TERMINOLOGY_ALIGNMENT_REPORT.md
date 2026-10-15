# Terminology Alignment Report — HuMoCo Layer 2

Status: Executed review and alignment report.
Base Git revision: `82f1c4221d0507cc669ef22d71816a10c439ce3b`
Local working tree context: active architecture interview state and glossary draft (`docs/ARCHITECTURE_INTERVIEW_*`, `docs/TRANSLATION_GLOSSARY.md`, `prompts/`).
Execution date: 2026-10-15.
Language policy: English repository documentation and code comments; German maintainer communication.

---

## 1. Scope & File Inventory

The terminology alignment audit inspected all active normative specifications, operational documentation, codebases, tests, and secondary surfaces across the repository.

### 1.1 Normative Specifications & Operational Guides (Inspected)
- `AGENTS.md`: Master Architecture, Coding Rules & System Context (Rules 1–11, 5 Pillars, 2-Tier Network).
- `docs/TRANSLATION_GLOSSARY.md`: Authoritative bilingual translation glossary (Canonical table, G-001–066, TERM-01–13).
- `docs/00_architektur_und_mental_model.md`: Layer-2 architecture and mental model.
- `docs/01_organischer_netzstart_und_topologie.md`: Network bootstrapping and topology.
- `docs/02_lock_zustandsautomat_und_konflikte.md`: Lock state machine and conflict resolution.
- `docs/03_routing_und_sharding.md`: HRW routing, Top-20 committee, and sync.
- `docs/04_datenstrukturen_und_rust_typen.md`: Data structures and wire types.
- `docs/05_spieltheorie_und_angriffsmatrix.md`: Threat matrix and game theory.
- `docs/06_dumb_server_smart_client_flow.md`: Dumb server / smart client interaction flow.
- `docs/07_admission_und_wot_buergschaften.md`: Admission and Web-of-Trust endorsements.
- `docs/08_topologie_dynamik_und_netz_merge.md`: Topology dynamics and network merge.
- `docs/09_netzwerk_thermometer_und_dynamische_quotas.md`: Network thermometer and quotas.
- `docs/10_p2p_wire_format_und_session_framing.md`: Wire framing, sessions, and fraud proofs.
- `docs/11_organische_praesenz_und_dunbar_gossip.md`: Presence heartbeats and Dunbar gossip.
- `docs/12_lock_storage_und_ram_index.md`: RAM index and hot-path storage.
- `docs/13_client_ingress_und_access_tiering.md`: Ingress tiers and Hashcash PoW.
- `docs/14_node_persistenz_und_redb_speicher.md`: Disk persistence and redb backend.
- `docs/15_p2p_transport_and_connection_management.md`: Transport connection pooling and lifecycle.
- `docs/16_chaos_testing_and_simulation.md`: Simulation scenarios and partition testing.
- `docs/17_topologie_telemetrie_und_social_defense.md`: Telemetry, diagnostics, and social defense.
- `docs/18_shard_kollaboration_und_perkolations_mathematik.md`: Shard collaboration mathematics.
- `docs/19_rueckkopplungs_dynamik_und_historische_p2p_postmortems.md`: Feedback dynamics and post-mortems.
- `docs/20_vogelperspektive_oekosystem_und_zukunftssicherheit.md`: Ecosystem and long-term invariants.
- `docs/99_faq_und_angriffsvektoren_deep_dive.md`: FAQ and attack deep dive.
- `docs/architektur_knotenperspektive_threat_model.md`: Local node threat model.
- `docs/MERCHANT_GUIDE.md`: Merchant operational guide.
- `docs/OPERATIONS.md`: Node operator operational manual.

### 1.2 Codebase Modules & Test Suites under `crates/` (Inspected)
- `crates/humoco-sim-core/src/`:
  - `types.rs`, `crypto.rs`, `lib.rs`, `resolver.rs`, `quota.rs`, `fraud.rs`, `storage.rs`, `client_flow.rs`, `state_machine.rs`, `wire.rs`, `chaos.rs`, `transport.rs`, `telemetry.rs`, `sim/*.rs`.
- `crates/humoco-node/src/`:
  - `main.rs`, `lib.rs`, `identity.rs`, `daemon.rs`, `error.rs`, `config.rs`, `cli.rs`.
  - `storage/`: `db.rs`, `engine.rs`, `filter.rs`, `recent.rs`, `mod.rs`.
  - `network/`: `clock.rs`, `manager.rs`, `framing.rs`, `transport.rs`, `peer.rs`, `tls.rs`, `mod.rs`.
  - `control/`: `types.rs`, `server.rs`, `client.rs`, `mod.rs`.
  - `ingress/`: `tier.rs`, `pow.rs`, `mod.rs`.
  - `alert/`: `mod.rs`.
  - `api/`: `mod.rs`, `dto.rs`, `hmc.rs`, `routes.rs`, `metrics.rs`, `events.rs`, `history.rs`, `dashboard.rs`, `health.rs`, `keys.rs`, `auth.rs`, `qr.rs`, `system_stats.rs`.
- `crates/humoco-sim-core/tests/` and `crates/humoco-node/tests/`:
  - Integration tests, invariant tests, chaos tests, simulation tests.

### 1.3 Maintained Prompts & Secondary Surfaces (Inspected)
- `prompts/README.md`
- `prompts/terminology_alignment_plan.md`
- `prompts/architecture_interview.md`

### 1.4 Separately Inventory Material (Historical / External / Excluded)
- **Historical audit and research reports (Preserved as historical evidence; not rewritten):**
  - `prompts/reports/*.md` (e.g., `2026-09-29_*`, `2026-10-13_*`).
  - `docs/archive/audit_und_optimierungspotenziale.md`, `docs/archive/spec_widerspruchs_analyse.md`.
- **Chronological Interview Records (Preserved as decision history):**
  - `docs/ARCHITECTURE_INTERVIEW_NOTES.md`
  - `docs/ARCHITECTURE_INTERVIEW_STATE.md`
  - `docs/ARCHITECTURE_INTERVIEW_HANDOFF.md`
- **Vendored / Third-Party Dependencies:**
  - `crates/clap_complete/`: vendored CLI completion utility crate.

---

## 2. Review of Dictionary Concepts (`docs/TRANSLATION_GLOSSARY.md`)

Each concept from the canonical domain mapping table and entries G-001 through G-066 was evaluated against project rules (`AGENTS.md`), specifications, code declarations, and current interview records.

### 2.1 Canonical Domain Mapping Table (Section 1)

| Headword | English Term | Status | Review Evidence & Rationale |
|---|---|---|---|
| Sperrregister | Collision Lock Registry | Established (refined) | Active double-spend registry (`parent_lock -> child_lock`). Qualified in row 22 as "history-stateless" (blind to transaction/currency history; client custody), acknowledging live RAM and disk collision state (`RamIndex`, `redb`). |
| Gutschein-Wurzel | Voucher Root / Root Anchor | Established | Genesis anchor bounding lock lifetime via authenticated `root.valid_until`. |
| Kassenpfad / Hot-Path | PoS Hot-Path / Checkout Path | Established | In-RAM collision filtering ($< 1\,\mu\text{s}$) with local node processing target $< 5\,\text{ms}$, distinguishing 800 ms quorum budget and end-to-end checkout. |
| Dorf-Merge | Village Merge / Local Mesh Merge | Established (refined) | Deterministic convergence of small isolated clusters into global mesh via $\min(H_{\text{canon}})$. Updated to reflect full island range ($N=1\dots19$) rather than obsolete historical "$N=1\dots3$". Reconciliation with FINAL/VOID semantics remains an active interview topic. |
| Community-Mesh / Insel-Netz | Community Mesh / Island Network | Established | Sub-quorum network ($N=1\dots19$) operating on adaptive provisional quorums $Q(N) = \lfloor \frac{2}{3} N \rfloor + 1$ (Status `PROVISIONAL`). |
| Weltnetz-Föderation | World Network / Federated Sharding | Established | Full federated network ($N \ge 20$) with fixed 14/20 BFT quorum (Status `FINAL`) and dynamic HRW sharding. |
| Knoten-Souveränität | Node Sovereignty | Established | Absolute operator configuration and veto sovereignty; zero background auto-updates. |
| First-Party Evidence | First-Party Evidence Doctrine | Established | Penalties and slashing require undisputed cryptographic self-proof (`EquivocationProof`). |
| Hörensagen-Verbot | Anti-Hearsay Principle | Established | Strict ban on gossiping peer reliability or subjective reputation rumors; prevents death spirals. |
| Todes-Spirale | Cascading Death Spiral | Established | Systemic failure loop from feedback amplification; prevented by dampening and $\Delta \text{Load} \le 0$. |
| Keine Kautionen / Staking | Zero Financial Deposits / No Staking | Established | No monetary bonds or stake slashing on L2. Punishments are cryptographic (NodePubKey ban, ticket loss, WoT severance). |
| Reputationsvernichtung | Identity Revocation & WoT Severance | Established | Permanent ban of `NodePubKey`, invalidation of `HrwRoutingId`, severing of all F2F edges. |
| Netzwerk-Thermometer | Network Thermometer | Established | Decentralized load feedback dynamically adjusting stateless BLAKE3 Hashcash difficulty. |
| Byte-Jahre | Byte-Years (Storage-Time Product) | Established | Accounting unit for storage reservation: $144\,\text{Bytes} \times \text{TTL}$. |
| 5x Wal-Bremse | 5x Whale Brake | Established | Exponential load dampening against burst traffic. |
| Subtraktion vor Konstruktion | Subtraction before Construction | Established | Core design philosophy: perfection is achieved when nothing more can be removed. |
| Zustandslosigkeit | Stateless Verification | Established | Nodes do not store full transaction histories; clients carry proof chains. |
| Schmarotzer / Trittbrettfahrer | Free-Riders / Free-Riding | Established (refined) | Peers consuming bandwidth/sync without reciprocating by signing shard attestations or serving shard RPC requests. Obsolete phrase "forwarding locks" corrected (locks are never gossiped). |
| Inkubationswand (24h) | 24h Shard Ticket Incubation Wall | Established | Mined Argon2d shard tickets mature for 24h before active participation in HRW scoring. |
| Besen-Topologie | Broom Topology | Established | Single-bridge botnet fan-in structure; mitigated via Dunbar-RED and edge budgets. |
| Bürgschaft / WoT-Bürgschaft | Voucher Endorsement / Admission Sponsor | Established | Web-of-Trust vouching for new node admission into the mesh. |
| Kausalitätskette | Causality ProofChain | Established | Client-side sequence of cryptographic locks proving origin and spend lineage. |
| Verdichtetes Digest | Compact Shard Digest | Established | Summary of shard lock state for pull synchronization. |
| Vorrang-Kontingent | Priority / VIP Quota Tier | Established | High-priority ingress queue for merchants via Byte-Year quota tokens. |

### 2.2 Section 3 Concepts (G-001 through G-066)

- **3.1 Participants and roles:**
  - G-001 (Client), G-002 (Wallet), G-003 (PoS terminal), G-004 (Node), G-005 (Gateway), G-007 (Node identity / `NodePubKey`), G-008 (Node operator): **Established**.
  - G-006 (Shard committee member): **Established**. Distinguishes Top-20 ranking candidates from authorized, eligible voting members of a frozen snapshot.
- **3.2 Voucher, locks and causality:**
  - G-009 (Voucher), G-010 (Voucher Root), G-011 (Origin lock), G-012 (Collision lock), G-013 (Lock record), G-015 (Successor / Output), G-016 (Lock identifier), G-017 (Causality proof), G-018 (Causality ProofChain), G-019 (Collision), G-020 (Idempotency): **Established**.
  - G-014 (Parent lock / Parent reference / “Eltern-Lock”): **Proposed / Ambiguous**. “Eltern-Lock” is proposed German headword; `parent_lock` in code references the specific spend slot / consumed output.
- **3.3 Signatures, votes and certificates:**
  - G-022 (Node attestation / Vote): **Established**. Clarified that each vote is an individual Ed25519 signature, NOT a threshold share or "partial signature".
  - G-023 (Binding signing decision), G-024 (Quorum), G-025 (Shard committee), G-026 (Committee snapshot), G-028 (Signing context), G-029 (TLS certificate): **Established**.
  - G-021 (Request authorization signature): **Proposed / Ambiguous**. Maintainer proposed candidates “Lock-Signatur” for client signature and “Freigabenachweis” for combined key disclosure/signature evidence. Remains provisional pending explicit selection.
  - G-027 (Quorum certificate): **Established**. Bundle of individual node attestations matching required threshold.
- **3.4 Outcomes, readiness and uncertainty:**
  - G-030 (Locally accepted), G-031 (Pending), G-032 (`PROVISIONAL`), G-035 (Expired), G-036 (Not ready / `NOT_READY`), G-037 (Unknown outcome / Timeout), G-038 (Status response): **Established**.
  - G-033 (`FINAL`), G-034 (`VOID`): **Substantive conflict / Ambiguous**. Reconciling FINAL irreversibility with partition merge and equivocation handling (DEC-022/DEC-023) is an active interview design item.
- **3.5 Shards, discovery and network boundaries:**
  - G-039 (Shard), G-040 (HRW ranking), G-041 (Shard ticket / `HrwRoutingId`), G-042 (Local network view), G-043 (F2F friend), G-044 (Known network node), G-045 (F2F gossip), G-046 (Shard-direct RPC), G-047 (Client friend token): **Established**.
- **3.6 Data takeover, transitions and recovery:**
  - G-048 (Synchronization), G-050 (State snapshot), G-053 (Final deltas), G-054 (Signing activation / Readiness), G-055 (Recovery): **Established**.
  - G-049 (Shard digest): **Proposed / Established**. German headword “Shard-Zusammenfassung” proposed by maintainer; technical concept "Shard digest" established.
  - G-051 (Shard handoff), G-052 (Old-write closure / Cutoff): **Established concepts / Unresolved implementation**. Abstract requirements established; concrete algorithm and proof open (Interview S3.2/S3.3).
- **3.7 Storage, admission and time:**
  - G-056 (RAM index), G-057 (Persistence queue reservation / `try_reserve`), G-058 (Durably committed), G-059 (Durable commit acknowledgement), G-060 (Storage rollback), G-061 (TTL / Valid-until bound), G-062 (Protocol time / `P2pClock` / `SimTime`): **Established**.
- **3.8 Misbehavior and evidence:**
  - G-063 (Double-spend), G-064 (Node equivocation), G-065 (Equivocation proof), G-066 (Node identity ban): **Established**.

---

## 3. Applied Changes & Findings Ledger

| Finding ID | Concept / Glossary ID | Location | Before (Observed Drift / Ambiguity) | After (Aligned Wording) | Rationale & Evidence |
|---|---|---|---|---|---|
| **TA-001** | G-022, G-027, TERM-08 | `crates/humoco-node/src/api/dto.rs:72` | `/// Assembled quorum certificate with partial signatures from shard nodes.` | `/// Assembled quorum certificate containing individual node attestations (Ed25519 signatures) from shard committee members.` | Attestations are full, individual Ed25519 signatures, not threshold / BLS partial signatures. |
| **TA-002** | G-022, G-027, TERM-08 | `crates/humoco-sim-core/src/client_flow.rs:13` | `pub signatures: Vec<Attestation>, // Ed25519 partials from Top-20` | `pub signatures: Vec<Attestation>, // Individual Ed25519 attestations from shard committee members` | Avoids misleading threshold-share terminology; aligns with `Attestation` struct. |
| **TA-003** | G-045, G-046, Rule 7 | `crates/humoco-node/src/network/manager.rs:1675` | `/// Gossip (Heartbeats and Lock Announcements) is ONLY accepted from direct F2F friends.` | `/// Gossip (Heartbeats and Equivocation Proofs) is ONLY accepted from direct F2F friends.` | Strict 2-stream gossip rule (`AGENTS.md` §2 & Rule 7): locks are NEVER gossiped across mesh edges. |
| **TA-004** | Bilingual policy (`AGENTS.md`) | `crates/humoco-node/src/identity.rs:209` | `/// Alias / Übergangs-Getter für public_key (verifying_key).` | `/// Alias / transition getter for public_key (verifying_key).` | Enforces English repository prose and code comments while maintaining German user dialogue. |
| **TA-005** | Bilingual policy (`AGENTS.md`) | `crates/humoco-node/src/network/manager.rs:1435, 1677` | `/// F2F check basiert strikt auf permanenter NodePubKey / NodeId...` / `/// Strikt auf permanenter NodePubKey...` | `/// F2F check is strictly based on the permanent NodePubKey / NodeId...` / `/// Strictly based on permanent NodePubKey...` | Enforces English comments in networking core. |
| **TA-006** | Bilingual policy (`AGENTS.md`) | `crates/humoco-node/src/storage/engine.rs:882` | `/// Atomares Ketten-Locking: Validates all hops in chain_req...` | `/// Atomic chain locking: Validates all hops in chain_req...` | Enforces English comments in storage engine. |
| **TA-007** | Bilingual policy (`AGENTS.md`) | `crates/humoco-sim-core/src/quota.rs:745, 751, 755, 759` | German test comments (`Halbwertszeit`, `übrig`, `Decay auf 0`) | Translated to idiomatic English (`half-life`, `remaining`, `decay to 0`). | Enforces English comments across simulation crate tests. |
| **TA-008** | G-022, G-027, TERM-08 | `docs/04_datenstrukturen_und_rust_typen.md:63` | `/// Ed25519 quorum partial signatures of the nodes...` | `/// Individual Ed25519 node attestations forming the quorum...` | Clarifies that quorum members produce individual Ed25519 signatures. |
| **TA-009** | G-022, G-027, TERM-08 | `docs/06_dumb_server_smart_client_flow.md:92, 202, 347` | `PartialSig`, `send partial signatures`, `Ed25519 partial signatures` | `Attestation / Vote`, `send signed attestations (votes)`, `individual Ed25519 node attestations` | Eliminates false threshold-cryptography implications in sequence diagram and flow descriptions. |
| **TA-010** | G-022, G-027, TERM-08 | `docs/03_routing_und_sharding.md:90` | `SigFast["19 fast partial signatures"]` | `SigFast["19 fast signed attestations"]` | Clarifies diagram node in Spec 03. |
| **TA-011** | G-022, G-064, G-065 | `docs/10_p2p_wire_format_und_session_framing.md:391, 399` | `2 partial signatures for the same parent_lock`, `2 partial certificates` | `2 conflicting signed attestations for the same parent_lock`, `2 conflicting node attestations` | Accurately describes equivocation evidence as conflicting individual attestations. |
| **TA-012** | G-022, G-064, G-065 | `docs/05_spieltheorie_und_angriffsmatrix.md:22, 36` | `2 partial signatures for same parent_lock`, `partial certificates` | `2 conflicting signed attestations for same parent_lock`, `conflicting node attestations` | Clarifies attack vector A2 in threat matrix and diagram. |
| **TA-013** | TERM-13, G-033, `LockStatus` | `docs/00_architektur_und_mental_model.md:94` | High Assurance presented without qualification | Added normative status note referencing TERM-13 and `LockStatus` binary regime omission. | Preserves historical table while recording active binary regime mandate (`AGENTS.md` Pillar 4). |
| **TA-014** | TERM-09, G-012, G-056 | `docs/TRANSLATION_GLOSSARY.md:22` | `Asynchronous, stateless registry for double-spend prevention...` | `Asynchronous, history-stateless collision registry for double-spend prevention (parent_lock -> child_lock; clients custody history, registry holds live collision locks).` | Resolves TERM-09 ambiguity; clarifies client custody vs live registry state. |
| **TA-015** | TERM-12, G-032 | `docs/TRANSLATION_GLOSSARY.md:25` | `...small isolated clusters ($N=1\dots3$)...` | `...small isolated clusters ($N=1\dots19$)...` | Aligns village merge row with full community mesh / island boundary. |
| **TA-016** | TERM-12, G-039, G-046 | `docs/TRANSLATION_GLOSSARY.md:39` | `...without signing or forwarding locks.` | `...without reciprocating by signing shard attestations or serving shard RPC requests.` | Removes erroneous mention of lock forwarding (locks are never gossiped). |
| **TA-017** | G-014, G-015, G-019 | `docs/12_lock_storage_und_ram_index.md:41` | `parent_lock corresponds to the consumed output...` | `parent_lock references the specific consumed spend slot / output...` | Clarifies spend slot binding under DAG split transactions. |

### 3.2 Ledger of Intentional Unchanged Identifiers & Aliases
- `parent_lock`: Retained as code identifier across DTOs, wire structs, and engine maps. Semantically refers to the predecessor output / spend slot.
- `node_id`: Retained in `AttestationDto` and wire formats as legacy 16-bit fallback field, but permanently superseded by 32-byte `node_pubkey` for identity and cryptographic verification.
- `ServerBann` / `BannedNodes`: Retained in simulation code as type alias; conceptually represents permanent cryptographic `NodePubKey` identity ban with shard ticket invalidation and WoT severance.
- `f2f_<hex>`: Retained as token prefix for client ingress Friends tier; distinct from P2P node-to-node F2F friendship edges (`trusted_pubkeys`).
- `signer_bitmap`: Retained in certificates as 32-bit index mask over the frozen Top-20 committee snapshot.

---

## 4. Unresolved Semantic & Design Conflicts

The following material conflicts and design gaps are documented and tracked rather than masked through synonym substitution:

1. **FINAL Irreversibility versus VOID Branch Revocation (TERM-10 / DEC-022 / DEC-023):**
   - *Conflict:* Early specifications describe deterministic mesh merges via $\min(H_{\text{canon}})$ where losing branches become `VOID`. However, core financial safety requires that payments confirmed as `FINAL` cannot be retroactively invalidated.
   - *Interview direction:* DEC-023 establishes that conflicting spend slots remain unresolved rather than forcibly revoked. Eventual reconciliation requires formal specification consolidation.
2. **Binary Regime versus High Assurance Tier (TERM-13 / DEC-022):**
   - *Conflict:* Specs 00, 03, 04, 08, 10 describe a third status tier (`0x02 HIGH_ASSURANCE`, $N \ge 100$, 16/20). `AGENTS.md` Pillar 4 and `LockStatus` in `types.rs` mandate a strict binary regime (PROVISIONAL vs FINAL) and intentionally omit High Assurance.
   - *Status:* High Assurance is qualified as omitted in code and glossary; spec cleanup pending final architectural consolidation.
3. **Durable-Before-Vote versus Sub-5ms In-RAM Checkout SLA (TERM-11 / DEC-029 / DEC-033):**
   - *Conflict:* The original specification states an asynchronous flush pipeline with pure in-RAM collision checks and a $< 5\,\text{ms}$ local processing target. Interview DEC-029 requires durable persistence acknowledgement before emitting binding shard votes to prevent double-signing across crashes.
   - *Status:* Pending consolidation of database flush latency, write-queue durability contracts, and checkout budgets.
4. **Client Authorization Naming & Proof Formats (G-021 / Naming Review):**
   - *Status:* Candidates “Lock-Signatur” (individual signature) versus “Freigabenachweis” (combined key revelation and signature) remain unselected pending maintainer decision. Existing code identifiers (`layer2_signature`, `auth_signature`) remain unchanged.
5. **Shard Handoff & Old-Write Cutoff Mechanism (G-051, G-052 / Interview Branch S3):**
   - *Status:* Concrete cutover algorithms, handoff certificates, and safe old-write retirement remain active design items in the architecture interview (Q-S3.3-01 parked).

---

## 5. Verification Checks Run & Results

1. **Whitespace & Diff Integrity Check:**
   - Command: `git diff --check`
   - Result: Exit code 0. Zero whitespace errors, zero trailing markers.
2. **Workspace Compilation & Test Suite Verification:**
   - Command: `cargo check --tests`
   - Result: Exit code 0. Both `humoco-sim-core` and `humoco-node` compile cleanly without warnings or broken doctests.
3. **Static Terminology Search Inspection:**
   - Validated that all replaced instances of "partial signature", "partial certificate", and "Lock Announcements" in active specifications and source comments were resolved.
   - Confirmed that code identifiers, serialization tags, and wire formats remain 100% unaltered.
4. **Bilingual Policy Compliance Check:**
   - Verified that all comments modified in Rust source files are written in idiomatic English.
   - Verified that maintainer communication remains strictly in German.

---

## 6. Handoff & Next Steps

1. **Glossary Detour Completion:**
   - Terminology alignment across active specifications, dictionary, and source comments is executed and verified.
   - Maintainer can review this report (`docs/TERMINOLOGY_ALIGNMENT_REPORT.md`) and the updated glossary (`docs/TRANSLATION_GLOSSARY.md`).
2. **Next Action in Architecture Interview:**
   - Resume architecture interview at branch **S3.3** (`docs/ARCHITECTURE_INTERVIEW_STATE.md`), addressing parked question **Q-S3.3-01** (one-round carrying vs two-round payment semantics and handoff cutoff rules).
