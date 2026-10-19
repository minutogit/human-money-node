# Terminology Alignment Report — HuMoCo Layer 2

Status: Editorial alignment completed for the screened terminology; naming is settled.
Substantive architecture conflicts remain open; no glossary feedback is required.
Continuation date: 2026-10-16 (Europe/Berlin). See section 8 for the latest scope, outcomes and verification limits.
Sections 1–7 preserve earlier audit evidence; section 8 supersedes their pending-name status.
Base Git revision: `82f1c4221d0507cc669ef22d71816a10c439ce3b`
Local working tree context: active architecture interview state and glossary draft (`docs/ARCHITECTURE_INTERVIEW_*`, `docs/TRANSLATION_GLOSSARY.md`, `prompts/`).
Execution date: 2026-10-15.
Language policy: English repository documentation and code comments; German maintainer communication.

---

## 1. Scope & File Inventory

The initial report recorded the scope below. The 2026-10-16 continuation inventories
additional current and historical surfaces and corrects overbroad completion claims
(see section 7 and the linked inventory). File-level screening is not a proof of
semantic consistency, implementation correctness or exhaustive review of every line.

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

Each canonical mapping and G-001–066 has a review outcome below. “Established” means
the underlying concept/English usage is supported; it does not mean every draft
German headword or proposed mechanism was approved. Section 7 refines these outcomes
where the earlier report conflated simulation with production or omitted aliases.

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
- `node_id`: Retained per declaration. The simulator uses `u16`; `NodeIdentity::node_id()` returns a BLAKE3 fingerprint; `AttestationDto` retains a legacy `u16` field. Production `verify_peer_attestation` still has a legacy key-lookup fallback; the initial “permanently superseded” claim was too broad. Frozen checkout also applies full-key/TLS membership checks (TA-019/020).
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
   - *Status:* Resolved by DEC-029 restoration: strict Durable-before-Vote / Durable-before-Release implemented. Local durable SLA is $< 20\,\text{ms}$ (asynchronous redb commit acknowledgment via bounded MPSC queue and group commit), well within the 800ms checkout collection budget.
4. **Client Authorization Naming & Proof Formats (G-021 / Naming Review):**
   - *Status:* Candidates “Lock-Signatur” (individual signature) versus “Freigabenachweis” (combined key revelation and signature) remain unselected pending maintainer decision. Existing code identifiers (`layer2_signature`, `auth_signature`) remain unchanged.
5. **Shard Handoff & Old-Write Cutoff Mechanism (G-051, G-052 / Interview Branch S3):**
   - *Status:* Concrete cutover algorithms, handoff certificates, and safe old-write retirement remain active design items in the architecture interview (Q-S3.3-01 parked).

---

## 5. Verification Checks Run & Results

1. **Whitespace & Diff Integrity Check:**
   - Command: `git diff --check`
   - Result: Exit code 0. Zero whitespace errors, zero trailing markers.
2. **Inherited compilation claim (not re-executed in this continuation):**
   - The initial report records `cargo check --tests`, exit code 0. Its command log was not retained here, so this continuation does not independently confirm that run or its warning status.
   - `cargo check --tests` type-checks test targets; it does not execute tests or doctests. The earlier claim about “broken doctests” was unsupported. Current checks are listed in section 7.5.
3. **Static Terminology Search Inspection:**
   - The initial replacements removed the cited instances. The continuation found additional “Partial quorum signatures” wording and an intentional runtime assertion string; see TA-022 and section 7.4. Zero global hits is not claimed.
   - Confirmed that code identifiers, serialization tags, and wire formats remain 100% unaltered.
4. **Bilingual Policy Compliance Check:**
   - Verified that all comments modified in Rust source files are written in idiomatic English.
   - Verified that maintainer communication remains strictly in German.

---

## 6. Handoff & Next Steps

1. **Glossary Detour Completion:**
   - Initial editorial changes are present in Git. The continuation completes the current inventory/review pass and records additional corrections; full language uniformity is not established while proposed names, legacy language and substantive conflicts remain.
   - Maintainer can review this report (`docs/TERMINOLOGY_ALIGNMENT_REPORT.md`) and the updated glossary (`docs/TRANSLATION_GLOSSARY.md`).
2. **Next Action in Architecture Interview:**
   - Keep **K3** active for the remaining naming/consolidation work. The parked return point is **S3.3 / Q-S3.3-01**; execution of a wording audit does not answer it or select a payment protocol.


## 7. Continuation audit — 2026-10-16

### 7.1 Reconciled starting point and coverage

Inspected revision: `02983adeda594d7610194cb6a4d0abcb118ef051` (`docs: execute terminology review and align domain concepts`).
The working tree was clean at the start. That commit already contains TA-001–017;
the CP-0011 cursor and draft notices still incorrectly said alignment had not run.
This continuation preserves that work and adds editorial corrections without a commit.
The older base hash at the top describes the initial report, not this continuation.

[File inventory and coverage](TERMINOLOGY_ALIGNMENT_INVENTORY.md) lists every discovered
Markdown/Rust file with its role and review outcome. All current numbered specs,
both 15/16 filename variants, root documents, guides, first-party Rust source/tests,
and maintained prompts were included in contextual terminology screening. Definitions,
ambiguous prose/diagrams and relevant declarations/consumers were read for the findings
below; other files received text/comment screening. The inventory distinguishes those
levels and retains unresolved language debt rather than marking it compliant.
Generated files, build artifacts, non-prose assets and external dependencies were not
semantically audited. The external `human-money-core` repository was not inspected;
local HMC adapters do not establish its complete authorization or split semantics.

The dated 2026-08-29 threat-model audit is historical evidence, despite its location
beside current specifications. Its BLS/Argon2id examples are preserved with a status
pointer. The audit registry and chronological interview records remain history.

### 7.2 Additional findings and applied corrections

Locations use current symbols/sections; TA-001–017 locations refer to the initial
snapshot. Each new finding names the affected object and its evidence.

| ID / concepts | Location and current meaning | Evidence / classification | Action and outcome |
| --- | --- | --- | --- |
| TA-018 / G-022/027/028, TERM-08 | `client_flow.rs`: `QuorumCertificate`, `DumbServer::verify_quorum_certificate`, free verifier; `types.rs::Attestation`; `crypto.rs::sign_deterministic_sig` | `sign_lock_attestation_for_network` fills a hash/ID/padding array and `verify_attestation_for_network` recomputes it. By contrast `verify_zero_trust_quorum` uses `ed25519_dalek::verify_strict`. Editorial misdescription in the initial audit. | Describe model attestations as deterministic test signatures; retain the separate real-Ed25519 path and every identifier. Glossary G-022 now explains the distinction. Applied. |
| TA-019 / G-007/027/030/038, TERM-01/02/07 | `api/dto.rs::AttestationDto::from_wire_bytes`, `QuorumCertificateDto::is_quorum_reached`; `api/routes.rs::verify_peer_attestation` | Current DTO has eight fields; the decoder also constructs it from a five-field legacy payload. Decoding performs no signature verification; the count helper checks vector length only. Consumer retains legacy prefix lookup; frozen checkout checks full-key/TLS membership separately. | Correct decoder documentation and explicitly scope the count helper. Preserve the top-level full-key requirement; document the observed fallback instead of claiming it was removed. Applied wording; general compatibility/identity-policy consolidation remains open. |
| TA-020 / G-007/040/041, TERM-07 | `KnownNodeInfo`, `update_routing_ticket`; Spec 15 in both filename variants; glossary G-007/041 | `NodeIdentity::node_pubkey` returns a key, `node_id` returns a fingerprint; `KnownNodeInfo` copies caller-provided identity bytes into its alias. Spec 07 defines Argon2d work plus BLAKE3 whitening for the separate routing ticket. | Remove claims that public keys, fingerprints and tickets are interchangeable. Correct the Spec 15 identity/ticket explanation and the migration-notice name. End-to-end identity-use correctness is not established by these comment changes. Applied. |
| TA-021 / G-012/066 | Specs 05/10/11: heartbeat-spam consequence and `BannedNodes` | The contexts explicitly describe a RAM/disk node ban filter, not a map of consumed voucher slots; project rules define identity bans and ticket invalidation separately. Editorial conflation. | Name the node identity ban list and Argon2d shard-ticket invalidation; retain every fraud condition and sanction. Applied. |
| TA-022 / G-022/027/029, TERM-01/08 | Spec 03 §2 diagram, Spec 06 proof/checkout/layout wording, Spec 12 hot-path diagram | One shard emits an attestation; the gateway assembles a certificate from individual signatures. These are not a threshold share or one aggregate signature. | Replace residual “Partial quorum signatures,” singular quorum-signature labels and ambiguous “aggregated” wording with node attestation or assembled quorum certificate as appropriate. Applied. |
| TA-023 / G-063/064/065 | Spec 07 §5; Spec 14 §4 | Project rule 8 requires two conflicting genuine signatures of the same node for the same slot. Ordinary conflicting spends are not evidence that a node signed twice. | Distinguish node equivocation from client double-spend and identify the signed objects as attestations. Independent proof verification is distinct from storing/enforcing a ban. Applied. |
| TA-024 / original mappings, G-009/012/056, TERM-09/12 | README introduction; glossary section 1 | RAM/disk collision state is present; client custody concerns full voucher histories. Admission vouching concerns nodes, not monetary vouchers. | Use plain descriptions of retained collision state/client history; clarify node-admission endorsement. Qualify existing local SLA separately from vote collection without changing either. Applied; durability/SLA conflict remains open. |
| TA-025 / G-014/021/049, TERM-01–13 | Glossary status/agenda, plan/index, compact interview state and notes | Revision contains an executed report while CP-0011 says execution is pending. G-014/021/049 naming remains unselected in §7.20–7.22. | Reconcile execution status, keep draft/proposal status and K3 active, append CP-0012; preserve old checkpoints and parked Q-S3.3-01. Applied. |
| TA-026 / G-007/028/033/048–060, TERM-03/04/10/11/13 | Specs 00/02/04/06/08/12/14 and interview register | FINAL/VOID, High Assurance, durable-before-vote and justified handoff/membership remain substantive conflicts. Compact bitmap layout also assumes authenticated context. | Preserve requirements and record concrete follow-up in §7.3; do not resolve them by renaming. Unresolved. |
| TA-027 / verification evidence | Initial report §§1/5/6 | `cargo check --tests` cannot establish passing tests/doctests; the initial report omitted current files and overstated uniformity. | Correct those claims, distinguish inherited execution claims from checks performed now, and add explicit file coverage. Applied. |
| TA-028 / bilingual policy | Source comments in `daemon.rs`, `ingress/pow.rs`, `network/manager.rs`, `client_flow.rs`, `fraud.rs`, `quota.rs`; legacy surfaces in inventory | Existing English-repository policy; several production comments and many test/spec passages remained German. | Translate the remaining identified German production-comment passages. Inventory the broader legacy test/document translation debt explicitly; no blanket bilingual-compliance claim. Applied to production passages; legacy prose translation remains open. |
| TA-029 / G-014/015/027/028/062, TERM-02/06/07 | Specs 04/06/10/12 vs local `LockRecord`, HMC adapter and DTO representations | Different structures use different field sets, encodings and clocks. Spec 06's compact certificate/bitmap is not evidence that the JSON/bincode DTO has the same wire layout; the simulator uses milliseconds, while some spec timestamps use seconds. | Keep identifiers/formats unchanged. Qualify parent/output terminology without claiming every path implements split binding. Require deliberate canonical-format/output/clock review under K2/C1; unresolved. |
| TA-030 / G-007/063/066 | Key-compromise prompt 09 | `NodePubKey` is public; theft/compromise concerns the corresponding private signing key. | Clarify the prompt's actor/key wording. Do not invoke the audit or send any message. Applied. |

### 7.3 Remaining decisions and implementation work

- **G-014/021/049 names:** maintain “Eltern-Lock,” “Lock-Signatur” versus combined
  “Freigabenachweis,” and “Shard-Zusammenfassung” as proposals. Recommendation remains
  to distinguish the individual authorization signature from combined authorization
  evidence. No name or proof packaging is selected by this audit.
- **TERM-10:** reconcile FINAL irreversibility and FINAL-to-VOID/minimum-hash paths
  using DEC-022/023, justified support and S2/S3/S5. In particular, the initial
  shorthand “DEC-023 means conflicting slots remain unresolved” is incomplete;
  the actual recorded support gates and limits govern, not that shorthand.
- **TERM-11:** Resolved via DEC-029 restoration. Replaced artificial sub-5ms in-RAM vote emission with strict Durable-before-Vote (< 20ms local durable SLA). Enqueued redb write operations await persistence worker acknowledgment before emitting votes or returning success.
- **TERM-03/04/06:** justify committee authority and safe state transfer/old-write
  closure/successor activation; ordinary sync, a digest, mature ticket or a frozen
  local list alone does not establish them. Q-S3.3-01 remains unanswered.
- **TERM-13:** reconcile the retained third-tier tables/tags in Specs 00/04/08/10
  with the binary regime and `LockStatus`; no status/wire-tag removal is made here.
- **TERM-07 / TA-019/020/029:** review retained prefix/fingerprint/key aliases and
  canonical formats across producers and consumers before compatibility changes.
- **Boundary inconsistencies:** Spec 13's “P2P emergency” client tier and Spec 15's
  wallet/terminal QUIC migration examples need consolidation with AGENTS' internal
  node-P2P/public-ingress separation. They are not approval for dual-role ingress.
- **Language debt (TA-028):** translate the identified legacy current guides/spec
  passages, root task/roadmap prose and test descriptions in a dedicated editorial
  pass while preserving commands, runtime strings, historical quotations and
  normative conditions. The inventory names the affected files. This vocabulary
  review does not represent those untranslated passages as policy-compliant.

### 7.4 Intentionally retained aliases and resolved ambiguity register

- `parent_lock`, `node_id`, `signer_bitmap`, `layer2_signature`, `auth_signature`,
  `QuorumCertificate*`, `BannedNodes`, endpoint/config/wire names and all runtime
  strings remain unchanged. Their conceptual scope is explained per declaration.
- `phase11_wire_level_adversarial_tests.rs` contains `expect("partial certificate")`:
  this is a runtime assertion string about an incomplete collected certificate,
  not terminology for a threshold-signature share. It is intentionally retained.
- Prompt 18's “lock announcements via Gossip” is a question about obsolete code,
  not an instruction to gossip locks. Historical reports retain their old aliases.
- “Stateless” still legitimately describes challenge regeneration or independent
  proof checking; it does not mean the daemon stores no collision or ban state.
- G-001–066 and every original mapping retain the section-2 review outcomes, refined
  by TA-018–030. G-007/022/027/041 received explicit factual qualifications. No IDs
  were removed or renumbered and no new competing dictionary was created.

| Ambiguity | Review outcome |
| --- | --- |
| TERM-01 | Applied actor/object distinctions; unresolved formats tracked under K2/C1. |
| TERM-02 | Applied local/count/decoded versus verified/durable distinctions; release contract remains open. |
| TERM-03 | Shard/committee/quorum meanings established; membership proof open. |
| TERM-04 | Transfer/readiness meanings distinguished; handoff/recovery proof open. |
| TERM-05 | Queue reservation distinct from binding choice; no new reservation subsystem selected. |
| TERM-06 | Root/state/member snapshots and time contexts distinguished; canonical formats open. |
| TERM-07 | Identity/key/fingerprint/ticket/client-token distinctions qualified; compatibility and boundary conflicts open. |
| TERM-08 | Individual attestations distinguished from threshold shares; simulation/production distinction corrected. |
| TERM-09 | Registry/client-history definition corrected; legitimate stateless operations retained. |
| TERM-10 | Substantive FINAL/VOID conflict unresolved; no policy rewritten. |
| TERM-11 | Resolved via DEC-029 Durable-before-Vote (< 20ms local durable SLA). |
| TERM-12 | Free-rider/shard-RPC and island range corrections retained; merge policy open under TERM-10. |
| TERM-13 | Binary/High-Assurance conflict documented; no new status adopted. |

### 7.5 Checks performed in this continuation

- `git diff --check`: passed (exit 0) after application; patch preflight also passed
  with `git apply --check --whitespace=error-all`. The new untracked inventory was
  included in the patch whitespace/content checks.
- Comment-only Rust comparison against the recorded baseline: passed for all nine
  modified Rust files. Their non-comment content is identical; Rust fenced examples
  in modified Markdown are also unchanged except for comments.
- All 10 introduced/edited Markdown links and anchors passed resolution checks;
  the 24 original mappings, unique ordered G-001–066 definitions and all 13 TERM
  outcomes are present. CP-0012 matches in state/notes; one active focus, 113-line state.
  Existing unrelated broken links, if any, were not certified by this check.
- Contextual searches/readback for replaced aliases and intentional remaining uses:
  passed final readback: all 30 applied files matched the reviewed patch; replaced
  misleading phrases are absent outside intentional historical/report quotations.
- No Rustdoc code example, executable logic, dependency, runtime string, API/wire
  field/tag, quorum/timer or database behavior was changed. No build, unit test,
  doctest or QUIC integration suite was run in this continuation: this is an
  editorial change, not verification of a network defense or protocol algorithm.

Next action: review the remaining K3 names and consolidate the
listed substantive conflicts, then return to S3.3 without inferring an A/B answer.

## 8. Autonomous vocabulary alignment — 2026-10-16

### 8.1 Authority, current scope and outcomes

Interview DEC-049/050 select the client-signature/evidence and parent/output names;
DEC-051 records Q-K3-G049-01 answer A for “Shard-Zusammenfassung.” The maintainer
then explicitly removes further glossary preference questions and authorizes
independent alignment and future refinements (DEC-052; notes §7.27).
This supersedes the pending-name/adoption gates in sections 2/4/6/7 above. Those
sections remain earlier audit evidence, not the current naming queue.

Revision remains `02983adeda594d7610194cb6a4d0abcb118ef051`. The working tree already
contained the preceding editorial audit and interview changes. This pass preserves
those inputs; its verification compares against a snapshot of the working files
at the start of this pass, not just HEAD. The inventory covers 248 Markdown/Rust
files including itself; 247 were already individually listed. Historical/vendor
material and project instructions are retained. Screening of current prose/comments
used terminology/alias searches followed by contextual reading of changed passages
and relevant producers/consumers; it is not an exhaustive semantic or security audit.

All 24 original mappings and ordered G-001–066 remain. Names are established for
editorial use under DEC-052, with definitions retained or clarified:

| Concepts | Current outcome |
| --- | --- |
| Original mappings | Retained; clarify cryptographic first-party evidence, the non-positive-load defense, “Kein Staking” and compact shard-summary wording. |
| G-001–013, G-015–020, G-022–048, G-050–066 | Existing scoped meanings retained; underlying design qualifications remain. No naming approval queue. |
| G-014 | “Eltern-Lock” / parent lock and “Vorgängerausgabe” / predecessor output established (DEC-050). Exact output-binding audit remains OPEN-06. |
| G-021 | “Lock-Signatur” / request authorization signature and “Freigabenachweis” / client authorization evidence established (DEC-049). Exact formats/enforcement remain OPEN-06. |
| G-049 | “Shard-Zusammenfassung” / shard digest established (DEC-051). A summary is distinct from state, payment quorum and recovery readiness. |
| TERM-01–09/12 | Apply object/actor/evidence distinctions; retain associated audit and format obligations. |
| TERM-10/11/13 and authority/handoff aspects of TERM-03/04/06/07 | Substantive architecture obligations, not editorial choices or approval blockers. |

### 8.2 Findings and changes

| Finding / concepts | Evidence and locations | Action / outcome |
| --- | --- | --- |
| TA-031 / G-014/021/049 | DEC-049–052; glossary, maintained alignment plan and prompt index still contained proposed-name/approval gates. | Adopt settled vocabulary, remove live naming-candidate queues, retain historical provenance in notes, and explicitly authorize autonomous future editorial maintenance. Applied. |
| TA-032 / G-021/022/027/028, TERM-01/08 | Specs 00/06/07/10/15 (both variants), ROADMAP and performance prompt still used “quorum signature” or “Partial Ed25519 signatures” where one node attestation or an assembled certificate was meant. `AttestationDto`/`QuorumCertificateDto` distinguish those objects. | Name individual node attestations, client request authorization signatures and assembled quorum certificates explicitly. Clarify actual HMC signature validators without claiming they alone check predecessor authorization. API/field names unchanged. Applied. |
| TA-033 / G-049/050/054, TERM-04/06 | `crypto.rs::compute_shard_digest_at` hashes only `parent_lock`, `receiver_pub`, `nonce`, `id` after shard/expiry/VOID filtering; `daemon.rs::run_shard_digest_pull_sync` compares/clusters responses and initiates pulls. | Replace overbroad explanatory claims of full-set equality and guaranteed healing with the actual encoded-projection comparison and scheduling. State that digest equality proves neither full-record equality nor membership, old-write closure or prior-vote recovery. Algorithm, timers and readiness behavior unchanged. Applied comments; protocol obligations remain S2/S3/N3/O2. |
| TA-034 / G-049 | TODO heading, Specs 20/99 and source comment headings retained inconsistent German/English digest aliases. | Use English “shard digest” in repository prose/comments and German “Shard-Zusammenfassung” in the glossary/conversation; retain identifiers and historical aliases. Applied. |
| TA-035 / G-064/065/066, TERM-07 | Both Spec 15 variants retain a future-idea paragraph about automatic social slashing/edge severance based on silent service refusal; both Spec 16 variants' Matrix 2 discuss client-signed conflicts, receipt gossip and a node ban. AGENTS rules 7/8 and INV-1701 distinguish node equivocation from telemetry/client double-spend and restrict gossip. | Substantive specification conflicts, not synonyms. Preserve normative text and record for F1/S6/N4 consolidation and subsequent real-QUIC verification. No new sanction, gossip stream or client-proof-based ban is adopted. Unresolved. |

Historical reports, archive material, chronological interview entries and runtime
identifiers such as `quorum_signatures`, `ShardDigestRequest`, `parent_lock` and
`layer2_signature` are intentional retained spellings. German legacy paragraphs
and test comments unrelated to these terminology corrections remain language debt
(TA-028); this pass is not a whole-repository prose translation.

### 8.3 Verification and next action

- Readback/context review of changed passages and glossary meanings performed.
- `git diff --check`: passed after removing trailing Markdown spaces on two edited lines.
- All changed Rust files compared against the pre-edit working-tree snapshot:
  every non-comment line, including executable code and runtime strings, is identical.
  No Rust code example was intentionally changed; the focused fence/link/ID checks
  and final file inventory are recorded in the continuation inventory.
- G-001–066 and original mappings retained; old section-3/section-5 glossary anchors
  retained explicitly for existing links. Current naming gates removed.
- No build, unit/QUIC tests or doctests run: changes are editorial, with no Rust code
  example modification. No workspace-green, safety-proof, commit or PR claim.

The autonomous editorial pass is complete for this scoped screening. Continue
ordinary vocabulary maintenance without asking naming questions. The architecture
return point is S3.3 / Q-S3.3-01 with its original unanswered A/B meanings; first
resume bounded closure/inclusion/installation analysis. Keep S2 membership and
other substantive conflicts explicit. Do not infer a payment-protocol answer from
any glossary answer or the instruction to unify terminology.
