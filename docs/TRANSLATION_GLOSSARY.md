# 🗣️ HuMoCo Bilingual Translation Glossary & Domain Dictionary (DE ↔ EN)

> **Purpose:** This document is the authoritative bilingual reference for developers, operators, and AI agents.  
> **Rule:** The human maintainer communicates in German; all codebase identifiers, commits, issues, pull requests, and public documentation are in idiomatic English.

---

## 🧭 1. Canonical Domain Mapping Table (Kanonische Begriffs-Tabelle)

| German (Deutscher Begriff) | Canonical English Term | Context & Technical Semantics (Bedeutung) | Forbidden / False Friends (Verboten) |
|---|---|---|---|
| **Sperrregister** | **Collision Lock Registry** | Asynchronous, stateless registry for double-spend prevention (`parent_lock -> child_lock`). | *lock register, blocking registry* |
| **Gutschein-Wurzel** | **Voucher Root / Root Anchor** | Origin lock (`root.valid_until`) anchoring TTL for all subsequent child locks. | *voucher tree, coupon origin* |
| **Kassenpfad / Hot-Path** | **PoS Hot-Path / Checkout Path** | In-memory collision check ($< 1\,\mu\text{s}$) with latency SLA $< 5\,\text{ms}$. | *register path, cashbox flow* |
| **Dorf-Merge** | **Village Merge / Local Mesh Merge** | Deterministic convergence of small isolated clusters ($N=1\dots3$) into global mesh via $\min(H_{\text{canon}})$. | *village fusion, rural merge* |
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
| **Schmarotzer / Trittbrettfahrer** | **Free-Riders / Free-Riding** | Peers consuming network bandwidth without signing or forwarding locks. | *parasites, hitchhikers* |
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
