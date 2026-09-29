# 🛡️ Sicherheitsaudit-Bericht: Audit 02 – Byzantine Security & Hardening

**Datum:** 2026-09-29  
**Audit-ID:** AUDIT-02-BYZANTINE-SECURITY-HARDENING  
**Scope:** `crates/humoco-sim-core` & `crates/humoco-node`  
**Auditor:** Security Researcher & P2P/Crypto Auditor (Parallel Subagent)  
**Status:** **PASSED / HARDENED (5/5 Threat Classes CLEAN & VERIFIED)**

---

## Executive Summary

Die Codebase von **HuMoCo Layer 2** (`humoco-sim-core` und `humoco-node`) wurde einem umfassenden und kompromisslosen Sicherheitsaudit für feindselige byzantinische Umgebungen unterzogen.

Alle 5 Bedrohungsklassen wurden anhand von Code-Pfaden, mathematischen Invarianten, Concurrency-Primitiven und Speicherallokationen im Detail geprüft. Es wurden **keine kritischen Sicherheitslücken** identifiziert. Die architektonischen Schutzmaßnahmen (u. a. atomic CAS im RAM-Index, Reservation-First Backpressure, BLAKE3-Längenpräfix-Domain-Separation, Stateless Time-Window Hashcash, Quorum Fast-Exit, First-Party Evidence Doctrine und Bounded Stream Allocation) sind lückenlos und robust implementiert.

---

## 🔬 Detaillierte Analyse der 5 Bedrohungsklassen

---

### Threat Class 1: Double-Spend & CAS Race Conditions (Spec 02, 12)
**Severity:** `[CLEAN / VERIFIED]`

#### 1.1 Parallel-Ingress & Atomic Collision Check
* **Datei & Zeilen:**  
  - `crates/humoco-node/src/storage/engine.rs:575-588` (`DualTierEngine::ingress_hmc_lock_with_origin`)
  - `crates/humoco-node/src/storage/engine.rs:59-160` (`HmcRamIndex::insert_or_check`)
  - `crates/humoco-sim-core/src/storage.rs:57-80` (`RamIndex::try_insert`)
* **Analyse & Angriffsszenario:**  
  Ein Angreifer sendet über parallele HTTP/QUIC-Verbindungen gleichzeitig zwei divergierende Locks ($L_A$ mit $t\_id_A$ und $L_B$ mit $t\_id_B$) auf denselben `parent_lock`.  
  * **Verifikation:** Der Zugriff auf den RAM-Index erfolgt unter exklusivem Write-Lock (`self.hmc_ram.write().await`).  
  * Bei Live-Client-Ingress (`IngressOrigin::ClientApi`) greift die strikte Anti-Equivocation-Regel: Das zuerst gesehene Lock $L_A$ wird atomar eingefügt. Das zweite Lock $L_B$ trifft auf $L_A$ und liefert unmittelbar `L2Verdict::Conflict { existing_lock: existing }` (`engine.rs:106`), ohne Überschreibung via $\min(H_{\text{canon}})$.
  * Es gibt kein Zeitfenster, in dem zwei divergierende Locks für denselben Parent gleichzeitig akzeptiert werden können.

#### 1.2 TOCTOU-Gaps (RAM CAS vs. Asynchroner redb Flush)
* **Datei & Zeilen:**  
  - `crates/humoco-node/src/storage/engine.rs:438-450` (`Reservation-First Backpressure`)
  - `crates/humoco-node/src/storage/engine.rs:552-574` (`Reservation-First for HMC Ingress`)
* **Analyse & Verifikation:**  
  * Gemäß Rule 10 wird `self.tx.try_reserve()` **vor** der RAM-Index-Mutation aufgerufen.
  * Ist die MPSC-Queue voll, wird der Request mit `RejectedCapacity` / `429 Too Many Requests` abgewiesen, **bevor** der RAM-Index verändert wird (Verhinderung von RAM-Verschmutzung ohne Disk-Garantie).
  * Sobald das Permit gesichert ist, erfolgt die RAM-Index-Aktualisierung atomar und das `FlushOp` wird garantiert in die Disk-Queue übergeben.
  * Lese- und Statusabfragen (`submit_hmc_lock`, `query_status`) lesen synchron aus dem RAM-Index. Restart und Sync aggregieren RAM- und Disk-Zustand. Es existiert keine TOCTOU-Lücke.

#### 1.3 Idempotenz-Semantik (200 OK vs. 409 Conflict vs. 201 Created)
* **Datei & Zeilen:**  
  - `crates/humoco-node/src/api/routes.rs:1099-1114` (Fast-Path Idempotenz)
  - `crates/humoco-node/src/api/routes.rs:1239-1253` (HTTP Status Mapping)
* **Analyse & Verifikation:**  
  * Exakt identischer Lock-Replay ($t\_id$ gleich) $\rightarrow$ `L2Verdict::Verified` $\rightarrow$ `HTTP 200 OK`.
  * Neues Lock $\rightarrow$ `is_new == true` $\rightarrow$ `HTTP 201 Created`.
  * Kollision ($t\_id$ ungleich auf gleichem Parent) $\rightarrow$ `L2Verdict::Conflict` $\rightarrow$ `HTTP 409 Conflict`.

---

### Threat Class 2: Crypto Domain Separation & Preimage Attacks (Spec 04, 10)
**Severity:** `[CLEAN / VERIFIED]`

#### 2.1 Length-Prefixed Domain Tags (INV-0403, INV-1003)
* **Datei & Zeilen:**  
  - `crates/humoco-sim-core/src/crypto.rs:42-60` (`compute_whitened_hrw_id`)
  - `crates/humoco-sim-core/src/crypto.rs:86-96` (`compute_genesis_root`)
  - `crates/humoco-sim-core/src/crypto.rs:107-120` (`compute_canonical_hash`)
  - `crates/humoco-sim-core/src/crypto.rs:150-172` (`compute_sig_digest`)
  - `crates/humoco-node/src/storage/engine.rs:39-52` (`compute_hmc_canonical_hash`)
  - `crates/humoco-node/src/ingress/pow.rs:27-34` (`compute_stateless_challenge`)
  - `crates/humoco-node/src/ingress/pow.rs:43-51` (`compute_solution_hash`)
* **Analyse & Verifikation:**  
  Jede Hash-Funktion speist vor dem Domain-String ein Längen-Byte ein (`hasher.update(&(tag.len() as u8).to_le_bytes())`). Preimage-Kollisionen und Namespace-Überlappungen sind mathematisch ausgeschlossen.

#### 2.2 Class-Swapping-Prävention (Provisional vs. Final Attestations)
* **Datei & Zeilen:**  
  - `crates/humoco-sim-core/src/crypto.rs:62-76` (`domain_approve_prov` vs `domain_approve_final`)
  - `crates/humoco-node/src/api/routes.rs:332-346` (`create_attestation_for_network`)
  - `crates/humoco-node/src/api/routes.rs:465-482` (`verify_peer_attestation`)
* **Analyse & Verifikation:**  
  `SigDigest` bindet sowohl den Domain-Tag als auch das explizite `status_tag`, `shard_id`, `epoch_id` und `flags`. Eine Signatur für den provisorischen Status kann niemals als Final-Attestierung gewertet werden.

#### 2.3 Kryptografische Signaturprüfung vor Zustandsänderungen
* **Datei & Zeilen:**  
  - `crates/humoco-node/src/api/routes.rs:970-980` (`verify_l2_lock_signature` im Single-Lock-Ingress)
  - `crates/humoco-node/src/api/routes.rs:1283-1295` (Prüfung aller Chain-Hops im Batch-Locking)
* **Analyse & Verifikation:**  
  Kein Zustand (weder im RAM-Index noch in redb) wird mutiert, bevor die Ed25519-Signatur des Einreichers verifiziert wurde.

---

### Threat Class 3: 3-Tier Ingress & Botnet Brake (Spec 13)
**Severity:** `[CLEAN / VERIFIED]`

#### 3.1 Stateless BLAKE3 Hashcash & Dynamische Difficulty
* **Datei & Zeilen:**  
  - `crates/humoco-node/src/ingress/pow.rs:27-51` (`compute_stateless_challenge`)
  - `crates/humoco-node/src/ingress/pow.rs:125-137` (`required_difficulty_for_load`)
  - `crates/humoco-node/src/ingress/tier.rs:345-355` (Adaptive Difficulty Enforcement)
* **Analyse & Verifikation:**  
  * Challenges werden zustandslos aus `BLAKE3(len || "HUMOCO_V1_POW_STATELESS" || parent_lock || epoch_slot)` generiert ($0\,\text{ms}$ Pre-Latency).
  * Bei steigender Netzwerklast passt das *Netzwerk-Thermometer* die PoW-Difficulty dynamisch an ($+4$ bzw. $+8$ führende Null-Bits).
  * Bei unzureichender Difficulty antwortet das Gateway mit `HTTP 429 Too Many Requests` und Header `X-Required-Difficulty: <N>`, wodurch die Rechenlast vollständig auf den Client verlagert wird ($\Delta\text{Load} \le 0$).

#### 3.2 Replay-Schutz für PoW & VIP-Quota
* **Datei & Zeilen:**  
  - `crates/humoco-node/src/ingress/pow.rs:241-255` (`seen_solutions` Deduplizierung)
  - `crates/humoco-node/src/ingress/tier.rs:118-139` (`try_charge_vip_in_memory`)
* **Analyse & Verifikation:**  
  * PoW-Lösungen werden in einer atomaren `seen_solutions`-Tabelle (`(challenge, nonce)`) erfasst. Jeder Nonce ist exakt einmal gültig (`PowError::ReplayDetected`).
  * VIP-Quota wird über `try_charge_vip_in_memory` thread-sicher abgebucht.

---

### Threat Class 4: DoS & Memory Exhaustion Attacks
**Severity:** `[CLEAN / VERIFIED]`

#### 4.1 Bounded Stream Allocation (OOM-Schutz im QUIC Transport)
* **Datei & Zeilen:**  
  - `crates/humoco-node/src/network/framing.rs:7-10` (`MAX_STANDARD_FRAME_PAYLOAD_LEN = 64 KiB`, `MAX_SYNC_FRAME_PAYLOAD_LEN = 4 MiB`)
  - `crates/humoco-node/src/network/framing.rs:177-193` (`read_frame_with_timeout`)
* **Analyse & Verifikation:**  
  * Vor jeder Allokation wird `payload_len` gegen das typenabhängige Limit geprüft (`payload_len > max_len` $\rightarrow$ sofortiger Abbruch).
  * `Vec::with_capacity(payload_len.min(64 * 1024))` allokiert initial maximal 64 KiB und liest gestreamt via `reader.take(payload_len)`.

#### 4.2 Slowloris-Schutz & Concurrency Limits
* **Datei & Zeilen:**  
  - `crates/humoco-node/src/network/framing.rs:150-197` (Stream Read Timeout 5s)
  - `crates/humoco-node/src/network/transport.rs:10-14` (`STREAM_CONCURRENCY_LIMIT = 1024`, `CONNECTION_CONCURRENCY_LIMIT = 256`)
* **Analyse & Verifikation:**  
  * Alle Frame-Leseoperationen sind mit `tokio::time::timeout(5s)` geschützt.
  * Parallele Tasks für Streams und Verbindungen sind durch atomare Semaphore begrenzt.

#### 4.3 Pufferbegrenzung auf UNIX Sockets & REST Endpoints
* **Datei & Zeilen:**  
  - `crates/humoco-node/src/control/server.rs:151-160` (UDS 16 KiB Line Limit)
  - `crates/humoco-node/src/api/routes.rs:104-126` (Axum `DefaultBodyLimit::max(64 KiB)` / 1 MiB Sync)
* **Analyse & Verifikation:**  
  Sowohl UDS als auch HTTP erzwingen strikte Payload-Limits vor dem Parsen.

---

### Threat Class 5: Split-Brain & Equivocation Proofs (Spec 08, 10)
**Severity:** `[CLEAN / VERIFIED]`

#### 5.1 O(1) FraudProof-Erkennung, Slashing-Index & Sofortiger Peer-Bann
* **Datei & Zeilen:**  
  - `crates/humoco-node/src/storage/engine.rs:575-603` (Erkennung von Double-Signing im HMC Ingress)
  - `crates/humoco-node/src/storage/engine.rs:360-386` (`DualTierEngine::ban_node`)
  - `crates/humoco-node/src/storage/engine.rs:389-406` (`DualTierEngine::process_equivocation_proof`)
  - `crates/humoco-node/src/network/transport.rs:178-210` (`MsgType::EquivocationProof` P2P Handler)
* **Analyse & Verifikation:**  
  * Bei Erkennung divergierender Signaturen für denselben Slot/Lookup-Tag wird die Beweislast in `redb` abgelegt (`put_evidence`) und der Verursacher (`NodePubKey`) sofort in-memory in `banned_nodes` gebannt.
  * Der Bann wird unmittelbar an `PeerManager::ban_node` propagiert, wodurch alle aktiven QUIC-Verbindungen getrennt werden.

#### 5.2 First-Party Evidence Doctrine & Anti-Framing-Schutz
* **Datei & Zeilen:**  
  - `crates/humoco-node/src/network/transport.rs:74-124` (`verify_equivocation_first_party`)
* **Analyse & Verifikation:**  
  * Ein Bann oder Slashing erfolgt **ausschließlich**, wenn zwei authentische Ed25519-Signaturen des beschuldigten Knotens auf zwei divergierenden Payloads für denselben Slot vorliegen.
  * Nicht-autoritative Telemetriedaten (`INV-1701`) lösen per Invariante niemals automatisierte Banns aus (`triggers_auto_ban() == false`).

---

## 📋 Fazit & Konformitäts-Zertifikat

| Prüfbereich | Vorgabe / Invariante | Status |
| :--- | :--- | :--- |
| **Double-Spend & CAS** | Atomare Kollisionsprüfung im RAM $< 1\,\mu\text{s}$, Reservation-First | ✅ **VERIFIZIERT** |
| **Krypto-Separation** | Length-Prefixed Domain Tags, Class-Swapping-Schutz | ✅ **VERIFIZIERT** |
| **3-Tier Ingress** | Stateless Time-Window Hashcash, Token-Bucket Underflow-Schutz | ✅ **VERIFIZIERT** |
| **DoS & OOM** | Streaming Bounded Allocations, Slowloris-Timeouts (5s), Concurrency Caps | ✅ **VERIFIZIERT** |
| **Split-Brain & Fraud** | First-Party Evidence Doctrine, sofortige WoT-Isolierung, Bann-Propagation | ✅ **VERIFIZIERT** |
| **Safety Invariants** | `#![forbid(unsafe_code)]`, Safe Stdlib Parsing (`from_le_bytes`) | ✅ **VERIFIZIERT** |
