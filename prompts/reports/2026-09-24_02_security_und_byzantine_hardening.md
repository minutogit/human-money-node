# 🛡️ Audit Report: Byzantine Security & Hardening (Prompt 02)

**Datum:** 2026-09-24  
**Modell:** `opencode/muse-spark-1.2-contributor-free` (via Model-Router)  
**Pillar:** 3. Byzantine Security  
**Status:** `🟡 Actionable Findings` (2 Critical, 3 High, 3 Medium, 2 Low)

---

## 🎯 Zusammenfassung der Befunde

Alle Befunde verifiziert per Code-Inspektion gegen `crates/humoco-sim-core` und `crates/humoco-node`.

### CRITICAL-01 – IngressCounterConflict forgebar (Anti-Hearsay Bruch)
* **Datei:** `crates/humoco-sim-core/src/fraud.rs:180-248` + `crates/humoco-sim-core/src/fraud.rs:383-512`
* **Szenario:** `sign_ingress_envelope()` konstruierte deterministische Fake-Signaturen ohne echten Secret Key. Jeder Angreifer konnte `digest` berechnen und gefälschte `FraudProofPayload::new_ingress_counter_conflict` erzeugen.
* **Maßnahme:** Ed25519-Signaturpflicht mit `SigningKey` und strikter `VerifyingKey::verify_strict`-Prüfung.

### CRITICAL-02 – PoW Parent-Binding Bypass via generischer Challenge
* **Datei:** `crates/humoco-node/src/ingress/pow.rs:204-213`
* **Szenario:** Bei `verify_pow_for_parent` wurde neben der erwarteten Challenge auch immer die generische Challenge `[0u8; 32]` akzeptiert. Ein Angreifer konnte so PoW 1x für Parent `0` lösen und für beliebig viele unterschiedliche Opfer-Parents wiederverwenden.
* **Maßnahme:** Wenn `expected_parent_lock` vorhanden ist (`Some`), darf ausschließlich die an den spezifischen Parent gebundene Challenge akzeptiert werden.

### HIGH-01 – Double-Spend kein Slash auf `RamIndex` Pfad + Verlust des Loser-VOID
* **Datei:** `crates/humoco-node/src/storage/engine.rs:444-482` und `crates/humoco-sim-core/src/resolver.rs:28-81`
* **Szenario:** Bei `IngressOrigin::PartitionSync` wurde der unterlegene Lock-Kandidat im Split-Brain (`Void`) im RAM überschrieben und nicht persistiert; kein `FraudProof` für Double-Signer generiert.
* **Maßnahme:** Unterlegenen Lock (`Void`) in Evidence-Table persistieren und Equivocation-Proof erzeugen.

### HIGH-02 – `POST /v1/sync` lädt gesamte DB mit `now=0` (State-Bloat & Read-DoS)
* **Datei:** `crates/humoco-node/src/api/routes.rs:179,203`
* **Szenario:** `all_valid_locks(0)` und `all_valid_hmc_locks(0)` übergeben Timestamp `0`, wodurch praktisch alle je gespeicherten Locks ungefiltert in den RAM geladen und ohne Obergrenze serialisiert werden.
* **Maßnahme:** Bereitstellung von `state.net_time_ms()` als TTL-Filter sowie hartes Obergrenzen-Limit (`MAX_SYNC_LOCKS = 10_000`).

### HIGH-03 – HMC `query_status` Prefix-Scan O(N*M) Read-DoS
* **Datei:** `crates/humoco-node/src/storage/engine.rs:206-238`
* **Szenario:** `locator_prefixes` unbeschränkt; Angreifer kann Tausende Prefixe senden und teure lineare Scans erzwingen.
* **Maßnahme:** Maximallimits für `locator_prefixes.len()` ($\le 32$) und `prefix.len()` ($\le 16$).

### MEDIUM-01 – VIP Quota TOCTOU & Blocking I/O im RwLock
* **Datei:** `crates/humoco-node/src/ingress/tier.rs:118-138`
* **Maßnahme:** Synchrone DB-Operationen aus dem in-memory `RwLock` entfernen und atomare DB-Verrechnung nutzen.

### MEDIUM-02 – Causality Chain CPU-Amplifikation
* **Datei:** `crates/humoco-sim-core/src/types.rs:1097-1100, 1138-1145`
* **Maßnahme:** Cheap-Checks-First (Genesis & Client-Sig vor Hop-Schleife) und Token-Bucket für Signaturverifikationen.

### MEDIUM-03 – Domain Separation Cross-Network Replay bei Testnet/Mainnet
* **Datei:** `crates/humoco-sim-core/src/crypto.rs:13-14`
* **Maßnahme:** Explizite Netzwerk-ID-Bindung für deterministische Attestation-Signaturen.

### LOW-01 – Framing Chunked Allocation
* **Datei:** `crates/humoco-node/src/network/framing.rs:176-178`
* **Maßnahme:** Inkrementelles Buffering statt `Vec::with_capacity(payload_len)`.

### LOW-02 – `SystemTime::now()` im PoW Ingress
* **Datei:** `crates/humoco-node/src/ingress/pow.rs:142,194`
* **Maßnahme:** Zeitangabe aus dezentraler P2P-Uhr (`state.net_time_ms() / 1000`) beziehen.
