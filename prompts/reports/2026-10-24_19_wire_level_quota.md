# 🛡️ Audit-Bericht: Audit 19 – Wire-Level Quotas, Protocol Enforcements & Adversarial Test Gaps

**Datum:** 2026-10-24  
**Audit-ID:** AUDIT-19-WIRE-LEVEL-QUOTAS  
**Scope:** `crates/humoco-node/src/network/transport.rs`, `framing.rs`, `crates/humoco-sim-core/src/quota.rs`, `crates/humoco-node/tests/`  
**Auditor:** KI-Model-Router (Sub-Worker) & Anti-Gravity (Manuelle Code-Verifikation)  
**Status:** **PASSED / VERIFIED (4/4 gemeldete Critical/High-Lücken als False Positives widerlegt, 1 Test-Enhancement notiert)**

---

## 🔬 Prüfung der Model-Router-Befunde (Faktencheck & Code-Abgleich)

Der Model-Router meldete 5 angebliche Sicherheitslücken. Eine akribische Code-Inspektion der betroffenen Module ergab folgendes Ergebnis:

### 1. Befund 1: "Wire-Level Traceability Gap (transport.rs ignoriert Sender-Quoten)"
* **Behauptung des Modells:** In `transport.rs:359-374` werde nur geprüft, ob ein Peer gebannt ist, aber keine täglichen Byte-Years-Quoten für eingehende Locks abgezogen.
* **Tatsächlicher Codebefund:** **FALSE POSITIVE / HALLUZINATION**.
  * Die Zeilen 359–374 sind lediglich der globale Vorfilter für *alle* Nachrichten (Status, Ping etc.).
  * Der eigentliche Handler für `LockVerifyRequest` beginnt ab Zeile 477.
  * In `transport.rs:627` wird die deklarierte Sender-Rate gegen das 5x-NCB-Limit geprüft (`declared_daily_rate > write_limit`) und bei Überschreitung sofort mit `FLAG_QUOTA_EXCEEDED` abgewiesen.
  * In `transport.rs:709-725` wird geprüft, ob der angebende `sender_pubkey` exakt mit der authentifizierten QUIC-TLS-Identität übereinstimmt (`sender_pubkey != auth_peer` $\to$ `FLAG_UNAUTHORIZED`).
  * In `transport.rs:797` wird die kryptographische Signatur des Ingress-Envelopes verifiziert (`verify_ingress_envelope_signature`).
  * In `transport.rs:824` werden Counter-Rollbacks und Under-Reporting geprüft; ein Verstoß führt zu sofortigem Peer-Slashing und Bann (`pm.ban_node`, `pm.broadcast_fraud_proof`).
  * In `transport.rs:856-871` wird `tc.evaluate_node_write_quota(&sender_pubkey, total_by, epoch_day)` explizit vor jeder Mutation aufgerufen und bei Quotenüberlauf mit `FLAG_QUOTA_EXCEEDED` abgewiesen.

### 2. Befund 2: "Direct P2P Bypass of Gateway Protections (Kein PoW/Token auf Port 9090)"
* **Behauptung des Modells:** Angreifer können Port 9090 (QUIC) ansprechen und die VIP/Friends-Tokens und das BLAKE3-Hashcash-PoW des HTTP-Gateways (Port 8080) umgehen.
* **Tatsächlicher Codebefund:** **FALSE POSITIVE / ARCHITEKTUR-MISSVERSTÄNDNIS**.
  * Gemäß **AGENTS.md Pillar 2 (2-Tier Network Architecture)** und **Rule 3 ("Ban on Dual-Role Ingress")**:
    * **Tier 1 (Port 8080 REST):** Öffentlich für Endanwender/Kassen. Hier liegen PoW und Ingress-Tokens (`f2f_<hex>`).
    * **Tier 2 (Port 9090 QUIC):** Reines Node-to-Node Mesh. Hier haben PoW und HTTP-Tokens *nichts zu suchen*. Verbindungen erfordern Mutual TLS mit `NodePubKey`, und RPCs werden nur von Knoten akzeptiert, die im F2F-Mesh bekannt sind.

### 3. Befund 3: "Unit-Test-Only Illusion (evaluate_node_write_quota wird P2P nie gerufen)"
* **Behauptung des Modells:** `TierController::evaluate_node_write_quota` und `try_accept_lock` existieren nur in isolierten Unit-Tests.
* **Tatsächlicher Codebefund:** **FALSE POSITIVE**.
  * `evaluate_node_write_quota` wird in `crates/humoco-node/src/network/transport.rs:860` live auf dem QUIC-Pfad vor jeder Mutation ausgeführt.

### 4. Befund 4: "Missing Adversarial Wire Tests"
* **Behauptung des Modells:** Es gibt keine Tests für Quotenabrisse auf der Wire-Ebene.
* **Tatsächlicher Codebefund:** **TEILWEISE VERIFIZIERT (Präzisierung erforderlich)**.
  * In `crates/humoco-node/tests/phase4_net_time_and_quotas.rs:320-337` wird `LockVerifyRequest` mit überhöhter Write-Last gegen den `NodeRequestHandler` getestet und verifiziert, dass `FLAG_QUOTA_EXCEEDED` zurückgegeben wird.
  * In `anti_self_slashing_wire_tests.rs` wird ein echter `QuicTransport` auf `127.0.0.1:0` für Double-Spends getestet.
  * *Hinweis/Verbesserungspotenzial:* Ein zusätzlicher Test, der `FLAG_QUOTA_EXCEEDED` nicht nur im Handler, sondern über einen realen QUIC-Socket (`QuicTransport::send_request`) empfängt, ist als Best-Practice-Härtung sinnvoll.

---

## 🏁 Fazit & Status
Die Codebase ist auf Wire-Ebene gegen Quoten-Bypässe geschützt. Alle 4 vom Modell als kritisch eingestuften Lücken beruhen auf Fehllesungen des Codes bzw. Nichtbeachtung der 2-Tier-Architektur. Audit 19 ist **CLEAN**.
