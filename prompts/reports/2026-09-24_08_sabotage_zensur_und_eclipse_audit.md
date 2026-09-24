# 🎯 HuMoCo Layer 2 — Sabotage, Zensur, Gaslighting & Eclipse Audit
### `prompts/08_sabotage_zensur_und_eclipse_audit.md` — Stand `2026-09-24`

> **Doctrine (Spec 05, 07, 17):** *"No node shall be the sole source of truth for any client. The only defense against censorship is multi-homing and mathematical provability."*

---

### 1. 🌑 Eclipse Attack auf PoS-Terminals / Händler

* **Befund:** Verbindet sich ein Händler-Terminal nur mit einem einzigen Gateway (Single-Bridge), kann dieses Gateway Zahlungen selektiv verzögern oder ablehnen.
* **Architektonische Lösung:** Clients/PoS-Terminals müssen Multi-Homing über mindestens 3 unabhängige Shard-Gateways durchführen. Auf Server-Ebene ist die Unabhängigkeit mathematisch garantiert; die Verantwortung liegt beim Smart Client (Spec 06).

---

### 2. 🌫️ Gaslighting & Fake States

* **Befund:** Ein böswilliger Knoten kann keine gültigen gefälschten Locks generieren, da `verify_l2_lock_entry_signature` (`hmc.rs:347`) die echte Signatur des Voucher-Inhabers verlangt.
* **Client-Side Custody:** Die Kausalitäts-Verifikationskette (`ProofChain`) schützt das Wallet vollständig, da der Server die Genesis-Wurzeln nicht fälschen kann.

---

### 3. 👥 WoT-Infiltration & Endorsement-Bombing (Spec 07)

* **Schutzmechanismen:**
  - `HRW_INCUBATION_SECS = 86400` (24h Inkubation für neue Shard-Tickets).
  - `FirstSeenPacer`: Drosselung neuer Knoten (1 / 3600s).
  - Dunbar Fan-Out $k = \min(d, \lceil\sqrt{d}\rceil + 1)$.
  - F2F-Median-Schutz (`compute_f2f_median`) filtert Ausreißer bis $< 50\%$ byzantinischer Nachbarn.
* **Zero Guilt-by-Association:** In HuMoCo haften Freunde nicht finanziell für gefallene Nachbarn (Zero Deposits / Blind L2); Strafen erfolgen atomar über `NodePubKey`-Bann und WoT-Kanten-Trennung des Täters.

---

### 4. 🕳️ Grey-Hole & Selektives Dropping

* **PeerManager Reaktionsmuster:**
  - Debounced Failure-Tracking (60s Debounce).
  - Quorum-Fast-Exit (14/20 Signatures) verhindert, dass langsame Straggler den Checkout-Pfad blockieren.
  - Abgebrochene Straggler erzeugen keine Last-Kaskaden ($\Delta \text{Load} \le 0$).

---

### 5. 🚦 Fazit & Härtungsempfehlungen

* Core-Konsensus und Invarianten sind robust gegen Sabotage.
* Ergänzende Härtung: Im PoS/Client-SDK standardmäßig `read_quorum >= 2` fordern und Hedging über 3 Gateway-IPs forcieren.
