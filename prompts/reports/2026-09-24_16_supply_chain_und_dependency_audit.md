# 📦 Audit-Bericht 16: Supply-Chain Security & Dependency Audit

**Datum:** 2026-09-24  
**Modell:** `opencode/muse-spark-1.2-contributor-free` (via Model-Router)  
**Status:** `🟢 Analysiert / Empfehlungen dokumentiert`

---

## 🎯 Zusammenfassung der 5 Prüfdimensionen

### 1. 🚨 Bekannte Schwachstellen & Advisories
* **Befund:** Keine kritischen CVEs in den Kernbibliotheken (`quinn`, `rustls`, `redb`, `blake3`, `argon2`, `tokio`).
* **Empfehlung:** `thiserror` von `1.0` auf `2.0` aktualisieren; `quinn` auf `0.11.12` heben.

### 2. 🌲 Abhängigkeitsbaum & Transitive Duplikate
* **Befund:** `Cargo.lock` enthält Duplikate bei `rand` (`0.7`, `0.8`, `0.9`, `0.10`) verursacht durch Legacy-Crates wie `cuckoofilter 0.5.0` und `proptest`.
* **Empfehlung:** `cuckoofilter` bereinigen oder durch moderne Alternativen ersetzen, um `rand 0.7` zu eliminieren.

### 3. ⚖️ Lizenz-Kompatibilität
* **Befund:** Alle genutzten Bibliotheken stehen unter permissiven Open-Source-Lizenzen (MIT, Apache-2.0, BSD-3-Clause, CC0).
* **Ergebnis:** Keine viralen Copyleft-Lizenzen (GPL/AGPL) im Abhängigkeitsbaum.

### 4. 🪶 Feature-Flag Minimierung
* **Befund:** `quinn`, `rustls`, `axum` und `mimalloc` sind bereits gut mit `default-features = false` minimiert.
* **Empfehlung:** `tokio` von `full` auf die tatsächlich genutzten Features (`rt-multi-thread`, `macros`, `net`, `sync`, `time`, `io-util`, `signal`) einschränken; `rustls` `tls12` Feature entfernen, da HuMoCo ausschließlich TLS 1.3 nutzt.

### 5. 🛠️ Konkreter Aktionsplan
* `deny.toml` für kontinuierliche Lizenz- und Advisory-Prüfungen in CI etablieren.
* `Cargo.toml` Abhängigkeiten minimal halten.
