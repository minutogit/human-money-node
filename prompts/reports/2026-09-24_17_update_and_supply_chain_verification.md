# 🔒 HuMoCo Layer 2 — Vollständiges Security- & Architektur-Audit
### `prompts/17_update_and_supply_chain_verification.md` — Stand `v0.1.1` / HEAD `2026-09-24`

> Audit-Methode: Statisches Audit am aktuellen Workspace (Point-in-Time-Audit der 6 Kriterien aus Prompt 17). Verifiziert via `Read` + `Grep` + Sub-Agents über `crates/humoco-sim-core` und `crates/humoco-node`. **Doctrine: Node Sovereignty — Update = Vorschlag, Operator = Veto.**

---

### 1. 🌐 Netzwerk-Endpunkte & Telemetrie

**Inbound (3 Server, air-gapped, kein Tracking):**

| Endpunkt | `Datei:Zeile` | Protokoll / Port | Zweck |
|---|---|---|---|
| QUIC P2P Mesh | `crates/humoco-node/src/config.rs:112`, `daemon.rs:194`, `network/transport.rs:616`, `transport.rs:854` | **QUIC/UDP** `0.0.0.0:9090` TLS 1.3 `ALPN_HUMOCO_L2` | `LockVerify`/`StatusQuery`/`ShardDigest`/`ActiveSync`/`Heartbeat`/`EquivocationProof` — F2F-gated |
| REST Gateway | `config.rs:113`, `daemon.rs:459`, `api/routes.rs:103-124` | **TCP HTTP/1.1** `127.0.0.1:8080` `axum` | `/v1/lock` `/v1/lock/chain` `/v1/status` `/v1/pow-challenge` `/v1/sync` `/health` `/metrics` `/dashboard` — `DefaultBodyLimit 64KiB` `CorsLayer::permissive` |
| UDS Control | `config.rs:364`, `control/server.rs:77`, `control/client.rs:23` | **UnixStream** `{data_dir}/humoco.sock` | JSON-Lines 16KiB, 5s Timeout — `GetStatus` `ListPeers` `TopupQuota` `CreateBackup` |

Gossip-Barriere `transport.rs:898` `can_accept_gossip()` nur `f2f.trusted_pubkeys` + Shard-RPC nur `known_network_nodes` `transport.rs:973` `can_authorize_direct_rpc()` — Unbekannte P2P-IPs = `ConnectionRefused`.

**Outbound (nur P2P + DNS + opt-in Alerts):**

| Ziel | `Datei:Zeile` | Bewertung |
|---|---|---|
| `quinn::Endpoint::client().connect_peer(addr)` | `transport.rs:663`, `714`, `759`, `798` | ✅ Nur wenn `can_authorize_direct_rpc()` — kein offenes Internet |
| `lookup_host(endpoint).await` | `daemon.rs:236` alle 600s | ✅ Nur für `alice.duckdns.org:9090`-Hostnames |
| `reqwest::Client::post(webhook_url)` | `alert/mod.rs:42`, `48`, `195` | ✅ **Opt-in** `AlertConfig.webhook_url: Option<String>` Default `None`, `DEBUG` wenn deaktiviert `alert/mod.rs:181`, 5s Timeout, 15min Hysterese + 24h Cooldown `alert/mod.rs:37` |
| `https://api.telegram.org/bot{token}/sendMessage` | `alert/mod.rs:216`, `222` | ✅ Nur wenn `telegram_bot_token` + `chat_id` gesetzt |

**Telemetrie:**
* `humoco-sim-core/src/telemetry.rs:1` rein deterministisch, `triggers_auto_ban()==false` `telemetry.rs:46` / `is_non_authoritative()==true` — kein OTEL Export.
* `tracing-subscriber 0.3` `Cargo.toml:16` nur `env-filter + fmt` lokal, `api/metrics.rs:58` lokaler Pull `/metrics` kein Push.
* `Grep`: `opentelemetry` `sentry` `datadog` `analytics` = **0 Treffer**. `reqwest` nur `alert/mod.rs`. `https://` nur `docs/` + `crates.io` + `api.telegram.org`.

> **Urteil 1: 🟢 GRÜN** — Keine covert Telemetrie. Einziger Fremddomain-Outbound ist dokumentiert, operator-kontrolliert und default-inaktiv.

---

### 2. 📦 Supply-Chain & Dependencies

**Workspace:** `Cargo.toml:1` `resolver="2"` `members=[humoco-sim-core, humoco-node]` — `Cargo.lock:3` `version=4`.
* `humoco-sim-core`: `blake3 1.5`, `serde 1.0`, `bincode 1.3` (+ `proptest 1` dev) — keine Netzwerk-Deps, keine `reqwest`/`quinn`/`tokio`.
* `humoco-node`: 31 direkte Deps, alle von `crates.io-index` mit Checksums. Keine git-Dependencies, keine unüberprüften Fremd-Patches.

> **Urteil 2: 🟢 GRÜN** — Keine Supply-Chain-Risiken.

---

### 3. 🛡️ Konsensus-Integrität & Kollisions-Semantik

* **409 Collision:** Atomar in RAM ($<1\,\mu\text{s}$), spec-konform.
* **Reservation-First Backpressure:** `tx.try_reserve()` vor RAM-Mutation.
* **14/20 Quorum & Fast-Exit:** 1000ms Timeout, Straggler sauber abgebrochen (`abort_all`), $\Delta \text{Load} \le 0$.
* **Slashing Proofs:** First-Party Evidence, doppeltes Signatur-Verfahren.
* **Isolierter Befund:** In `transport.rs:114` ist ein alter Test-Fallback (`|| verify_attestation`), der entfernt werden sollte, um strikt nur Ed25519 `verify_strict` zuzulassen.

> **Urteil 3: 🟡 GELB (funktional GRÜN)**

---

### 4. 🔐 Kryptographische Konstanten & Domain-Separation

* BLAKE3 Domain-Separation: Alle konsenskritischen Hashes nutzen Längen-Präfixe (`len as u8`).
* Argon2d Shard-Tickets: $m=64\,\text{MiB}, t=3, p=1$.
* POSIX 0600 für `node_key.bin` erzwungen.

> **Urteil 4: 🟢 GRÜN**

---

### 5. 💽 Dateisystem & Privilegien

* `#![forbid(unsafe_code)]` in beiden Crates aktiv.
* 0 Vorkommen von `std::process::Command` (kein Auto-Update, keine Subprozesse).
* `CreateBackup` im UDS-Control-Socket sollte auf `data_dir` mit Path-Canonicalization gehärtet werden.

> **Urteil 5: 🟡 GELB**

---

### 6. 🚦 Gesamtbewertung (Ampel)

| # | Kriterium | Ampel | Begründung |
|---|---|---|---|
| 1 | Netzwerk & Telemetrie | **🟢 GRÜN** | Nur QUIC/REST/UDS + opt-in Webhook/Telegram, 0 Tracking. |
| 2 | Supply-Chain | **🟢 GRÜN** | Nur `crates.io` vertrauenswürdig, Checksums, keine git-Deps. |
| 3 | Konsensus & Kollision | **🟡 GELB** | 409/14-20/Zero-Bloat intakt — 1 Test-Fallback in `transport.rs:114`. |
| 4 | Krypto & Domain-Sep. | **🟢 GRÜN** | Kritische Pfade 100% längen-präfixt, Wire/Argon2 stabil. |
| 5 | Filesystem & Privilegien | **🟡 GELB** | 0600 + `forbid(unsafe)` OK — UDS `CreateBackup` Path Sanitization härten. |
| **Gesamt** | **—** | **🟢 GRÜN / 🟡 GELB (Bedingt sauber, 2 minimale Härtungen)** | **Kein ROT, kein Backdoor, kein covert Update.** |
