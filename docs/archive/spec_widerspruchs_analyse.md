# Strukturierte Widerspruchs- & Konsistenz-Analyse: HuMoCo Layer-2 Sperrregister

> **Scope:** `docs/00`–`docs/19`, `docs/99`, `docs/audit_und_optimierungspotenziale.md`, `docs/architektur_knotenperspektive_threat_model.md`, `README.md` vs. `crates/humoco-sim-core/src/*.rs`  
> **Analysiert durch:** Model-Router (`opencode/muse-spark-1.2-contributor-free`)  
> **Datum:** 2026-09-01  
> **Methodik:** Volltext-Vergleich aller Markdowns untereinander + Diff gegen Rust-Sim (`types.rs`, `crypto.rs`, `quota.rs`, `storage.rs`, `wire.rs`, `state_machine.rs`, `resolver.rs`, `fraud.rs`, `client_flow.rs`)

---

## 1. Executive Summary

| Kritikalität | Anzahl | Kernaussage |
|---|---|---|
| **🔴 Konsens-kritisch** | **6** | Divergierende `FINAL`-Signatur führt zu gespaltenem Grün/Gelb ohne byzantinischen Täter |
| **🟠 Hoch (Liveness/DoS)** | **11** | Merge `<500ms`, 10:10-Split, Argon-Saturation, TTL-Resurrection |
| **🟡 Mittel (Privacy/Spec-Präzision)** | **9** | `valid_until`-Leak, unbounded RAM, Dunbar-Formel-Divergenz |
| **🔵 Simplicity/Deprecated** | **5** | 4 Schichten Ballast (Byte-Jahre-Inflation, BLS, HIGH_ASSURANCE) |
| **🟣 Doku ↔ Code** | **8** | `malus_score>>=1` vs. `=0`, 12h vs. 24h Uptime, `nonce` vs. `Sig` in `H_canon` |

---

## 2. Konsens-kritische Widersprüche (sofort normieren)

### K-01 — Zwei konkurrierende Signatur-Preimages (Class-Swapping)
* **Primär:** `docs/10:193-217` `SigDigest = BLAKE3(len||DOMAIN_TAG||epoch_id_le||session_seq_le||flags_le||shard_id_le||status_tag||payload_digest)`  
  **vs.** `docs/03:236-247` & `docs/08:58-60` `BLAKE3(status_tag||LockHash)` & `docs/04:265-272` `BLAKE3(HUMOCO_V1_CANON_RESOLVER||Parent||Receiver||Sig)` & `docs/04:255-261` `BLAKE3("HuMoCo-L2"||VERSION||T0)` ohne Längenpräfix.
* **Kollateralschaden:** `docs/10:186` `hasher.update(domain_tag)` ohne `len` → Präfix-Kollision `"HUMOCO_V1_RAW"+"EXTRA" == "HUMOCO_V1_RAWEXTRA"`. Tabelle `docs/10:181-191` listet 5 Tags, Code nutzt ≥8 (`HUMOCO_V1_INGRESS_DECL`, `HUMOCO_V1_SHARD_WORK` in `docs/10:295-313` fehlen).
* **Angriff:** Signiert mit `HUMOCO_V1_APPROVE_PROV (0xA2)` + `FLAG_PROVISIONAL`, Gateway verifiziert verkürzt via `status_tag`-Pfad → akzeptiert als `FINAL` wenn `signer_bitmap.count_ones()>=14` (`docs/08:134` `INV-0805`).
* **Code-Status:** `crates/humoco-sim-core/src/crypto.rs:9-19` nutzt `BLAKE3(DOMAIN||Parent||Receiver||nonce)` ohne `len`, `epoch_id`, `status_tag` — inkompatibel zu `docs/10:193`. Keine `len`-Bindung.
* **Empfehlung:** SSOT `fn sig_digest(...)` aus `docs/audit: K-01` (`len||tag||epoch_id_le||...||status_tag||payload_digest`) in `docs/04:276-295` + `docs/10:193` verankern, alle Kurz-Preimages aliasen, `GENESIS_ROOT` auf `BLAKE3(len||"HuMoCo-L2"||VERSION_le||T0_le)` + `HUMOCO_V1_GENESIS` normieren. Verifikationstest: `PROV`-Sig in `FINAL`-Kontext muss `false` liefern.

### K-02 — BLS12-381 vs. Ed25519 Aggregat fälschbar
* **Files:** `docs/04:60-65` `aggregate_signature: [u8;96] BLS` vs. `docs/10:321-328` `[u8;64] Ed25519` vs. `docs/10:498` `BLAKE3-Aggregat` trivial fälschbar; `docs/04:58-62` `signer_bitmap: u32` (20 Bits) order-independent.
* **Angriff:** 1 Node signiert 14× mit gleicher `sk` über verschiedene `session_seq` → `count_ones>=14` passiert, ohne `proof-of-possession`.
* **Code:** `crates/humoco-sim-core/src/client_flow.rs:83-120` + `src/wire.rs` nutzt ausschließlich Ed25519 `Vec<Attestation>` (kein BLS). `src/fraud.rs:186-200` erzeugt `FraudProofPayload::new_shard_equivocation` strikt Ed25519-deterministisch. BLS existiert nur in Doku — Implementierung weicht ab.
* **Empfehlung:** Ed25519 Batch-Verify als SSOT (Simplicity): BLS streichen; ShardWorkAttestation ersatzlos streichen zugunsten schlanker P2P-Reziprozität.

### K-03 — Quorum-Formel `floor` vs. `ceil` (+`min`)
* **Files:** `README.md:22` jetzt korrekt `Q(R)=min(R, floor(2R/3)+1)`, aber `docs/05:110-116` + `docs/00:94-97` `floor`, historisch `ceil` in Audit. `R=10`: `floor →7/10` vs. `ceil →8/10` (1 Stimme = FINAL vs. PROVISIONAL). `R=20` zufällig gleich (14/20) verdeckt Bug.
* **Code:** `crates/humoco-sim-core/src/types.rs:149-163` `required_quorum() = (2*N)/3+1` = `floor`, `(14,true)` bei `>=20` — korrekt per `docs/00:96`. Fix in README bereits erfolgt, aber keine kanonische Testvektor-Tabelle in `docs/04:296-304`.
* **Empfehlung:** Zentraler Helper `pub fn quorum(r:u16)->u16{ (r*2)/3+1 }` in `docs/04:296-304` + `crates/.../types.rs:149` verlinken, Tabelle `R=1..20` abnehmen, alle `ceil`-Relikte streichen.

### K-04 — `FINAL` hat 3 inkompatible Definitionen (sofort vs. 24h Hysterese)
* **Files:** `docs/00:88-94`, `docs/02:70-73` `N>=20 && sigs>=14 => FINAL` (sofort) **vs.** `docs/03:178-181`, `docs/08:36-60` `N>=20 seit ≥24h stabil + status_tag=0x01`. `docs/06:98-101` Hot-Path gibt Ware bei `>=14/20` sofort grün frei, ehrliche Nodes signieren aber noch `0x00`.
* **Fenster 0–24h:** Gateway sammelt 14 Sigs mit `0x00` → nach `docs/02` FINAL, nach `docs/08` PROVISIONAL → Händler-Split ohne Täter. `docs/audit: K-04` bestätigt aus Knotenperspektive `docs/architektur...:374-390`.
* **Code:** `crates/humoco-sim-core/src/types.rs:153-163` & `src/state_machine.rs:94-112` `is_final_threshold = active_nodes>=20` ohne Hysterese-Check. `src/client_flow.rs:76` `is_final = sigs>=14 && top20.len()>=20` ebenso ohne 24h-Gate. `INV-0802` nicht implementiert.
* **Empfehlung:** Zweistufig normieren: `FINAL_candidate (14 Sigs, status 0x00 bis Hysterese)` vs. `FINAL_stable (0x01)`, `docs/02:70`, `docs/06:98` um `&& hysteresis_ok` ergänzen, `INV-0806` neu, `GET /network_status {N_aktiv, hysteresis_remaining_sec}` für Wallet-UX.

### K-05 — `PROVISIONAL→FINAL` Promotion-Race & Gratis-Loop
* **Files:** `docs/02:142-148` `POST /promote_lock` kostenlos vs. `docs/09:20-24` `192/224B×TTL` & `docs/06:211` Batch. Kein Idempotenz-Key, kein Retry-Backoff.
* **Bruch:** `INV-0901` (jedes BJ zählt) gebrochen, `INV-1204` umgangen. Promotion kurz vor `valid_until` (`docs/12:68`) oder mitten in Hysterese undefiniert.
* **Code:** `crates/humoco-sim-core/src/state_machine.rs:114-134` `promote_to_final_if_eligible()` prüft nur `Void`+`sig.len>=Q`, keine `µBJ`-Verrechnung, keine `status_tag`-Monotonie (`0x00<0x01<0x02` ist kein Conflict).
* **Empfehlung:** Neue `INV-0206 Idempotente Promotion`: `lock_hash` identisch + `status_tag` monoton = Upgrade, gratis nur bei identischem `lock_hash` ohne TTL-Verlängerung, sonst `µBJ` voll. 1-RTT, Retry alle 60s exp. max 3, `409 ConflictWithEvidence` bricht ab → `VOID`.

### K-06 — Shard-ID Off-by-One (3-Byte Slice)
* **Files:** `docs/03:14` `Genesis_Hash[0..2] mod 65536` (3 Bytes!) + `docs/06:77` identisch **vs.** korrekt `docs/04:308-310` `u16::from_be_bytes([genesis_hash[0], genesis_hash[1]])`.
* **Effekt:** `u16::from_be_bytes` erwartet 2 Bytes, `[0..2]` = 3 Bytes → Compile-Panic oder implizites Truncate, Gateway vs. Shard routen auseinander → `First-Seen` verfehlt, Double-Spend übersehen.
* **Code:** `types.rs` nutzt `hrw_score(node_id.to_le_bytes||shard_id.to_le_bytes)` — korrekt 2-Byte, aber kein `get_shard_id()` Helper vorhanden. Inkonsistenz bleibt.
* **Empfehlung:** `docs/03:14` + `docs/06:77` korrigieren auf `from_be_bytes([0],[1])` ohne `mod`, `INV-0302` ergänzen: „Trust-Tree Lokalität via 2-Byte Big-Endian Präfix“, Fuzz-Test.

---

## 3. Hoch-kritische Liveness/DoS-Widersprüche

### H-01 — `session_seq` global vs. per-Connection + `epoch_seq` Doppelzählung
`docs/10:62-64,250` `session_seq:u64` strikt `seq_{n+1}=seq_n+1` exakt → Migration/Packetloss false `SequenceGap`. Parallel `epoch_seq:u32` global pro `epoch_day` (`docs/10:295-309`), aber Gateway sendet parallel an Shard A `seq=5` und Shard B `seq=5` (`docs/03:44-54`) → fälschlich Säule-1-Double-Signing. `INV-1007` kollidiert.  
**Fix:** `session_seq` nur per-Connection via `quinn`, applikatorisch nur `epoch_seq` global monoton pro `(gateway_pubkey,epoch_day)` validieren; `INV-1007` auf `(pubkey== && epoch_day== && epoch_seq== && lock_hash!= && shard_id≥2 verschieden)` präzisieren.

### H-02 — 0-RTT Whitelist divergiert
`docs/10:100-122` & `docs/15:78-88` whitelisten `ActiveSyncRequest` idempotent, aber Code-Beispiel `docs/10:474-480` implementiert nur 3 Typen (`StatusQuery|LatencyProbe|ShardMapPing`). `ShardDigestRequest` (`docs/03:125-159`) nirgends gewhitelisted.  
**Code fixt partiell:** `crates/.../src/wire.rs:123-129` erlaubt bereits `ActiveSyncRequest` 0-RTT — damit divergiert Doku-Code-Beispiel von echter Impl. 32B Request → Stream Amplification.  
**Fix:** SSOT `docs/10:100-122` + Code vereinheitlichen, beide `ShardDigestRequest`+`ActiveSyncRequest` whitelisten **mit** per-IP Rate-Limit + globalem `W=4096` Bloom Filter.

### H-03 — Gradienten-Proof unprüfbar (EMA vs. Bit-Shift)
`docs/10:359-386` `e^{-delta/24h}` transzendent vs. Verbot in `docs/04:224` (`deterministic_decay` via `>>`), `144B` vs. `192B` vs. `224B` Footprint (`docs/09:18` vs `docs/12:108-110`) → 25% Delta false Slashing. `timestamp_ms` Sättigung undefiniert.  
**Code:** `src/quota.rs:10` `STORED_LOCK_BYTES=192` fest, aber `docs/09:126` fordert `240k` vs. `960k` Baseline.  
**Fix:** Ingress-Abrechnung `144B×Δt_TTL` (Wire), `192/224B` nur interne Kosten; `e^x` durch `deterministic_decay` (`docs/04:224`) ersetzen; Toleranz ±2%.

### H-04 — `FINAL` ohne Hysterese-Bindung fälschbar (Insel 14 Nodes)
Hysterese nur lokale Policy, nicht im `QuorumCertificate` beweisbar (`signer_bitmap.count_ones()>=14 && status==0x01` reicht). Insel `N=14` mit 14 bösen Nodes signiert sofort `0x01` → als `FINAL` akzeptiert. `HIGH_ASSURANCE 0x02` bei `N>=100` gleiches `14/20` → kein Gewinn.  
**Fix:** `N_aktiv+epoch_day+hysteresis_proof` ins Preimage + `N_aktiv_at_signing>=20` via WOT-Multiset (Merkle-Root 20 Heartbeats) fordern; `HIGH_ASSURANCE` auf `16/20 (80%)` oder streichen.

### H-05 — Argon2id DoS: 50µs Vorfilter unzureichend
`docs/13:130-149` Ed25519 offline kostenlos → passiert 50µs immer. `4×64MB=256MB` Bounded Pool bei 100k req/s saturiert, VIP-Isolation nur Scheduling, gleicher UDP-Socket. `Challenge=BLAKE3(...Client_IP_Prefix||Epoch_Minute||Node_Secret)` mit `/24` → CGNAT-Precomputation. `docs/15:98-106` Tokio-Actor gleiches Problem.  
**Code:** `src/wire.rs:213-255` `verify_pow()` deterministischer `blake3` Stand-in ohne Memory-Hardness, `TokenBucket` nicht pro-IP.  
**Fix:** Tier-3 zuerst `Argon2id(Challenge||nonce)<Target` **vor** Ed25519, per-IP token bucket, Pool auf `CPU_cores` isoliert, separate UDP-Ports VIP 443 vs. Public 8443.

### H-06 — TTL/Tilgung vs. Lazy Ingestion Resurrection
`valid_until < now` getilgt, Ingress erlaubt `now-30s<valid_until` (`docs/12:39-41`) → sofort abgelaufen aber signierbar. Wallet-Batch `[Tx2,Tx3,Tx4]` mit `valid_until=now+5s` während Node A tilgt, Node B hält noch → Merge + Lazy Ingestion reanimiert. Titel `O(1) TTL-Bucket-Ringpuffer` 0 Implementierung (scan `TABLE_ACTIVE_LOCKS` → `O(n)` täglich, bricht `INV-1201` bei 24M Locks).  
**Code:** `src/storage.rs:8-16` `ingress_time_window_valid(now+30_000)` & `should_prune(now+30_000 grace)` korrekt, aber `prune_expired()` scannt `HashMap` `O(n)`, kein Bucket.  
**Fix:** Ingress `valid_until > now+30s && <=root.valid_until`, Tilgung `valid_until+30s grace`, `TABLE_TTL_BUCKETS:(bucket_id=valid_until/86400→Vec<ParentLockKey>)` + `O(1)` Drop.

### H-07 — Partition-Merge `<500ms` vs. reale 8h/24h Präsenz
`docs/08:68-83` verspricht Merge `<500ms` via Heartbeat-Lernen, aber `docs/11:171-195` `popcount>=8/24 && m>=3` + `docs/07:58-61` 8h Hysterese + 1 HB/h + TTL16 → Dorf `N=5` frühestens nach Stunden `ACTIVE` für HRW. `docs/08:82` `Zero Lock-Dump` widerspricht `docs/03:125` Digest-First PULL.  
**Fix:** Merge-Zeit aufteilen: P2P Peering `<100ms`, Presence `ACTIVE` frühestens 8h, `FINAL` frühestens 24h, PoS-Latenz nur via First-Seen garantieren.

### H-08 — 10:10 Split Widerspruch
`docs/06:213-218` `10:10 → kein Quorum, beide Kassen verweigern` vs. `docs/02:79-102` `min(H_canon)` in `<1ms`. Live-First-Seen vs. Merge-Resolver ohne Priorität, Timeout-Fragmentierung 50ms/200ms/600ms.  
**Fix:** Automat `docs/02:12-50` vervollständigen `Pending→Provisional/Final→Void (nur via min(H_canon) oder ConflictWithEvidence)→Expired`; `10:10 → 409 ConflictWithEvidence + Resolver-Hinweis`, `T_quorum=600ms` zentral in `docs/04`.

### H-09 — `INV-0301/0803` Zero Replication vs. Digest-PULL
Absolute Push-Verbote widersprechen explizit erlaubtem selbst-initiiertem PULL. Schwellen `>=14` vs. `11..13` Toleranzfenster (`docs/03:148`) nirgends INV, kollidiert mit `INV-0805`.  
**Fix:** `INV-0803` präzisieren: „Kein proaktiver Push-Dump; reaktiver Digest-First PULL nur selbst-initiiert nach `GetShardDigest` Quorum-Digest `D*`“; `>=14` quorum / `<11` backoff 500ms kodifizieren, `11..13` streichen.

### H-10 — Byte-Jahre Inkonsistenz 192 vs. 224
`docs/12:108-110` `192 RAM` vs. `224 inkl. DashMap`, `docs/09:62` `240k BJ/Tag =>333×5-Jahres` falsch (korrekt 286 bei 224). `promote_lock` 0-Kosten → Quota-Umgehung.  
**Code:** `src/quota.rs:10` `192` fest, `HARD_FLOOR=960_000` vs. `INV-0902` `240_000` intra-Dokument Widerspruch `docs/09:60-62` vs `docs/09:126`.  
**Fix:** Quota deterministisch auf `224B` normieren (oder Wire 144B+RAM 192B trennen), Rechnung `docs/09:62` neu belegen, `promote_lock` nur gratis bei identischem `lock_hash` ohne TTL.

---

## 4. Mittel — Spezifikations-Präzision & Edge Cases

* **M-01 Cold-Path unbounded:** `docs/00:77` `1,2,4,8…` logarithmisch vs. `README:15` `max 16` vs. `docs/06:141,204` `Vec<String>` unbounded, Batch ohne `valid_until>now` & `max_batch` → Monster-Historie umgeht `INV-0301`.  
  *Fix:* `locator_prefixes max 16×10 Zeichen`, `L2BatchLockRequest max 64` + `µBJ`-Quota, pro Glied `valid_until>now`.
* **M-02 Silent Drop vs. Zensur:** `docs/09:106` `INV-0906` Silent Drop ohne Alert nicht von Zensur unterscheidbar, `Receipt-Gossip` nur bei Erfolg (`docs/10:332`) → Gradient Klasse 3 greift nicht.  
  *Fix:* Pflicht `SignedRejection{reason,current_anl,quota}` `HUMOCO_V1_REJECT`, Receipt auch auf Rejections `p=1%`.
* **M-03 Unbounded RAM:** `docs/12:83-110` `DashMap` + `persist_tx: mpsc::Sender<StoredLock>` unbounded, `total_byte_seconds: AtomicU64` ohne Hard Cap → 20 Gateways × 333 5-Jahres/Tag → 6.6k/Tag → 10J 24M Locks → ~5GB RAM + `redb` Append-Only OOM. `ShardDigest = BLAKE3(Shard_ID||Locks)` sortiert `O(m log m)` → CPU-DoS.  
  *Code:* `src/storage.rs:69-81` `prune_expired()` scannt alles, `DualTierStorage.wal: VecDeque` unbounded.  
  *Fix:* `INV-1207` `max_ram_locks=max(100k, quota_BJ×2)` + 48h LRU, `mpsc(10k)` bounded `try_send→429`, Digest auf inkrementellen Merkle-Root.
* **M-04 Privacy-Leak:** `valid_until` (`docs/04:30-41`) korreliert mit Wert (16 vs 1920 BJ), `AccountTag=BLAKE3(PubKey||Salt)` (`docs/13:63`) bei Leak linkbar, `Shard_ID` deterministisch → DAG-Splits korrelierbar.  
  *Fix:* `valid_until` auf Wochen-Bucket runden + ±1h Noise, `AccountTag` via VRF/Blind Sig, `Shard_ID=BLAKE3(Genesis||salt_epoch)`.
* **M-05 Digest 11..13 Fenster bricht BFT:** `docs/03:145-158` `C_max 11..13` erlaubt Finalisierung mit 11 statt 14 → 13 böse Nodes gewinnen. Widerspricht `INV-0304`.  
  *Fix:* streichen, Regel `>=14 sonst 500ms Backoff`.
* **M-06 Dunbar-RED Divergenz:** `m(Z)` strikt Empfänger-Grad (`docs/11:80` korrekt) aber Tabelle `docs/11:138` ohne `Z`; `R_soft` Formel `docs/11:49` vs `11:214` differiert; Receipt 64 vs 96B → 3.8KB/s falsch. Code hat keine `R_soft` Formel implementiert.  
  *Fix:* `m(Z)=min(3,deg(Z))` überall, `R_soft` einmalig `11:49`, Receipt 96B vereinheitlichen.
* **M-07 `N_aktiv` fragmentiert:** `docs/11:171-175` `popcount>=8/24+m>=min(3,deg)` vs `docs/07:40-50` `8 Heartbeats` vs `docs/15:113` `20-25s/75s` KeepAlive vs `docs/14:107` Recovery sofort voten. Zwei Nodes `R=20` vs `R=19` → HRW-Divergenz.  
  *Fix:* `docs/11` SSOT für `is_active` (8/24+m), `15:113` nur QUIC-Keepalive, `14:111` nach Restart `is_active=false` bis `tau_on`.
* **M-08 WoT Max-Flow Lücke:** `INV-0702` `1.0` pro Node begrenzt Stern, nicht Kette `H(1.0)→B1→B2→...` → Ford-Fulkerson 1.0 umgeht, `m(Z)>=3` via Fan-out `k=√d+1` erreichbar trotz Cut=1.0.  
  *Fix:* `M_eff=MaxFlow×γ^{depth}` (`γ=0.9`), Tiefe>3 nur mit zusätzlichem Anker-Pfad, `distinct_edge_mask>=m(Z) && M_eff>=1.0` für `ACTIVE`.

---

## 5. Doku ↔ Code-Diskrepanzen

| ID | Doku | Code | Widerspruch / Auswirkung |
|---|---|---|---|
| **C-01** | `docs/11:192-195` `DORMANT → malus_score=0, backoff=0` vollständig | `src/types.rs:248-251` `malus_score >>= 1` (halbiert), `backoff=0` | Guter Server Score 0/8 startet sauber, chronisch schlechter (48→24→Stufe 3) behält Misstrauen — Doku verspricht Tabula Rasa, Code dämpft asymmetrisch. |
| **C-02** | `docs/03:150` `24h` QUIC-Uptime vor Idle-Abstufung | `src/types.rs:335` `STABLE_PREDECESSOR_MIN_UPTIME_SECONDS = 12*3600` | Nachrücker rüstet nach 12h ab statt 24h → Thrashing bei 12–24h Flap. |
| **C-03** | `docs/09:60` `960k BJ/Tag` (40k/h) & Rechnung 1000×5-Jahres, `docs/09:126` `240k` | `src/quota.rs:18` `960_000` fest | Intra-Doku 4× Faktor, Code folgt 960k, `INV-0902` (240k) veraltet. |
| **C-04** | `docs/02:97` `H_canon = BLAKE3(DOMAIN\|\|Parent\|\|Receiver\|\|Sig)` | `src/crypto.rs:9-19` `BLAKE3(DOMAIN\|\|Parent\|\|Receiver\|\|nonce)` | Sig vs. nonce — deterministisch verschieden, Simulator konvergiert anders als Spec-Resolver. |
| **C-05** | `docs/11:138-145` `Slot=NodeID%128, 75min stale, 50min spam` | `src/fraud.rs:340-399` identisch, aber `Slot = NodeId(u16)%128` (16-Bit) vs. Doku `PubKey32%128` | Kollision 4 Nodes/Slot bei `N=500`; `verify` prüft nur `lock_id` Diff, nicht `parent_lock` — `parent_lock` Gleichheit nicht verifiziert (`src/fraud.rs:248-278`). |
| **C-06** | `docs/10:474-480` Code-Beispiel whitelist 3 Typen | `src/wire.rs:123-129` whitelisted 4 Typen inkl. `ActiveSyncRequest` | Doku-Beispiel veraltet, echte Impl erlaubt mehr 0-RTT → Replay-Fläche größer als Doku behauptet. |
| **C-07** | `docs/07:53` `DORMANT → ACTIVE` mit 2 HBs allein | `src/types.rs:292-315` `evaluate_state()` verlangt zusätzlich `maturity>=24 && (mask&0b11)==0b11` **oder** `popcount>=8` | Code verlangt implizit 8/24, Doku isoliert 2 HBs — widersprüchliche `INV-0704` Auslegung. |
| **C-08** | `docs/12:68-69` `O(1) TTL-Bucket-Ringpuffer` täglich | `src/storage.rs:70-81` `scan HashMap O(n)` jeden Prune | Kein Bucket-Index, `INV-1201` Zero-Disk-I/O im Hot Path bei 24M Locks verletzt. |

**Zusätzlich:** `src/types.rs:586` `hrw_score_normalized` nutzt `u128::from_be_bytes(hash[0..16])` vs. Doku `BLAKE3(NodeID||Shard_ID)/2^256` — Skalierungsdivergenz; `src/client_flow.rs:171-185` `IngressAccount` nutzt `AtomicU64/AtomicU32` ohne Sync zu `NetworkThermometer` (`src/quota.rs`).

---

## 6. Veraltete / Überholte Konzepte

1. **Argon2d vs. Argon2id Namenschaos:** `docs/07:14-18` `Argon2d` für NodeID (public, data-dependent) vs. `docs/13:114` `Argon2id` für Client-Puzzles. Ein festes Profil `m=1536MiB,t=180,p=4` normieren, `docs/04` als SSOT.
2. **Jury-ADRs (ADR-011):** `docs/10:282-309` explizit eliminiert („Jury vollständig eliminiert durch SignedIngressEnvelope + Receipt-Gossip“) — alle Rest-Referenzen auf Auditor-Jury in `docs/03, 08` tilgen.
3. **Alters-/Senioritätskurve:** `docs/09:108-121` „logarithmisch `log2(1+Longevity)` vollständig verworfen“ wegen Partition-Divergenz — de-facto Nachfolger ist `docs/11:139-142` `demanded_difficulty_index + F2F-Median + Anti-Surge M_surge 2–4×` mit Tiefpass `+5%/30 Tage`.
4. **BLS-Aggregation:** `docs/04, 06` historisch — Code ist bereits auf Ed25519. BLS-Referenzen in Doku streichen.
5. **500ms Merge-Versprechen:** `docs/08:68-83` & `README:59` überholt durch `docs/11` Hysterese. Auf `Presence 8h / FINAL 24h` korrigieren.
6. **`HIGH_ASSURANCE (0x02)`:** `docs/08:36` `N>=100, 14/20` identisch zu `FINAL` → kein Sicherheitsgewinn. Auf `16/20 (80%)` anheben oder streichen.

---

## 7. Priorisierte Bereinigungs-Roadmap

| Phase | Befunde | Aufwand | Wirkung |
|---|---|---|---|
| **P0 — Konsens-kritisch (vor Code-Freeze)** | K-01, K-02, K-03, K-04, K-06 + C-04 | 1–2 Tage Spec + Tests | Verhindert FINAL-Fälschung, Shard-Fehlrouting, gespaltenes Grün/Gelb |
| **P1 — Partition & DoS** | K-05, H-01, H-02, H-05, H-06, H-07, H-08 + C-01, C-02, C-07 | 3–5 Tage Spec + DST | Schließt 10:10-Split, Replay, Saturation, Resurrection, Merge-Lüge |
| **P2 — Härtung & Privacy** | H-03, H-04, H-09, H-10, M-01..M-08 + C-03, C-05, C-08 | 1 Woche | Gradient-Slashing korrekt, Blindness, RAM-Hard-Limit, WoT-Depth |
| **P3 — Simplicity** | O-01..O-04 + Deprecated Liste | 2 Tage | −40% Spec-Zeilen, halbierte Wire-Größe, 2 statt 4 Streams |
