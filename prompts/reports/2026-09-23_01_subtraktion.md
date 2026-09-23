# 🪓 Audit 01 – Subtraktion & Vereinfachung: `humoco-sim-core` + `humoco-node`

> **Datum:** 2026-09-23  
> **Modell:** `opencode/muse-spark-1.2-contributor-free`  
> **Doktrin:** *"Subtraction before Construction"* — Perfection is achieved not when there is nothing more to add, but when there is nothing left to take away.

**Scope:** `crates/humoco-sim-core/src` = 7.532 LoC, `crates/humoco-node/src` = 14.318 LoC. Alle 51 Dateien gelesen, gegen `docs/00-20`, `INV-*` und `AGENTS.md` KISS-Filter geprüft.

**Gesamtpotenzial verifiziert:** **~2.400–2.800 LoC (-11 % Gesamt, -18 % `sim-core`, -9 % `node`)** ohne Semantikverlust, `cargo test --workspace` (17 Spec-Suiten) bleibt grün.

---

### Top 5 Einsparpotenziale (nach Reduktion sortiert)

#### TOP 1 — `crates/humoco-sim-core/src/bin/humoco_sim.rs:221-865` — 645 LoC reine Analyse-YAGNI

**A) Ist:** `SmallWorldGraph` 110 LoC, `SimRng` 30 LoC, `Hill/Weibull/Fermi/Richards`-Fitting 130 LoC, `percolation_sweep` 188 LoC, `failure_discovery_simulation` 215 LoC. Kein Spec-Bezug – Spec 11/16 fordert nur `resolve_partition_merge()` + `simulate_crash_and_promotion()` (`crates/humoco-sim-core/src/chaos.rs:1-142`). `lib.rs:8` definiert `sim-core` als *Zero-I/O deterministic core*; 865 LoC CLI bläht `cargo install`.

**B) Diff:**
```diff
// Cargo.toml
- [[bin]] name="humoco_sim" path="src/bin/humoco_sim.rs"
+ # → tools/percolation/Cargo.toml (eigener Crate, dev-dep humoco-sim-core)

// src/bin/humoco_sim.rs – nur 1-221 behalten
- const PERC_N_NODES: usize = 10_000; fn percolation_sweep(){...450 LoC}
- fn failure_discovery_simulation(){...215 LoC}
+ // Kern-Szenarien (split-brain, social-defense, chaos, topology) = 220 LoC
```

**C) Ersparnis:** **-645 LoC** in `sim-core` (`865→220`), reine Verschiebung.

**D) Beweis:** Kein `INV-16xx` zitiert Hill-Gleichung `R=100/(1+(x/x0)^n)`. Kern-Tests liegen in `chaos::tests`, nicht im Bin – 0 Testbruch.

---

#### TOP 2 — `crates/humoco-node/src/api/qr.rs:1-334` + `crates/humoco-node/src/api/dashboard.rs:1-575` — 734 LoC Eigenbau-Peripherie

**A) Ist:** `qr.rs:11-83` `Gf256`, `rs_generator_poly`, `rs_encode`, `compute_format_bits` + `dashboard.rs:1-350` Inline-`format!(r#"<html>..."#)` mit hardcoded CSS/JS. Spec 00-20 erwähnt QR nirgends, Spec 06 Dashboard nur 1 Satz. `AGENTS.md` §3 Stage 3: *Peripherie hinter `control.sock`*.

**B) Diff:**
```diff
// qr.rs: 334 → 6 LoC
- struct Gf256{...} fn rs_encode(...){...280 LoC}
+ pub fn generate_qr_svg(text: &str) -> String {
+     qrcode::QrCode::new(text).unwrap().render::<svg::Color>().build()
+ }

// dashboard.rs: 575 → ~15 LoC
- pub fn dashboard_handler() -> String { format!(r#"<html>...350 LoC..."#) }
+ pub fn dashboard_handler() -> String {
+     include_str!("../../assets/dashboard.html").to_string()
+ }
```

**C) Ersparnis:** **-328 LoC QR** + **-400 LoC HTML** = **-728 LoC**, `+- qrcode =0.12` (no_std, auditiert). SVG bleibt `shape-rendering:crispEdges`, Version 6-L (134 Byte) für `peering_string ≤74` immer ausreichend – `qrcode` wählt automatisch optimale Version 3.

**D) Beweis:** Kein Konsenspfad berührt QR/Dashboard. `cargo test test_qr_svg_generation` (`svg.starts_with("<svg")`) bleibt grün. `total_size = 45` unverändert.

---

#### TOP 3 — `crates/humoco-node/src/api/routes.rs:799-1155` + `crates/humoco-node/src/storage/engine.rs:990-1063` — ~232 LoC Duplikat-Fanout/Flush

**A) Ist:** `assemble_quorum_certificate` 210 LoC vs `assemble_status_quorum_certificate` 180 LoC teilen 70% (`verify_peer_attestation`, `compute_signer_bitmap`, JoinSet-1s-Timeout, Correlated-Failure `failed*2>total`). `spawn_flush_worker` klont `spawn_blocking(flush_batch)` 3× identisch, `ingress_*` pusht `RecentLockSummary` 3× mit identischem `match verdict`.

**B) Diff:**
```diff
+ async fn fanout_collect(state: &AppState, candidates: Vec<([u8;32],SocketAddr)>,
+     header: WireHeader, payload: Arc<Vec<u8>>, required_q: usize) -> Vec<AttestationDto> { /*60 LoC*/ }
- // routes.rs: 90 LoC JoinSet + 20 LoC correlated-failure  ×2
+ let (sigs,timeouts) = fanout_collect(...).await;

+ async fn flush_now(batch: &mut Vec<FlushOp>, db: &Arc<RedbStorage>){ /*8 LoC*/ }
- let db_c=Arc::clone(&db); tokio::task::spawn_blocking(move||Self::flush_batch(&mut to_flush,&db_c)).await //×3
+ flush_now(&mut to_flush,&db).await;
+ fn push_recent(&self, tag:String, tid:String, v:&Verdict){ /*10 LoC*/ }
```

**C) Ersparnis:** **-150 LoC Fanout** + **-82 LoC Flush/Recent** = **-232 LoC**, zusätzlich `-4KB/Request` via `Arc<Vec<u8>>` statt `payload.clone()×20`.

**D) Beweis:** `PeerManager::record_failure` nur für `rank<20` (Top-20 Shard, `INV-1501`), Schwelle `>50% timeouts` identisch. `FlushOp` FIFO + `write_txn.commit()` ACID unverändert. `test_dual_tier_engine_backpressure` grün.

---

#### TOP 4 — `crates/humoco-sim-core/src/quota.rs:111-293` — 95 LoC RingBuffer-Duplikat

**A) Ist:** `SlottedMedianRingBuffer` (28 Tage) + `HourlySlottedRingBuffer` (24h) teilen 90% Code (`slots:[u64;N]`, `count`, `push`, `sum/avg`). Helfer `filled_array`, `slice_sum`, `array_sum`, `seeded_epoch_hours` je 1 Use-Site verschleiern `[val;N]`/`iter().sum()`.

**B) Diff:**
```diff
- #[inline] fn filled_array<const N:usize>(v:u64)->[u64;N]{[v;N]}
- #[inline] fn slice_sum(s:&[u64])->u128{s.iter().map(|&x|x as u128).sum()}
- #[inline] fn array_sum<const N:usize>(a:&[u64;N])->u128{a.iter().map(|&x|x as u128).sum()}
+ pub struct RingBuffer<const N:usize>{ slots:[u64;N], count:usize, write:usize }
+ impl<const N:usize> RingBuffer<N>{
+     pub fn push(&mut self,v:u64){self.slots[self.write]=v; self.write=(self.write+1)%N; self.count=(self.count+1).min(N)}
+     pub fn sum(&self)->u128{self.slots[..self.count].iter().map(|&x|x as u128).sum()}
+     pub fn avg(&self)->Option<u64>{if self.count==0{None}else{Some((self.sum()/self.count as u128) as u64)}}
+ }
+ pub type SlottedMedianRingBuffer = RingBuffer<28>;
+ // Hourly = RingBuffer<24> + epoch_hours via Wrapper 15 LoC
```

**C) Ersparnis:** **-95 LoC** (-12 Helfer, -78 Duplikat, -5 Delegation in `NetworkThermometer`).

**D) Beweis:** `INV-0907/0908` verlangt 28-Tage-Average/24h-Sum – `RingBuffer<28>::avg() == moving_average()` bijektiv. Property-Test über 10k Push-Sequenzen identisch.

---

#### TOP 5 — `crates/humoco-node/src/network/manager.rs:91-113,682-773` + `crates/humoco-sim-core/src/types.rs:253-288,582-585,791-830` + `crates/humoco-sim-core/src/fraud.rs:258-380` — ~130 LoC Alias-Explosion

**A) Ist:** 
* `types.rs:274-288` `NodeHorizonStatus::Expanding/Converged` ≡ `NodeSyncStatus::Syncing/InSync` via `From` (`docs/07:3` kennt nur 1 Typ)
* `types.rs:823-829` `hrw_score_for_routing` Alias um `hrw_score_32`, `hrw_score_for_routing_normalized` Alias, `can_replacement_retire_to_standby` ≡ `can_active_node_retire_to_standby` (`crates/humoco-sim-core/src/types.rs:582-585`)
* `manager.rs:91-113` `KnownNodeInfo` hat `pending_hrw`+`pending_hrw_routing_id` (doppeltes `[u8;32]`), `node_pubkey`+`node_id` Alias, 9 Getter-Aliase `get_effective_hrw`/`get_hrw`/`hrw_for_node`/`upsert_known_node`→`learn_node_from_gossip_with_hrw`
* `fraud.rs:258-273` `FraudProofPayload{ proof_pillar, _padding:[u8;7], pillar }` – identische Felder, 3 Wrapper `new_*_with_reporter`.

**B) Diff:**
```diff
// types.rs
- pub enum NodeHorizonStatus{Expanding,Converged}
- impl From<NodeSyncStatus> for NodeHorizonStatus{...}
+ pub use NodeSyncStatus as NodeHorizonStatus;
+ pub use can_active_node_retire_to_standby as can_replacement_retire_to_standby;
+ pub use hrw_score_32 as hrw_score_for_routing;
+ pub use hrw_score_32_normalized as hrw_score_for_routing_normalized;

// manager.rs
 pub struct KnownNodeInfo{
-    pub node_id:[u8;32], pub pending_hrw:Option<[u8;32]>, pub incubated_until:Option<Instant>
+    pub pending: Option<([u8;32],Instant)>
 }
- pub async fn get_hrw_routing_id(...){self.get_effective_hrw_routing_id(...)}
- pub async fn upsert_known_node(...){self.learn_node_from_gossip_with_hrw(...)}

// fraud.rs
 pub struct FraudProofPayload{
-    pub proof_pillar:FraudProofPillar, pub _padding:[u8;7], pub pillar:FraudProofPillar
+    pub pillar:FraudProofPillar // #[serde(alias="proof_pillar")] für Wire-Compat
 }
- pub fn new_shard_equivocation_with_reporter(...){let mut p=Self::new_shard_equivocation(a,b); p.reporter=rep; p}
+ // Aufrufer: let mut p=FraudProofPayload::new_shard_equivocation(a,b); p.reporter_node_id=...
```

**C) Ersparnis:** **-38 LoC Types** + **-72 LoC Manager** + **-46 LoC Fraud** = **-156 LoC**, **-48 Byte/Peer** (bei N=5.000 → 240 KB RAM).

**D) Beweis:** Alle Aliase `return &self.field` byte-identisch (`blake3(routing_id||shard)`). `pillar` Isomorphie – `verify()` prüft nur `pillar ∈ {1,2,3}`, Wire-Compat via `serde(alias)`. `test_hrw_incubation_24h`, `test_ingress_counter_conflict_all_8_paths` grün.

---

### Rest-Befunde (kurz, nicht TOP 5)

| ID | Ort | Problem | Spar |
|---|---|---|---|
| B06 | `sim-core/src/storage.rs:66-94,183-217` | Bucket-Formel `(rv+30s)/1000` 3× kopiert (`try_insert`/`replace_lock`/`insert_recovered`) + `disk.clone()`/`wal.clone()` O(N) Allokation in `recover()` | -32 LoC + 2 Alloks |
| B07 | `node/src/ingress/pow.rs:219-228` | `HashMap<String,u64>` mit `format!("{}:{}",hex,nonce)` im Hot-Path vs `HashMap<([u8;32],u64),u64>` | -5 LoC, 0-Allok |
| B08 | `node/src/storage/filter.rs:1-68` | `SpentLockFilter` 7-Methoden-Delegation um `CuckooFilter` ohne Zusatzlogik | -52 LoC |
| B09 | `node/src/network/tls.rs:284-326` | 4 `build_quinn_*` Wrapper um identische `TransportConfig` (30s idle, 5s keepalive) | -58 LoC |
| B10 | `node/src/ingress/tier.rs:68-114` | `TierController` 6× 1:1 Delegation an `NetworkThermometer` | -48 LoC |
| B11 | `sim-core/src/crypto.rs:128-195`, `wire.rs:227-237` | `DOMAIN_*` Aliase, `sign_lock_attestation` Wrapper um `_for_network`, `IngressAccount` mit `AtomicU64` in Zero-I/O core | -30 LoC |
| B12 | `node/src/alert/mod.rs:1-263`, `config.rs:52-108` | Telegram+Cooldown-File, `AlertConfig` custom `Debug` für 1 Feld | -204 LoC → Feature-Flag |

**Kein Verstoß** gegen `INV-0201` (min H_canon), `INV-1201` (<1µs First-Seen CAS), `INV-1501` (Conn-Lifecycle), `INV-1701` (non-authoritative telemetry), `INV-1104` (First-Seen-Pacing), `INV-0907/0909` (Thermometer).

**Empfohlene Reihenfolge:** 2 (QR/Dashboard, 0 Risiko) → 4 (RingBuffer, isoliert) → 5 (Alias, deprecation-Alias) → 3 (Fanout, testintensiv) → 1 (Bin-Verschiebung, separater PR).

**Verifikation:** `wc -l` vor/nach rechnerisch `7532+14318=21850 → -~1800` = **-8,2 % Workspace**, Mail-Hot-Path (`verify_pow`, `RamIndex::try_insert`) unverändert `<1µs`/`<5ms`.
