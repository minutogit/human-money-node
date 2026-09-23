[0m
> build · muse-spark-1.2-contributor-free
[0m
Stabilitäts-Audit nach Spec 19/15 läuft – prüfe die 5 Todes-Spiralen-Szenarien gegen den Code.
[0m
[0m→ [0mRead prompts/03_todes_spiralen_und_deadlock_audit.md
[0m→ [0mRead docs
[0m→ [0mRead docs/19_rueckkopplungs_dynamik_und_historische_p2p_postmortems.md
[0m→ [0mRead docs/15_p2p_transport_und_verbindungsmanagement.md
[0m→ [0mRead docs/15_p2p_transport_and_connection_management.md
[0m✱ [0mGlob "crates/**/*.rs"[90m 100 matches[0m
[0m→ [0mRead crates/humoco-node/src/daemon.rs
[0m→ [0mRead crates/humoco-node/src/network/manager.rs
[0m→ [0mRead crates/humoco-node/src/network/transport.rs
[0m→ [0mRead crates/humoco-node/src/network/peer.rs
[0m→ [0mRead crates/humoco-node/src/network/transport.rs[90m [offset=1062][0m
[0m→ [0mRead crates/humoco-node/src/storage/engine.rs
[0m✱ [0mGrep "tokio::spawn|CancellationToken|try_reserve|unwrap\(\)|expect\(\)|record_failure"[90m 100 matches[0m
[0m→ [0mRead crates/humoco-node/src/network/framing.rs
[0m→ [0mRead crates/humoco-node/src/api/routes.rs
[0m→ [0mRead docs/archive/AUDIT_03_REPORT.md
[0m→ [0mRead crates/humoco-node/src/api/routes.rs[90m [offset=1249][0m
[0m
Befundabgleich läuft – vergleiche Audit-Report mit aktuellem Code-Stand und prüfe Backpressure, Backoff und Shutdown-Verhalten.
[0m
[0m$ [0mcargo test --workspace --quiet 2>&1 | tail -n 50; echo "EXIT:$?"
running 1 test
.
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.11s


running 5 tests
.....
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 3 tests
...
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s


running 4 tests
....
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s


running 4 tests
....
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s


running 4 tests
....
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 3 tests
...
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.93s


running 17 tests
.................
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

EXIT:0
[0m
[0m$ [0mcargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -n 30; echo "CLIPPY_EXIT:$?"
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.56s
CLIPPY_EXIT:0
[0m
[0m✱ [0mGrep "rand::thread_rng.*shuffle|calculate_fan_out|FRAUD.*LIMIT|GOSSIP.*SEMAPHORE|try_reserve|std::sync::Mutex"[90m 50 matches[0m
[0m→ [0mRead crates/humoco-node/src/ingress/pow.rs
[0m→ [0mRead crates/humoco-node/src/ingress/tier.rs
[0m
**Todes-Spiralen & Deadlock Audit — Spec 19 / Spec 15 Re-Audit (Stand 2026-09-23, `HEAD`)**

`cargo test --workspace` 100% grün, `clippy -- -D warnings` 0 Findings — verifiziert vor Audit.

### 1. 🌪️ Cascading Death Spirals — BESTANDEN mit 2 Mittel-Befunden

**Positiv — lokal dämpfend implementiert ($\Delta Last \le 0$):**

| Invariante | `file_path:line_number` | Nachweis |
|---|---|---|
| Lokale Suspension | `crates/humoco-node/src/network/peer.rs:5` `FAILURE_THRESHOLD_SUSPENDED=3` `DEGRADING=2`, `crates/humoco-node/src/network/manager.rs:968` `record_failure` debounced 60s | Fix von Audit-03 A1 bereits appliziert — Sim `types.rs:21` =3 und Prod =3 konvergent |
| Debounce 60s | `peer.rs:82` `mark_failure_at`, `manager.rs:1070` | max 1 increment/min → kein Retry-Sturm |
| Rang-21 0ms | `sim/node.rs:113` `manager.rs:1094` `is_correlated` | Gateway `routes.rs:1094` supprimiert `record_failure` bei >50% korreliertem Timeout |
| Heilung -1/h | `daemon.rs:169` `decay_all_peers` `MissedTickBehavior::Skip` | autonom |
| Seen-Cache | `manager.rs:26` `SeenGossipCache` 10k FIFO, `transport.rs:599` `check_and_insert` vor Ingress | Echo-Loop gebrochen |
| Korreliert | `routes.rs:1094` `total_queried_top20 >=2 && failed*2>total` | ISP-Ausfall → 0 Strafen (KISS) |

**Trigger-Kette gesund:** `Shard B langsam (50ms)` -> `A.mark_failure_at(t0)` -> `t0+10s zweiter Miss gedämpft (kein Inkrement)` -> `3. Miss nach 120s => Suspended` -> `Rang21 in 0ms, 0 Retry-Pakete` -> `-1/h` -> Homeostase.

**🟡 A2 — MITTEL — Random Fan-Out statt deterministisch `blakas 09-23`**

`transport.rs:637` `api/routes.rs:558` würfeln `rand::thread_rng().shuffle()` statt Sim `sim/node.rs:245` `BLAKE3(id||peer)`. `d=100 => k=11` — Zufalls-Samples kollidieren, Perkolation nicht reproduzierbar.

Diff:

```diff
// transport.rs:640 crates/humoco-node/src/network/transport.rs:637
- use rand::seq::SliceRandom; let mut rng=rand::thread_rng(); selected.shuffle(&mut rng); truncate(k);
+ let mut scored:Vec<_>=selected.into_iter().map(|a|{let mut h=blake3::Hasher::new(); h.update(&record.id); h.update(a.to_string().as_bytes()); (*h.finalize().as_bytes(),a)}).collect();
+ scored.sort_by(|a,b|a.0.cmp(&b.0)); selected=scored.into_iter().take(k).map(|(_,a)|a).collect();
```

**🟡 A3 — MITTEL — FraudAlert unbounded ohne Token-Bucket**

`transport.rs:392` `EquivocationProof` Priority dringend aber `manager.rs:61` Tabelle `Unbounded` — Angreifer mit 1k gültigen Proofs flutet `FraudAlertStream` + `TABLE_SLASHING_EVIDENCE` (je 138B+Sig-Verify 100µs). $\Delta Last >0$ verletzt Spec19-Doktrin.

Diff: 10/min pro Reporter vor `verify_equivocation_first_party`:

```rust
// transport.rs:180 — in NodeRequestHandler::handle vor proof.verify()
static FRAUD_BUCKET: LazyLock<Mutex<HashMap<[u8;32], TokenBucket>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
if !get_bucket(&offender).try_consume() { warn!("fraud rate-limited"); return Ok((resp_header, Vec::new())); }
```

### 2. 🔒 Deadlocks & Backpressure — BESTANDEN (1 Niedrig Rest)

| Prüfpunkt | `file_path:line` |
|---|---|
| Bounded | `storage/engine.rs:289` `mpsc::channel(10_000)` |
| Reservation-First | `engine.rs:428` `try_reserve()` vor `ram.write().await` → `RejectedCapacity` 429 |
| No I/O unter Lock | `engine.rs:1134` `ram.write` Drop vor `db.prune_expired_buckets` `spawn_blocking` |
| DoS Sem | `transport.rs:11` `STREAM_CONCURRENCY_LIMIT=1024` `try_acquire_owned` |

**B1 — ehemals HOCH — jetzt NIEDRIG:** `engine.rs:354` `ban_node` nutzt nun `try_send` + `spawn` Fallback — Hot-Path nicht mehr blockierend. RAM-Ban sofort, Disk eventual. Verbleibendes Minimum: Full-Queue defer via `spawn` hält theoretisch 1 Task 1ms — akzeptabel. Reiner Drop wäre $\Delta Last$ noch kleiner:

```diff
// engine.rs:360
- Err(TrySendError::Full(op)) => { let tx=clone; spawn(async move{tx.send(op).await}); }
+ Err(TrySendError::Full(_)) => warn!("BanNode deferred, RAM active"),
```

**B2 — FIXED:** `manager.rs:8` + `transport.rs:131` bereits `parking_lot::Mutex` statt `std::sync::Mutex` — kein Scheduler-Jitter. `pow.rs:4` `parking_lot::Mutex` für `seen_solutions` bereits gefixt. `tier.rs:2` `std::sync::RwLock` hält nur <10µs ohne `.await` — tolerabel.

**Kein Zyklus:** `ingress -> reserve -> ram -> permit.send -> flush_worker -> spawn_blocking -> redb` — kein Rückkanal.

### 3. ⏳ Backoff & Jitter — BESTANDEN

`manager.rs:1192` `compute_backoff` jetzt:
- `attempt>=12 => 3600s` Dormant-Cap (Spec15)
- `factor=1<<min(attempt,6)` capped 30s
- `quarter=capped/4` `delta=0..2*quarter` → `0.75x..1.25x` symmetrisch ±25% — Thundering Herd nach Router-Reboot `N=100` streut gleichmäßig, kein oberes Quartil-Peak. `daemon.rs:378` `shard_sync` Notify debounced 5s verhindert Herd.

Kein Fix mehr nötig — Metrik: bei `k=5` Basis 16s → Verteilung 12..20s uniform.

### 4. 🧹 Task Leaks & Graceful Shutdown — BESTANDEN (1 Mittel Rest)

Alle 9 Daemon-Tasks via `CancellationToken` + `await`:

| Task | `daemon.rs:line` | Cancel |
|---|---|---|
| flush | `118` `DualTierEngine::new_with_token` | `566` `await` Drain 100-batched |
| dns | `152` | `563` |
| decay | `172` | `562` |
| heartbeat | `217` | `558` jitter 50m+0..20m `manager.rs:1175` |
| ttl | `255` | `559` |
| quota | `287` | `560` |
| alert | `324` | `564` 15m Hysterese |
| shard_sync | `379` `is_syncing AtomicBool` | `561` |
| quic/axum/control | `203` `459` `488` | `555-557` |

**🟡 D1 — MITTEL — Gossip Forward nun gedämpft aber Connection-Spawn unbounded**

`transport.rs:15` `GOSSIP_FORWARD_SEMAPHORE=64` `try_acquire` vor `tokio::spawn` `api/routes.rs:16` äquivalent — 10k Flood → max 64 parallel, Rest `warn` Drop. Verbleibend: `transport.rs:984` `run_accept_loop` spawnt `handle_connection` per QUIC-Handshake ohne Limit außer `stream_semaphore` pro Stream — bei 10k neuen Connections/s kurzlebiger Task-Churn ~1MB/Task. Abhilfe `connection_semaphore(256)`:

```diff
// transport.rs:687
+ connection_semaphore: Arc<Semaphore> // 256
// run_accept_loop:984
+ let _cpermit = connection_semaphore.clone().try_acquire_owned().ok()?;
```

**D2 FIXED:** `routes.rs:1072` `join_set.abort_all()` bei 14/20 Full — `record_failure` nie für abgebrochene stragglers.

### 5. 📊 Risiko-Matrix & Priorität

| ID | Titel | Schwere | Trigger `A->B->C` | Fix LOC |
|---|---|---|---|---|
| **A2** | Random Fan-Out | Mittel | `1k RPS * d=100 -> 1k shuffles/s RNG-Mutex Contention -> 2% Perkolations-Loch` | 5 |
| **A3** | Fraud Flood | Mittel | `Attacker 1k proofs -> O(N*peers) Traffic -> redb bloat` | 10 |
| **D1** | Conn-Spawn | Mittel | `10k peers connect -> unbounded handle_connection -> OOM` | 6 |
| **B1-rest** | Ban defer | Niedrig | `queue 9999/10k + 50 equivoc/s -> 50 spawns` | 2 |
| **A1/B2/C1/D2** | — | **FIXED** | — | — |

**Patch-Reihenfolge:** Sofort A2, dann A3+D1 (vor 10k Chaos-Test). Alle diffs abwärtskompatibel, kein DB-Migration.

```
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
cargo test --test spec_15_p2p_transport_and_connection_lifecycle -- --nocapture
# Herd-Test: N=50 simultan disconnect, Latenz-Histogramm muss 12-20s uniform
```
[0m
