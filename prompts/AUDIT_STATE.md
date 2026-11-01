# 🧠 HuMoCo Automated Audit Memory & Coverage Ledger

> **Doctrine:** *"Subtraction before Construction – One Universal Loop, Zero Blind Spots."*  
> **Status:** Active memory ledger for `prompts/AUDIT_LOOP.md`.

---

## 🎯 Selection Rules for AI Agents
1. **Priority 1 (Initial Baseline Sweep):** Select any slice with `Last_Run == never` or status `⚪ Pending`. If multiple exist, pick in slice order (`S01` to `S09`) or higher weight (`P1 > P2 > P3`). This guarantees 100% of workspace code is inspected once before getting locked into local fix/re-check loops.
2. **Priority 2 (Re-Verifications):** Once all slices have completed their initial run (`Last_Run != never`), select any slice marked `🟡 ReCheck` to verify recent fixes.
3. **Priority 3 (Continuous Hardening):** Among remaining slices NOT marked `🔴 Fix_Open`, select the slice with the lowest `Clean_Streak` (tie-breakers: oldest `Last_Run`, higher weight `P1 > P2 > P3`, lower Slice ID).

---

## 📊 Coverage Matrix (100% Codebase Scope)

| Slice | Weight | Target Files (`crates/...`) | Key Invariants & In-Scope Focus | Clean_Streak | Total_Finds | Last_Run | Status |
|---|---|---|---|---|---|---|---|
| **S01** | P1 | `humoco-node/src/api/{routes,hmc,dto,live,events}.rs` | PoS 800ms budget, 14/20 fast-exit, HTTP 200/201/409 idempotency, cancellation safety (`JoinSet`), INV-0310 | 0 | 6 | 2026-11-01 | `🟡 ReCheck` |
| **S02** | P1 | `humoco-node/src/storage/{engine.rs,db.rs,db/signing.rs,activity.rs,recent.rs}` | DEC-029 Durable-before-Vote (<20ms), atomic RAM CAS, G5 fail-closed signing history latch, rollback on I/O error | 0 | 2 | 2026-11-01 | `🟡 ReCheck` |
| **S03** | P1 | `humoco-node/src/storage/{engine/recovery.rs,db/install.rs,db/projection.rs,db/roots.rs,db/snapshot.rs,db/support.rs,filter.rs}` | DEC-064/DEC-022 monotonic classes (2>1>0), `min(H_canon)` tie-breaker, `TABLE_PROVISIONAL_HMC_LOCKS` quarantine, TTL + 30s grace pruning | 1 | 0 | 2026-11-01 | `🟢 Clean` |
| **S04** | P1 | `humoco-node/src/network/{transport,framing,pool}.rs` | Pre-allocation 64 KiB cap, safe `from_le_bytes`/`checked_*`, QUIC stream deadlines, LRU pool cleanup, TLS `NodePubKey` binding, neutral quota flags | 0 | 5 | 2026-11-01 | `🟡 ReCheck` |
| **S05** | P1 | `humoco-node/src/ingress/{mod,pow,tier}.rs`, `humoco-node/src/api/auth.rs` | Cheap-filters-first, stateless BLAKE3 PoW (`HUMOCO_V1_POW_STATELESS`) parent+slot binding, time-based EMA, `f2f_` token vs `NodePubKey` separation | 0 | 0 | never | `⚪ Pending` |
| **S06** | P2 | `humoco-node/src/network/{clock,discovery,peer,manager,tls}.rs` | `P2pClock` direct-F2F median (`hops == 0`), 24h `HrwRoutingId` incubation, subjective peer liveness, first-party equivocation proof only | 0 | 0 | never | `⚪ Pending` |
| **S07** | P1 | `humoco-proto/src/*.rs`, `humoco-sim-core/src/{crypto,resolver,types,wire,fraud}.rs` | Client causal verification, length-prefixed BLAKE3 tags (`HUMOCO_V1_*`), deterministic conflict resolution, serialization parity | 0 | 0 | never | `⚪ Pending` |
| **S08** | P2 | `humoco-sim-core/src/{ceh/*.rs,p0/*.rs,quota.rs,state_machine.rs,storage.rs,client_flow.rs,transport.rs}` | Committee snapshot determinism, barrier/collection bounds, voucher tree validity (`root.valid_until`), Byte-Years quota math | 0 | 0 | never | `⚪ Pending` |
| **S09** | P3 | `humoco-node/src/{daemon,identity,config,cli,error}.rs`, `humoco-node/src/control/*.rs`, `humoco-node/src/api/{operator*,dashboard,health,metrics,qr,keys,system_stats,history*}.rs`, `humoco-node/src/alert/*.rs` | 0600 key permissions, UDS control frame bounds, graceful shutdown lifecycle, INV-1701 non-authoritative telemetry (`triggers_auto_ban() == false`) | 0 | 0 | never | `⚪ Pending` |

---

## 🔄 State Lifecycle & Transition Rules
- **`Clean_Streak`:** Incremented by `+1` on every run finding **0 issues**. If a verified issue is found, reset to `0`.
- **`Status` Values:**
  - `⚪ Pending`: Not yet audited (`Last_Run = never`). Awaits initial baseline sweep.
  - `🟢 Clean`: Audited, 0 open issues in this slice.
  - `🔴 Fix_Open`: Defect(s) uncovered. Fix prompt generated.
  - `🟡 ReCheck`: Fix implemented and tested; awaits independent verification once baseline sweep is complete.
