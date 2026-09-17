# ⚖️ AI Audit Prompt: Invariant & Specification Guardian

> **Doctrine:** *"The specification is law. Every deviation is a consensus break."*

---

## 🎯 Goal of This Audit
Perform a bit-exact reconciliation between the **specification** (`docs/00_...` through `docs/20_...`) and the **implementation** (`crates/humoco-sim-core` and `crates/humoco-node`). Ensure that no mathematical invariant (`INV-*`), constant, or consensus guarantee has been violated or watered down.

---

## 📋 Prompt Text to Copy / Run:

```markdown
You are the chief invariant auditor for the HuMoCo Layer 2 Collision Lock Registry.
Your task is the gapless reconciliation between the specification documents (docs/) and the actual Rust code (crates/).

Verify the following 6 core invariants for bit-exact compliance:

1. 📐 Quorum & Finality Formulas (Spec 02, 08):
   - Is the quorum formula $Q(R) = \min(R, \lfloor \frac{2R}{3} \rfloor + 1)$ exact everywhere?
   - Does $N < 20$ strictly yield `PROVISIONAL` (yellow) and only $N \ge 20$ with $\ge 14/20$ signatures after 24h hysteresis yield `FINAL` (green)?
   - Is the 24h hysteresis protected against flapping?

2. ⚖️ Deterministic Resolver (Spec 02):
   - Is $H_{\text{canon}} = \text{BLAKE3}(\text{len} \parallel \text{"HUMOCO\_V1\_CANON\_RESOLVER"} \parallel \text{Parent} \parallel \text{Receiver} \parallel \text{Sig})$ bit-identical in the resolver and in wire verification?
   - Does the minimal hash $\min(H_{\text{canon}})$ always win strictly on collisions?

3. 🗺️ Sharding & HRW Rendezvous Formula (Spec 03):
   - Are the $2^{16} = 65,536$ buckets deterministically distributed across active nodes via Highest Random Weight (HRW)?
   - Is the top-20 shard ordering stable and reproducible?

4. ⏳ Time Windows, TTL & Zero State Bloat (Spec 12, 14):
   - Does the ingress window hold strictly: `now + 30s < valid_until <= root.valid_until` (INV-1202)?
   - Does pruning apply only after the 30s grace period: `now > root.valid_until + 30s` (INV-1203)?
   - Are expired locks physically purged (Zero State Bloat)?

5. 🌡️ Network Thermometer & Quotas (Spec 09):
   - Does the storage-time product (Byte-Years) exactly equal $(192 \cdot \text{ttl\_seconds}) / 31,536,000$ (rounded commercially, minimum 1)?
   - Is the non-undercuttable hard-floor baseline of 960,000 Byte-Years/day enforced?
   - Are the 5x Whale Brake ($K \le 5.0$) and the 28-day slotted-median smoothing applied correctly?

6. 📝 Output Format:
   - List all verified invariants (`INV-xxxx`) with status [COMPLIANT] or [DIVERGENCE].
   - For each divergence: cite the spec text (`docs/...:line`) and the faulty code (`crates/...:line`).
   - Provide the immediately applicable corrective patch.
```
