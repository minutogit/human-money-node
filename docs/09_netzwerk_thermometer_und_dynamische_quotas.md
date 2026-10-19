# 09. Network Thermometer, Byte-Years & Dynamic Quotas

> **Status:** Standard  
> **Model:** Logic & State Graph First  

> **Consolidation boundary:** DEC-077–089 select requirements, not measured capacity or implemented protection. Quota observations are local diagnostics/pacing only; they never prove fraud or determine presence, committee membership or bans. See [invariant registry](INVARIANT_REGISTRY.md) and [consolidation/evidence map](ARCHITECTURE_CONSOLIDATION.md).

This document specifies the **decentralized Network Thermometer**, the fundamental accounting unit of **Byte-Years (Storage-Time Product)**, the **organic quartile damping** and the **Whale Brake**. It bounds local admission and supports small village nodes. Local received statistics are not an authoritative global load oracle or an adversarial fault bound.

---

## 1. The Physical Currency: Storage-Time Product (Byte-Years)

Layer 2 holds no balances or monetary transaction fees. Vouchers circulate as fully-fledged decentralized means of payment and store of value **over periods of several months to several years (mean: approx. 5 years)**.

The actual hardware cost of a shard node arises from **retaining this active ownership and collision state in RAM over the entire voucher lifetime**.

### 1.1 Mathematical Definition

Since each `StoredLock` in RAM is $192\,\text{Bytes}$ in size (144 B wire `LockEntry` + 32 B Canon Hash + 8 B `valid_until` + shard/padding) or approx. $224\,\text{Bytes}$ including index overhead, the accounting example below is computed from size and validity duration ($\Delta t = \text{valid\_until} - \text{now}$):

$$\text{Footprint}_{\text{Byte}\cdot\text{s}} = 192\,\text{Bytes} \times \Delta t_{\text{sec}}$$

In the standardized accounting unit **Byte-Years** ($1\,\text{year} = 31.536.000\,\text{seconds}$):

$$\text{Footprint}_{\text{Byte-Years}} = 192 \times \Delta t_{\text{years}}$$

```mermaid
flowchart TD
    subgraph SpaceTime["Storage-Time Product for Vouchers as Means of Payment"]
        L1["⚡ Short-lived lock (1 month TTL):<br>192 B * (1/12) year = 16 Byte-Years"]
        L2["🎟️ Annual voucher (1 year TTL):<br>192 B * 1 year = 192 Byte-Years"]
        L3["💶 Standard means of payment (5 years TTL):<br>192 B * 5 years = 960 Byte-Years (0.96 KB-Years)"]
        L4["🏛️ Long runner / endowment (10 years TTL):<br>192 B * 10 years = 1,920 Byte-Years"]
    end
```

The 192-byte accounting example and numeric policy are retained here; they are not a measurement of every deployed memory layout. Exact wire, storage and index sizes must remain distinguishable. Successor lifetime is derived from the authenticated Voucher Root Anchor, never a caller-selected TTL.

### 1.2 Economic Incentive & Anti-Spam Brake
* **Real payment usage:** A 5-year voucher occupies $960\,\text{Byte-Years}$.
* **Physical protection:** A spammer wanting to dump millions of artificial 5-year locks into the network requires gigantic ingress budgets physically capped by the Network Thermometer.

---

## 2. Decentralized Quartile Capture ($Q1$ and $Q3$) & Cold Start ($N < 4$)

Each shard node continuously aggregates the consumed Byte-Years volume of all incoming locks.

```mermaid
flowchart LR
    subgraph QuartilVerteilung["Statistical Quartile Distribution (Byte-Years / h)"]
        direction LR
        Q1["🔵 25th percentile (Q1)<br>Small village nodes & altruists"]
        Median["🟢 50th percentile (Median)<br>The normal baseline (NCB)"]
        Q3["🟣 75th percentile (Q3)<br>Large merchant gateways"]
    end
```

### 2.1 Cold Start & Absolute Minimum (Hard Floor Baseline)

For a nonzero accounting baseline in idle periods and micro-networks ($N < 4$):

* **Unbreachable hard-floor baseline:**
  $$\text{NCB}_{\text{min}} = 960.000\,\text{Byte-Years / day} \quad (40.000\,\text{Byte-Years / hour})$$
* **Minimum accounting baseline:** Even if the computed median in the network arithmetically tends to 0, the computed baseline retains at least this base quota ($\text{NCB}_{\text{eff}} = \max(\text{NCB}_{\text{calc}}, \text{NCB}_{\text{min}})$).
* **Practical meaning:**
  A single village node has an accounting budget equivalent to **1,000 new five-year vouchers** per day (or **5,000 one-year vouchers** or **60,000 monthly locks**) with the base quota. This is a budgeting example, not a promise of disk, network or quorum availability.

### 2.2 Statistical Aggregation ($N \ge 4$), 24-Hour Integral & 28-Day Smoothing

Once $N \ge 4$ active nodes are present in the mesh:
1. **Quartile capture ($Q1$, Median, $Q3$):** From heartbeats received via Dunbar gossip, each node locally computes quartiles.
2. **24-hour hourly ring buffer (`HourlySlottedRingBuffer`):**
   * To reduce diurnal sampling bias, hourly medians are entered into a ring buffer of **24 hourly slots**.
   * The sum or average of these 24 slots yields at any arbitrary point in time the **unweighted aggregate of the 24 recorded hourly slots** (e.g., from yesterday 07:00 to today 06:00).
3. **28-day sliding median (Slotted ring buffer):**
   * The daily 24h sum integral is written into a ring buffer of **28 daily slots**.
   * The effective reference value $\text{NCB}_{\text{day}}$ is the 28-day moving average of this median.
   * **Effect:** Smoothing reduces sensitivity to diurnal fluctuations and short spikes; it does not prove Byzantine resistance of the supplied statistics.

---

## 3. Physical Inertia (24h Daily Cycle & Time-Based Integer EMA)

Real economic traffic fluctuates over the day:
1. **24-hour daily epoch (`epoch_day`):** Quotas are allocated as **daily budgets**.
2. **Time-based integer EMA for burst damping:** To avoid millisecond spikes, the gateway computes the Exponential Moving Average time-based in $\mu\text{BJ}$ ($10^6$ fixed-point):
   $$\text{decay} = \frac{\text{old\_ema} \times \min(\Delta t_{\text{sec}}, 86.400)}{86.400}, \quad \text{new\_ema} = (\text{old\_ema} - \text{decay}) + \text{footprint}$$
   At $\Delta t = 0$ (burst in same second) no decay occurs; after 24h inactivity the value decays to 0.
3. **Organic inertia ($\tau$):** Smoothed via the 28-day low-pass filter.

---

## 4. The Zipf Spread Damper (Protection of Small Village Nodes)

In a healthy network $Q1$ and $Q3$ stand in natural ratio ($Q1 / Q3 \approx 0{,}33$):

$$\text{Spread\_Damper} = \max\left(0{,}5, \; \min\left(1{,}0, \; \frac{1 - \frac{Q1}{Q3}}{0{,}66}\right)\right)$$

---

## 5. The Deterministic 2-Stage Quota Model & Whale Brake

Instead of an unverifiable age curve (which would break on network merges), a clear, partition-safe 2-stage model applies to all nodes:

$$\text{Daily quota}(N) = \text{NCB}_{\text{eff}} \times K(N) \times \text{Spread\_Damper}$$

$$K(N) = \begin{cases}
0{,}05 & \text{if unconfirmed / sandbox / incubation } (\text{Status IMMATURE}) \\
1{,}0 & \text{if fully active after 24h } (\text{Status ACTIVE})
\end{cases}$$

* **Absolute Whale Brake ($K \le 5{,}0$):** Even with merchant clusters operating multiple networked nodes or maximal multipliers, no single node may ingest more than **5× the 28-day moving-average median ($\text{NCB}_{\text{eff}}$)** ($K \le 5{,}0$).
* **Scaling via network growth:** Additional honest nodes can increase available service and change locally observed demand statistics. A larger node count alone does not prove honest traffic, global agreement or successful quota availability.
* **Local capacity enforcement:** Reject excess admitted requests promptly with the specified quota/capacity response; malformed or unauthorized packets may be dropped under the transport rules. Capacity refusal does not alter heartbeat presence, voting authority or identity status. Normal NOT_READY/capacity responses and quorum cancellations are neutral. No alarm gossip is added.

### 5.2 Active Quota Feedback (`429 QuotaExceeded`) & 3-Zone Diagnostics

A sender may compare a quota response with its own counter, but the counters can legitimately differ in order, timing and view. **[INV-0909]** preserves the numeric zones only as a local diagnostic/backoff aid:

| Local observed consumption | Interpretation and permitted action |
| --- | --- |
| Below 75% of the local limit | Unexpected early refusal; inspect local counters and apply bounded sender pacing. It is not proof of laziness or fraud. |
| 75%–125% | Border/cutoff region; differences are expected. Respect capacity feedback without a failure penalty. |
| Above 125% | Local overload indication; reduce offered work and respect admission limits. |

No zone increments presence `missing_count`, suspends HRW eligibility, broadcasts blame or authorizes a ban. Three missed hourly F2F heartbeats are a separate presence rule. Checkout does not expand beyond its frozen committee after quota refusal. Genuine cryptographic equivocation remains the only automatic identity-sanction basis.

### 5.3 [INV-0907] New-Node Bootstrap & Seed Initialization (Anti-Deadlock)

When a new node joins an existing large network:
* **Seed initialization (Day 0):** New node determines the current daily median of known peers $\text{Median}_{\text{start}}$ and immediately initializes **all 28 slots** of its ring buffer with this value:
  $$\text{slots}[0 \dots 27] = \max(\text{Median}_{\text{start}}, \; \text{NCB}_{\text{min}})$$
* **Rolling transition (Day 1 to 28):** Each day one seed slot is replaced by own locally measured daily truth. After 28 days buffer is 100 % autonomous.
* **24h initialization grace (`IMMATURE`):** Treat seed/local-counter discrepancies as uncertainty. No quota observation authorizes a peer sanction before or after this period. Ticket maturation and presence have separate rules.

### 5.4 [INV-0908] Network Merge & Fast Re-Seed (Merge Hysteresis)

When a small village network ($N=5$) merges with a global large network ($N=50.000$):
* **Merge detection:** If a node detects a jump in network size ($N_{\text{new}} \ge 2 \times N_{\text{old}}$ or $\Delta N \ge 20$), it switches to merge mode.
* **Fast re-seed:** Node immediately overwrites all 28 slots of its ring buffer with the new locally learned aggregate median.
* **24h merge hysteresis (`INV-0802`):** Preserve the accounting re-seed window. Quota discrepancies never authorize bans, including outside this window. No global view or committee transition proof is inferred from re-seeding.

---

## 6. The Decentralized Network Read Thermometer (5:1 Read-Load Coupling)

While write locks bind persistent State Bloat in RAM and on disk (Storage-Time Product in Byte-Years), read queries (`POST /v1/status`, P2P `StatusQuery`, `POST /v1/sync`) burden ephemeral resources: CPU (Ed25519 signature generation of `L2Verdict`), CAS lookups, and socket bandwidth.

### 6.1 Read Credits & Weighting
Since $\Delta t = 0$ for read requests, the read thermometer measures **read operations (credits)**:
* **Simple status check (`/status`, `StatusQuery`):** $1\,\text{Read-Credit}$.
* **`ShardDigestRequest`:** $2\,\text{Read-Credits}$.
* **`POST /v1/sync` / `ActiveSyncRequest`:** $1 + \left\lceil \frac{\text{Locks}}{10} \right\rceil\,\text{Credits}$ (weighted chunk compensation).

### 6.2 The 5:1 Ratio & Hard Floor ($50.000\,\text{Reads/day}$)
* **5:1 planning ratio:** A voucher may be checked multiple times before being locked. The accounting design uses approximately $5 : 1$ as a planning relationship; deployed traffic must be measured.
* **Read hard floor:** Analogous to write hard floor ($1.000$ locks/day = $960.000\,\text{BJ/day}$) the accounting baseline assigns at least $50.000\,\text{read credits / day}$ ($\approx 2.083\,\text{reads/h}$):
  $$\text{NCB}_{\text{read, eff}} = \max\left(\text{MovingAverage28}(\text{DailyReadMedians}), \; 50.000\right)$$
  Since read operations are served toll-free from RAM and gateways distribute read load across Top-20 shard nodes (`UniformRandom` per `INV-0310`), the arithmetic aggregate is $1.000.000$ credits/day across 20 nodes. This is not a measured capacity or availability guarantee. Normal status remains read_quorum=1; payment release separately requires a fully verified current quorum proof.
* **Read Whale Brake:** For read operations too the absolute cap $K \le 5{,}0$ ($500\,\%$ of 28-day median) applies.

---

## 7. Invariants of the Network Thermometer

1. **[INV-0901] Byte-Years accounting unit:** Ingress and storage capacity for write locks is measured exclusively in the Storage-Time Product $\text{Byte} \times \Delta t_{\text{TTL}}$ (standard: Byte-Years).
2. **[INV-0902] Hard floor baseline ($960.000\,\text{BJ/day}$):** Effective write baseline $\text{NCB}_{\text{eff}}$ must never fall below the fixed minimum of $960.000\,\text{Byte-Years/day}$ ($40.000\,\text{BJ/h}$).
3. **[INV-0903] 28-day median smoothing:** Apply the 28-day slotted buffer to reduce sensitivity to short spikes; smoothing does not prove the reports honest.
4. **[INV-0904] 24h daily budget:** Quotas are computed per 24-hour epoch (`epoch_day`) for accounting; physical-time burst damping and capacity checks still apply. Calendar epoch_day does not define committee tenure.
5. **[INV-0905] Whale cap:** Multiplier $K$ is invariantly capped at $5{,}0$ ($K \le 5{,}0$).
6. **[INV-0906] Local enforcement:** Bounded admission refusals/drops follow the interface contract, without global blame, presence penalties or bans.
7. **[INV-0907] Seed initialization for new nodes:** New nodes fill all 28 slots of their ring buffer on joining with the current peer median to prevent cold-start deadlocks in large networks.
8. **[INV-0908] Fast re-seed on network merges:** On abrupt network growth ($N_{\text{new}} \ge 2\times N_{\text{old}}$) the 28-day buffer is immediately re-seeded with the new locally learned aggregate median; the 24h accounting hysteresis grants no authority over peer identity or committee membership.
9. **[INV-0909] Three-zone local diagnostics:** Below 75%, 75%–125% and above 125% are counter-comparison/backoff zones only. No fraud inference, presence change, committee exclusion or ban follows.
10. **[INV-0910] Read hard floor ($50.000\,\text{reads/day}$):** The calculated baseline has a minimum of $50.000$ read credits per day ($\approx 2.083\,\text{reads/h}$).
11. **[INV-0911] 28-day read median smoothing:** Read queries are smoothed via a separate 28-day slotted ring buffer to cushion scraping and crawler attacks.
12. **[INV-0912] Read Whale Brake ($K \le 5{,}0$):** No single node may fetch more than $5\times$ the smoothed read median per 24h epoch.
13. **[INV-0913] Pre-filter quota check for read CPU:** Quota check for `/status` occurs before CAS lookup and before Ed25519 signature computation to reject excess work before costly signing; this does not assert zero processing cost.


## 8. Delivery and evidence boundary

The physical-time integer EMA and numeric accounting policy above are retained. Decay depends on physically elapsed justified time, never request count; spam cannot accelerate its own decay. Checked arithmetic, bounded counters and authenticated root expiry must be verified in implementation. Read/status admission remains independent of write reservation.

For writes, apply Spec 12/14 reservation-first RAM admission and await the exact atomic durable lock/own-choice acknowledgment before any binding signature release. No request/runtime thread performs unmanaged blocking disk I/O; no RAM guard spans the wait. Bounded batching and protected internal shard/sync budgets do not guarantee completion within a particular latency. Real receiver-side QUIC flood/quota tests, relevant HTTP checks and measured workloads are required by Spec 16; none is executed by this document consolidation.
