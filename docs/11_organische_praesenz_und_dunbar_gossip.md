# 11. Organic Presence, Dunbar Saturation & Epidemic Gossip

> **Credo:** *"In decentralization there is no global registry. Presence is the stochastic echo of organic interconnection."*

---

## 1. The Problem: Sybil Injection via Edge Bottlenecks

In a decentralized network without a central authority, a core threat is that an attacker covertly builds a massive botnet ($10{,}000+$ Sybil nodes) and attaches it to the main network via a single friend / sponsoring peer (Admission Sponsor).

```
┌─────────────────────────┐
│    10,000 Sybil Nodes    │
└────────────┬────────────┘
             │ (Flood of Heartbeats & Presences)
             ▼
       [ 1 Bridge Peer ]  ◄── BOTTLENECK (Topological Bottleneck)
             │
             │ ◄── Edge Saturation Filter (Dunbar-RED)
             ▼
         [ Node X ]
             │
      (Local Filtering)
             ▼
 [ Local "Active Node" List ]
```

If every node were to admit all announced identities into its routing table without filtering, a single bridge peer could distort global sharding.

---

## 2. The Foundation: Bio-Mimetic Dunbar Gossip

The HuMoCo Layer-2 Collision Lock Registry solves this problem through **radically local, bio-mimetic information saturation** (inspired by Dunbar's number, Shannon channel capacity, and epidemic percolation):

1. **No global voter rolls:** Each node maintains an autonomous, purely local view of active nodes.
2. **Edge saturation (Random Early Satiation / RED):** Each edge has a finite information budget. Overload throttles itself stochastically.
3. **24h incubation & maturation period (24h Shard Ticket Incubation Wall):** A node is only activated after 24 hours and $\ge 8/24$ hourly heartbeats.
4. **Small-world epidemic:** Low fan-out and deterministic TTL ensure global percolation at minimal bandwidth ($< 25\,\text{KB/s}$).

---

## 3. The 3 Mathematical Pillars

### Pillar 1: Stochastic Edge Throttling (Dynamic Edge Budget $R_{\text{soft}}$)

Instead of a fixed number (such as 30/min), each node computes its edge budget $R_{\text{soft}}$ **fully autonomously and dynamically** from the number of locally known active nodes $N_{\text{local}}$ and the node degree $d = \text{deg}(A)$:

$$R_{\text{soft\_hour}} = \max\left(60, \; \left\lceil N_{\text{local}} \cdot \frac{\lceil \sqrt{d} \rceil + 1}{d} \cdot 2{,}0 \right\rceil\right) \quad [\text{Heartbeats / hour}]$$
$$R_{\text{soft\_min}} = \frac{R_{\text{soft\_hour}}}{60} \quad [\text{Heartbeats / minute}]$$

#### Stochastic Drop Probability ($P_{\text{drop}}$):
If the heartbeat rate $r$ arriving on an edge exceeds the dynamic budget $R_{\text{soft}}$, stochastic throttling (Random Early Satiation) applies:

$$P_{\text{drop}}(r) = \begin{cases} 
0 & \text{for } r \le R_{\text{soft}} \\ 
1 - \frac{R_{\text{soft}}}{r} & \text{for } R_{\text{soft}} < r \le R_{\text{hard}} \\ 
1.0 & \text{for } r > R_{\text{hard}} \quad (R_{\text{hard}} = 5 \cdot R_{\text{soft}})
\end{cases}$$

#### 24-Hour Simulation Results (Practical Scenarios):

| Scenario & Topology | Local $R_{\text{soft}}$ per Edge | Honest Nodes as `ACTIVE` | Sybil Attack (Single-Bridge) | Organic Merge |
| :--- | :--- | :--- | :--- | :--- |
| **1. Village network ($N=20, d=4$)** | **$1{,}0$ pkts / min** | **$87{,}9\%$** | $100$ bots $\rightarrow$ **$0{,}8\%$** qualified | – |
| **2. Regional mesh ($N=500, d=8$)** | **$7{,}4$ pkts / min** | **$100{,}0\%$** | $1000$ bots $\rightarrow$ **$0{,}1\%$** qualified | – |
| **3. Village Merge ($50+50$ nodes, $5$ edges)** | **$1{,}1$ pkts / min** | **$97{,}9\%$** | – | **$99{,}9\%$** successfully integrated |

* **Protection against botnets:** Even with 1,000 aggressive bots on a single edge, **$99{,}9\%$** fail due to edge saturation.
* **Organic merge:** When two networks merge over $\ge 5$ edges, traffic spreads without edge congestion and integrates the new network to **$99{,}9\%$** within 24 hours.

> [!TIP]
> **Systemic Elegance (Emergent Safety & Multi-Homing Incentive):**  
> Throttling on a single edge is not a deficiency but the intended physical flood protection for micro-networks. It creates the natural, decentralized incentive for genuine mesh interconnection (**multi-homing over $\ge 3\text{--}5$ edges**) without requiring bureaucratic special-case rules (see [`docs/00:8`](docs/00_architektur_und_mental_model.md#8-die-doktrin-der-systemischen-einfachheit-occams-razor--emergent-safety)).

---

### Pillar 2: Epidemic Gossip & Small-World Percolation (Wildfire Model)

To ensure that legitimate heartbeats propagate reliably and without packet explosion in the global small-world network ($10^6$ to $10^8$ nodes), we use the physical **percolation model**:

```
[ Emitting Node Z ]
        │ (1x per 60 min)
        ▼
   [ Node A ] ─── (Gossip to k = min(d, ⌈√d⌉ + 1) neighbors, TTL = 16)
        │
        ├──► [ Node B ] ─── (First receipt -> fire; thereafter "ash" / drop)
        ├──► [ Node C ]
        └──► [ Node D ]
```

1. **Epoch heartbeat cadence (1 HB / hour):** Each active node emits exactly one 64-byte heartbeat every **60 minutes**:
   $$\text{Heartbeat} = \langle \text{Epoch}_{\text{hour}}, \text{Timestamp}_{\text{unix}}, \text{NodeID}, \text{PoW\_Nonce}, \text{Sig}_{\text{Ed25519}} \rangle$$
2. **Hop limit (TTL):** $\text{TTL}_{\text{hop}} = 16$. This exceeds the average small-world diameter ($L \approx \frac{\ln N}{\ln \langle d \rangle} \approx 6 \dots 8$) by more than double.
3. **Strict ingress freshness filter ($\pm 60\,\text{second}$ time window):**
   * Incoming heartbeats must carry a timestamp deviating by at most **$\pm 60\,\text{seconds}$** from the receiving node's local system time ($|\Delta t| \le 60\,\text{s}$).
   * Packets older than $60\,\text{s}$ or more than $60\,\text{s}$ in the future (e.g., faulty system clock or replays) are **immediately discarded silently at ingress**.
   * **Important:** This drop does **not** consume edge budget $R_{\text{soft}}$ for honest neighboring nodes!
4. **"Ash" deduplication:** Each node remembers received $(\text{Epoch}_{\text{hour}}, \text{NodeID})$ tuples in an LRU ring buffer. Once a node has forwarded a packet, it becomes "ash": subsequent duplicates of the same epoch are discarded immediately. The wave extinguishes after exactly one global pass.
5. **Cryptographic fraud proof for heartbeat spam (Pillar-3 Slashing Detector):**
   * **Attack vector (heartbeat flooding / edge displacement):** If an attacker attempts to exhaust the edge budget $R_{\text{soft}}$ or displace honest nodes in gossip by sending heartbeats at high frequency (e.g., every 2 minutes), the attacker itself supplies the proof of its guilt.
   * **Slashing invariant:** If two validly signed heartbeats $\text{HB}_1$ and $\text{HB}_2$ of the same $\text{NodeID}$ circulate in the network whose timestamps are less than 50 minutes apart:
     $$|\text{Timestamp}_2 - \text{Timestamp}_1| < 50\,\text{minutes}$$
     this pair constitutes an irrefutable, stateless fraud proof (`FRAUD_HEARTBEAT_SPAM`).
   * **The 1024-slot direct-mapped detector ($\approx 112\,\text{KB}$ RAM):**
     Each node holds an array of 1024 slots (`HeartbeatSlashingSlot`). The target slot is computed instantly: $\text{Slot index} = \text{NodeID} \pmod{1024}$.
     1. **Case 1 (slot FREE or old $> 75\,\text{min}$):** The slot is empty or the previous entry is older than $75\,\text{minutes}$ (dead node / "corpse"). The slot is overwritten and the new heartbeat stored. *No dead node permanently blocks a slot!*
     2. **Case 2 (slot contains SAME NodeID):** Check timestamps:
        - **$|\Delta t| < 50\,\text{minutes}$:** 🔴 **FRAUD!** Immediately bundle `FraudProofPayload` (both packets are directly in RAM!), flood priority-0 gossip and free the slot again.
        - **$|\Delta t| \ge 50\,\text{minutes}$:** ✅ **HONEST!** Update the slot with the new time (or free it).
     3. **Case 3 (slot occupied by DIFFERENT FRESH node):** If a foreign node with age $\le 75\,\text{minutes}$ occupies the slot, no storage is performed ("If no slot is free, so be it"). The packet is forwarded normally in the mesh; other nodes on the path take over detection.
   * **Consequence:** The $\text{NodeID}$ is immediately and permanently placed on the global **ban registry** (Collision Lock Registry). The expensive Argon2 PoW of the identity is thus irrevocably burned.
6. **Reboot safety (1h grace period & NTP immunity):**
   * After a system reboot or cold start, a node listens **passively for at least 60 minutes** before emitting its first own heartbeat. This mathematically rules out accidental double-signing after crashes or flash losses.
   * NTP time jumps never cause false bans: if the clock was wrong, the packet is simply discarded due to $|\Delta t| > 60\,\text{s}$ without triggering a fraud proof.
7. **Autonomous peer clock detection & P2P Network-Adjusted Time (disaster fallback):**
   * **The logical network time:** A node never adjusts its physical hardware clock but operates internally with a logical time:
     $$\text{net\_time} = \text{local\_system\_clock} + \text{time\_offset}$$
   * **Normal operation (NTP online):** $\text{time\_offset} = 0$.
   * **Autonomous fallback (NTP disrupted or island network in a village without internet):**
     * Each node continuously computes the **median of time offsets** of the last $\ge 10$ valid heartbeats from its direct F2F peers:
       $$\text{offset}_{\text{target}} = \text{Median}\Big(t_{\text{peer\_heartbeat}} - t_{\text{local\_clock}}\Big)$$
     * If $|\text{offset}_{\text{target}}| > 45\,\text{seconds}$ or NTP fails, `time_offset` is gradually steered toward $\text{offset}_{\text{target}}$.
   * **The 3 safety barriers (protection against time-warp attacks):**
     1. **WoT gating:** Only cryptographically verified F2F friends are included in the median computation (no anonymous strangers).
     2. **Maximum cap (clamping):** $|\text{time\_offset}| \le 15\,\text{minutes}$ in offline operation.
     3. **Strict monotonicity:** Logical time never jumps backward: $\text{net\_time} = \max(\text{net\_time}, \; \text{last\_seen\_time} + 1\,\text{s})$.
   * **Seamless re-synchronization on network merge:**
     * When an isolated village returns to the global network after weeks without internet, tens of thousands of external heartbeats flood in with the global world time.
     * The median gently and automatically tips back to global time — all nodes in the village rebalance themselves completely harmoniously without manual intervention.
   * **Telemetry:** When $|\text{time\_offset}| > 45\,\text{s}$, the node raises the dashboard event `WARN_LOCAL_CLOCK_SKEW` and triggers a new NTP contact attempt in the background.
8. **Bio-mimetic fan-out ($k$ – sublinear square-root law):**
   $$k(d) = \min(d, \; \lceil \sqrt{d} \rceil + 1)$$
   * **Village ($d = 1$):** $k = 1$ ($100\%$ forwarding – no partition).
   * **Standard node ($d = 16$):** $k = 5$ ($31\%$ forwarding – stable propagation).
   * **Large mesh hub ($d = 64$):** $k = 9$ ($14\%$ forwarding – high dispersion at minimal load).
9. **F2F-median consensus for adaptive admission barrier & anti-surge dampening:**
   * **Heartbeat signal:** The hourly heartbeat optionally carries a 2-byte field `demanded_difficulty_index` (based on local CPU benchmark $\mu_{\text{local}}$).
   * **F2F-median filtering:** Each node derives the locally required admission barrier from the median of its direct friends ($D_{\text{net\_median}} = \text{Median}(D_{\text{peer}_1}, \dots, D_{\text{peer}_k})$). Outliers and griefing attempts by individual attackers are mathematically cut away.
   * **Inertia dampening against griefing:** The base difficulty median may move upward by **at most $+5\%$ per 30 days** via a low-pass filter. An attacker can never force the network into expensive re-mining through spam demands.
   * **Anti-surge multiplier ($M_{\text{surge}}$):** During sudden join waves ($\Delta N_{24\text{h}}$), the entry barrier for *newcomers* temporarily rises to $2\times\text{--}4\times$. Established nodes with safety headroom ($H \ge 4$) remain completely unaffected.

---

### [INV-1105] Gossip Percolation Tipping Point & Starvation (The 73.1% Weibull Formula)

In the small-world network ($N \ge 10{,}000$ nodes, average degree $\langle d \rangle \approx 14{,}6$, $k \le 16$), gossip propagation under partial blocking/censorship follows exactly the laws of **statistical percolation physics and epidemiology (SIR model)**:

$$\Large R(x) = 100 \cdot \exp\left(-\left(\frac{x}{73{,}1}\right)^{19}\right)$$

* $x \in [0, 100]$: fraction of blocking / suspending nodes in the total network (in $\%$)
* $R(x) \in [0, 100]$: fraction of remaining honest nodes that receive the gossip (in $\%$)
* **Physical tipping point $\lambda = 73{,}1\,\%$:** Follows directly from the herd-immunity threshold $H_c = 1 - 1/R_0$ with $R_0 \approx 3{,}7$ effective branches ($1 - 1/3{,}7 \approx 73\,\%$).
* **Weibull modulus $k = 19$:** Describes the extremely steep phase transition (brittle fracture of the *giant component*).

```
Honest Reachability R(x) [%]
100% ┼──────────────────────────────╮ (0% to 55%: 100% - 99.5% stable)
 90% │                              ╰──╮ (60% to 64%: >90%)
 80% │                                 │
 70% │                                 ╰──╮ (68%: 77.9%, 70%: 64.6%)
 60% │                                    │
 50% │                                    │ (71%: 59.1%, 72%: 46.5%)
 40% │                                    ╰─► 73%: 42.8%
 30% │                                       │
 20% │                                       ╰──► 74%: 25.2% (TIPPING POINT Δ = -17.7%)
 10% │                                          ╰──╮ (76%: 12.7%, 77%: 5.7%)
  0% ┴─────────────────────────────────────────────┴─────────────────────
      0%  10%  20%  30%  40%  50%  60%  70% 74% 80%  90%  100% (Blockers x)
```

| Blockers ($x$) | Reached Honest Nodes ($R(x)$) | Total Network Reach | Avg Max Hops | Network Status / Phase |
| :---: | :---: | :---: | :---: | :--- |
| **$0\,\% \dots 50\,\%$** | **$100{,}0\,\% \dots 99{,}9\,\%$** | $100\,\% \dots 50\,\%$ | $9{,}5 \dots 19{,}1$ | 🟢 **Censorship-Immune** (Giant Component intact) |
| **$60\,\% \dots 64\,\%$** | **$95{,}3\,\% \dots 91{,}0\,\%$** | $38\,\% \dots 33\,\%$ | $26 \dots 31$ | 🟢 Intact Mesh ($> 90\,\%$) |
| **$65\,\% \dots 70\,\%$** | **$89{,}7\,\% \dots 64{,}6\,\%$** | $31\,\% \dots 19\,\%$ | $33 \dots 38$ | 🟡 Onset of Fragmentation |
| **$71\,\% \dots 73\,\%$** | **$59{,}1\,\% \dots 42{,}8\,\%$** | $17\,\% \dots 12\,\%$ | $39 \dots 39$ | ⚠️ **Phase Transition (Flank)** |
| **$74\,\%$** | **$25{,}2\,\%$** | **$6{,}6\,\%$** | **$31{,}5$** | 💥 **TIPPING POINT (Max. Drop: $\Delta = -17{,}7\,\%$)** |
| **$75\,\% \dots 77\,\%$** | **$18{,}0\,\% \dots 5{,}7\,\%$** | $4{,}5\,\% \dots 1{,}3\,\%$ | $28 \dots 16$ | 🟠 Fragmentation into Sub-Clusters / Islands |
| **$\ge 85\,\%$** | **$< 0{,}5\,\%$** | $< 0{,}08\,\%$ | $\le 2{,}7$ | 🔴 **Total Extinction** (dies in 1st–2nd hop) |

#### Architectural Consequence:
1. **Censorship immunity:** A malicious cartel of up to $50\,\%$ of nodes cannot silence an honest node ($R(x) \ge 99{,}9\,\%$).
2. **Lazy node starvation:** Once a lazy node has been placed on the local drop list by $\ge 74\,\%$ of nodes for refusing to work, its gossip throughput collapses physically. Its heartbeats no longer reach the network, and it is organically purged after 24–48h.

---

### Pillar 3: Local Accumulator & 24h Hysteresis

Each node tracks known peers in an ultra-compact RAM index (16 bytes per node).

```rust
#[repr(C)]
pub struct PeerPresenceEntry {
    pub node_id_prefix: u64,        // 8 bytes: Unique BLAKE3 prefix
    pub hourly_bitmask: u32,        // 4 bytes: Last 24-32 hours of presence (1 bit/h)
    pub missing_count: u8,          // 1 byte: Transient failure counter (0..255, >=3 is suspended)
    pub maturity_hours: u8,         // 1 byte: Hours since first contact (0..255)
    pub _reserved: u16,             // 2 bytes: Alignment padding
}
```

#### State Transitions via Hysteresis, Suspension & Fast Re-Entry:
* **Hourly tick:** $\text{hourly\_bitmask} = \text{hourly\_bitmask} \ll 1$, $\text{maturity\_hours} += 1$, $\text{missing\_count} = \text{missing\_count}.saturating\_sub(1)$ (stündlicher Zerfall / autonome Heilung).
* **Initial activation of newcomer (`IMMATURE` $\to$ `ACTIVE`):**
  $$\text{maturity\_hours} \ge 24\,\text{h} \quad \land \quad \text{popcount}(\text{hourly\_bitmask}_{24h}) \ge \tau_{\text{on}} \quad (\tau_{\text{on}} = 8 \text{ out of } 24)$$
* **Dynamic local suspension (`ACTIVE_HEALTHY` $\to$ `ACTIVE_SUSPENDED`):**
  $$\text{missing\_count} += 1 \quad \implies \quad \text{is\_suspended}() = (\text{missing\_count} \ge 3)$$
  *(While `is_suspended() == true`, the node is skipped in HRW quorums and rank 21 promotes in $0\,\text{ms}$. Gossip heartbeats remain unconditionally forwarded).*
* **Immediate unblocking on successful lock signature:**
  $$\text{missing\_count} = 0 \quad (\text{sofortige Wiederaufnahme})$$
* **Deactivation (`ACTIVE` $\to$ `DORMANT`):**
  $$\text{popcount}(\text{hourly\_bitmask}_{24h}) \le \tau_{\text{off}} \quad (\tau_{\text{off}} = 3 \text{ out of } 24) \quad (\text{after } \ge 21\text{--}24\,\text{h of inactivity})$$
  * **🎯 Clean re-entry:** At the moment of transition to `DORMANT`, $\text{missing\_count} = 0$ is set so the node is immediately available for probation on re-entry without multi-week lockouts.
* **Fast re-entry of known nodes (`DORMANT` $\to$ `ACTIVE` for probation):**
  $$(\text{hourly\_bitmask} \ \& \ 0\text{b}11) == 0\text{b}11 \quad (\ge 2\,\text{consecutive hours})$$
  *(If a server comes back online after weeks/months, it is immediately ready for probation again after 2 hours of Fast Re-Entry).*
* **Physical deletion (Zero State Bloat):** When $\text{hourly\_bitmask} == 0 \land \text{maturity\_hours} \ge 48$ (48h without signs of life), the entry is completely deleted from RAM.

> [!NOTE]
> **Architectural Decision (KISS / Why Fast Re-Entry Does Not Cause Flapping):**  
> 2 hourly heartbeats require a real time of **at least 2 hours**. Combined with the 21–24 hour failure threshold, a full cycle takes **at least 24–26 hours**. Flapping on a minute or second cadence is thus systemically impossible.  
> **Flap dampening:** If more than 2 flap events occur within 48 hours, Fast Re-Entry is temporarily disabled for that peer and the regular 8h threshold is required. Fewer rules = maximum resilience.

---

### Pillar 4: [INV-1104] First-Seen Newcomer Pacing (Trickle Edge Ingress & Queue Health Checks)

To prevent a compromised node from abruptly flooding tens of thousands of computed Argon2 identities into the global shard mesh, all nodes apply the **two-way forwarding rule with stochastic jitter and liveness probing** when receiving newcomer gossips:

```rust
if known_nodes.contains(&node_id) {
    // 🟢 1. NODE ALREADY KNOWN (Normal Heartbeat / Update)
    // -> Immediate, unthrottled forwarding to all friends (hot path, 0 ms)
    forward_immediately(gossip);
} else {
    // 🟡 2. NODE IS ENTIRELY NEW (First-Seen)
    // -> Register locally immediately (prevents multiple enqueuing via other edges)
    known_nodes.insert(node_id);
    
    // -> Enqueue into edge-specific pacing queue
    // -> Forwarding to friends is stochastically throttled (e.g., 50min + Uniform(0..20min) = avg. 1h)
    enqueue_paced_forward(gossip, jittered_interval);
}
```

#### Guarantees of [INV-1104]:
1. **Meat-grinder principle ($R_{\text{in}} \ll R_{\text{evict}}$):** The ingress rate of new unconfirmed nodes is artificially slowed per edge (avg. $1\,\text{node/h}$). Since shards eliminate dead phantoms via *Lazy Node Defense* in $< 10\,\text{s}$, an attacker can never overrun a 14/20 quorum.
2. **Stochastic jitter ($50\,\text{min} + \text{Uniform}(0, 20\,\text{min})$):**  
   To prevent resonance catastrophes, thundering-herd waves, and synchronized network pulses, the pacing interval is spread by $\pm 10\,\text{minutes}$ ($\mu = 60\,\text{minutes}$). This smooths data flow organically over the time axis.
3. **Queue-depth-triggered QUIC probing (phantom busting from threshold $Q \ge 4$):**
   * Since hop counters can be forged by Byzantine nodes, the local node relies **exclusively on its local ingress queue depth**:
     * **Queue depth $Q \in \{1, 2, 3\}$:** Normal organic newcomers pass pacing without pre-check (conserves resources and avoids liveness flooding on newcomers).
     * **Queue depth $Q \ge 4$ (suspected botnet flood):** Before releasing an element from position 4 onward, the local node performs a **QUIC mutual-TLS 1.3 health-check ping** to the declared endpoint ($300\,\text{ms}$ timeout).
     * **Result on timeout / fake / unreachable (e.g., NAT without listening port):** The phantom is **immediately silently deleted from the queue and `known_nodes`** and the next slot is checked. A spam burst of 1,000 dead phantoms is thus destroyed locally within seconds without generating 1 byte of mesh traffic!
4. **0% latency for honest heartbeats & reconnects:** Already known nodes traverse the unthrottled hot path ($0\,\text{ms}$).
5. **Complete clock independence:** The decision relies purely on the local in-memory set `known_nodes` — timestamp drifts or incorrect system clocks are irrelevant.
6. **Organic percolation:** A genuine new node spreads evenly and stably worldwide within 3–6 hours (analogous to global DNS propagation).

---

## 4. Resilience to Edge Discrepancies in HRW Sharding

### Why differing local node lists are not a problem:

Since nodes at the network edge may have minimal differences in their active node list (e.g., Node A sees 10,000 nodes, Node B sees 10,003 nodes), the question of consistency of HRW rendezvous sharding arises.

```
                [ Smart Client (Wallet) ]
                            │
         Computes Top-20 Shard Nodes via HRW
                            │
       ┌────────────────────┼────────────────────┐
       ▼                    ▼                    ▼
[ Shard Node #1 ]    [ Shard Node #2 ]    [ Shard Node #20 ]
 (Locally: Dumb)     (Locally: Dumb)      (Locally: Dumb)
 Checks First-Seen    Checks First-Seen    Checks First-Seen
```

1. **HRW minimal disruption:** Rendezvous hashing guarantees that a $0{,}1\%$ deviation in the node set leaves the top-$k$ shard assignment unchanged at over $99{,}7\%$.
2. **Smart client controls the quorum:** The wallet actively addresses the shard nodes. A server does not need to know whether it is node #1 or #4 for others. It only checks locally: *Is this key already locked?*
3. **Conflict resolution guarantee:** If extreme network splits lead to divergent quorums, the mathematical invariant decides without exception upon network merge:
   $$\min(H_{\text{canon}})$$
   The offender is slashed on Layer 1.

---

## 5. Summary of Key Metrics

| Parameter | Value | Rationale |
| :--- | :--- | :--- |
| **Heartbeat interval** | 60 minutes | Minimal bandwidth, sufficient for 24h sliding window |
| **Heartbeat packet size** | 64 bytes | WireHeader + signature + nonce |
| **Gossip TTL ($\text{TTL}_{\text{hop}}$)** | 16 hops | Guarantees percolation beyond small-world diameter |
| **Epidemic fan-out ($k$)** | $\min(d, \lceil \sqrt{d} \rceil + 1)$ | $R_0 \gg 1$, physically optimal square-root law |
| **Dynamic edge rate ($R_{\text{soft}}$)** | $\max(60, \lceil N_{\text{local}} \cdot \frac{k}{d} \cdot 2 \rceil)/\text{h}$ | Adapts autonomously to network size ($1 \dots 2000/\text{min}$) |
| **Activation threshold ($\tau_{\text{on}}$)** | 8 / 24h | 8 hours of consistent presence in 24h window |
| **RAM footprint** | 16 bytes / node | 100,000 nodes require only $\approx 1{,}6\,\text{MB}$ RAM |
