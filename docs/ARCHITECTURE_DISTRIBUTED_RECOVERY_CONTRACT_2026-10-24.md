# R03 distributed-recovery and coverage contract worksheet

Scope: F03 / R03; Z02, Z06, Z07; G2, G3 and E04. Builds directly upon R02's verified-support contract (`ARCHITECTURE_INHERITED_SUPPORT_CONTRACT_2026-10-24.md`).

## 1. Proof obligation and scenario worksheet: Distributed AB/A/B support

### Problem formulation

Consider a frozen top-20 committee $C = \{n_1, \dots, n_{20}\}$ for shard $S$. Suppose two compatible exclusions $A$ and $B$ (distinct parent collision slots or non-colliding causal chains) were admitted across the network during an asymmetric connectivity event:
- 8 nodes $H_{AB} = \{n_1, \dots, n_8\}$ hold $\{A, B\}$.
- 6 nodes $H_A = \{n_9, \dots, n_{14}\}$ hold $\{A\}$ only.
- 6 nodes $H_B = \{n_{15}, \dots, n_{20}\}$ hold $\{B\}$ only.

Every fact independently has 14 qualified holders ($|H_{AB} \cup H_A| = 14$, $|H_{AB} \cup H_B| = 14$). In an honest-quorum model with at most $f = 6$ faults, both $A$ and $B$ are genuine confirmed exclusions.
However, their whole-state active digests disagree:
- $\text{digest}(\{A, B\})$ is held by 8 nodes (< 14 required).
- $\text{digest}(\{A\})$ is held by 6 nodes (< 14 required).
- $\text{digest}(\{B\})$ is held by 6 nodes (< 14 required).

A recovering target $T$ (either a joining 21st applicant transitioning into the committee or node $n_i$ recovering after reboot) that requires **identical whole-state active digests** across 14 peers cannot progress. It observes zero quorums for any single full-state digest, despite both facts possessing true 14-node distributed support.

### Safe progress premises vs. unsupported cases

1. **Target membership & voter counting:**
   - The frozen committee contains exactly 20 members ($|C| = 20$).
   - A recovering target node $T$ cannot witness its own cut (`recovering self` exclusion).
   - If $T \in C$, $T$ can consult at most 19 remote peers. Progress requires 14 remote witnesses when $T$ is unready, or 14 total witnesses where $T$'s durable acknowledged fact is already committed.
   - Missing members cannot be substituted with rank-21 nodes; committee boundaries remain frozen by HRW score.

2. **Existence support vs. omission evidence:**
   - **Existence of fact $X$:** Proven when $\ge 14$ qualified members of $C$ commit to the existence and canonical representation of $X$ within their fixed, active cut at timestamp $t$.
   - **Completeness (Omission coverage):** An exclusion $X'$ is proven absent from shard $S$ only when $\ge 14$ qualified members attest that their fixed cut contains no entry for $X'$ (e.g. by bounding active collision slots or range proofs within a bucketed MVCC snapshot). A missing key from an unverified subset is never proof of non-existence or class 0.

3. **Conflicting choices in the same collision slot:**
   - If $A$ and $A'$ compete for the same parent slot, R02's verified support semantics govern:
     - Admitted Class 2 dominates Class 1 and Class 0.
     - Equal confirmed classes follow the canonical hash tie-breaker (`min(hash)`).
     - Conflicting minority choices (e.g. 10 vs 3) are safely isolated into `TABLE_PROVISIONAL_HMC_LOCKS` / quarantine without poisoning the active digest.

4. **Turnover & signer rotation:**
   - Exclusions and support survive sequential turnover across epochs, provided each transitional cut retains the intersection property ($\ge 14$ overlap) with the preceding committee.
   - Departed historical signer certificates are never archived; current qualified quorums witness inherited cuts under the R02 domain-separated signature scheme.

## 2. Recovery reconciliation mechanism

1. **Bounded Cold Sync Reconciliation:**
   - Instead of discarding all peers when whole-state digests differ, `sync_single_shard` identifies the common admissible core of facts that have $\ge 14$ verifiable cut witnesses.
   - Sources are sampled via fixed cuts under the R02 lease contract (`HUMOCO_V1_INHERITED_SUPPORT_CUT`).
   - Writes committed after the freeze cut timestamp are staged and applied only after the base cut is durably installed.

2. **Anti-Patterns explicitly prohibited:**
   - **No unconditional union:** Simply unioning all received rows from any responder violates safety and invites Byzantine state poisoning.
   - **No majority-of-whoever-responds:** Quorum threshold remains strictly 14 of 20 (or adaptive island threshold $\lceil \frac{2N+1}{3} \rceil$).
   - **No empty bootstrap inference:** A network restart with matching empty digests does NOT constitute a valid bootstrap. Explicit operator bootstrap (`operator_bootstrap`) remains mandatory (G2).
   - **No raw integer promotion:** All admitted facts must carry cryptographic cut commitments conforming to R02.

3. **Staging and Durable Installation:**
   - Reconciled state is validated in bounded staging storage.
   - A single atomic `Immediate` transaction installs roots, locks, support, indexes, and quarantine rows.
   - Durable fsync commit precedes RAM index publication; RAM publication precedes `mark_shard_ready`.
