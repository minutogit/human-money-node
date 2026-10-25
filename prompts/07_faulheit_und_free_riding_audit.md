# 🦥 AI Audit Prompt: Laziness, Free-Riding & Asymmetric Leeching

> **Doctrine (Spec 03, 11, 17 & AGENTS.md):**  
> *"In decentralization there is no trust, only mathematical proofs. A node is banned or slashed network-wide ONLY upon irrefutable cryptographic self-proof (EquivocationProof). Telemetry metrics and health probes serve the human operator for diagnosis only; no telemetry metric ever triggers an automated ban (Non-Authoritative Telemetry / INV-1701). Ingress rights and P2P consensus are decoupled (INV-1306/1307)."*

---

## 🎯 Goal of This Audit
Examine the system for **node laziness (lazy node problem), Free-Riding, and asymmetric leeching** under the strict constraints of **Living-Mesh Routing, Non-Authoritative Telemetry (INV-1701–1705), First-Party Evidence, and Neutral Explicit Refusals (INV-0909)**. Find ways in which malicious or negligent operators could save server resources (CPU, RAM, bandwidth) at the expense of the network while retaining benefits, and verify that the protocol defenses remain sound without violating core invariants.

---

## 📋 Prompt Text to Copy / Run:

```markdown
You are a game theorist and protocol auditor specializing in Free-Rider problems in P2P networks.
Your task is the lazy-node and Free-Riding audit of the HuMoCo Layer 2 codebase (Spec 03, 09, 10, 11, 13, 15, 17, 19).

Examine the code for the following 5 leeching and laziness patterns under current specification invariants:

1. 😴 The Silent Signer (Validation Hotpath & Committee Participation):
   - A node accepts ingress write requests from its own clients but ignores LockVerifyRequests from other shard peers to save signature CPU.
   - Check: The collector requires 14 verified distinct signatures from the frozen top-20 committee (INV-0601 / DEC-053). Does a silent node prevent quorum progress? Does the collector cleanly abort without inventing replacement voters (rank 21-40 substitution is strictly forbidden)?
   - Invariant check: Ingress admission (Tier 1) is decoupled from P2P consensus (Tier 2); operator telemetry warnings (e.g. validation rate < 80%) serve diagnostic observation only (INV-1701) and MUST NEVER trigger automated ingress revocation or committee drift.

2. 🕳️ Storage Availability & Shard State Custody (G2 / G3):
   - A node stores only its own customers' locks and deletes foreign locks from RAM/redb to conserve disk and memory.
   - Check: What happens when peers request an on-demand shard sync or digest pull? Does a node returning Not Found or empty digests fail readiness verification without poisoning dominant quorum digests?
   - Invariant check: Storage availability is verified through dominant quorum digests (INV-0304 / INV-1605). Nodes that fail to provide complete state remain NOT_READY. In accordance with First-Party Evidence, unresponsiveness or empty answers must NOT trigger hearsay-based network bans.

3. 🐌 Latency, Capacity Signals & Neutral Refusals (INV-0909 / INV-1501):
   - A node returns artificial latency, drops gossip heartbeats, or emits capacity refusals to shed load.
   - Check: Are explicit capacity signals (FLAG_QUOTA_EXCEEDED across all 3 plausibility zones, FLAG_NOT_READY, FLAG_PEER_SUSPENDED) treated as strictly neutral protocol feedback with missing_count == 0?
   - Invariant check: Verify that neither quota rejections nor cancelled checkout stragglers ever invoke record_failure or degrade peer presence (INV-0909, INV-1501). Passive presence tracking runs strictly on hourly Dunbar heartbeats (3 missed hours -> local suspension, INV-0704).

4. 📉 Empty Certificates & Bitmap Integrity:
   - Does a node attempt to submit quorum certificates without contributing valid signatures itself?
   - Check: Are signer bitmaps and attestation counts strictly validated against the actual public keys and the frozen HRW committee (routes.rs / humoco-proto verify.rs)?
   - Invariant check: Verify that duplicate signers, unknown public keys, and malformed bitmaps are strictly rejected.

5. 💡 Incentive Alignment & Protocol Hardening:
   - Identify edge cases where laziness or unilateral non-cooperation could be technically profitable without detection.
   - Propose hardening measures that preserve First-Party Evidence, Non-Authoritative Telemetry, and Subjective Local Autonomy without introducing cascading death spirals or hearsay bans.
```
