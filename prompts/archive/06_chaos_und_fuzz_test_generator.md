# 💥 AI Audit Prompt: Chaos, Fuzzing & Edge-Case Test Generator

> **Doctrine (Spec 16):** *"Deterministic Simulation Testing (DST) — If a system has not been tested under 70% malicious packet loss and chaotic network partitions, it is not ready for reality."*

---

## 🎯 Goal of This Audit
Generate new, aggressive **chaos tests, fuzzing vectors, and Jepsen-style edge-case scenarios**. Push the system to its limits in a controlled way (concurrent split-brains, Byzantine forgeries, out-of-order packets, cold-start crashes).

---

## 📋 Prompt Text to Copy / Run:

```markdown
You are an uncompromising chaos engineer and test architect (inspired by Jepsen testing and FoundationDB Deterministic Simulation Testing).
Your task is to design and implement aggressive edge-case and chaos tests for the HuMoCo Layer 2 Collision Lock Registry.

Pick one of the following 5 chaos scenarios and implement a complete, deterministic integration test for it:

1. 🌪️ Asymmetric Split-Brain with Multi-Edge Merge:
   - A 20-node cluster is partitioned into two unequal halves (13 nodes vs. 7 nodes).
   - Both halves issue local locks on colliding parents.
   - The halves are reconnected via 3 bridge nodes with 100 ms latency jitter.
   - Assertion: After the merge, the entire network converges 100% deterministically on `min(H_canon)` — not a single deadlock, no split state.

2. 🎭 Byzantine Equivocation & Sybil Storm:
   - 5 of 20 nodes behave in a Byzantine manner: they send conflicting signatures for the same lock slot to different neighbors.
   - Assertion: Honest nodes immediately generate `FraudProof::Equivocation`, ban the offenders in O(1), and exclude them from the quorum.

3. ⚡ Crash Loop & Cold Start Under Load:
   - While 500 parallel lock requests are in flight, the node process is abruptly terminated via SIGKILL.
   - The node restarts (cold start): loads redb tables, prunes expired buckets, and restores the RAM index.
   - Assertion: Zero data loss for already confirmed transactions, consistent RAM state, immediate resumption of operation in < 50 ms.

4. 🌊 P2P Packet Reordering & Extreme Jitter:
   - QUIC gossip packets arrive in reverse order and with random delays (0 to 2,000 ms).
   - Assertion: The Causality ProofChain self-heals via lazy ingestion; no hangs.

5. 🧬 Fuzzing of Wire & HTTP Inputs:
   - Generate maliciously mutated payloads for `/v1/lock` and the 32-byte wire header protocol (truncated frames, invalid UTF-8 nonces, overflow timestamps, null bytes).
   - Assertion: The server NEVER panics, never crashes, and always responds with a clean HTTP 400/409 or socket drop.

Deliverable:
Write the complete, executable Rust test code (including imports, mocks, and assertions) that can be dropped directly into `crates/humoco-node/tests/` or `crates/humoco-sim-core/tests/`!
```
