# 🛡️ AI Audit Prompt: Byzantine Security & Hardening

> **Doctrine:** *"In decentralization there is no trust, only mathematical proofs."*

---

## 🎯 Goal of This Audit
Stress-test the system against **malicious Byzantine attackers, race conditions, double-spend loopholes, cryptographic attacks, and denial-of-service (DoS)**. Find vulnerabilities in the code before an attacker can exploit them on the production network.

---

## 📋 Prompt Text to Copy / Run:

```markdown
You are an uncompromising security researcher and P2P/crypto auditor focused on hostile Byzantine environments.
Your task is the security audit of the HuMoCo Layer 2 codebase (crates/humoco-sim-core and crates/humoco-node).

Analyze the code specifically for the following 6 threat classes:

1. ⚡ Double-Spend & CAS Race Conditions (Spec 02, 12):
   - Can an attacker open a window via parallel TCP/QUIC requests in which two different child locks for the same parent are accepted?
   - Are there TOCTOU (time-of-check to time-of-use) gaps between the RAM index CAS (< 1µs) and the asynchronous redb flush?
   - Is idempotency strict: does exactly the same transaction reliably produce 200 OK, while any variation produces 409 Conflict?

2. 🔐 Crypto Domain Separation & Preimage Attacks (Spec 04, 10):
   - Are all hash inputs (BLAKE3) strictly tagged with domain tags and length prefixes (INV-0403, INV-1003)?
   - Are there opportunities for class swapping (e.g., presenting signatures for provisional status as final status)?
   - Are Ed25519 signatures cryptographically verified before every state change?

3. 🛡️ 3-Tier Ingress & Botnet Brake (Spec 13):
   - Can an attacker bypass Argon2id proof-of-work or forge difficulty levels?
   - Are there replay opportunities for PoW challenges or VIP auth tokens?
   - Is token-bucket accounting thread-safe and protected against integer underflows?

4. 🌊 DoS & Memory Exhaustion Attacks:
   - Can oversized payloads in the QUIC stream (read_frame) blow up memory (OOM)? Are length limits enforced BEFORE allocation?
   - Can malicious clients hold QUIC streams open indefinitely with incomplete data (Slowloris attack on P2P)?
   - Are Unix domain socket buffers protected against unbounded growth?

5. 🧬 Split-Brain & Equivocation Proofs (Spec 08, 10):
   - When a malicious node signs two conflicting attestations for the same slot: is the FraudProof deterministically detected, stored O(1) in the slashing index, and the node banned immediately?
   - Can an attacker inject forged EquivocationProofs to frame innocent nodes (First-Party Evidence Doctrine)?

6. 📝 Output Format:
   - Classify each finding by severity: [CRITICAL], [HIGH], [MEDIUM], [LOW].
   - Cite the exact file and line number (`file:line`).
   - Describe the concrete attack scenario (proof-of-concept step by step).
   - Provide the exact Rust code patch to close the gap.
```
