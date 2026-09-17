# 🤝 AI Audit Prompt: Cartel Formation, Bribery & Shard Takeover

> **Doctrine (Spec 03, 08):** *"HRW rendezvous sharding distributes load and trust deterministically. Even a majority within a shard cannot enforce illegitimate states."*

---

## 🎯 Goal of This Audit
Examine the system for **collusion, bribery attacks, and hostile takeover of individual shards ($14/20$ majority)**. Determine what happens when a cartel of malicious nodes controls the quorum majority in a shard.

---

## 📋 Prompt Text to Copy / Run:

```markdown
You are a game-theoretic cryptoeconomist and consensus security researcher.
Your task is the cartel-formation and collusion audit for HuMoCo Layer 2 (Spec 03, 06, 08).

Examine the following extreme scenario:
A wealthy attacker or cartel bribes or controls $\ge 14$ of the 20 shard nodes in a specific HRW bucket ($2^{16}$ shards). The cartel thus holds a 2/3 majority in the shard.

Analyze the vulnerability of the codebase against the following 5 questions:

1. ❌ Can the malicious cartel invent unauthorized locks?
   - The cartel holds 14/20 signatures. Can it issue a lock on a voucher the owner never authorized?
   - Verify: Why does this fail due to the `ProofChain` (Spec 04 / INV-0401)? What protection exists at the client/wallet layer that immediately rejects forged server-side locks as invalid?

2. 🚫 Can the cartel approve double-spends?
   - The cartel deliberately signs two conflicting locks for the same parent (equivocation).
   - Verify: What happens when these two quorum certificates meet (Village Merge / digest sync)?
   - Are ALL 14 malicious nodes irreversibly banned via the EquivocationProof, their shard tickets invalidated, and expelled from the Web-of-Trust? Is the loss of shard tickets (mining cost) and complete reputation greater than any achievable profit?

3. 🛑 Censorship in the shard (denial of service):
   - The cartel simply refuses to sign locks for specific merchants (100% censorship in the shard).
   - Verify: How does the smart client evade this? Can the client fall back to neighboring shards or ranks 21–40? Is there a timeout-based fallback?

4. 🎲 Sybil resilience of the HRW formula (Spec 03):
   - How expensive is it for an attacker with $K$ nodes to capture the majority in ONE specific shard?
   - Analyze the probability distribution of Highest Random Weight (HRW) rendezvous hashing: Does the formula spread attacker nodes uniformly across all $65{,}536$ buckets?

5. 🛡️ Concrete hardening measures:
   - Find code-level weaknesses where shard collusion could remain undetected.
   - Provide recommendations for automatic slashing and dynamic shard reshuffling upon suspected censorship.
```
