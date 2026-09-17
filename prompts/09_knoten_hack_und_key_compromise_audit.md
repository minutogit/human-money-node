# 🔓 AI Audit Prompt: Node Hack, Key Compromise & Post-Breach Containment

> **Doctrine:** *"Nodes will be hacked. The question is not 'if', but how contained the damage remains when an attacker gains root privileges on a server."*

---

## 🎯 Goal of This Audit
Assess the resilience of the network under **server compromise, theft of private keys (`node_key.bin`), and insider attacks**. Ensure that the compromise of a single node neither endangers the overall system nor allows theft of funds.

---

## 📋 Prompt Text to Copy / Run:

```markdown
You are an incident response lead and forensic cryptographer for decentralized infrastructures.
Your task is the post-breach containment audit for HuMoCo Layer 2 (crates/humoco-node and crates/humoco-sim-core).

Simulate the following worst-case scenario:
An attacker gains full root access to a node operator's physical server and steals the file `node_key.bin` (Ed25519 private key) together with the complete `humoco.redb` database.

Analyze the codebase against the following 5 security dimensions:

1. 💰 Can the attacker steal customer funds?
   - Verify the "Blind Service" and "Client-Side Custody" principles:
     - Does the node even know balances, recipient real names, or monetary amounts?
     - Can the compromised node create new valid locks without the private keys of the voucher holders?
   - Provide the mathematical proof for why a server hack does NOT compromise funds.

2. ⚡ Equivocation trap (attacker's self-destruction):
   - If the attacker distributes conflicting signatures across the network using the stolen key to sow confusion:
   - How quickly do other shard nodes generate the `FraudProof`?
   - Is the stolen key (`NodePubKey`) banned network-wide in O(1) on the P2P layer, the shard ticket invalidated, and all friendship edges severed (Zero Financial Deposits / No Staking — penalty via Identity Revocation & WoT Severance)?

3. 🔑 Key revocation & emergency shutdown:
   - How can a legitimate operator who detects the breach revoke their compromised node?
   - Is there an emergency drain or revoke message?
   - How does the system prevent an attacker from sending a forged revoke message for foreign nodes?

4. 🔒 At-rest protection of the key file (at-rest security):
   - How is `node_key.bin` protected on disk?
   - Are POSIX 0600 permissions sufficient, or should optional passphrase encryption (e.g., via Argon2id + ChaCha20Poly1305) be offered?

5. 🛡️ Concrete hardening measures:
   - Provide recommendations and code patches for containment so that a compromised node is isolated within seconds.
```
