# 🎯 AI Audit Prompt: Sabotage, Censorship, Gaslighting & Eclipse Attacks

> **Doctrine (Spec 05, 07, 17):** *"No node shall be the sole source of truth for any client. The only defense against censorship is multi-homing and mathematical provability."*

---

## 🎯 Goal of This Audit
Examine the network for **targeted sabotage, censorship of specific merchants, eclipse attacks (edge monopolies), and gaslighting (fabrication of false states)**. Determine how malicious operators could sabotage competing PoS terminals.

---

## 📋 Prompt Text to Copy / Run:

```markdown
You are an offensive red-team specialist for censorship resilience and P2P topology attacks.
Your task is the sabotage and censorship audit of the HuMoCo Layer 2 architecture (Spec 05, 06, 07, 11, 17).

Analyze the code for the following 5 censorship and sabotage scenarios:

1. 🌑 Eclipse Attack on PoS Terminals / Merchants (Single-Bridge Monopoly):
   - A malicious operator offers a merchant a free gateway. The merchant connects exclusively to this single node (single edge).
   - The malicious node selectively blocks payments at certain PoS terminals (e.g., on a high-traffic Saturday) or reports artificial 409 conflicts.
   - Check: Does the smart client (Spec 06) detect the edge monopoly? Does the PoS terminal enforce multi-homing across at least 3 independent shard gateways?

2. 🌫️ Gaslighting & Fake States:
   - A node serves a wallet a stale or forged lock history.
   - Check: Does the cryptographic Causality ProofChain prevent a server from feeding the wallet invalid states? Why does gaslighting fail when the wallet itself custodies the root certificates?

3. 👥 WoT Infiltration & Endorsement Bomb (Spec 07):
   - An attacker operates an honest node for 6 months, earns the trust of neighboring friends, and collects endorsements.
   - After 6 months, the attacker vouches for 30 Sybil nodes and flips them all to hostile at once.
   - Check: Does F2F median protection apply (Spec 07)?
   - Guard-Rail: Recall that on Layer 2 there are **Zero Financial Deposits / No Staking** and no monetary bonding liability for friends; slashing on L2 operates purely cryptographically (permanent NodePubKey ban, Argon2d ticket loss, voiding via min(H_canon), and complete WoT severance).

4. 🕳️ Grey-Hole / Selective Dropping (Stealth Sabotage):
   - A saboteur does not drop all packets (which would trigger an immediate ban) but drops exactly 15% of data streams and delays lock attestations by 800 ms to break the $< 5\,\text{ms}$ PoS guarantee.
   - Check: How does the PeerManager respond (Spec 15)? Does it switch to `Degrading` on repeated delays and replace the node in the active quorum with rank 21?
   - Guard-Rail: **Non-Authoritative Telemetry (INV-1701):** Telemetry and latencies are purely diagnostic for human operators; high latencies or missing pings must never trigger an automated network ban (`triggers_auto_ban() == false`).

5. 🛠️ Concrete Hardening Measures:
   - Find vulnerabilities in the code where a single saboteur can harm consensus or a merchant.
   - Provide code fixes for automatic censorship detection and enforced multi-homing.

### 🚫 Explicit Negative Guard-Rails for This Audit:
1. **Zero Financial Deposits / No Staking on Layer 2:** Reject any suggestions requiring monetary deposits, stake slashing, or financial liability chains.
2. **Safe Standard Library (`from_le_bytes`) over Unsafe Crates:** Do not propose external transmute crates (`bytemuck`, `zerocopy`); uphold `#![forbid(unsafe_code)]`.
3. **Non-Authoritative Telemetry (`INV-1701`):** Telemetry and latency statistics never trigger automated bans.
```
