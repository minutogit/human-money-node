# 🛡️ Security Policy & Node Sovereignty Guide

> **Credo:** *"In decentralization there is no trust, only mathematical proofs."*  
> **Principle:** *"Software is merely a proposal by the developers. The node operator decides."*

---

## 🏛️ 1. The Iron Principle: No Automatic Updates (Zero Auto-Update)

In HuMoCo there are **no automatic background updates and no remote restart commands**.

### Why this is a fundamental security guarantee:
* **Protection against supply-chain attacks:** If the GitHub repository, a maintainer account, or the build server is compromised, an attacker can **never** automatically deploy malicious code to node operators' servers.
* **Node Sovereignty:** As the operator of a HuMoCo node you are liable for your node's signatures (equivocation / double-signing triggers immediate permanent P2P ban, shard-ticket invalidation, and Identity Revocation & WoT Severance). You must never delegate control over your executed software to a third party.
* **Every update is a deliberate, manual step by the operator** (`git pull`, audit, build, restart).

---

## 🔬 2. Threat Model: What Happens If the Repository Is Hijacked?

Should an attacker gain access to this repository or maintainer accounts and attempt to inject a backdoor, four independent layers of defense apply:

1. **Layer 1 – Mathematical Consensus:**  
   Even if 30–40% of all nodes unknowingly install a faulty update: the HRW shard quorum requires **14 of 20 votes** (`FINAL`). Modified nodes are isolated by the honest majority. For double-spends, the cryptographic `EquivocationProof` irrefutably proves fraud, leading to immediate permanent ban of the offender and invalidation of their shard tickets and WoT friendship edges.
2. **Layer 2 – Wire-Format Quarantine:**  
   The 32-byte `WireHeader` (Spec 10) validates version and magic bytes without panicking. Incompatible frames are immediately discarded with `VersionMismatch`.
3. **Layer 3 – No Stealth Binaries:**  
   Operators build from source or verify official releases against reproducible SHA-256 checksums and signed Git tags (`git tag -v`).
4. **Layer 4 – Democratized AI Audit:**  
   Any operator — even without programming knowledge — can have an AI review the differences between versions in two minutes before building.

---

## 🤖 3. The 2-Minute AI Audit for Node Operators (Before Every Update)

Thanks to modern AI models (Claude, ChatGPT, Gemini, local LLMs) you do not need to be a Rust expert to verify what has changed in the software.

### 3-Step Guide:

#### Step 1: Generate the Git diff for the new version
Switch to your node directory and display the changes against the previous version:
```bash
# Example: compare current previous version with the new release tag
git fetch --tags
git diff v0.1.0..v0.2.0 > update_diff.txt
```
*(Alternatively, open the link `https://github.com/humoco/human-money-node/compare/v0.1.0...v0.2.0` directly in your browser on GitHub.)*

#### Step 2: Pass the prompt to your AI
Copy the following prompt along with the contents of `update_diff.txt` into your AI (detailed template see [`prompts/17_update_and_supply_chain_verification.md`](prompts/17_update_and_supply_chain_verification.md)):

> *"Analyze this Git code diff of a decentralized HuMoCo consensus node. Critically review it for the following security risks:*  
> *1. Are there any new, unexpected outbound network connections, URLs, or telemetry?*  
> *2. Have new external libraries (dependencies) been added in Cargo.toml?*  
> *3. Have cryptographic domain tags, consensus rules (double-spend 409) or slashing conditions been weakened?*  
> *4. Is there suspicious code that reads or writes files outside the data directory?*  
> *Give me a clear traffic-light verdict (GREEN = Safe, YELLOW = Review Required, RED = Suspicious) and explain all changes in simple, understandable terms."*

#### Step 3: Build and start only on a green verdict
Only when the explanation is plausible and comprehensible to you should you proceed with the update:
```bash
git checkout v0.2.0
cargo build --release -p humoco-node
# Restart service
```

---

## 🔐 4. Cryptographic Release Verification

Every official release is cryptographically signed by the core maintainers.

1. **Verify signed Git tags:**
   ```bash
   git tag -v v0.1.0
   ```
2. **Checksum verification (`SHA256SUMS`):**
   ```bash
   sha256sum -c SHA256SUMS
   ```

---

## 🚨 5. Reporting a Security Vulnerability (Responsible Disclosure)

If you discover a security vulnerability or a potential consensus issue in HuMoCo:
* **Please do not open a public GitHub issue.**
* Send an encrypted report via GPG or contact the security team through the [GitHub Security Advisory Dashboard](https://github.com/humoco/human-money-node/security/advisories/new).
* We strive to respond and confirm within 48 hours.
