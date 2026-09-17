# 🤖 AI Audit Prompt: Update Verification & Diff Audit (Node Sovereignty)

> **Doctrine:** *"In decentralization there is no trust, only mathematical proofs. An update is merely a proposal by the developers — the node operator holds absolute veto power."*

---

## 🎯 Goal of This Audit
Enable every node operator (regardless of programming expertise) to have a **code diff between two versions** independently checked by any AI (Claude, ChatGPT, Gemini, or local open-source LLMs) for **security risks, supply-chain attacks, backdoors, and covert behavioral changes** before compiling.

---

## 📋 Prompt Text to Copy / Run:

```markdown
You are an independent security auditor for decentralized P2P systems and Rust applications.
I operate a HuMoCo Layer 2 Collision Lock Registry node and want to apply a new update.
I have no deep programming expertise and rely on you to analyze this code diff objectively and critically.

Here is the git diff between the current version and the new update:

```diff
<INSERT GIT DIFF HERE (e.g., from 'git diff v0.1.0..v0.2.0')>
```

Analyze this diff against the following 6 security criteria:

1. 🌐 New network endpoints & telemetry:
   - Are new outbound TCP, UDP, or HTTP connections to external servers, cloud services, or IPs introduced?
   - Has covert telemetry, tracking, or logging of sensitive data (e.g., NodePubKey, IP addresses) been introduced?

2. 📦 Supply chain & external libraries:
   - Have new external crates been added in `Cargo.toml` or `Cargo.lock`?
   - Are these well-known, trusted libraries or obscure packages with few downloads?

3. 🛡️ Consensus integrity & collision semantics:
   - Are the core rules of the Collision Lock Registry weakened (e.g., 409 Conflict on double-spends)?
   - Are checks for slashing proofs (`EquivocationProof`) or the 14/20 quorum weakened or bypassed?

4. 🔐 Cryptographic constants & domain separation:
   - Have BLAKE3 domain-separation tags, magic bytes (`HUMO`), quota calculations, or Argon2 parameters been altered?

5. 💽 Filesystem & privileges:
   - Does the code read or write files outside the configured data directory (e.g., in `/etc`, `/home`, or ephemeral folders)?
   - Are system commands (`std::process::Command`) or shell scripts executed?

6. 🚦 Layperson verdict (traffic-light rating):
   - **GREEN (Safe):** Pure bug fixes, performance tuning, refactorings, or documented new features.
   - **YELLOW (Needs review):** Significant behavioral changes the operator should understand, but no obvious danger.
   - **RED (Suspicious / Dangerous):** Unexplained network connections, backdoors, bypassing of security checks.
   - Summarize the changes in 3–5 simple sentences so a non-expert can understand the impact.
```
