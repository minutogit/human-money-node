# 📦 AI Audit Prompt: Supply-Chain Security & Dependency Audit

> **Doctrine:** *"Every dependency is code you did not write but are liable for. A decentralized system must not drag along unverified giant trees."*

---

## 🎯 Goal of This Audit
Examine all external libraries for **known security vulnerabilities (CVEs), unmaintained crates, transitive dependencies, license compatibility, and binary bloat**.

---

## 📋 Prompt Text to Copy / Run:

```markdown
You are a supply-chain security specialist for Rust and open-source ecosystems.
Your task is the dependency and supply-chain audit of the HuMoCo Layer 2 workspace configuration (`Cargo.toml` and `Cargo.lock`).

Analyze the dependencies against the following 5 risk factors:

1. 🚨 Known vulnerabilities (advisories & CVEs):
   - Check all dependencies against the RustSec Advisory Database (equivalent to `cargo audit`).
   - Are there outdated versions of `quinn`, `rustls`, `rcgen`, `argon2`, `redb`, `tokio`, or `blake3` with known vulnerabilities?

2. 🌲 Dependency tree & transitive duplicates:
   - Are there crates compiled in multiple incompatible versions (e.g., two different versions of `syn`, `bytes`, `rand`, or `ring`)?
   - How can the workspace be cleaned up via `Cargo.lock` (`cargo tree --duplicates`)?

3. ⚖️ License compatibility:
   - Are all crates used compatible with a permissive open-source license (MIT / Apache-2.0)?
   - Have viral copyleft licenses (GPL/AGPL) been inadvertently pulled in as transitive dependencies?

4. 🪶 Feature-flag minimization (minimal builds):
   - Are crates imported with `default-features = false` where only partial functionality is needed (e.g., Tokio features, Quinn features)?
   - Can binary size and compile time be reduced through targeted feature flags?

5. 🛠️ Concrete action plan:
   - List all recommended version upgrades or dependency replacements.
   - Provide the cleaned-up `Cargo.toml` patch.
```
