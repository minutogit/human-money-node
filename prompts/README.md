# 🤖 HuMoCo AI Audit & Maintenance Prompts (Prompt Suite)

> **Credo:** *"In decentralization there is no trust, only mathematical proofs."*  
> **Principle:** *"Subtraction before Construction"*

This prompt suite contains **17 highly specialized, reusable AI audits** covering the full spectrum of modern software engineering: from **mutation testing** and **memory safety** to **Byzantine hardening**, **clean code**, and **performance tuning**.

---

## 🗂️ Overview of the Audit Suite & Systematic Orchestrator

> **Central Orchestrator & Tracking:**
> * **[00_master_audit_orchestrator.md](00_master_audit_orchestrator.md)**: **Master Prompt** to autonomously select, parallel-dispatch (via Model-Router & Muse Spark), and dynamically chain audits until sufficient findings are discovered and fixed.
> * **[AUDIT_REGISTRY.md](AUDIT_REGISTRY.md)**: **Central Status Matrix & Audit Log** tracking the execution timestamps, findings count, priority scores, and health status for all 17 audit prompts.

---

### 🔬 1. Software Engineering, Test Effectiveness & Memory Safety
| File | Focus | Primary Goal |
|---|---|---|
| **[12_mutation_testing_und_test_blindspot_audit.md](12_mutation_testing_und_test_blindspot_audit.md)** | **Mutation Testing** | Mutates code in a targeted way (inverting conditions, falsifying calculations) and checks whether tests immediately turn red. Finds fake tests. |
| **[13_unsafe_code_und_memory_safety_audit.md](13_unsafe_code_und_memory_safety_audit.md)** | **Memory Safety & Unsafe** | Scans all `unsafe` blocks, raw pointers, alignment, and Miri violations to guarantee 100% freedom from undefined behavior. |
| **[14_property_based_testing_und_fuzzing.md](14_property_based_testing_und_fuzzing.md)** | **Property-Based Testing** | Generates thousands of random inputs via `proptest` to formally prove algebraic laws (idempotency, round-trip, monotonicity). |
| **[15_clean_code_und_idiomatic_rust_audit.md](15_clean_code_und_idiomatic_rust_audit.md)** | **Clean Code & Idioms** | Eliminates unguarded `unwrap()`/`expect()` in libraries, sharpens error enums, and satisfies `clippy::pedantic`. |
| **[16_supply_chain_und_dependency_audit.md](16_supply_chain_und_dependency_audit.md)** | **Supply Chain & CVEs** | Checks dependencies for vulnerabilities (`cargo audit`), transitive duplicates, and license compliance. |
| **[17_update_and_supply_chain_verification.md](17_update_and_supply_chain_verification.md)** | **Update Diff & Node Sovereignty** | Enables laypersons and operators to perform a 2-minute AI-assisted audit of version diffs before applying any update. |

---

### 🏛️ 2. Code Architecture, Minimalism & Invariants
| File | Focus | Primary Goal |
|---|---|---|
| **[01_subtraktion_und_vereinfachung.md](01_subtraktion_und_vereinfachung.md)** | **Subtraction & Simplification** | Eliminate accidental complexity, over-engineering, and dead code (KISS / YAGNI). |
| **[04_invarianten_und_spezifikations_waechter.md](04_invarianten_und_spezifikations_waechter.md)** | **Invariant & Spec Guardian** | Bit-exact reconciliation between code (`crates/`) and specifications (`docs/`). |
| **[05_performance_und_latency_audit.md](05_performance_und_latency_audit.md)** | **Performance & Latency Guardian** | PoS Hot-Path $< 5\,\text{ms}$, RAM filter $< 1\,\mu\text{s}$, eliminate clones & heap allocations. |

---

### 🛡️ 3. Byzantine Attacks, Sabotage & Hacking
| File | Focus | Primary Goal |
|---|---|---|
| **[02_security_und_byzantine_hardening.md](02_security_und_byzantine_hardening.md)** | **Byzantine Security & Hardening** | Uncover double-spend gaps, CAS races, signature swaps, and DoS attack surfaces. |
| **[08_sabotage_zensur_und_eclipse_audit.md](08_sabotage_zensur_und_eclipse_audit.md)** | **Sabotage, Censorship & Eclipse** | Defend against edge monopolies, selective dropping (grey-hole), WoT poisoning, and gaslighting. |
| **[09_knoten_hack_und_key_compromise_audit.md](09_knoten_hack_und_key_compromise_audit.md)** | **Node Hack & Key Compromise** | Post-breach containment: damage limitation after theft of `node_key.bin`. |
| **[10_kartellbildung_und_shard_takeover_audit.md](10_kartellbildung_und_shard_takeover_audit.md)** | **Cartel Formation & Shard Collusion** | Resilience against bribery/takeover of $\ge 14/20$ shard nodes (ProofChain protection). |

---

### 🌪️ 4. System Dynamics, Free-Riding & Time
| File | Focus | Primary Goal |
|---|---|---|
| **[03_todes_spiralen_und_deadlock_audit.md](03_todes_spiralen_und_deadlock_audit.md)** | **Anti-Cascade & Deadlock Audit** | Find positive feedback loops, gossip storms, channel blocking, and task leaks (Spec 19). |
| **[07_faulheit_und_free_riding_audit.md](07_faulheit_und_free_riding_audit.md)** | **Free-Riding & Laziness** | Expose Free-Riders that save bandwidth/RAM and refuse to sign foreign locks. |
| **[11_time_warp_und_uhren_manipulation_audit.md](11_time_warp_und_uhren_manipulation_audit.md)** | **Time-Warp & Clock Manipulation** | Protection against NTP spoofing, malicious premature TTL pruning, and clock skew (F2F median). |

---

### 🧪 5. Chaos & Integration Testing
| File | Focus | Primary Goal |
|---|---|---|
| **[06_chaos_und_fuzz_test_generator.md](06_chaos_und_fuzz_test_generator.md)** | **Chaos & Test Generator** | Directly writes new executable Rust test code for extreme Jepsen/DST scenarios. |

---

## 🚀 How to Use These Prompts

### Option A: In Interactive Chat (Antigravity)
1. Select the appropriate file from `prompts/`.
2. Copy the prompt content into the chat.
3. The AI performs an in-depth review and delivers concrete code patches.

### Option B: Automated via OpenCode CLI
```bash
# Example: Run mutation testing
opencode run --file prompts/12_mutation_testing_und_test_blindspot_audit.md
```

### Option C: Focused Module Scope
Append the desired target directory to the prompt:
> *"Run prompt `13_unsafe_code_und_memory_safety_audit.md` exclusively for `crates/humoco-sim-core/src/wire.rs`."*
