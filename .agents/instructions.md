# HuMoCo Layer 2 – Agent Master Instructions

Welcome to the **`human-money-node`** repository.

> ⚠️ **CRITICAL INVARIANT – CANONICAL CONTEXT:**  
> The canonical, complete development guide, mental model, and all programming rules are located in **[`AGENTS.md`](../AGENTS.md)** in the project root. This document is automatically loaded on every startup.  
> 🗣️ **BILINGUAL LANGUAGE POLICY (DE ↔ EN):**
> * **User / Maintainer communication:** The maintainer / user communicates in **German**. Agents **MUST ALWAYS** reply to the user in **German** (`Antworte dem Benutzer immer auf Deutsch`).
> * **Codebase & documentation:** Source code, Rustdoc comments (`///`), Git commits, GitHub issues, pull requests, and official documentation are written in idiomatic **English**.
> * This invariant is non-negotiable and overrides any other language preference. See [`docs/TRANSLATION_GLOSSARY.md`](../docs/TRANSLATION_GLOSSARY.md) for canonical term mappings.

---

## 🎯 Project Context

The HuMoCo Layer 2 Collision Lock Registry is **not a blockchain** and **not a monetary system**, but an asynchronous, stateless **Collision Lock Registry** for mathematical double-spend prevention (`parent_lock -> child_lock`).

---

## 🏛️ The 5 Guiding Filters for Every Decision (Occam's Razor)

1. **Subtraction before Construction:**
   * *"What happens if we COMPLETELY REMOVE this step / role / message?"*
2. **Smart Client, Dumb Server (Client-Side Custody):**
   * The client proves causality (`ProofChain`); the server only checks the RAM filter.
3. **Physics Trumps Negotiation:**
   * Split-brain conflicts heal deterministically and timelessly via $\min(H_{\text{canon}})$. Zero Financial Deposits: offenders are irreversibly banned via `HUMOCO_V1_EQUIVOCATION`, their shard ticket invalidated, and friendship edges severed (Identity Revocation & WoT Severance).
4. **Subjective Local View (Spec 19):**
   * Each node judges only from its direct experience. No global hearsay bashing!
5. **Zero State Bloat & TTL:**
   * After `root.valid_until + 30s` locks are physically purged.

---

## 🗂️ Directory Structure

* **`AGENTS.md`**: Master system context, programming rules & codebase map.
* **`README.md`**: The manifest & architectural pillars.
* **`ROADMAP.md`**: Production roadmap (phases 0 through 6 fully approved).
* **`crates/humoco-sim-core/`**: Mathematical core & deterministic simulation models.
* **`crates/humoco-node/`**: Production daemon (Quinn QUIC, Axum REST, redb, control IPC, CLI).
* **`docs/`**: 21 specifications (`00` to `20`, `99`).
* **`prompts/`**: 17 specialized AI audit prompts (mutation testing, security, Cascading Death Spirals, etc.).
