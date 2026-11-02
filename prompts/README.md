# 🤖 HuMoCo Universal Quality & Conformance Loop

> **Credo:** *"In decentralization there is no trust, only mathematical proofs."*  
> **Doctrine:** *"Subtraction before Construction – One Single Review Loop, 100% Module Coverage."*

This directory contains the streamlined, self-orchestrating AI quality review system for `human-money-node`. The previous 25 fragmented prompts have been consolidated into **one single universal conformance loop** powered by a persistent coverage ledger.

---

## 🗂️ Structure

* **[`AUDIT_LOOP.md`](AUDIT_LOOP.md)**: **The ONE prompt.** Framed for first-party QA & specification conformance, self-orchestrating, and produces either a clean streak confirmation or a ready-to-use maintenance task prompt.
* **[`AUDIT_STATE.md`](AUDIT_STATE.md)**: **The coverage ledger.** Divides 100% of workspace code into 9 deterministic slices (`S01`–`S09`) and tracks `Clean_Streak`, `Last_Run`, and `Status` (`⚪ Pending`, `🟢 Clean`, `🔴 Fix_Open`, `🟡 ReCheck`).
* **[`reports/`](reports/)**: Historical review reports, regression test logs, and implementation notes.
* **[`archive/`](archive/)**: Preserved legacy prompt suite (Prompts `00`–`25`, Stufen 1–6, and `AUDIT_REGISTRY.md`).

---

## 🚀 How to Run the Review Loop

### Option 1: In AI Chat (Antigravity, ChatGPT, Claude)
Simply reference or copy [`prompts/AUDIT_LOOP.md`](AUDIT_LOOP.md):
> *"Führe den Quality-Review-Loop aus: @prompts/AUDIT_LOOP.md"*

The AI will:
1. Check [`prompts/AUDIT_STATE.md`](AUDIT_STATE.md) for any unreviewed slice (`⚪ Pending`), pending `🟡 ReCheck`, or lowest `Clean_Streak`.
2. Review the files in that slice against all architectural invariants and engineering quality rules.
3. Update [`prompts/AUDIT_STATE.md`](AUDIT_STATE.md).
4. If clean: output a 3-line confirmation. If defects were found: output **exactly one copy-pasteable Maintenance Task Prompt** for your coding agent.

### Option 2: Automated via OpenCode or Model-Router
```bash
# Run the review loop via OpenCode
opencode run --file prompts/AUDIT_LOOP.md

# Or via model-router
model-router run "$(cat prompts/AUDIT_LOOP.md)"
```

---

## 🔄 The Closed-Loop Lifecycle

```mermaid
flowchart LR
    A["1. Run AUDIT_LOOP.md"] --> B{"Inspects next slice\n(1. ⚪ Pending Sweep\n2. 🟡 ReCheck\n3. Lowest Clean_Streak)"}
    B -- "0 Defects" --> C["Clean_Streak + 1\n(🟢 Clean)"]
    B -- "Defects Found" --> D["Clean_Streak = 0\n(🔴 Fix_Open)\nOutputs 1 Fix Prompt"]
    D --> E["2. Run Fix Prompt\n(Fixes Code + Tests)"]
    E --> F["Updates status to\n🟡 ReCheck in AUDIT_STATE.md"]
    F --> A
```
