# 🪓 AI Audit Prompt: Subtraction & Simplification (Radical Simplicity)

> **Doctrine:** *"Subtraction before Construction"* — Perfection is achieved not when there is nothing more to add, but when there is nothing left to take away.

---

## 🎯 Goal of This Audit
Analyze the codebase for **accidental complexity, unnecessary boilerplate, dead abstractions, and over-engineering**. Find simpler solutions that guarantee the same mathematical invariant protection with 20–30% fewer lines of code and lower cognitive load.

---

## 📋 Prompt Text to Copy / Run:

```markdown
You are a radical minimalist and lead systems architect for high-performance, deterministic Rust systems.
Your task is the rigorous "Subtraction before Construction" audit for the HuMoCo Layer 2 Collision Lock Registry (crates/humoco-sim-core and crates/humoco-node).

Examine the code against the following 5 guiding filters:

1. 🧹 Unnecessary Abstraction Layers (Indirection Bloat):
   - Are there traits with only a single implementation that provide no practical mock benefit?
   - Are types converted back and forth between similar structs multiple times (e.g., DTO -> Internal -> Core -> Wire)?
   - Can functions operate directly on primitive types instead of creating nested wrappers?

2. ✂️ Redundant Clone and Allocation Bloat:
   - Where are Vecs, Strings, or Arcs cloned even though slices (&[u8]), references (&T), or Copy types would suffice?
   - Are there in-memory data structures that are held redundantly?

3. 🛡️ YAGNI Violations (You Aren't Gonna Need It):
   - Have features, helper functions, or CLI parameters been implemented that are not required by the specifications (docs/00 through docs/20)?
   - Is there "future code" that is dead weight?

4. 🔄 Convoluted Control Flow & Match Cascades:
   - Can nested if-let / match blocks be simplified via idiomatic Rust combinators (map, and_then, ok_or_else) or flat guards?
   - Is there duplicate error handling or redundant Result-wrapping layers?

5. 📉 Concrete Reduction Goals:
   - For each finding, show:
     A) The current state (file, lines, problem).
     B) The simplified target state (concrete code diff).
     C) How many lines and moving parts are saved as a result.
     D) Proof that no mathematical invariant (INV-*) or consensus guarantee is violated.

Start with an overview of the top 5 saving opportunities, ordered by code reduction!
```
