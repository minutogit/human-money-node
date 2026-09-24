# 🔬 AI Audit Prompt: Unsafe Code, Memory Safety & Undefined Behavior Audit

> **Doctrine:** *"A single undefined behavior destroys all cryptographic and logical guarantees. Unsafe code must be mathematically proven and hermetically isolated."*

---

## 🎯 Goal of This Audit
Scan the entire codebase for **`unsafe` blocks, raw-pointer transmutations, memory alignment, buffer overflows, and undefined behavior (UB)**. Verify that Rust's memory-safety guarantees are never violated.

---

## 📋 Prompt Text to Copy / Run:

```markdown
You are a Rust compiler and memory-safety auditor with deep expertise in the Rust memory model, LLVM optimizations, and Miri's undefined-behavior detection rules.
Your task is the unsafe and memory-safety audit for HuMoCo Layer 2 (crates/humoco-sim-core and crates/humoco-node).

Analyze the codebase specifically for the following 5 hazard zones:

1. 🔍 Scan of all `unsafe` blocks:
   - Search for every occurrence of `unsafe` across the entire workspace (e.g., in `wire.rs:42` with `std::ptr::read` or `copy_nonoverlapping`).
   - Verify the safety invariants:
     - Is the buffer guaranteed to be correctly aligned (`align_of::<WireHeader>() == 8`)?
     - Is the pointer guaranteed to be non-dangling, non-null, and backed by at least `size_of::<WireHeader>()` bytes of valid memory?
     - Are there aliasing violations (`&mut` overlapping with `&`)?

2. 🛡️ Safe alternatives & zero-copy:
   - Prefer safe slice decoding via std methods (`from_le_bytes`, `to_le_bytes`, `try_from`, `checked_*`).
   - Do NOT introduce external transmutation crates (`bytemuck`, `zerocopy`); uphold `#![forbid(unsafe_code)]` in the production daemon (`humoco-node`).
   - Why was `unsafe` needed at any location in the first place?

3. 💥 Integer overflows & truncation:
   - Search for all arithmetic operations (`+`, `-`, `*`, `as u32`, `as u16`).
   - Can an inadvertent cast (`len as u32` or `timestamp as u64`) lead to silent truncation overflow?
   - Are `saturating_*`, `checked_*`, or `wrapping_*` used where values originate from external network streams?

4. 🧠 Stack overflows & recursion:
   - Is there unbounded recursion when traversing `ProofChain`s or DAG locks?
   - Can oversized data structures be allocated on the thread stack?

5. 🛠️ Concrete hardening measures:
   - For each `unsafe` block, document:
     A) Proof of whether it is 100% UB-free.
     B) A proposal for a 100% safe alternative using stdlib primitives.
     C) Test instructions for `cargo miri test`.

### 🚫 Explicit Negative Guard-Rails for This Audit:
1. **Zero Financial Deposits / No Staking on Layer 2:** Reject any suggestions requiring monetary deposits or staking slashing.
2. **Safe Standard Library (`from_le_bytes`) over Unsafe Crates:** Reject suggestions adding `bytemuck` or `zerocopy`. Standard library byte conversions with `#![forbid(unsafe_code)]` are mandatory.
3. **Non-Authoritative Telemetry (`INV-1701`):** Telemetry metrics are purely diagnostic and never trigger automated bans.
```
