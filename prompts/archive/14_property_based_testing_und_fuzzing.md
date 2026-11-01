# 🎲 AI Audit Prompt: Property-Based Testing & Algebraic Invariants

> **Doctrine:** *"Unit tests check what the programmer expected. Property-based testing checks what the programmer overlooked."*

---

## 🎯 Goal of This Audit
Extend test coverage through **property-based testing (proptest / QuickCheck)**. Generate thousands of random inputs and prove mathematical invariants such as **idempotence, associativity, round-trip fidelity, and monotonicity** across the full input space.

---

## 📋 Prompt Text to Copy / Run:

```markdown
You are an expert in formal verification and property-based testing in Rust (using the `proptest` crate).
Your task is to design and implement property-based tests for the HuMoCo Layer 2 Collision Lock Registry.

Formulate and implement proptests for the following 5 mathematical properties:

1. 🔄 Round-trip invertibility (encode/decode equivalence):
   - For any arbitrarily generated `WireHeader`: `WireHeader::from_bytes(&header.to_bytes()) == header`.
   - For any arbitrarily generated `LockRecord`: `bincode::deserialize(&bincode::serialize(&record)?)? == record`.
   - For any account tag: `parse_account_tag(tag.to_hex()) == tag`.

2. ⚡ Idempotence of the state machines (f(f(x)) == f(x)):
   - An arbitrary LockRecord is inserted twice into the RAM index / DualTierEngine:
   - The second call MUST return `Ok(IngressVerdict::Verified)` (or an identical status) for EVERY conceivable input, never `RejectedCollision` or `Conflict`.

3. ⚖️ Deterministic collision total ordering (strict weak ordering):
   - For any two locks A and B on the same parent:
   - It ALWAYS holds that either $H_{\text{canon}}(A) < H_{\text{canon}}(B)$ or $H_{\text{canon}}(B) < H_{\text{canon}}(A)$ (collision in BLAKE3 is practically impossible).
   - The winner selection is commutative: $\min(H_{\text{canon}}(A), H_{\text{canon}}(B)) == \min(H_{\text{canon}}(B), H_{\text{canon}}(A))$.

4. ⏳ Monotonicity of TTL pruning:
   - Let $t_1 \le t_2$: the number of locks still valid after $t_2$ is ALWAYS less than or equal to the number after $t_1$.
   - No pruning operation may ever increase the number of locks.

5. 🌡️ Quota monotonicity & hard-floor bounds:
   - For any TTL in seconds $s \ge 0$: `ByteYears::from_ttl_seconds(s) >= 1`.
   - For $s_1 \le s_2$: `ByteYears::from_ttl_seconds(s_1) <= ByteYears::from_ttl_seconds(s_2)`.

Deliverable:
Write the complete, compilable Rust test code using `proptest` that can be integrated directly into the project.
```
