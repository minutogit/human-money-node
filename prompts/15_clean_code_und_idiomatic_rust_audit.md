# ✨ AI Audit Prompt: Clean Code, Idiomatic Rust & Error-Handling Hygiene

> **Doctrine:** *"Good Rust code reads like a mathematical specification. It never panics in libraries and uses the type system as an incorruptible compiler proof."*

---

## 🎯 Goal of This Audit
Inspect the codebase for **Rust API Guidelines, idiomatic clean code, and error-handling hygiene**. Eliminate `unwrap()` / `expect()` calls on production paths, sharpen type interfaces, and raise the code to `clippy::pedantic` standards.

---

## 📋 Prompt Text to Copy / Run:

```markdown
You are a Rust API designer and clean-code reviewer following the official Rust API Guidelines (C-GOOD-API).
Your task is the clean-code and idiom audit of the HuMoCo Layer 2 codebase.

Analyze the codebase specifically for the following 5 quality dimensions:

1. 🚫 Panic freedom (no unwrap / expect in library code):
   - Find all occurrences of `.unwrap()` and `.expect()` in `crates/humoco-sim-core` and `crates/humoco-node/src/` (excluding tests).
   - Can malicious external input ever trigger a thread panic or process crash?
   - Replace every unguarded access with typed errors (`Result<T, NodeError>`).

2. 🎭 Error type design & thiserror hygiene:
   - Are error messages precise and context-rich (e.g., including paths, ports, faulty IDs)?
   - Are there undifferentiated string errors (`String` instead of structured enum variants)?
   - Are foreign errors (`std::io::Error`, `redb::Error`, `quinn::ConnectionError`) wrapped cleanly?

3. 🔒 Visibility hygiene (visibility leaks):
   - Are internal helper functions and struct fields erroneously `pub` instead of `pub(crate)` or private?
   - Does the library expose exactly and only what clients and the daemon actually need?

4. 📖 API ergonomics & type safety:
   - Are primitive types overused ("primitive obsession", e.g., `[u8; 32]` for everything) where newtype wrappers (`ParentLock(Hash256)`, `LockId(Hash256)`) would make confusion impossible at compile time?
   - Do types implement all standard traits (`Debug`, `Clone`, `PartialEq`, `Eq`, `Hash`, `Default`, `Display`) where appropriate?

5. 🧹 Clippy pedantic & lints:
   - What warnings does `cargo clippy --workspace --all-targets -- -W clippy::pedantic` emit?
   - Provide the immediately applicable refactoring patch for the most important findings.
```
