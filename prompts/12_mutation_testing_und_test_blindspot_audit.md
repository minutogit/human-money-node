# 🧬 AI Audit Prompt: Mutation Testing & Test Blind-Spot Audit

> **Doctrine:** *"A test that does not fail when the code is broken is worthless. 100% code coverage means nothing without 100% mutation kills."*

---

## 🎯 Goal of This Audit
Perform systematic **mutation testing (mutation analysis)**: deliberately mutate the code with intentional faults (invert conditions, off-by-one, falsify calculations, delete lines) and verify whether the test suite immediately turns red. Find **blind spots** in the tests (sham tests with weak assertions).

---

## 📋 Prompt Text to Copy / Run:

```markdown
You are an uncompromising test-quality engineer and mutation-testing expert (inspired by cargo-mutants and Stryker).
Your task is to uncover blind spots in the HuMoCo Layer 2 test suite (crates/humoco-sim-core/tests and crates/humoco-node/tests).

Select a core module (e.g., `storage/engine.rs`, `crypto.rs`, `wire.rs`, `network/framing.rs`, or `ingress/tier.rs`) and perform the following 5 mutation attacks:

1. 🔀 Operator mutation (condition inversion & off-by-one):
   - Mutant 1: Change `valid_until > now + 30_000` to `valid_until >= now + 30_000` or `valid_until > now`.
   - Mutant 2: Change the quorum threshold `2 * R / 3 + 1` to `2 * R / 3` or `R / 2 + 1`.
   - Mutant 3: Change the hard-floor baseline from `960_000` to `959_999`.
   - Question: Does at least one existing test fail immediately? If NOT: Why did the test suite fail to kill this surviving mutant?

2. ✂️ Statement deletion & return falsification:
   - Mutant 4: Delete the line `self.wal.push_back(...)` in the ingress path.
   - Mutant 5: Modify a signature check `verify() -> bool` so it always returns `true`.
   - Mutant 6: Make `prune_expired` simply return `0` without deleting anything.
   - Question: Are there tests that detect this fraud, or do the tests only check "no panic" instead of actual state?

3. 🔍 Assertion depth (tautology detection):
   - Inspect assertions in the test files: Are there tests that perform tautological checks (e.g., `assert!(result.is_ok())` without verifying the contents of `Ok(val)`)?
   - Are there mocked paths that obscure real error handling?

4. 🧪 Writing missing kill tests:
   - For each surviving mutant, write the exact, minimal Rust unit test that is guaranteed to kill that fault.

5. 📊 Output format:
   - List all tested mutations with status [MUTANT KILLED 💀] or [MUTANT SURVIVED 🧟].
   - Detailed analysis for each surviving mutant.
   - Concrete Rust test code to close the coverage gap.
```
