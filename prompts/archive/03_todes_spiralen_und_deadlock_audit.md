# 🔄 AI Audit Prompt: Cascading Death Spirals, Cascades & Deadlock Audit

> **Doctrine (Spec 19):** *"Every protective measure MUST have a locally dampening effect ($\Delta \text{Load} \le 0$). If the response to a failure generates additional global traffic, there exists a mathematical resonance point at which the network destroys itself."*

---

## 🎯 Goal of This Audit
Examine the asynchronous Tokio workflows, channel pipelines, and P2P protocols for **positive feedback loops (Cascading Death Spirals), infinite retry storms, channel blocking (backpressure deadlocks), and asynchronous lock inversions**.

---

## 📋 Prompt Text to Copy / Run:

```markdown
You are an expert in nonlinear system dynamics, control theory, and highly concurrent async Rust architectures.
Your task is the system-stability and anti-cascade audit of the HuMoCo Layer 2 codebase according to Spec 19 and Spec 15.

Analyze the code for the following 5 systemic failure scenarios:

1. 🌪️ Cascading Death Spirals & Positive Feedback Loops (Spec 19):
   - When a shard node responds more slowly under load: do neighboring nodes react with local dampening (local suspension, rank-21 failover in 0 ms) or do they generate aggressive retries / hearsay gossip that finally brings the overloaded node to its knees?
   - Are there gossip amplification effects where a small message triggers an exponential cascade of broadcasts?
   - Does the bloom / seen cache reliably prevent echo loops in Dunbar gossip?

2. 🔒 Deadlocks & Async Channel Backpressure:
   - Are Tokio MPSC channels (e.g., for the asynchronous redb flush) bounded?
   - What happens when the MPSC channel is full: does the sender block (backpressure on the Hot-Path) or is there regulated throttling?
   - Are there cyclic dependencies between Tokio tasks (e.g., task A waits for channel B while task B waits for lock A)?
   - Are standard `std::sync::Mutex` instances incorrectly held across `.await` points (async deadlock hazard)?

3. ⏳ Exponential Backoff & Jitter (Spec 15 / INV-1502):
   - Is backoff on reconnect to disconnected peers deterministic with jitter to prevent the thundering-herd effect (all nodes reconnecting at the exact same millisecond)?
   - Is there a fixed cap on retries so that disconnected nodes do not burn CPU in infinite loops?

4. 🧹 Task Leaks & Graceful Shutdown:
   - Are all Tokio background tasks spawned in the daemon (QUIC acceptor, flush worker, PeerManager, HTTP server, control server) guaranteed to be cancelled via the `CancellationToken`?
   - Can hanging connections or unfinished streams leave zombie tasks that accumulate RAM and sockets over weeks?

5. 📊 Output Format:
   - Identify the top risks for cascade failures and deadlocks.
   - Show the exact trigger (trigger chain: event A -> reaction B -> cascade C).
   - For each vulnerability found, provide the concrete mathematical / control-theoretic dampening solution (including Rust diff).
```
