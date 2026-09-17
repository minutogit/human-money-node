# 🦥 AI Audit Prompt: Laziness, Free-Riding & Asymmetric Leeching

> **Doctrine (Spec 03 & 17):** *"Those who do not work shall not lock. Ingress rights must be earned through continuous consensus participation in the shard."*

---

## 🎯 Goal of This Audit
Examine the system for **node laziness (lazy node problem), Free-Riding, and asymmetric leeching**. Find ways in which malicious or negligent operators save server resources (CPU, RAM, bandwidth) at the expense of the network while retaining full benefit.

---

## 📋 Prompt Text to Copy / Run:

```markdown
You are a game theorist and protocol auditor specializing in Free-Rider problems in P2P networks.
Your task is the lazy-node and Free-Riding audit of the HuMoCo Layer 2 codebase (Spec 03, 09, 13, 17).

Examine the code for the following 5 leeching and laziness patterns:

1. 😴 The Silent Signer (Validation Free-Rider):
   - A node diligently accepts lock fees and ingress requests from its own merchants but ignores LockVerifyRequests from other shard candidates (to save signature CPU).
   - Check: Does Spec 17 trigger (validation rate < 80% revokes ingress rights)? Can a node game the system by serving only friendly nodes?

2. 🕳️ The Forgetful Storage Leech (Storage Leech):
   - A node stores only its own customers' locks and immediately deletes foreign locks from RAM/redb to save RAM.
   - Check: What happens when neighbors request a sparse sync or digest pull? Is a node that consistently answers "Not Found" detected and suspended?

3. 🐌 Faked Latencies & "Fast-Drop" Excuses:
   - A node fakes artificial latency or drops foreign gossip heartbeats under the pretext of network congestion to save bandwidth.
   - Check: Does the Dunbar topology detect asymmetric edges (Spec 11 / RED dampening)?

4. 📉 Empty Certificates & Bitmap Tricks:
   - Does a node attempt to submit quorum certificates without contributing valid signatures itself?
   - Are signer bitmaps cryptographically validated against the actual public keys?

5. 💡 Concrete Hardening Measures:
   - Uncover loopholes where laziness is economically or technically profitable.
   - Provide code fixes that make laziness mathematically unprofitable (proof-of-validation / automatic ingress revocation).
```
