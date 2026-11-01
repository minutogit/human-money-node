# ⏰ AI Audit Prompt: Time-Warp, Clock Manipulation & Pruning Attacks

> **Doctrine (Spec 07, 12):** *"In distributed systems there is no global clock. Time must never be trusted blindly from the operating system — it must be disciplined by the F2F median."*

---

## 🎯 Goal of This Audit
Examine the system for **clock drift, NTP hijacking, time-warp attacks, and malicious premature TTL pruning**. Determine how attackers can delete locks or break ingress windows by manipulating local or relayed timestamps.

---

## 📋 Prompt Text to Copy / Run:

```markdown
You are a specialist in distributed time synchronization, clock-skew attacks, and deterministic timestamp validation.
Your task is the time-warp and clock audit for HuMoCo Layer 2 (Spec 07, 11, 12, 14).

Analyze the codebase against the following 5 time-manipulation scenarios:

1. ⏩ Premature pruning via clock fast-forward (premature deletion attack):
   - A malicious node manipulates its system clock and advances it by 1 year.
   - The node then calls `prune_expired(now)`: Does it prematurely delete valid locks from its database?
   - What happens when an honest neighbor attempts to sync from this node? Does the honest node pull the deleted state or detect the time divergence?

2. 🕰️ F2F median clock protection (Spec 07 / INV-0701):
   - How does the node compute its effective consensus time?
   - Does the node rely exclusively on `std::time::SystemTime::now()` (insecure!) or does it filter local timestamps against the median of its F2F neighbors?
   - Is a neighbor whose clock deviates by more than 45s warned or ignored in gossip (Spec 17)?

3. 🪟 Ingress window bypass (INV-1202):
   - Ingress condition: `now + 30s < valid_until <= root.valid_until`.
   - Can an attacker inject locks with forged client timestamps that are either already expired or far in the future?
   - Is the 30s buffer check robust against millisecond overflows?

4. 💤 Dormant locks & TTL reanimation:
   - What happens when an expired lock (after `root.valid_until + 30s` grace period) is resubmitted?
   - Does the system reliably prevent an old, purged lock from being reborn as a "new lock"?
   - Why does the fixed expiry date in the root certificate (`root.valid_until`) of the `ProofChain` protect against any reanimation?

5. 🛠️ Concrete hardening measures:
   - Identify every location in the code where unsanitized system time is used.
   - Provide code patches for F2F median time reconciliation and strict time-window validation.
```
