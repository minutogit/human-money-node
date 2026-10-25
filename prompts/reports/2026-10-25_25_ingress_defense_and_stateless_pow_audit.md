# Audit 25 — Ingress defense and stateless PoW

Date: 2026-10-25 (Europe/Berlin). Reviewed HEAD: `a41459aa120d730f7f99ea38450780b7a5f2df9d`.
Status: **5 open findings**; no production fixes performed by this audit.

## Scope and authority

Read AGENTS.md, the complete audit prompt, current Specs 09, 10 and 13 and relevant invariant-registry entries. Reviewed HTTP routing/admission, token provisioning, daemon tier initialization, PoW verification, accounting calls and binary framing. Current Spec 13 explicitly requires the direct single-domain puzzle and forbids mandatory used-solution state; these findings do not rely solely on a stale formula in AGENTS.md. Historical Clean labels are not evidence.

This is an independent review, not a proof of the entire ingress boundary. Concurrent unrelated changes to storage files were observed and preserved. No production file was modified by this auditor. The temporary test target was removed after preserving its source and logs.

## Findings

### A25-01 — P2: Implemented work format differs from the selected puzzle and accepts generic work for nonzero parents

Locations: `crates/humoco-node/src/ingress/pow.rs:27`, `:38`, `:242`.

Spec 13 section 4 requires `BLAKE3(len(domain) || HUMOCO_V1_POW_STATELESS || parent || slot || nonce)`, explicitly without a second HUMOCO_POW_SOLUTION domain. Production hashes parent/slot first and then hashes the challenge/nonce under that second domain. Consequently a client following the selected protocol can provide valid canonical work that production rejects. In addition, the parent verifier accepts generic zero-parent challenges even when a concrete nonzero parent is expected.

Executed component evidence: at explicit time 6000 seconds and difficulty 8, canonical nonce 867 satisfies the selected direct puzzle, whereas production rejects it with `InsufficientDifficulty { required: 8, provided: 2 }`. A solved generic challenge was accepted for parent `[2;32]` on one engine and parent `[9;32]` on an independent engine. This demonstrates work-context transplant at the component boundary. It does not demonstrate a double spend, forged lock signature or full cross-gateway checkout; the existing per-engine replay cache restricts repeat use on one engine.

Mitigation: implement one shared canonical parent/slot/nonce hashing function and matching solver. Retain bounded wire metadata only as required for compatibility; never treat a generic challenge as concrete-parent work. Define genesis work binding consistently in the shared client/server contract. Update consumers together and keep the justified time-window policy explicit.

### A25-02 — P2: Mandatory replay map breaks stateless admission and rejects repeated identical work

Locations: `crates/humoco-node/src/ingress/pow.rs:90`, `:262–273`; public admission at `crates/humoco-node/src/ingress/tier.rs:768`.

Every valid challenge/nonce is inserted into `seen_solutions`. Repeating the exact same work returns ReplayDetected. Spec 13 forbids a mandatory seen-solutions table and permits exact retries subject to ordinary time/difficulty/rate limits. The map also has no live-entry cap: the 10000 threshold starts expiry scanning, not admission limiting. Once more than 10000 still-live entries exist, each additional accepted solution scans them while holding a global mutex. This contradicts bounded constant-work verification and creates a load-amplification risk.

Executed component evidence: first verification succeeds and the unchanged second verification returns ReplayDetected. Memory growth and CPU saturation were not benchmarked. A non-genesis full HTTP exact-retry failure was not reproduced; genesis has a separate early durable-idempotency shortcut, and an existing genesis-only retry test therefore does not cover this issue.

Mitigation: remove mandatory solution storage after establishing parent-bound canonical work. Preserve durable exact-lock idempotency and bounded admission/rate protection separately. Keep live-proof recipient nonces as their separate protocol purpose; do not remove those replay protections.

### A25-03 — P2: P2P peer configuration is copied into HTTP friend credentials

Locations: `crates/humoco-node/src/daemon.rs:442–446`, `crates/humoco-node/src/config.rs:235`, `crates/humoco-node/src/ingress/tier.rs:550`, `:581`; operator custom input at `crates/humoco-node/src/api/dashboard.rs:1216`.

Daemon startup registers every `config.f2f.peers` string as an HTTP friend token. The same configuration parser explicitly supports bare hex/base58 NodePubKeys. The credential registry accepts arbitrary strings, and operator custom token provisioning likewise lacks the required random-secret format restriction. Thus a legitimate P2P-only configuration can silently grant public HTTP PoW exemption using a public identity or endpoint string.

Executed evidence: the HTTP fixture performs the same `register_f2f_peer(public_key_hex)` call as daemon startup and submits a root through a real local TCP HTTP listener with that public key in X-Peer-Token. Result: **201 Created without PoW**. This is a combination of daemon code tracing and an HTTP tier reproduction, not a complete daemon-boot test. The existing token-origin test only tests an unregistered key and cannot detect this case.

Mitigation: stop registering P2P peer strings as ingress credentials. Keep a dedicated client-secret source, validate `f2f_` plus 32 hex digits at all provisioning boundaries, generate 16 random bytes by default, and fail clearly on invalid legacy client credentials. Do not alter P2P friendship for client credential changes.

### A25-04 — P2: Unadmitted HTTP requests trigger asymmetric signing and can reach blocking root reads

Locations: `crates/humoco-node/src/api/routes.rs:406`, `:745`, `:1898`, `:2043`; signing implementation `crates/humoco-node/src/api/hmc.rs:831`.

The lock route parses its bounded JSON before admission and performs root-dependent validation before validating work. The helper named fetch_remote_voucher_root actually executes a synchronous redb `voucher_root` lookup; it does not make a remote RPC. An unknown-root spend without a supplied TTL reaches this disk path before credential verification. Multiple early failures, including the ordinary missing-work 401, call wrap_and_sign_verdict, which performs Ed25519 signing. An anonymous caller can therefore request asymmetric operations without paying the work barrier. No public lock route burst limiter was found in the inspected router/admission path.

Executed evidence: **32 real HTTP requests without credentials or work each returned 401 with a server_signature**. This establishes asymmetric signing before successful admission. It is not a CPU saturation, disk-latency or sustained DoS measurement. The blocking disk path was established by code inspection, not by tracing a live disk operation. JSON is capped at 64 KiB, so an unbounded JSON allocation exploit is not established.

Mitigation: introduce bounded early request admission, parse only bounded fields needed for work/token context, authenticate work/credentials and reserve capacity before disk/expensive crypto. Return a lightweight unsigned structured rejection before admission; signatures remain required for admitted binding receipts. Move necessary disk work to the managed blocking/storage path. Apply the same ordering to aliases and chain endpoints.

### A25-05 — P2: Public admission ignores the daily-quota rejection result

Locations: `crates/humoco-node/src/ingress/tier.rs:755–760`, `:766–773`.

Both public branches ignore the bool returned by `thermo.try_accept_lock`. With valid work, evaluation still records ingress and returns Tier3Public after the quota check rejects. The zero-difficulty branch has the same defect. Increasing difficulty does not enforce a hard quota.

Executed component evidence: at a 960000 Byte-Year daily quota, a valid-work admission requiring 1152000 Byte-Years returns `Ok(Tier3Public)`. The fixture uses a synthetic 6000-year TTL to cross the threshold in one call. **This is not evidence that such a TTL passes full authenticated-root HTTP ingress.** A regular-life accepted-root sequence exhausting the daily limit remains required. The ignored boolean is a confirmed code defect independently of that end-to-end evidence gap.

Mitigation: inspect the quota result under the same thermometer lock and return structured QuotaExceeded when false. Increment accepted counters and accepted-load accounting only according to the selected accounting contract. Check all public branches, including explicitly configured zero difficulty; add full HTTP coverage using authenticated valid roots and realistic lifetimes.

## Checks and evidence limits

- `cargo test -p humoco-node --test audit25_probes -- --nocapture`: final confirmed run **5 passed, 0 failed**; three component probes and two real local TCP HTTP probes. These are observation tests asserting current behavior, not completed red-green fix regressions.
- `cargo test -p humoco-node --lib network::framing::tests`: **7 passed, 0 failed**. This is component framing coverage, not receiver-side QUIC evidence.
- Initial sandbox execution: 3 component probes passed, 2 HTTP binds failed with PermissionDenied. These environment failures are not findings. A subsequent permitted run exposed a probe assertion using the wrong JSON signature field; the probe was corrected to server_signature and rerun. Both logs are preserved, not presented as product regressions.
- Static framing review: 64 KiB cap is checked before body allocation; fixed-header decoding uses explicit safe endian conversions; timeout covers header and body; admission permits are acquired before allocation. No confirmed allocation exploit was found. No new receiver-side malformed-frame, truncated-frame or over-quota QUIC test was executed in this audit. Existing test names alone do not establish that protection.
- Status fallback selects one candidate from up to 20 using a deterministic tag-derived index. This review did not establish uniform distribution, full committee eligibility correctness, burst-rate enforcement or measured sub-microsecond service.
- GET pow-challenge returns baseline difficulty; admission uses dynamic difficulty. Exact feedback/client retry behavior needs separate validation.
- EMA code uses elapsed seconds and u128 intermediates in Byte-Years conversion. This is not exhaustive overflow/fuzz verification. Extreme u64 TTL conversions and publication counters remain candidates for focused boundary tests, not additional confirmed network exploits.
- Scope overlap: Audit 19 owns receiver-side root-derived footprint and quota accounting. Do not count this public admission boolean defect as evidence for its separate wire TTL finding.
- Full workspace suite and Clippy were intentionally delegated to the parent for one shared final execution. No clean release or whole-system DoS resilience claim is made.

Evidence directory: `prompts/reports/evidence/2026-10-25_audit_25/`.
Separate implementation plan: `2026-10-25_25_ingress_defense_and_stateless_pow_fix_plan.md`.

## Shared coordinator validation

The complete shared standard run finished with **708 passed, 5 failed, 14 ignored**
(exit 101). Four failures belong to the concurrently added Audit23 regression target;
one quorum assembly test received 503 instead of 200/201. Formatting check failed on
existing source differences; Clippy stopped at compiler E0505 in concurrently edited
`storage/db/signing.rs:203`. No clean release claim is made. Full commands, provenance
limits and raw logs are recorded in
[evidence/2026-10-25_audits_19_25_shared/README.md](evidence/2026-10-25_audits_19_25_shared/README.md).
