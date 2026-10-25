# Audit 19 — Wire-level quotas and adversarial verification

Date: 2026-10-25 (Europe/Berlin). Status: **3 open findings; no production fix**.

This is a fresh defensive source and coverage review. The 2026-10-24 Clean entry is historical context, not executed evidence. Source baseline: `a41459aa120d730f7f99ea38450780b7a5f2df9d`; other audit agents changed unrelated files during this review. No new attack/probe target was created. Findings below distinguish an established code defect, missing required evidence, and an unresolved design question. No successful on-wire quota bypass was reproduced in this run.

## Results

| ID | Priority | Finding | Evidence level |
| --- | --- | --- | --- |
| A19-01 | P2 | Receiver charges Byte-Years using the gateway's unvalidated wire lifetime, independently of the authenticated root used by storage | Confirmed source/data-flow defect; targeted wire reproduction remains required |
| A19-03 | P2 | Ordinary low-zone quota refusal increments peer presence failure state outside merge hysteresis | Confirmed source path; dedicated collector wire regression not executed |
| A19-02 | P2 | Specific receiver quota/whale/counter defenses lack the required real QUIC adversarial tests | Confirmed coverage gap in reviewed tests; not proof the implemented limits never reject |

A19-01 is rated P2 pending a complete receiver reproduction and impact assessment. This is not a claim of a demonstrated production exploit or unlimited admission: handshake, learned-peer authorization, readiness, queue bounds and signatures remain independent gates.

## A19-01 — Authenticate lifetime before calculating the recipient charge

**Normative requirement.** Spec 09, line 44, requires successor lifetime to derive from the authenticated Voucher Root Anchor. `docs/INVARIANT_REGISTRY.md:113` (INV-0901) explicitly requires that supplied shorter/longer successor TTL cannot evade/extend accounting. AGENTS.md rule 6 has the same root-derived Byte-Years requirement.

**Actual path.** `network/transport.rs:774–798` destructures `LockWirePayload::Hmc.root_valid_until`, subtracts the envelope timestamp, computes both integer Byte-Years and micro-Byte-Years, and multiplies by chain length. This is an unauthenticated lifetime assertion by the forwarding gateway: the gateway signs its resulting footprint, but that signature does not make the lifetime authoritative. `transport.rs:804` constructs and verifies the envelope against that same chosen footprint. `transport.rs:869` reserves `total_by` against the sender quota.

The subsequently invoked durable ingress does not receive that wire lifetime: the single-lock durable ingress call in the non-chain branch and chain call at `transport.rs:965` pass request/chain content into storage. `storage/engine.rs:69–139` registers authenticated root metadata; `engine.rs:217–247` resolves the entry lifetime from the stored root and enforces its time window. Thus correct storage TTL validation does not correct the earlier quota charge. The optional Byte-Years argument in the engine is metadata, not a second recipient quota check.

**Consequence supported by source.** A shorter envelope lifetime computes a smaller charge, down to zero with saturating subtraction, while a valid signed root/child can retain its actual longer lifetime. Nothing in this reviewed path checks wire lifetime equality with the root before quota reservation. The source establishes inconsistent accounting authorities; a positive/negative real-QUIC regression is still needed before claiming the complete bypass is experimentally established.

**Scope.** Both singleton and chain forwarding use this calculation. This is not the false-positive claim that `evaluate_node_write_quota` is absent; it exists and receives the wrong authority for its amount. A matching gateway signature, fresh timestamp, proper TLS identity and ready shard must all be included in the eventual reproduction. Unknown roots must continue to fail before durable mutation.

**Minimal remediation direction.** Resolve a validated root lifetime before footprint/signature/quota admission and derive one canonical amount from that lifetime and the admission-time snapshot. For an incoming chain, validate its root deed and causal relationships before it can supply the anchor. Reject a mismatching lifetime assertion, or eliminate its authority from accounting while keeping any wire compatibility decision explicit. Preserve reservation-before-mutation and durable-before-release. Do not silently change units, chain charging policy or signature domains as part of this isolated fix.

## A19-02 — Handler tests are not receiver QUIC proof

**Normative requirement.** AGENTS.md engineering rule 7 requires real QUIC adversarial verification. Spec 09 final section, Spec 13 section 8 and Spec 16 evidence rules require receiver-side limits and actual evidence, rather than relying on test naming or library assertions.

**Reviewed tests.** `phase4_net_time_and_quotas.rs:227`, `:402`, `:531` and `:716` cover declared-rate rejection, repeated 5x rejection, under-reporting and piggyback evidence. Their network-like requests are delivered using `handle_authenticated` (for example `:320`), not `QuicTransport::send_request`. They do not prove TLS identity extraction, connection authorization, frame admission or quota execution after actual stream dispatch. The repeated whale test sends an already excessive declaration; it is not a test consuming an initially available recipient daily budget through authenticated requests until the next request is refused. The status high-declaration test likewise does not establish recipient-side cumulative read exhaustion.

The inventories in the evidence directory locate all reviewed quota rejection assertions and QUIC fixtures. Actual QUIC exists elsewhere: `anti_self_slashing_wire_tests.rs:105` verifies conflicting approval protection, and phase11 covers other transport/committee properties. Those are valuable, but do not assert these quota boundary cases. Similarly, `chaos_wire_http_fuzz.rs:125`, `:199`, `:219` use byte buffers, cursors or Tokio duplex streams for malicious lengths/header fuzz/read timeout; they are not remotely executed server tests. Other suites must not be credited merely because they contain QUIC elsewhere in the same file.

**Impact.** A production quota amount error such as A19-01 can survive a green handler suite. The historical report correctly identified quota hooks and the HTTP/P2P tier distinction, but its Clean conclusion exceeds the mandatory evidence threshold: its own quota-wire enhancement is a required verification item under current AGENTS.md.

**Remediation direction.** Add bounded real loopback QUIC regressions for recipient write/read exhaustion, declared 5x limits, identity mismatch, malformed framing, and counter/reordering behavior under the current contract. Each must include a valid control request proving it reached the intended handler. Assert exact refusal and unchanged durable collision state where applicable; ordinary quota refusal must not alter presence, ban identity or expand the frozen committee. This is an evidence gap, not a justification to add HTTP PoW or friend bearer tokens to internal QUIC.

## A19-03 — Quota feedback still changes presence failure state

**Requirement.** Current Spec 09 §5.2 (`docs/09_netzwerk_thermometer_und_dynamische_quotas.md:120–128`) permits all three zones only as diagnostic/backoff input. It explicitly prohibits incrementing `missing_count`, suspending HRW eligibility or authorizing a ban based on a quota comparison. This prohibition is unconditional, including outside the merge grace period. Spec 13:104–106 and AGENTS.md local-autonomy rules agree.

**Actual path.** `api/routes.rs:1240–1270` handles `PeerQueryResult::QuotaExceeded`, compares `my_load` against `quota_limit`, and classifies the lowest zone as `FraudulentRejection`. Outside `is_in_merge_hysteresis`, a rank below 20 calls `record_failure(addr)` at `:1266`. `network/manager.rs:1883–1896` forwards that into `PeerInfo::mark_failure_at`; `network/peer.rs:129–143` increments `missing_count` subject to a ten-second debounce, eventually suspends the peer and removes its connection at the failure threshold. Thus ordinary refusal changes the very failure/presence state forbidden by the current norm. No permanent cryptographic ban is asserted here.

**Evidence boundary.** This is an exact source-to-spec discrepancy in the live collector's response processing, not a newly executed on-wire suspension reproduction. Debouncing reduces the increment frequency; it does not make the event neutral. Existing moratorium suppression covers only the merge interval and therefore does not satisfy the unconditional contract.

**Remediation direction.** Remove quota-derived `record_failure` in every zone, preserving bounded pacing/diagnostic logging and the frozen committee. Use neutral terminology instead of implying cryptographic fraud from the local load comparison. Verify unchanged `missing_count`, peer status and eligibility after legitimate quota feedback both inside and outside merge hysteresis. Do not conflate this with genuine independently verified equivocation or missed hourly heartbeat handling.

## Requirement-to-path/test map

| Requirement | Actual implementation reviewed | Existing evidence and limit |
| --- | --- | --- |
| P2P is learned-node infrastructure, separate from public PoW/tokens | QUIC handshake/peer manager authorization; `transport.rs:743` TLS sender check | Existing QUIC authorization fixtures; no finding that HTTP PoW must exist here |
| Declared 5x write brake | `transport.rs:641–655` | phase4 handler rejection only for quota case |
| Per-sender receiver write reservation | `transport.rs:863–881`; daemon attaches controller at `daemon.rs:550` | Hook exists; lifetime amount defective (A19-01), real quota regression absent |
| Read 5x and recipient credits | `transport.rs:1282–1299`, `:1430–1446` | Hook exists; phase4 declared-rate case is direct handler execution |
| Envelope signature and sender binding | `transport.rs:743–815`, `:1301–1372` | Handler negative evidence; no assertion that signature verification alone authenticates root TTL |
| Counter evidence | `transport.rs:830–860`, `:1376–1406`; core `fraud.rs:862–978` | phase4 checks existing legacy behavior; exact restart/reorder/counter semantics remain a Spec 10 integration obligation |
| Bounded allocation/read deadlines | `framing.rs` bounded reader; transport uses `read_frame_admitted` at `:2865`; stream/connection semaphores at `:2097–2100` | Buffer/duplex tests exist; no unconditional end-to-end resource-exhaustion guarantee |
| Durable-before-vote | durable ingress then original-approval retention in LockVerify path | Existing real anti-self-slashing QUIC test is separate from quota evidence |

## Open questions, not additional confirmed findings

1. **Identity bucket isolation.** `ingress/tier.rs:500` and `:522` truncate a P2P sender key to its first 16 bits; `quota.rs:440–441` stores daily counters by `NodeId`. Two different full keys with the same prefix therefore share counters. The effect is clear from source, but the current reviewed numeric quota specs do not explicitly settle whether prefix bucket contention is an allowed local admission limit or a forbidden loss of per-identity isolation. AGENTS.md defines NodePubKey as the identity; formalize the quota isolation contract and add a two-key receiver test before counting an independent protocol defect. This is distinct from intentional public HTTP client buckets.
2. **Current vs historical counter sanction rules.** Spec 10 explicitly rejects simplistic timestamp/reordering-based fraud conclusions and marks exact shared semantics as an integration gate. Legacy handler tests expect immediate bans. This review does not establish a new remotely demonstrated framing attack or resolve the shared K2 contract. Do not add new slashing expectations just to match the old prompt; test legitimate reordering/restarts as well as authentic incompatible statements.
3. **Full resource audit.** No load/capacity measurement, packet capture, resumed-session/0-RTT experiment or exhaustive invariant proof was performed. Presence/ticket/authority and HTTP PoW are covered by other audits; Audit 25 overlaps only in the broader admission/evidence requirement.

## Executed validation and limitations

- `cargo test -p humoco-node --test phase4_net_time_and_quotas -- --nocapture`: **8 passed, 0 failed**, 0 ignored. These results establish handler/core checks only.
- `anti_self_slashing_wire_tests`: first attempt could not bind loopback UDP (`EPERM`). That result is environmental and provides no red security regression. The authorized loopback repeat **passed: 1 passed, 0 failed**, proving the existing conflicting-approval scenario only; raw output is in `anti_self_slashing_wire_unrestricted.log`.
- Full workspace standard tests, formatting and Clippy are performed once by the parent coordinator to avoid simultaneous competing suite runs. They are not claimed as completed here.

Evidence directory: `prompts/reports/evidence/2026-10-25_audit_19/`, including exact commands, logs and source search inventories. No production code or shared registry was edited by this audit. No finding is closed by a green existing suite; A19-01 still needs the targeted red/green wire evidence specified in the separate plan.

## Shared coordinator validation

The complete shared standard run finished with **708 passed, 5 failed, 14 ignored**
(exit 101). Four failures belong to the concurrently added Audit23 regression target;
one quorum assembly test received 503 instead of 200/201. Formatting check failed on
existing source differences; Clippy stopped at compiler E0505 in concurrently edited
`storage/db/signing.rs:203`. No clean release claim is made. Full commands, provenance
limits and raw logs are recorded in
[evidence/2026-10-25_audits_19_25_shared/README.md](evidence/2026-10-25_audits_19_25_shared/README.md).
