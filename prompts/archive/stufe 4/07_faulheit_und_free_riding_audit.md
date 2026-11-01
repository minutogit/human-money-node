# Audit 07 — Laziness and free-riding

2026-10-25 · Stage 4 · Commit `9a28517d0a02e34721c102bccbf786b8443c3664` · Source: `/home/basti/Coding/humoco/human-money-node`.
Audit only. Paths below are relative to that root. No additional runtime vulnerability was established; two audit/verification defects remain.

## Findings

- **A07-01 [LOW] — The old prompt demands sanctions that current specifications forbid.** `prompts/07_faulheit_und_free_riding_audit.md:22` demands ingress revocation below 80% validation, `:26` expects suspension for missing storage answers, and `:38` suggests automatic revocation. Current `docs/17_topologie_telemetrie_und_social_defense.md:98` explicitly treats 80% as a diagnostic example; INV-1701/1703 and `docs/13_client_ingress_und_access_tiering.md:117` separate diagnostics, passive presence and authorization. Following the old prompt literally would introduce unsupported sanctions and committee drift. This is prompt drift, not evidence that such sanctions should be added.
- **A07-02 [LOW, coverage gap] — The neutral-quota regression does not execute the collector.** `crates/humoco-node/tests/audit19_regressions.rs:449` constructs a PeerManager, calls the pure quota-plausibility helper and then checks that the untouched PeerManager's counter remains unchanged. It neither feeds a response through `collect_peer_attestations` nor traverses QUIC. Consequently this test alone would not catch reintroducing `record_failure` in the collector's quota branch. Existing receiver-side QUIC tests cover other quota properties; this finding concerns this specific assertion.

## Integrated fix plan

1. **A07-01:** Rewrite the historical prompt against INV-0909, INV-1306/1307 and INV-1701–1705 before reuse. Require bounded offered load, neutral explicit refusals, separate heartbeat presence, verified distinct quorum signatures and first-party sanctions. Treat operator service diagnostics and storage availability as observations; require a protocol argument before proposing any new punishment. Remove the unconditional “mathematically unprofitable” claim.
2. **A07-02:** Replace/supplement the vacuous test with a production collector scenario against authenticated QUIC peers. Return `FLAG_QUOTA_EXCEEDED` below, around and above quota-comparison boundaries; verify unchanged failure counters, authorization and committee selection, including merge hysteresis. Add NOT_READY and quorum-cancellation controls; legitimate refusals must stay neutral, while forged signatures must not count.
3. Re-run targeted wire regressions and `cargo test-std` after any future fix. Shared runtime findings A02-02 and A20-01 retain their plans in their respective audit files and are not counted again here.

## Checked behavior and evidence limits

- **Silent signer:** collector requires actual verified eligible signatures, exits on sufficient quorum and does not invent replacement voters (`api/routes.rs:1117`, `:1194`; frozen membership in `network/manager.rs:2078`). Missing participation may prevent progress; unconditional honest participation is not proved.
- **Storage leech:** frozen snapshot/digest support, staged transfer and readiness checks exist (`network/transport.rs:1835`, `:1848`; `daemon.rs:1184`). Authenticated reports are not a universal proof that every peer retains all required state; G2/G3 remain qualified.
- **Latency/drop excuses:** current quota responses and NOT_READY remain neutral (`api/routes.rs:1241`). A component probe applied three debounced transport failures to a mature, fresh known peer: address diagnostic suspension `true`, HRW candidates unchanged `true`, direct RPC authorization `true`, global ban `false`. This probe exercised public PeerManager methods, not QUIC.
- **Empty certificates/bitmap tricks:** collector deduplicates full signer identities and verifies context/signatures (`api/routes.rs:1171`, `:1185`); bitmap generation derives positions from the frozen committee (`:757`). Shared `../humoco-proto/src/verify.rs:23` rejects empty/infeasible committees, insufficient votes, duplicate signers and invalid signatures. That dependency's standalone unit suite was not separately run.

Standard workspace suite: **755 passed, 0 failed, 14 ignored**, exit 0. This does not establish universal incentive compatibility, measured 100-node availability or complete storage-custody proofs.
