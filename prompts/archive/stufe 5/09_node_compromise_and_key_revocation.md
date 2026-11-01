# Audit 09 — Node compromise and key revocation

Date: 2026-10-25. Snapshot: `9a28517d0a02e34721c102bccbf786b8443c3664`. All probes used disposable identities/storage under `/tmp`; no real identity was revoked and no production files were modified.

## Findings

**A09-01 · P2 · The CLI's claimed network revocation is not implemented by acceptable evidence.** `crates/humoco-node/src/cli.rs:2025–2133` generates two simulator `sign_heartbeat()` messages using a 16-bit node ID, creates a `HeartbeatSpam` proof, optionally writes the local database and prints “PERMANENT BANNED & WoT SEVERED.” It neither sends this proof to peers nor drains the running daemon or removes the key. The simulator signatures are BLAKE3, not the stolen identity's Ed25519 signatures (`humoco-sim-core/src/fraud.rs:48–63`), and production deliberately rejects this proof family (`network/transport.rs:148–152`). Its inferred perpetrator key also differs from the actual identity.

A probe executed the CLI against a fresh temporary identity, read its stored proof and submitted those exact bytes to a real QUIC peer. Observed: `local_ban=true`, `strict_valid=false`, `perpetrator_matches_key=false`, `key_present=true`, `remote_ban=false`. The safe-behavior assertion failed. The peer's rejection is correct anti-framing behavior; weakening it is not a fix. Local shutdown/deleting one key copy cannot revoke an attacker's stolen copy.

**A09-02 · P2 · Revocation reports success even when the local ban was never written.** The same function silently ignores database-open/write failures at `cli.rs:2107–2115`. Holding the temporary database open, as an active daemon would, then calling `execute_revoke(..., DELETE)` returned success while `is_node_banned()` remained false. The safe-behavior assertion failed. A running-daemon control operation and durable acknowledgment are missing; this is distinct from the invalid remote evidence in A09-01.

Containment boundary: node keys sign node attestations/TLS, not voucher-holder authorization. The blind lock DTO contains no amount/balance, but does contain pseudonymous identifiers and signatures; theft is not zero metadata exposure. Under signature unforgeability and correct recipient L1/causality validation, possession of the node key/database alone does not yield a holder's private key or authorize an arbitrary transfer. This is not an unconditional zero-financial-loss theorem: captured quorums, small meshes, censorship and false clearance remain separate risks (Audit 10).

At rest, a newly created key passed an explicit POSIX **0600** and save/load probe. The 80-byte format is plaintext; 0600 does not stop root or protect stolen backups. Optional passphrase encryption may help an offline theft model but cannot protect a live unlocked process from root. A complete incident-response/encryption feature is outside this audit.

Genuine same-slot double-signature evidence is accepted and forged/cross-network evidence is rejected in the existing real-QUIC test `test_phase11c_adversarial_tls_close_and_fake_fraud_rejected_wire` (passed). This does not prove global detection in seconds: evidence must reach honest peers, forwarding is bounded/best-effort, and local edge removal scans peer entries. Audit 10's lost durable-ban finding also limits restart containment.

## Integrated fix plan

1. Make CLI output truthful immediately: distinguish local drain/ban, durable completion and submitted/observed remote revocation. Return storage/control errors; do not claim irreversible global success from a local best-effort write.
2. Route active-daemon revocation through the authenticated local control socket, durably record the local state, stop signing and drain resources. Preserve a safe offline path for an unlocked database. Test both paths, failures and restart behavior with disposable identities.
3. Specify a genuine full-key, network-bound self-revocation predicate and transport it within the existing authenticated evidence stream, with replay/anti-framing rules and receiving-side persistence. Until that protocol exists, remove the network-revocation promise. Never accept simulator timing evidence or ban foreign keys on an operator's assertion.
4. Preserve both failed probes as regression tests, including actual peer receipt, copied-key attempts, wrong-author/domain proofs, database locking/failure and durable reload. Retain the genuine/forged proof tests and close Audit 10's persistence gap.
5. Document operator recovery: isolate the compromised host, stop local service, notify/reconfigure direct peers through authenticated operator procedures, and restore service under an explicitly new identity where appropriate. Key replacement does not retroactively invalidate stolen credentials; optional encrypted backup storage has a separate threat model.

## Validation boundary

The prescribed standard suite ran in the isolated snapshot with a 240-second external limit: `timeout 240s env CARGO_TARGET_DIR=/home/basti/Coding/humoco/human-money-node/target cargo test-std --no-fail-fast`. It ended with exit 124 while `inherited_support_tests` was unfinished. Completed targets reported **326 passed, 0 failed, 0 ignored** across 27 result summaries; five visible passes in the unfinished target are not included. This is an incomplete baseline, not a clean full-suite result. Existing causality (7/7), current-proof boundaries (3/3), and anti-self-slashing wire coverage (1/1) passed during that run. The separately targeted genuine/forged-proof QUIC test passed 1/1.

Additional safe-behavior probes were written and executed exclusively in `/tmp/humoco-stufe5-audit/human-money-node/crates/humoco-node/tests/stufe5_probes.rs`; their expected assertion failures establish the reported open findings. No additional tests/mutations were installed in the repository. This single file contains the finding and integrated fix plan for its audit; the registry and pre-existing deleted report files were left untouched.
