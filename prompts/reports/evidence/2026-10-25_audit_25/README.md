# Audit 25 execution evidence

Reviewed HEAD: a41459aa120d730f7f99ea38450780b7a5f2df9d. Date: 2026-10-25 Europe/Berlin.

Temporary source: audit25_probes.rs (copied from the removed integration target).

Commands:

```bash
cargo test -p humoco-node --test audit25_probes -- --nocapture
cargo test -p humoco-node --lib network::framing::tests
```

probes.log: first sandbox run, three component successes and two listener permission failures; not product failure evidence.
probes_network.log: permitted local-listener run, four successes and a probe error expecting the wrong JSON field. Corrected only that observation assertion from node_signature/signature to server_signature.
probes_confirmed.log: final corrected observation suite, five successes. Three component observations and two actual TCP HTTP observations. Not a red-green implementation run.
framing_component.log: seven framing unit successes; no real receiver-side QUIC in this command.

No production fixes. Main agent runs shared full suite and Clippy. Concurrent unrelated storage changes were preserved; the auditor's temporary target was removed after this record was written.
