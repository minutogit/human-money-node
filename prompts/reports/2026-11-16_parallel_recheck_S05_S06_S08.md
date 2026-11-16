# Parallel follow-up audit: S05, S06 and S08

Date: 2026-11-16. Reviewed revision: `073adb64fc7b202310835d537215bac87393131e`.
Initial working tree: clean.

Exactly three agents each executed `prompts/AUDIT_LOOP.md` once for one distinct
Priority 2 ReCheck slice, in slice order: S05, S06 and S08. The coordinator
independently checked findings and repeated the component/router/QUIC probes.
Only the three selected ledger rows were updated centrally. No file under
`crates/` was changed; no production fix or permanent regression was added.

## Results

| Slice | New verified findings | Clean_Streak | Total_Finds | Last_Run | Status |
| --- | --- | ---: | ---: | --- | --- |
| S05 | S05-20, Medium | 0 | 20 | 2026-11-16 | `Fix_Open` |
| S06 | S06-17, Medium; S06-18, Medium | 0 | 18 | 2026-11-16 | `Fix_Open` |
| S08 | S08-17, Medium | 0 | 17 | 2026-11-16 | `Fix_Open` |

Four new findings. Previously repaired findings were reviewed and not counted
again. All other ledger rows were preserved.

## Verified findings and evidence

### S05-20 — Present but invalid admission inputs reach root lookup and signing

AGENTS Rule 6 and Spec 13 section 4 require cheap admission filters before disk
and asymmetric signing. At `crates/humoco-node/src/api/routes.rs:2524`, the
single-lock handler checks only credential/work header presence. Actual tier
validation at `:2732` follows unknown-root handling at `:2605` and a signed
HTTP 400 response at `:2609`. Root fallback at `:755` performs a bounded redb
read through `spawn_blocking` at `:768` when a permit is available.

The external router probe `/tmp/humoco_s05_20_filter_probe.rs` independently
rejects its VIP secret and parent-/slot-correct insufficient work through the
underlying validators, then submits unknown-root requests. A closed root-read
semaphore and captured tracing make root-fallback entry observable. The probe
cryptographically verifies the returned server signature. Results, repeated by
the coordinator:

```text
missing: status=401, root_lookup_attempted=false, verified_server_signature=false
invalid_vip: status=400, root_lookup_attempted=true, verified_server_signature=true
invalid_friend: status=400, root_lookup_attempted=true, verified_server_signature=true
unsolved_pow: status=400, root_lookup_attempted=true, verified_server_signature=true
```

This demonstrates fallback reachability and signature work; actual disk I/O in
the available-permit branch is source-verified, not exercised by this probe.
No successful lock admission or quorum bypass is claimed. Existing missing-
credential regressions do not exercise present-but-invalid credentials.

### S06-17 — Offline annual expiry does not deactivate a configured friend

Spec 07 section 4 / INV-0705 requires explicit operator reactivation after the
direct friendship inactivity window. At
`crates/humoco-node/src/network/manager.rs:1600`, startup skips an observation
older than its retention window without deactivating the configured friend.
The runtime prune at `:4337` only considers `known_network_nodes`, which no
longer contains that friend. Importing already persisted deactivation records
in `daemon.rs:628` cannot repair an expiry that first occurs while offline.

The external current-library probe `/tmp/humoco_s06_20261116_probe.rs` stores
a qualified friend observation with last-seen 366 days ago, then executes
production observation restoration, deactivation restoration and pruning.
Both agent and coordinator observe:

```text
STARTUP_EXPIRED friend=true gossip=true db_deactivated=false known=false
```

The prior S06-16 regression deactivates the friend before restart, so it does
not cover crossing the boundary while offline. This is a distinct missing
startup transition, not a recount of the repaired live-pruning defect.

### S06-18 — Relayed self-presence double-counts the local identity

`crates/humoco-node/src/network/manager.rs:4222` adds the mature local ticket to
known eligible identities without excluding a learned local identity;
`mature_network_size` at `:4227` and `total_network_size` at `:4239` have the same issue. The real heartbeat receive
path admits a genuine local-origin heartbeat relayed by an authenticated F2F
friend. In contrast, `shard_committee` excludes the local key from remote
endpoints at `:3817` before adding it once.

The receive checks are at `network/transport.rs:4365–4386` and learning at
`:4502`. The existing S06-16 direct-heartbeat attempts use hops 1, which can
independently fail hop validation; their positive known-entry check does not
prove fresh heartbeat acceptance. This is an uncounted test-quality observation;
the maintenance prompt requires a genuine state change and direct hops 0.

The same external probe delivers an origin-signed local heartbeat through two
real QUIC endpoints, using a friend as transport sender, hops 1 and TTL 1.
Simulation mode accelerates ticket age; it does not replace the transport.
Both agent and coordinator observe:

```text
BEFORE_LOOP active=19 unique_committee_total=19
AFTER_LOOP known_self=true active=20 mature_size=20 unique_committee_total=19 stability_initial=false stability_after24h=true
```

The finality hysteresis at `manager.rs:4291` can therefore pass its population
condition with only 19 distinct identities. The probe advances the explicit
hysteresis time argument; it does not wait 24 hours or demonstrate release of
a FINAL signature, quorum bypass or double-spend.

### S08-17 — Saturation before division understates hourly averages

Spec 09 lines 74–76 require the unweighted aggregate of recorded hourly slots.
At `crates/humoco-sim-core/src/quota.rs:456`, `rolling_24h_average` divides the
already saturated public sum (`:451`). Two or 24 slots containing `u64::MAX`
have a representable average of `u64::MAX`, but the implementation returns
`u64::MAX / 2` or `u64::MAX / 24`.

The agent reproduced this against the current compiled library. The
coordinator independently compiled and ran
`/tmp/humoco-audit-2026-11-16-average.rs` against the current library:

```text
slots=1: observed=18446744073709551615, expected=18446744073709551615
slots=2: observed=9223372036854775807, expected=18446744073709551615
slots=24: observed=768614336404564650, expected=18446744073709551615
```

No daemon runtime caller of this exported executable-specification type was
found. No production quota or QUIC consequence is claimed. Existing small-
range property tests derive their comparison from the already narrowed sum.

## Coverage and previous repairs

- S05: all four target files, direct ingress/HTTP, credential, accounting,
  quota/EMA, persistence and crypto callers. S05-19 domain hashing is repaired
  consistently across the four production paths; its regression passes.
- S06: all five target files and direct transport, daemon, database, clock,
  ticket/presence and authorization callers. S06-14 bounded evidence admission
  and S06-15 autonomous retry are repaired. Obsolete identity-as-ticket learning
  wrappers and the unauthenticated production TLS test builder are removed.
- S08: all existing target files (`quota.rs`, `storage.rs`, `client_flow.rs`)
  plus direct HRW/time, tier and daemon integrations. S08-16 delayed merge
  reseeding is repaired and has real-QUIC coverage. Historical `ceh/`, `p0/`,
  `state_machine.rs` and `transport.rs` targets remain absent; the inherited
  ledger scope limitation is not counted as a code defect.

No additional verified compatibility shim requiring deletion was identified.
The audit-only scope defers production changes to the maintenance task.

## Validation

- `cargo clippy --workspace --all-targets -- -D warnings`: passed, exit 0.
  Log: `/tmp/humoco-audit-2026-11-16-clippy.log`.
- Initial sandboxed `cargo test-std`: 213 node library tests passed; three
  failed on local QUIC socket binding with `EPERM`. This is an environment
  restriction, not a code finding. Log:
  `/tmp/humoco-audit-2026-11-16-test-std.log`.
- Full socket-enabled `cargo test-std`: passed, exit 0; 89 result groups,
  **896 passed, 0 failed, 14 ignored, 0 filtered out**. Log:
  `/tmp/humoco-audit-2026-11-16-test-std-network.log`.
- Focused agent checks: nine `audit25_regressions` tests and the S05-19
  regression; 56 network library tests; 44 core library, eight S08 regression
  and 13 Spec 09 tests passed. These overlap the full suite.
- External probes used unchanged compiled libraries. They demonstrate the
  observed defects, not passing regressions for the expected behavior. Probe
  files under `/tmp` are temporary evidence, not future test dependencies.
- No ignored deep simulations were run. Existing passing tests do not cover
  the four newly demonstrated boundaries.

Use the [combined maintenance prompt](2026-11-16_S05_S06_S08_REMEDIATION_PROMPT.md).
