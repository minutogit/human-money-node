# Root anchors, immutable L1 tags and operator bootstrap

Date: 2026-10-23. This contract records the maintainer's explicit choices.

## Root and spend namespaces

Genesis creates no exclusion. It is stored only in `voucher_roots`, with the
voucher validity and physical deletion deadline. It never occupies `locks`,
receives an original spend approval, or contributes to a shard lock digest.
The first actual spend creates the first collision row. Exact retries preserve
the root deed; a foreign author, changed validity or signed-proof downgrade cannot
replace an existing root. Roots and spends are physically removed after expiry
plus the grace period, without permanent tombstones.

The L1 SST tag remains exactly `human-money-core::crypto::get_ds_tag`:
SHA3-256 over the length-prefixed previous canonical transaction state hash and
sender ephemeral public key. The previous state hash is the hash of the complete
canonical L1 transaction, not its `t_id`. Receiver and change ownership hashes
are SHA3 hashes of the respective ephemeral public keys. Split branches retain
independent collision slots. L1 serialization, signatures and SST remain intact.

The version-1 author-signed `CausalOutputProof` is separate L2 metadata. It binds
voucher, transaction ID, complete state hash, author, receiver/change commitments,
root validity and root/spend role. Each full-chain edge checks ownership and the
unchanged SST formula. The engine validates and durably commits each next step
sequentially; an invalid suffix cannot roll back a valid durable prefix. Original
wallet T0 is checked at receiving-shard admission, not refreshed by a gateway.

## Migration limits

Legacy genesis self-loops migrate into the separate root table, with bounded
migration batches. Existing private signing-history evidence remains protected;
migration does not invent new original genesis votes. A new canonical hex voucher
root needs the original author's signed output proof and its existing L1 root-ID
preimage check. A legacy root can receive its author's matching proof without
changing its immutable deed. Another participant cannot sign missing historical
sidecars on behalf of an earlier owner. Legacy histories without those proofs
remain qualified and cannot justify automatic goods release.

The optional proof is consistently encoded in the L2 binary DTO. Deploy matching
Proto/Core/Node/App versions together; this is not a claim of unversioned binary
compatibility. The L1 voucher and transaction format is unchanged.

## Explicit new-region bootstrap

`humoco run --bootstrap-new-region` is a one-time operator assertion that a NEW
regional registry starts empty. It is not an automatic emptiness proof. The
one-shot marker is synced, database creation uses an exclusive `create_new` file
reservation, and initialized redb tables commit before shard readiness is opened.
Existing databases and interrupted bootstrap markers reject another bootstrap.
An interrupted attempt requires deliberate operator investigation, not automatic
fallback. Do not remove either guard to reopen an existing network.

Normal starts, joins and restarts start with every shard unready. Even a database
originally created with this flag is not automatically reauthorized on restart.
Ready sources must justify each demanded shard through quorum digest agreement.
Root metadata registration does not authorize a spend, original vote or FINAL.

`operator_bootstrap_tests` starts the real daemon and verifies over authenticated
QUIC: initial explicit empty digest, closed restart, and refusal to reuse the flag.
The existing manually prepared collector fixtures do not prove automatic recovery.

## Remaining closure limits

MVCC snapshot cuts, authenticated streaming cursors, independent admission queues
and bounded RAM staging are implemented. Complete disk-staged atomic publication
of arbitrarily large shard deltas, support inheritance through turnover, and the
full no-gap recovery matrix remain open. HMC compact verified support survives
local recovery; native support and complete sync inheritance remain open.

The Core durable intent, recipient challenge and atomic purchase APIs exist, as
do App exact-byte dispatch and public cold discovery. Full productive UI intent
orchestration, terminal resolution, authenticated roster refresh, crash/fault
coverage and App-to-QUIC-to-PoS E2E acceptance remain open. Full historical offline
chain admission must still compose with the 30-second signed T0 rule. A full,
internally consistent offline directory rollback remains outside local detection
without contradictory external first-party evidence; no new trust anchor is used.
