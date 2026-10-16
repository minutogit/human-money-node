# Terminology audit — file inventory

Date: 2026-10-16 (Europe/Berlin). Baseline: `02983adeda594d7610194cb6a4d0abcb118ef051`;
working tree clean at start. [Report and findings](TERMINOLOGY_ALIGNMENT_REPORT.md).

This list records the `rg --files --hidden` Markdown/Rust inventory at the start,
excluding `.git`, `target` and `node_modules`. Every current spec and first-party
source-comment area is accounted for. “Screened” means full-file text/comment
searches and relevant context review, not an exhaustive line-by-line semantic audit.
Changed passages and evidence paths were read in context; unresolved meanings and
legacy language debt are explicitly retained in the report. German filenames and
historical quotations do not themselves require renaming. Other asset extensions,
generated/build outputs and external repositories were not audited.

Production examples read include model signatures/certificates, DTO parsing,
count helpers, full-key/TLS verification, discovery identities and aliases, root
signature validation, RAM/queue admission and the existing storage origin paths.
No claim is made that a search or a file inventory proves cryptographic safety.

| File | Role | Outcome / limitation |
| --- | --- | --- |
| `.agents/instructions.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `.agents/prompts/plan_audit.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `.agents/prompts/spec_consistency_audit.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `.agents/rules/coding-agent.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `.agents/rules/planer-agent.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `.agents/rules/status-maintenance.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `AGENTS.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `README.md` | current/docs-prompts | Context read and editorial corrections applied. |
| `ROADMAP.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `SECURITY.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `STATUS.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `TODO.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/clap_complete/src/lib.rs` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `crates/humoco-node/src/alert/mod.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/api/auth.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/api/dashboard.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/api/dto.rs` | source/comments | Context read and editorial corrections applied. |
| `crates/humoco-node/src/api/events.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/api/health.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/api/history.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/api/hmc.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/api/keys.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/api/metrics.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/api/mod.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/api/qr.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/api/routes.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/api/system_stats.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/bin/cluster_sim.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/cli.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/config.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/control/client.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/control/mod.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/control/server.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/control/types.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/daemon.rs` | source/comments | Context read and editorial corrections applied. |
| `crates/humoco-node/src/error.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/identity.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/ingress/mod.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/ingress/pow.rs` | source/comments | Context read and editorial corrections applied. |
| `crates/humoco-node/src/ingress/tier.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/lib.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/main.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/network/clock.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/network/framing.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/network/manager.rs` | source/comments | Context read and editorial corrections applied. |
| `crates/humoco-node/src/network/mod.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/network/peer.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/network/tls.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/network/transport.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/storage/db.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/storage/engine.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/storage/filter.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/storage/mod.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/src/storage/recent.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/alert_notification_tests.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/api_tests.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-node/tests/audit_hardening_tests.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/chaos_wire_http_fuzz.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/cluster_e2e_tests.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/control_tests.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/dos_resilience_test.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/dual_stack_and_sunset_tests.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-node/tests/f2f_gossip_and_shard_rpc_tests.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/health_test.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/mutant_kills.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/network_tests.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/phase11_wire_level_adversarial_tests.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/phase3_integration_tests.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/phase4_net_time_and_quotas.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/phase5_pull_sync_and_readiness.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/realistic_protocol_simulation_tests.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/sim_01_evolutionary_growth.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/sim_02_island_bridge_merge.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-node/tests/sim_03_byzantine_resilience.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-node/tests/sim_04_scale_30_churn_and_failover.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-node/tests/sim_05_shard_baton_handover_integration.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/sim_06_lazy_gateway_free_rider_resilience.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/simulation/diagnostic.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/simulation/mod.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/simulation/node_handle.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/simulation/reporter.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/simulation/simulator.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/simulation/time.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/simulation/topology.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/simulation/wallet_handle.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/spec_07_pow_headroom_and_monotonicity_tests.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-node/tests/storage_tests.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/src/bin/humoco_sim.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/src/chaos.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/src/client_flow.rs` | source/comments | Context read and editorial corrections applied. |
| `crates/humoco-sim-core/src/crypto.rs` | source/comments | Context read and editorial corrections applied. |
| `crates/humoco-sim-core/src/fraud.rs` | source/comments | Context read and editorial corrections applied. |
| `crates/humoco-sim-core/src/lib.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/src/quota.rs` | source/comments | Context read and editorial corrections applied. |
| `crates/humoco-sim-core/src/resolver.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/src/sim/mod.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/src/sim/network.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/src/sim/node.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/src/state_machine.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/src/storage.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/src/telemetry.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/src/transport.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/src/types.rs` | source/comments | Context read and editorial corrections applied. |
| `crates/humoco-sim-core/src/wire.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/tests/mutant_kills.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/tests/proptest_invariants.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/tests/proptests_humoco_properties.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/tests/spec_00_spec_consistency_tests.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_02_canon_resolver.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/tests/spec_02_lock_lifecycle.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/tests/spec_03_digest_first_pull_sync.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_03_lazy_node_defense.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_03_replacement_node_lifecycle.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_03_shard_baton_handover_and_growth.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/tests/spec_04_lazy_ingestion_causality_chain.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/tests/spec_06_order_statistics_quorum.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/tests/spec_06_smart_client_dumb_server_flow.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_07_asymmetric_wot_and_village_merge.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_07_f2f_median_gaslighting_defense.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_08_split_brain_equivocation_proof.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/tests/spec_08_split_brain_merge.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_08_village_shard_transition.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_09_network_thermometer_and_quotas.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_10_13_wire_framing_and_access_tiering.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/tests/spec_10_fraud_proofs.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_11_dunbar_red_merge_simulation.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_11_f2f_10k_censorship_simulation.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_11_first_seen_ingress_pacing.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_11_gossip_propagation.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_11_multi_edge_merge_hysteresis_simulation.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_12_14_ram_index_and_storage_persistence.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_15_p2p_transport_and_connection_lifecycle.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `crates/humoco-sim-core/tests/spec_16_chaos_and_partition_resilience.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_17_telemetry_and_social_defense.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `crates/humoco-sim-core/tests/spec_chaos_aggressive.rs` | source/comments | Terminology/comment text screened; no further unambiguous correction selected. |
| `docs/00_architektur_und_mental_model.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `docs/01_organischer_netzstart_und_topologie.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `docs/02_lock_zustandsautomat_und_konflikte.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `docs/03_routing_und_sharding.md` | current/docs-prompts | Context read and editorial corrections applied. |
| `docs/04_datenstrukturen_und_rust_typen.md` | current/docs-prompts | Context read and editorial corrections applied. |
| `docs/05_spieltheorie_und_angriffsmatrix.md` | current/docs-prompts | Context read and editorial corrections applied. |
| `docs/06_dumb_server_smart_client_flow.md` | current/docs-prompts | Context read and editorial corrections applied. |
| `docs/07_admission_und_wot_buergschaften.md` | current/docs-prompts | Context read and editorial corrections applied. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `docs/08_topologie_dynamik_und_netz_merge.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `docs/09_netzwerk_thermometer_und_dynamische_quotas.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `docs/10_p2p_wire_format_und_session_framing.md` | current/docs-prompts | Context read and editorial corrections applied. |
| `docs/11_organische_praesenz_und_dunbar_gossip.md` | current/docs-prompts | Context read and editorial corrections applied. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `docs/12_lock_storage_und_ram_index.md` | current/docs-prompts | Context read and editorial corrections applied. |
| `docs/13_client_ingress_und_access_tiering.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `docs/14_node_persistenz_und_redb_speicher.md` | current/docs-prompts | Context read and editorial corrections applied. |
| `docs/15_p2p_transport_and_connection_management.md` | current/docs-prompts | Context read and editorial corrections applied. |
| `docs/15_p2p_transport_und_verbindungsmanagement.md` | current/docs-prompts | Context read and editorial corrections applied. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `docs/16_chaos_testing_and_simulation.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `docs/16_chaos_testing_und_simulation.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `docs/17_topologie_telemetrie_und_social_defense.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `docs/18_shard_kollaboration_und_perkolations_mathematik.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `docs/19_rueckkopplungs_dynamik_und_historische_p2p_postmortems.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `docs/20_vogelperspektive_oekosystem_und_zukunftssicherheit.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `docs/99_faq_und_angriffsvektoren_deep_dive.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `docs/ARCHITECTURE_INTERVIEW_HANDOFF.md` | decision/history | Current register/relevant details read; append-only provenance retained. |
| `docs/ARCHITECTURE_INTERVIEW_NOTES.md` | decision/history | Current register/relevant details read; append-only provenance retained. |
| `docs/ARCHITECTURE_INTERVIEW_STATE.md` | decision/history | Current register/relevant details read; append-only provenance retained. |
| `docs/MERCHANT_GUIDE.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `docs/OPERATIONS.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `docs/TERMINOLOGY_ALIGNMENT_REPORT.md` | current/docs-prompts | Context read and editorial corrections applied. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `docs/TRANSLATION_GLOSSARY.md` | current/docs-prompts | Context read and editorial corrections applied. |
| `docs/architektur_knotenperspektive_threat_model.md` | historical audit (2026-08-29) | Original findings preserved; current-status pointer added (TA-020/025). |
| `docs/archive/AUDIT_03_REPORT.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `docs/archive/AUDIT_05_REPORT.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `docs/archive/AUDIT_13_REPORT.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `docs/archive/audit_und_optimierungspotenziale.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `docs/archive/spec_widerspruchs_analyse.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/00_master_audit_orchestrator.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/01_subtraktion_und_vereinfachung.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/02_security_und_byzantine_hardening.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/03_todes_spiralen_und_deadlock_audit.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/04_invarianten_und_spezifikations_waechter.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/05_performance_und_latency_audit.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/06_chaos_und_fuzz_test_generator.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/07_faulheit_und_free_riding_audit.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/08_sabotage_zensur_und_eclipse_audit.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/09_knoten_hack_und_key_compromise_audit.md` | current/docs-prompts | Context read and editorial corrections applied. |
| `prompts/10_kartellbildung_und_shard_takeover_audit.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/11_time_warp_und_uhren_manipulation_audit.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/12_mutation_testing_und_test_blindspot_audit.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/13_unsafe_code_und_memory_safety_audit.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/14_property_based_testing_und_fuzzing.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/15_clean_code_und_idiomatic_rust_audit.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/16_supply_chain_und_dependency_audit.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/17_update_and_supply_chain_verification.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/18_legacy_code_and_architectural_drift_audit.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/19_wire_level_quota_and_adversarial_verification_audit.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/20_adler_perspektive_und_systemische_vollstaendigkeit.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. Legacy German prose/test comments remain (TA-028); commands/strings are preserved. |
| `prompts/AUDIT_REGISTRY.md` | decision/history | Historical execution ledger; not rewritten. |
| `prompts/README.md` | current/docs-prompts | Context read and editorial corrections applied. |
| `prompts/architecture_interview.md` | current/docs-prompts | Terminology/comment text screened; no further unambiguous correction selected. |
| `prompts/reports/2026-09-15_02_security_und_byzantine_hardening.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-15_04_invarianten_und_spezifikations_waechter.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-15_08_sabotage_zensur_und_eclipse_audit.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-15_13_unsafe_code_und_memory_safety_audit.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-23_01_subtraktion.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-23_03_todes_spiralen.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-23_11_time_warp.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-23_18_legacy_code_and_architectural_drift.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_01_subtraktion.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_02_security_und_byzantine_hardening.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_03_todes_spiralen.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_04_invarianten_und_spezifikations_waechter.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_05_performance_und_latency_audit.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_06_chaos_und_fuzz_test_generator.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_07_faulheit_und_free_riding_audit.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_08_sabotage_zensur_und_eclipse_audit.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_09_knoten_hack_und_key_compromise_audit.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_10_kartellbildung_und_shard_takeover_audit.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_11_time_warp.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_12_mutation_testing_und_test_blindspot_audit.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_13_unsafe_code_und_memory_safety_audit.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_14_property_based_testing_und_fuzzing.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_15_clean_code_und_idiomatic_rust_audit.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_16_supply_chain_und_dependency_audit.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_17_update_and_supply_chain_verification.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-24_18_legacy_code_and_architectural_drift.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-28_03_todes_spiralen_und_deadlocks.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-28_08_10_byzantine_security_and_cartel_audit.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-28_09_knoten_hack_und_key_compromise.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-28_12_07_mutation_testing_and_free_riding_audit.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-28_18_legacy_code_and_architectural_drift.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_01_subtraction_simplification.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_02_byzantine_security.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_03_todes_spiralen_deadlocks.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_04_invariant_guardian.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_05_performance_latency.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_06_chaos_fuzzing.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_07_faulheit_free_riding.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_08_sabotage_censorship.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_09_node_hack_key_compromise.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_10_cartel_shard_takeover.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_11_time_warp_clock_manipulation.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_12_mutation_testing.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_13_unsafe_code_memory_safety.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_14_property_based_testing.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_15_clean_code.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_16_supply_chain.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_17_sovereign_update.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-09-29_18_legacy_code_drift.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-10-13_quorum_resilience_research.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/reports/2026-10-13_system_architecture_completeness_audit.md` | historical/vendor | Excluded from current-language editing; historical/vendor evidence preserved. |
| `prompts/terminology_alignment_plan.md` | current/docs-prompts | Context read and editorial corrections applied. |

New support file: this inventory itself. The report, glossary and compact state
are updated in the same editorial continuation; their baseline entries above
refer to the pre-edit snapshot. Hashes of the inspected inputs were recorded in
the local task's `work/terminology/baseline.json` during this run.


## Autonomous alignment continuation — 2026-10-16

Current scope: the 248 Markdown/Rust paths in the working-tree snapshot, including
this inventory itself (the other 247 are listed above). Existing modifications
were preserved. Current prose/comments were re-screened for signature/certificate,
parent/output and shard-summary aliases; changed passages and relevant code were
read in context. Historical/vendor material and project rules remain unchanged.
This is terminology screening, not an exhaustive semantic audit or full translation.
Current findings/status are in report §8; its settled naming policy supersedes
proposed-name statuses in the older inventory/report descriptions.

| File changed in this continuation | Outcome |
| --- | --- |
| `ROADMAP.md` | Context-reviewed editorial vocabulary alignment; executable examples/identifiers and normative conditions preserved. |
| `TODO.md` | Context-reviewed editorial vocabulary alignment; executable examples/identifiers and normative conditions preserved. |
| `crates/humoco-node/src/api/hmc.rs` | Comment-only clarification; every non-comment line matches the pre-edit working tree. |
| `crates/humoco-node/src/daemon.rs` | Comment-only clarification; every non-comment line matches the pre-edit working tree. |
| `crates/humoco-sim-core/src/crypto.rs` | Comment-only clarification; every non-comment line matches the pre-edit working tree. |
| `docs/00_architektur_und_mental_model.md` | Context-reviewed editorial vocabulary alignment; executable examples/identifiers and normative conditions preserved. |
| `docs/06_dumb_server_smart_client_flow.md` | Context-reviewed editorial vocabulary alignment; executable examples/identifiers and normative conditions preserved. |
| `docs/07_admission_und_wot_buergschaften.md` | Context-reviewed editorial vocabulary alignment; executable examples/identifiers and normative conditions preserved. |
| `docs/10_p2p_wire_format_und_session_framing.md` | Context-reviewed editorial vocabulary alignment; executable examples/identifiers and normative conditions preserved. |
| `docs/15_p2p_transport_and_connection_management.md` | Context-reviewed editorial vocabulary alignment; executable examples/identifiers and normative conditions preserved. |
| `docs/15_p2p_transport_und_verbindungsmanagement.md` | Context-reviewed editorial vocabulary alignment; executable examples/identifiers and normative conditions preserved. |
| `docs/20_vogelperspektive_oekosystem_und_zukunftssicherheit.md` | Context-reviewed editorial vocabulary alignment; executable examples/identifiers and normative conditions preserved. |
| `docs/99_faq_und_angriffsvektoren_deep_dive.md` | Context-reviewed editorial vocabulary alignment; executable examples/identifiers and normative conditions preserved. |
| `docs/ARCHITECTURE_INTERVIEW_NOTES.md` | Record settled names/autonomous maintenance and return to S3.3; CP-0017. |
| `docs/ARCHITECTURE_INTERVIEW_STATE.md` | Record settled names/autonomous maintenance and return to S3.3; CP-0017. |
| `docs/TERMINOLOGY_ALIGNMENT_REPORT.md` | Current findings, scope, classifications and verification evidence. |
| `docs/TRANSLATION_GLOSSARY.md` | 24 mappings and G-001–066 retained; vocabulary adopted, legacy anchors preserved, protocol qualifications explicit. |
| `prompts/05_performance_und_latency_audit.md` | Context-reviewed editorial vocabulary alignment; executable examples/identifiers and normative conditions preserved. |
| `prompts/README.md` | Context-reviewed editorial vocabulary alignment; executable examples/identifiers and normative conditions preserved. |
| `prompts/terminology_alignment_plan.md` | Context-reviewed editorial vocabulary alignment; executable examples/identifiers and normative conditions preserved. |
| `docs/TERMINOLOGY_ALIGNMENT_INVENTORY.md` | Current findings, scope, classifications and verification evidence. |

Checks: `git diff --check` passed; all three edited Rust files retain identical
non-comment lines, including runtime strings; Rust fences in changed Markdown
retain identical non-comment content. G-001–066 are unique/ordered, all 24 original
mappings and 52 decision IDs remain. State/notes share CP-0017, one active S3.3
focus and a compact state below 120 lines. No new relative Markdown link was
introduced in the pass; glossary legacy anchors are explicit and local glossary
links were checked. No Rust code example changed; no build, unit test, QUIC suite,
doctest, commit or PR was run/created. Legacy prose language debt and report
TA-035's substantive conflicts remain explicitly recorded outside naming work.
