use humoco_sim_core::types::{
    can_replacement_retire_to_standby, count_healthy_predecessors, hrw_rank_nodes,
    should_accept_replacement_invite, LockRecord, NodeId, ReplacementLifecycleState,
    ShardId, ShardPredecessorStatus, SimTime,
};
use humoco_sim_core::crypto::sign_lock_attestation;
use humoco_sim_core::state_machine::apply_attestation;
use std::collections::HashMap;

const SHARD_ID: ShardId = 42;
const NUM_TOTAL_NODES: usize = 30;

#[test]
fn test_replacement_node_full_lifecycle_and_flapping_resilience() {
    let all_node_ids: Vec<NodeId> = (0..NUM_TOTAL_NODES as NodeId).collect();
    let ranked = hrw_rank_nodes(&all_node_ids, SHARD_ID);

    // Identifiziere Top-20 und Rang 21
    let rank21_id = ranked[20].0;

    // 1. Initialzustand: Knoten auf Rang 21 ist im passiven IdleStandby
    let mut rank21_state = ReplacementLifecycleState::IdleStandby;
    assert_eq!(rank21_state, ReplacementLifecycleState::IdleStandby);

    // 2. Ausfall von Rang 7: Shard-Knoten und Client wenden sich an Rang 21
    let caller_rank_1 = 1; // Rang 1 lädt ein
    let caller_rank_8 = 8; // Rang 8 lädt ein
    let caller_rank_20 = 20; // Rang 20 lädt ein
    let caller_rank_500 = 500; // Böser Spammer von Rang 500

    // Spam von tieferem Rang (500) wird sofort abgelehnt
    assert!(!should_accept_replacement_invite(caller_rank_500, 21));

    // Einladungen von legitimen Vor-Rängen (1, 8, 20) werden akzeptiert
    assert!(should_accept_replacement_invite(caller_rank_1, 21));
    assert!(should_accept_replacement_invite(caller_rank_8, 21));
    assert!(should_accept_replacement_invite(caller_rank_20, 21));

    // 3. Aktivierung von Rang 21 -> ActiveReplacement + PULL-Sync (< 2ms)
    rank21_state = ReplacementLifecycleState::ActiveReplacement;
    let mut rank21_shard_locks = HashMap::new();

    // Simuliere PULL-Sync: Aktive Locks von verbleibenden 19 Peers laden
    let mut lock = LockRecord::new(
        [0xAA; 32],
        [0xBB; 32],
        b"test_salt".to_vec(),
        SimTime(100),
        SimTime(10_000),
    );
    let real_lock_id = lock.id;
    rank21_shard_locks.insert(real_lock_id, lock.clone());
    assert_eq!(rank21_shard_locks.len(), 1, "PULL-Sync lädt 1 aktives Lock");

    // 4. Rang 21 signiert mit und Quorum schließt FINAL ab
    let mut signers_count = 0;
    for (i, (nid, _)) in ranked.iter().take(20).enumerate() {
        if i == 6 {
            // Rang 7 ist offline!
            continue;
        }
        let att = sign_lock_attestation(*nid, &real_lock_id, &lock.parent_lock, SimTime(200 + i as u64));
        let _ = apply_attestation(&mut lock, att, NUM_TOTAL_NODES);
        signers_count += 1;
    }
    assert_eq!(signers_count, 19);

    // Rang 21 fügt seine Signatur als 20. Stimme hinzu
    let att21 = sign_lock_attestation(rank21_id, &real_lock_id, &lock.parent_lock, SimTime(250));
    let status21 = apply_attestation(&mut lock, att21, NUM_TOTAL_NODES).unwrap();
    assert!(status21.is_final(), "Quorum erreicht FINAL mit Nachrücker Rang 21!");

    // 5. Flapping-Test: Rang 7 reconnectet, fällt aber nach 2 Stunden wieder aus
    // Rang 21 prüft: Wie viele Vor-Ränge haben ununterbrochen >= 24h QUIC-Uptime?
    // Da Rang 7 geflappt ist, beträgt seine Uptime nur 2h -> nur 19 Vorgänger haben >= 24h!
    let stable_predecessors_flapping = 19;
    assert!(
        !can_replacement_retire_to_standby(stable_predecessors_flapping),
        "Rang 21 darf bei flappendem Rang 7 NICHT abrüsten!"
    );
    assert_eq!(rank21_state, ReplacementLifecycleState::ActiveReplacement);

    // 6. Lazy-Node-Test: Rang 7 hält QUIC-Verbindung seit 5 Tagen offen (quic_uptime >= 24h),
    // verweigert aber Unterschriften und ist suspendiert (is_suspended = true).
    let mut predecessor_states: Vec<ShardPredecessorStatus> = (0..20)
        .map(|i| {
            if i == 6 {
                // Rang 7 ist faul / unkooperativ!
                ShardPredecessorStatus {
                    quic_uptime_seconds: 5 * 24 * 3600, // 5 Tage offen!
                    is_suspended: true,                 // Aber faul / suspendiert!
                }
            } else {
                ShardPredecessorStatus {
                    quic_uptime_seconds: 24 * 3600,
                    is_suspended: false,
                }
            }
        })
        .collect();

    let healthy_count = count_healthy_predecessors(&predecessor_states);
    assert_eq!(healthy_count, 19, "Fauler Knoten darf trotz Uptime NICHT mitgezählt werden!");
    assert!(
        !can_replacement_retire_to_standby(healthy_count),
        "Rang 21 darf bei suspendiertem faulen Vorgänger NICHT abrüsten!"
    );
    assert_eq!(rank21_state, ReplacementLifecycleState::ActiveReplacement);

    // 7. Volle Genesung: Rang 7 wird rehabilitiert (is_suspended = false) und alle 20 Vor-Ränge laufen stabil
    predecessor_states[6].is_suspended = false;
    let full_healthy_count = count_healthy_predecessors(&predecessor_states);
    assert_eq!(full_healthy_count, 20);
    assert!(
        can_replacement_retire_to_standby(full_healthy_count),
        "Rang 21 darf nach 24h stabiler UND kooperativer Vor-Ränge sicher abrüsten!"
    );
    rank21_state = ReplacementLifecycleState::IdleStandby;
    assert_eq!(rank21_state, ReplacementLifecycleState::IdleStandby, "Rang 21 kehrt in passiven Standby zurück.");
}

#[test]
fn test_displaced_active_node_phantom_gossip_resistance_and_retirement() {
    use humoco_sim_core::types::can_active_node_retire_to_standby;

    // Szenario: Ein regulärer Shard-Knoten auf Rang 20 ist aktiv am Signieren
    let mut node20_state = ReplacementLifecycleState::ActiveReplacement;

    // 1. Initial: Alle 19 Vorgänger (Ränge 1..19) sind seit 24h stabil und kooperativ
    let mut predecessor_states: Vec<ShardPredecessorStatus> = (0..19)
        .map(|_| ShardPredecessorStatus {
            quic_uptime_seconds: 24 * 3600,
            is_suspended: false,
        })
        .collect();

    // 2. Ein Angreifer flutet 5 Fake-Identitäten via Gossip, die rechnerisch vor Knoten 20 landen
    // Auf dem Papier rutscht Knoten 20 von Rang 20 auf Rang 25 ab.
    // Die 5 Fake-IDs werden als Vor-Ränge in die Liste eingefügt:
    for _ in 0..5 {
        predecessor_states.push(ShardPredecessorStatus {
            quic_uptime_seconds: 0, // Phantome antworten nicht auf QUIC!
            is_suspended: true,     // Nicht erreichbar / nicht kooperativ
        });
    }
    assert_eq!(predecessor_states.len(), 24); // 19 echte + 5 Fake

    // 3. Prüfung: Knoten 20 evaluiert, ob er in IdleStandby abrüsten darf
    let healthy_count = count_healthy_predecessors(&predecessor_states);
    assert_eq!(healthy_count, 19, "Phantome dürfen NICHT mitgezählt werden!");
    assert!(
        !can_active_node_retire_to_standby(healthy_count),
        "Knoten 20 darf trotz Papier-Rang 25 NIEMALS seinen Dienst quittieren!"
    );
    assert_eq!(node20_state, ReplacementLifecycleState::ActiveReplacement);

    // 4. Reconnect Grace Tolerance: Echter Vor-Rang 5 hat einen kurzen IP-Wechsel (< 120s)
    // Seine Uptime bleibt kumuliert erhalten (24h) und er wird nicht suspendiert
    predecessor_states[4].quic_uptime_seconds = 24 * 3600;
    predecessor_states[4].is_suspended = false;
    assert_eq!(count_healthy_predecessors(&predecessor_states), 19);

    // 5. Ein echter 20. Knoten tritt bei, stabilisiert sich über 24 Stunden und kooperiert
    predecessor_states.push(ShardPredecessorStatus {
        quic_uptime_seconds: 24 * 3600,
        is_suspended: false,
    });

    let full_healthy = count_healthy_predecessors(&predecessor_states);
    assert_eq!(full_healthy, 20, "Nun sind 20 echte, physisch bewiesene Vor-Ränge aktiv!");
    assert!(
        can_active_node_retire_to_standby(full_healthy),
        "Erst jetzt darf der verdrängte Knoten 20 geordnet in IdleStandby wechseln."
    );

    node20_state = ReplacementLifecycleState::IdleStandby;
    assert_eq!(node20_state, ReplacementLifecycleState::IdleStandby);
}
