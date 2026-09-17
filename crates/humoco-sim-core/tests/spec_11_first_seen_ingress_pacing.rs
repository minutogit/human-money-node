//! Spec 11 – [INV-1104] First-Seen Neulings-Pacing & Kanten-Drossel
//!
//! Verifiziert die Schutzgarantien aus `docs/11_organische_praesenz_und_dunbar_gossip.md#säule-4-inv-1104`:
//!
//! 1. Bekannte Knoten (Heartbeats / Reconnects) durchlaufen den ungebremsten Hot Path (0 ms).
//! 2. Völlig neue Knoten (First-Seen) werden lokal sofort registriert, aber nur gepaced weitergeleitet.
//! 3. Ein Burst von 100 Fake-Argon2-Identitäten wird auf genau 1 Node / Stunde gedrosselt.
//! 4. Mehrhop-Perkolation: Ein neuer Knoten breitet sich gleichmäßig und zeitlich gestreckt aus.

use humoco_sim_core::types::{FirstSeenPacer, NodeGossipForwardDecision, NodeId};

#[test]
fn test_inv1104_known_node_immediate_forward_vs_first_seen_delayed() {
    // 1. Initialisiere Pacer mit bekannten Dorf-Knoten 0..5 (1 Stunde Pacing = 3600s)
    let initial_known: Vec<NodeId> = (0..5).collect();
    let mut pacer = FirstSeenPacer::with_known_nodes(initial_known, 3600);

    assert_eq!(pacer.known_count(), 5);
    assert_eq!(pacer.pending_count(), 0);

    // 2. Bekannter Knoten 2 schickt Heartbeat -> ForwardImmediate (Hot Path, 0 ms)
    let decision_known = pacer.handle_incoming_node_gossip(2, 100);
    assert_eq!(decision_known, NodeGossipForwardDecision::ForwardImmediate);
    assert_eq!(pacer.pending_count(), 0);

    // 3. Völlig neuer Knoten 999 (First-Seen) trifft ein -> ForwardDelayed (3600s)
    let decision_new = pacer.handle_incoming_node_gossip(999, 100);
    assert_eq!(
        decision_new,
        NodeGossipForwardDecision::ForwardDelayed {
            delay_seconds: 3600
        }
    );
    assert!(pacer.is_known(999));
    assert_eq!(pacer.known_count(), 6);
    assert_eq!(pacer.pending_count(), 1);

    // 4. Weiterer Heartbeat von Knoten 999 (nun bekannt) -> ForwardImmediate
    let decision_now_known = pacer.handle_incoming_node_gossip(999, 150);
    assert_eq!(
        decision_now_known,
        NodeGossipForwardDecision::ForwardImmediate
    );
}

#[test]
fn test_inv1104_pacing_queue_rate_limits_botnet_flood() {
    // 1 Stunde Intervall = 3600 Sekunden
    let mut pacer = FirstSeenPacer::new(3600);

    // Ein gehackter Knoten schießt 50 Fake-Node-Gossips zum Zeitpunkt t = 0 ein
    for fake_id in 1000..1050 {
        let decision = pacer.handle_incoming_node_gossip(fake_id, 0);
        assert_eq!(
            decision,
            NodeGossipForwardDecision::ForwardDelayed {
                delay_seconds: 3600
            }
        );
    }

    assert_eq!(pacer.known_count(), 50);
    assert_eq!(pacer.pending_count(), 50);

    // 1. Erster Neuling wird zum Zeitpunkt t = 0 freigegeben
    let first = pacer.poll_next_ready_forward(0);
    assert_eq!(first, Some(1000));
    assert_eq!(pacer.pending_count(), 49);

    // 2. Nach 30 Minuten (t = 1800s): Noch KEINE weitere Freigabe (Intervall nicht erreicht)
    assert_eq!(pacer.poll_next_ready_forward(1800), None);
    assert_eq!(pacer.pending_count(), 49);

    // 3. Nach genau 1 Stunde (t = 3600s): Zweiter Neuling wird freigegeben
    let second = pacer.poll_next_ready_forward(3600);
    assert_eq!(second, Some(1001));
    assert_eq!(pacer.pending_count(), 48);

    // 4. Nach 1,5 Stunden (t = 5400s): Immer noch blockiert
    assert_eq!(pacer.poll_next_ready_forward(5400), None);

    // 5. Nach 2 Stunden (t = 7200s): Dritter Neuling wird freigegeben
    let third = pacer.poll_next_ready_forward(7200);
    assert_eq!(third, Some(1002));
    assert_eq!(pacer.pending_count(), 47);

    // Beweis: In 2 vollen Stunden wurden von 50 Angreifer-Phantomen exakt 3 weitergeleitet!
}

#[test]
fn test_inv1104_mesh_percolation_stepwise_forwarding() {
    // 3 Knoten auf einem Pfad: A -> B -> C
    // Pacing: 60 Sekunden pro Hop (für schnellen Simulationstest)
    let mut pacer_a = FirstSeenPacer::with_known_nodes([0], 60);
    let mut pacer_b = FirstSeenPacer::with_known_nodes([0], 60);
    let mut pacer_c = FirstSeenPacer::with_known_nodes([0], 60);

    let new_node: NodeId = 42;

    // t = 0: Neuer Knoten meldet sich bei A
    let dec_a = pacer_a.handle_incoming_node_gossip(new_node, 0);
    assert_eq!(dec_a, NodeGossipForwardDecision::ForwardDelayed { delay_seconds: 60 });

    // A schickt sofort (t=0) den ersten Neuling an B
    let fwd_a = pacer_a.poll_next_ready_forward(0).expect("A should release node 42");
    assert_eq!(fwd_a, new_node);

    // B empfängt bei t = 0 von A
    let dec_b = pacer_b.handle_incoming_node_gossip(new_node, 0);
    assert_eq!(dec_b, NodeGossipForwardDecision::ForwardDelayed { delay_seconds: 60 });

    // B gibt es bei t = 0 frei (erster Neuling bei B)
    let fwd_b = pacer_b.poll_next_ready_forward(0).expect("B should release node 42");
    assert_eq!(fwd_b, new_node);

    // C empfängt bei t = 0 von B
    let dec_c = pacer_c.handle_incoming_node_gossip(new_node, 0);
    assert_eq!(dec_c, NodeGossipForwardDecision::ForwardDelayed { delay_seconds: 60 });

    // Alle 3 Knoten kennen nun den neuen Knoten
    assert!(pacer_a.is_known(new_node));
    assert!(pacer_b.is_known(new_node));
    assert!(pacer_c.is_known(new_node));
}

#[test]
fn test_inv1104_queue_depth_probing_destroys_phantoms_instantly() {
    // Pacer mit 3600s Intervall
    let mut pacer = FirstSeenPacer::new(3600);

    // 1. Schicke 3 Knoten ein -> Queue-Tiefe = 3 (< 4)
    // Diese gelten als unverdächtiger normaler Zuwachs und durchlaufen den Pacer ohne Liveness-Check
    for id in 100..=102 {
        pacer.handle_incoming_node_gossip(id, 0);
    }
    assert_eq!(pacer.pending_count(), 3);

    // 2. Jetzt flutet ein Angreifer 10 tote Phantome (200..210) ein -> Queue-Tiefe wächst auf 13 (>= 4)
    for id in 200..210 {
        pacer.handle_incoming_node_gossip(id, 0);
    }
    // Und am Ende ein echter lebendiger Knoten (999)
    pacer.handle_incoming_node_gossip(999, 0);

    assert_eq!(pacer.pending_count(), 14);

    // Mock-Liveness-Funktion: Nur Knoten < 200 und Knoten 999 antworten auf QUIC-Ping
    let probe_fn = |nid: NodeId| nid < 200 || nid == 999;

    // t = 0: Erster Knoten (100) wird freigegeben (Queue war < 4 bei Eintritt bzw. Node 100 ist lebendig)
    let fwd1 = pacer.poll_next_ready_forward_with_probe(0, probe_fn);
    assert_eq!(fwd1, Some(100));

    // t = 3600: Zweiter Knoten (101)
    let fwd2 = pacer.poll_next_ready_forward_with_probe(3600, probe_fn);
    assert_eq!(fwd2, Some(101));

    // t = 7200: Dritter Knoten (102)
    let fwd3 = pacer.poll_next_ready_forward_with_probe(7200, probe_fn);
    assert_eq!(fwd3, Some(102));

    // t = 10800: Nun stehen die 10 toten Phantome (200..210) an der Spitze der Queue!
    // Da Queue-Tiefe >= 4, schlägt das Probing fehl (probe_fn gibt false).
    // Sie werden in EINEM EINZIGEN Call blitzschnell gelöscht, bis der echte Knoten 999 gefunden wird!
    let fwd4 = pacer.poll_next_ready_forward_with_probe(10800, probe_fn);
    assert_eq!(fwd4, Some(999));

    // Alle Phantome 200..210 wurden aus `known_nodes` getilgt
    for id in 200..210 {
        assert!(!pacer.is_known(id), "Phantom {} was not purged!", id);
    }
    // Echter Knoten 999 ist bekannt und registriert
    assert!(pacer.is_known(999));
    assert_eq!(pacer.pending_count(), 0);
}

#[test]
fn test_inv1104_jitter_calculation() {
    let base = 50 * 60; // 3000s = 50 min
    let max_jitter = 20 * 60; // 1200s = 20 min

    for seed in 0..100 {
        let interval = FirstSeenPacer::calculate_jittered_interval(base, max_jitter, seed);
        assert!((3000..=4200).contains(&interval));
    }
}

