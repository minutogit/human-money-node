//! Spec 11 – Organische Präsenz & Dunbar-Gossip
//!
//! Verifiziert die Small-World-Epidemie und Dunbar-Gossip-Verbreitung aus
//! `docs/11_organische_praesenz_und_dunbar_gossip.md`:
//!
//! 1. Dunbar-Topologie mit 15 Nodes (Knotengrad d <= 4 pro Node).
//! 2. Konfiguration mehrerer Nodes mit Zeitdrift (z. B. Node 3 mit -30s, Node 7 mit +45s, Node 12 mit -15s).
//! 3. Einspeisung eines LockRequest bei Node 0.
//! 4. Deterministische Simulation (virtuelle Zeit <= 1000ms).
//! 5. Verifikation:
//!    - Der Lock erreicht alle 15 Nodes innerhalb von maximal 4 Hops.
//!    - Alle 15 Nodes erstellen eine gültige Attestation und aktualisieren ihren
//!      lokalen Lock-Status auf PROVISIONAL (N=15 < 20, Quorum Q=11).
//!    - Der SeenCache verhindert endlose Echo-Schleifen (deterministischer Abbruch / leere Event-Queue).

use std::collections::BTreeMap;

use humoco_sim_core::sim::{SimMessage, SimNetwork, SimNode};
use humoco_sim_core::types::{LockId, LockRecord, LockStatus, SimTime};

/// Anzahl der Knoten im Dunbar-Test-Mesh (Spec 11 verlangt 15).
const N_NODES: u16 = 15;

/// Erzeugt ein deterministisches 15-Knoten-Dunbar-Mesh (Ring-Lattice mit Knotengrad d = 4).
///
/// Jeder Knoten i ist mit seinen nächsten 4 Nachbarn (i±1 und i±2 modulo 15) verbunden.
/// Dadurch gilt für jeden Knoten strikt d <= 4 und der maximale Durchmesser des Netzwerks
/// beträgt genau 4 Hops (15 Knoten = 1 [Hop 0] + 4 [Hop 1] + 4 [Hop 2] + 4 [Hop 3] + 2 [Hop 4]).
fn build_dunbar_mesh(net: &mut SimNetwork) {
    for id in 0..N_NODES {
        net.add_node(SimNode::new(id, N_NODES as usize));
    }

    let n = N_NODES as usize;
    for i in 0..n {
        for offset in [1usize, 2, n - 1, n - 2] {
            let peer = ((i + offset) % n) as u16;
            net.nodes.get_mut(&(i as u16)).unwrap().add_peer(peer);
        }
    }
}

/// Liefert den Hop-Counter aus einer `GossipLock`-Nachricht.
fn gossip_hops(msg: &SimMessage) -> Option<u8> {
    match msg {
        SimMessage::GossipLock { hops, .. } => Some(*hops),
        _ => None,
    }
}

#[test]
fn test_dunbar_gossip_propagation_15_nodes_with_drift() {
    let mut net = SimNetwork::new();
    net.set_latency(5, 15);
    build_dunbar_mesh(&mut net);

    // 1. Überprüfe Knotengrad d <= 4 für alle 15 Nodes
    for id in 0..N_NODES {
        let deg = net.nodes[&id].peers.len();
        assert!(
            deg <= 4,
            "Knoten {} hat Knotengrad {} > 4 (Dunbar-Vorgabe verletzt)",
            id,
            deg
        );
        assert_eq!(
            deg, 4,
            "Knoten {} sollte regulären Knotengrad 4 besitzen",
            id
        );
    }

    // 2. Konfiguriere mehrere Nodes mit Zeitdrift (innerhalb des ±60s-Fensters aus Spec 11)
    // Node 3 mit -30s, Node 7 mit +45s, Node 12 mit -15s sowie weitere realistische Drifts
    let drifts: &[(u16, i64)] = &[
        (3, -30_000),  // -30s
        (7, 45_000),   // +45s
        (12, -15_000), // -15s
        (1, 10_000),   // +10s
        (5, -20_000),  // -20s
        (9, 35_000),   // +35s
        (14, -5_000),  // -5s
    ];
    for &(id, drift) in drifts {
        net.nodes.get_mut(&id).unwrap().clock_drift_ms = drift;
    }

    // 3. Speise bei Node 0 einen neuen LockRequest ein
    let parent_lock = [0xAA; 32];
    let receiver = [0xBB; 32];
    let nonce = b"dunbar_spec_11_test".to_vec();
    let lock = LockRecord::new(
        parent_lock,
        receiver,
        nonce,
        SimTime(0),
        SimTime(60_000), // 60s Gültigkeit
    );
    let lock_id: LockId = lock.id;

    // First-Seen Hop Tracking
    let mut first_seen_hop: BTreeMap<u16, u8> = BTreeMap::new();
    let mut first_seen_at: BTreeMap<u16, SimTime> = BTreeMap::new();

    // Node 0 ist der Einspeise-Knoten (Hop 0 zur Startzeit t=10ms)
    first_seen_hop.insert(0, 0);
    first_seen_at.insert(0, SimTime(10));

    net.schedule(SimTime(10), 0, 0, SimMessage::LockRequest(lock));

    // 4. Lasse die Simulation laufen (Überwachung der Hop-Tiefen pro Event bis max 1000ms)
    let time_limit = SimTime(1_000); // 1000ms virtuelle Zeit
    while let Some(event) = net.events.peek().cloned() {
        if event.deliver_at > time_limit {
            break;
        }
        net.current_time = event.deliver_at;
        if let Some(hops) = gossip_hops(&event.msg) {
            let entry = first_seen_hop.entry(event.to).or_insert(hops);
            if hops < *entry {
                *entry = hops;
                first_seen_at.insert(event.to, event.deliver_at);
            }
        }
        net.step();
    }
    net.run_until(time_limit);
    net.run_all();

    // 5. Überprüfungen:

    // 5a. Der Lock erreicht alle 15 Nodes innerhalb von maximal 4 Hops
    assert_eq!(
        first_seen_hop.len(),
        N_NODES as usize,
        "Gossip hat nicht alle 15 Knoten erreicht: {:?}",
        first_seen_hop
    );
    let max_hop = *first_seen_hop.values().max().unwrap();
    assert!(
        max_hop <= 4,
        "Maximaler Hop-Count {} überschreitet das 4-Hop-Budget: {:?}",
        max_hop,
        first_seen_hop
    );

    // Alle Knoten haben den Lock vor dem 1000ms-Limit erhalten
    for (id, time) in &first_seen_at {
        assert!(
            time.0 <= 1_000,
            "Knoten {} sah den Lock erst bei {}ms (> 1000ms)",
            id,
            time.0
        );
    }

    // 5b. Alle 15 Nodes erstellen eine gültige Attestation und aktualisieren ihren
    // lokalen Lock-Status auf PROVISIONAL (N=15 < 20 -> Quorum floor(2/3*15)+1 = 11).
    let required_quorum = (2 * N_NODES as usize) / 3 + 1; // 11
    for id in 0..N_NODES {
        let node = &net.nodes[&id];
        assert!(
            node.locks.contains_key(&lock_id),
            "Knoten {} hat den Lock nicht in seinem Speicher",
            id
        );

        let lock_rec = &node.locks[&lock_id];

        // Eigene Signatur enthalten
        assert!(
            lock_rec.signers.contains(&id),
            "Knoten {} hat den Lock nicht selbst signiert",
            id
        );

        // Alle 15 Signaturen aggregiert
        assert_eq!(
            lock_rec.signers.len(),
            N_NODES as usize,
            "Knoten {} hat nur {}/15 Signaturen gesammelt",
            id,
            lock_rec.signers.len()
        );

        // Status ist PROVISIONAL mit Quorum erfüllt
        match lock_rec.status {
            LockStatus::Provisional { sigs, required } => {
                assert_eq!(sigs, N_NODES as usize);
                assert_eq!(required, required_quorum);
            }
            ref other => {
                panic!("Knoten {} hat unerwarteten Lock-Status: {:?}", id, other);
            }
        }
        assert!(lock_rec.status.is_active());
        assert!(!lock_rec.status.is_void());
        assert!(!lock_rec.status.is_final());
    }

    // 5c. Der SeenCache verhindert endlose Echo-Schleifen
    // Wenn der SeenCache korrekt arbeitet, ist die Event-Queue nach net.run_all() vollständig leer
    assert!(
        net.events.is_empty(),
        "Event-Queue ist nach Abschluss nicht leer (Echo-Schleife!)"
    );
    for id in 0..N_NODES {
        let node = &net.nodes[&id];
        // Jeder Knoten muss den Lock und die Quittungen in seen_gossips haben
        assert!(
            node.seen_gossips.contains(&lock_id),
            "Knoten {} hat LockId nicht im seen_gossips-Cache",
            id
        );
        assert!(
            !node.seen_gossips.is_empty(),
            "Knoten {} hat leeren seen_gossips-Cache",
            id
        );
    }
}

#[test]
fn test_dunbar_gossip_seen_cache_deduplication_prevents_echo_flooding() {
    let mut net = SimNetwork::new();
    net.set_latency(1, 2);
    build_dunbar_mesh(&mut net);

    let parent_lock = [0xCC; 32];
    let receiver = [0xDD; 32];
    let nonce = b"seen_cache_dedup_test".to_vec();
    let lock = LockRecord::new(parent_lock, receiver, nonce, SimTime(0), SimTime(60_000));
    let lock_id = lock.id;

    // Lock einspeisen
    net.schedule(SimTime(0), 0, 0, SimMessage::LockRequest(lock.clone()));
    net.run_until(SimTime(500));
    net.run_all();

    // Alle Knoten sind synchronisiert
    for id in 0..N_NODES {
        assert_eq!(net.nodes[&id].locks[&lock_id].signers.len(), 15);
    }

    // Re-Inject denselben Lock erneut an mehreren Knoten
    net.schedule(SimTime(510), 1, 1, SimMessage::LockRequest(lock.clone()));
    net.schedule(SimTime(510), 5, 5, SimMessage::LockRequest(lock.clone()));
    net.schedule(
        SimTime(510),
        10,
        10,
        SimMessage::GossipLock { lock, hops: 0 },
    );

    let initial_time = net.current_time;
    net.run_all();

    // Da alle Knoten den Lock bereits in `seen_gossips` / `parent_to_lock` haben,
    // darf keine neue Nachrichten-Flut entstehen.
    // Die Simulation muss sofort terminieren.
    assert!(
        net.events.is_empty(),
        "Re-Injection führte zu endloser Nachrichten-Welle"
    );
    assert!(
        net.current_time <= initial_time + 10,
        "Re-Injection erzeugte unnötige Verzögerungen: Zeit stieg von {} auf {}",
        initial_time,
        net.current_time
    );
}

#[test]
fn test_dunbar_gossip_clock_drift_edge_cases_within_60s() {
    let mut net = SimNetwork::new();
    net.set_latency(5, 10);
    build_dunbar_mesh(&mut net);

    // Extreme Drifts an den Rändern des ±60s Fensters (-60s bis +60s)
    let drifts = [
        -60_000, 60_000, -59_000, 59_000, -30_000, 30_000, -15_000, 15_000, -45_000, 45_000,
        -1_000, 1_000, -50_000, 50_000, 0,
    ];
    for (id, &d) in drifts.iter().enumerate() {
        net.nodes.get_mut(&(id as u16)).unwrap().clock_drift_ms = d;
    }

    let parent_lock = [0xEE; 32];
    let receiver = [0xFF; 32];
    let nonce = b"extreme_drift_test".to_vec();
    let lock = LockRecord::new(
        parent_lock,
        receiver,
        nonce,
        SimTime(0),
        SimTime(120_000), // 120s Gültigkeit
    );
    let lock_id = lock.id;

    net.schedule(SimTime(10), 0, 0, SimMessage::LockRequest(lock));
    net.run_until(SimTime(1_000));
    net.run_all();

    // Alle 15 Knoten müssen trotz extremer Zeitdrift erfolgreich teilgenommen haben
    for id in 0..N_NODES {
        let node = &net.nodes[&id];
        assert!(node.locks.contains_key(&lock_id));
        let lock_rec = &node.locks[&lock_id];
        assert_eq!(lock_rec.signers.len(), N_NODES as usize);
        assert!(lock_rec.status.is_active());
        assert!(!lock_rec.status.is_void());
    }
}
