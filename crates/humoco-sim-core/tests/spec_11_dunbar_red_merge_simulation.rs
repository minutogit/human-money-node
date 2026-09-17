use std::collections::{BTreeMap, BTreeSet};

/// Berechnet das dynamische Kanten-Budget R_soft_hour gemäß docs/11:49
fn compute_r_soft_hour(n_local: usize, degree: usize) -> f64 {
    let d = degree.max(1) as f64;
    let sqrt_d_ceil = (d.sqrt().ceil()) + 1.0;
    let base = (n_local as f64) * (sqrt_d_ceil / d) * 2.0;
    60.0_f64.max(base.ceil())
}

/// Berechnet die stochastische Drop-Wahrscheinlichkeit P_drop(r) gemäß docs/11:55-59
fn compute_p_drop(r_incoming: f64, r_soft: f64) -> f64 {
    let r_hard = 5.0 * r_soft;
    if r_incoming <= r_soft {
        0.0
    } else if r_incoming <= r_hard {
        1.0 - (r_soft / r_incoming)
    } else {
        1.0
    }
}

/// Deterministischer Pseudo-Zufallsgenerator für reproduzierbare Monte-Carlo-Simulation
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_f64(&mut self) -> f64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        (x % 100_000) as f64 / 100_000.0
    }
}

#[test]
fn test_single_bridge_choke_vs_multi_homing_merge() {
    let mut rng = DeterministicRng::new(42);

    // =========================================================================
    // Szenario 1: Single-Bridge Edge (1 Kante zwischen Dorf N=10 und Riesennetz N=500)
    // =========================================================================
    let n_village = 10;
    let n_large_net = 500;
    let village_degree = 4; // Typischer Dorfknotengrad

    let r_soft_single = compute_r_soft_hour(n_village, village_degree);
    // Bei N=10, d=4: R_soft = 60 HB/h (1 HB/min)
    assert_eq!(r_soft_single, 60.0);

    // 500 Knoten aus dem Riesennetz senden jeweils 1 HB pro Stunde
    let incoming_rate_single = n_large_net as f64; // 500 HB/h über 1 Kante
    let p_drop_single = compute_p_drop(incoming_rate_single, r_soft_single);

    // Da 500 > R_hard (5 * 60 = 300), ist P_drop = 100% (Hard Drop!)
    assert_eq!(p_drop_single, 1.0);

    // Simuliere 24 Stunden Heartbeat-Eingang im Dorf über diese 1 Kante
    let mut received_heartbeats_single: BTreeMap<usize, usize> = BTreeMap::new();
    for _epoch in 0..24 {
        for node_id in 0..n_large_net {
            // Prüfung: Kommt der Heartbeat durch?
            if rng.next_f64() >= p_drop_single {
                *received_heartbeats_single.entry(node_id).or_default() += 1;
            }
        }
    }

    // Zähle, wie viele der 500 Knoten die 24h-Schwelle (>= 8 Heartbeats) erreichen
    let qualified_single = received_heartbeats_single
        .values()
        .filter(|&&count| count >= 8)
        .count();

    // ERGEBNIS Szenario 1: 0% der fernen Knoten qualifizieren sich über die 1 Kante!
    // Das Dorf bleibt vollkommen ungestört und autark.
    assert_eq!(qualified_single, 0);

    // =========================================================================
    // Szenario 2: Multi-Homing Merge (5 Kanten zwischen Dorf und Riesennetz)
    // =========================================================================
    let num_bridge_edges = 5;
    // Der Traffic von 500 Nodes verteilt sich auf 5 unabhängige Kanten:
    let incoming_per_edge = (n_large_net as f64) / (num_bridge_edges as f64); // 100 HB/h pro Kante

    // An jeder der 5 Kanten gilt R_soft = 60 HB/h, R_hard = 300 HB/h
    let p_drop_multi = compute_p_drop(incoming_per_edge, r_soft_single);
    // P_drop = 1 - 60 / 100 = 40% Drop-Rate (moderates RED)
    assert!((p_drop_multi - 0.40).abs() < 0.01);

    let mut received_heartbeats_multi: BTreeMap<usize, usize> = BTreeMap::new();
    let mut path_diversity: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();

    for _epoch in 0..24 {
        for node_id in 0..n_large_net {
            // Jeder Knoten propagiert über die 5 Kanten (stochastisches Mesh)
            for edge_idx in 0..num_bridge_edges {
                if rng.next_f64() >= p_drop_multi {
                    *received_heartbeats_multi.entry(node_id).or_default() += 1;
                    path_diversity.entry(node_id).or_default().insert(edge_idx);
                }
            }
        }
    }

    // Ein Knoten qualifiziert sich, wenn:
    // Er über 24h mindestens 8 stündliche Heartbeats geliefert hat (24h-Inkubationsschwelle >= 8/24)
    let qualified_multi = (0..n_large_net)
        .filter(|node_id| {
            let total_hbs = received_heartbeats_multi.get(node_id).copied().unwrap_or(0);
            total_hbs >= 8
        })
        .count();

    let qualification_ratio = (qualified_multi as f64) / (n_large_net as f64);

    // ERGEBNIS Szenario 2: Durch die 5 Kanten integrieren sich > 99% der Knoten
    // stabil und verlässlich in das Dorf-Wissen!
    assert!(
        qualification_ratio > 0.99,
        "Erfolgsquote beim 5-Kanten-Merge sollte > 99% sein, war aber {:.2}%",
        qualification_ratio * 100.0
    );
}
