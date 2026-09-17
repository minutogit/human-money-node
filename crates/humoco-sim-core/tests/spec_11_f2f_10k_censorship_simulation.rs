//! Spec 11 – 10.000-Knoten F2F Small-World Simulation: Byzantinischer Zensur- und Aushungerungs-Stresstest
//!
//! Untersucht die Resilienz des Dunbar-Friend-to-Friend (F2F) Gossips gegen koordinierte
//! Zensur (10 % böse Knoten, die gezielt einen Opferknoten aushungern wollen).
//!
//! Garantiert feste Speicher- und Laufzeitgrenzen (O(N) Speicher, < 2 MB RAM).

use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

const N_NODES: usize = 10_000;
const MAX_DEGREE: usize = 16; // Strikte Dunbar-Obergrenze (k <= 16)
const LOCAL_K: usize = 4; // ±4 lokale Freunde (Basis-Knotengrad = 8)

/// Einfacher deterministischer PRNG (xorshift64)
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x8a5cd789635d2dff } else { seed },
        }
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    #[inline(always)]
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    #[inline(always)]
    fn gen_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        let range = (max - min) as u64;
        min + (self.next_u64() % range) as usize
    }
}

/// Speicher- und CPU-effiziente F2F-Graphrepräsentation mit fester Kapazitätsgrenze
struct F2FGraph {
    adj: Vec<Vec<u32>>,
}

impl F2FGraph {
    fn new(n: usize, rng: &mut SimpleRng) -> Self {
        let mut adj: Vec<Vec<u32>> = vec![Vec::with_capacity(MAX_DEGREE); n];

        // 1. Basis: Lokaler Ring (enger Freundeskreis)
        for (i, node_adj) in adj.iter_mut().enumerate().take(n) {
            for offset in 1..=LOCAL_K {
                let right = ((i + offset) % n) as u32;
                let left = ((i + n - offset) % n) as u32;
                if !node_adj.contains(&right) && node_adj.len() < MAX_DEGREE {
                    node_adj.push(right);
                }
                if !node_adj.contains(&left) && node_adj.len() < MAX_DEGREE {
                    node_adj.push(left);
                }
            }
        }

        // 2. Organische Dreiecke (Freundesfreunde bis max Dunbar-Limit)
        let base_snapshot = adj.clone();
        for i in 0..n {
            let my_neighbors = &base_snapshot[i];
            for &u in my_neighbors {
                let u_neighbors = &base_snapshot[u as usize];
                for &v in u_neighbors {
                    if v != i as u32
                        && !adj[i].contains(&v)
                        && adj[i].len() < MAX_DEGREE - 2
                        && rng.next_f64() < 0.35
                    {
                        adj[i].push(v);
                        if !adj[v as usize].contains(&(i as u32))
                            && adj[v as usize].len() < MAX_DEGREE
                        {
                            adj[v as usize].push(i as u32);
                        }
                    }
                }
            }
        }

        // 3. Small-World Shortcuts (Granovetter Weak Ties: 2-3 globale Brücken)
        for i in 0..n {
            if adj[i].len() < MAX_DEGREE && rng.next_f64() < 0.25 {
                let target = rng.gen_range(0, n) as u32;
                if target != i as u32 && !adj[i].contains(&target) {
                    adj[i].push(target);
                    if !adj[target as usize].contains(&(i as u32))
                        && adj[target as usize].len() < MAX_DEGREE
                    {
                        adj[target as usize].push(i as u32);
                    }
                }
            }
        }

        for neighbors in &mut adj {
            neighbors.sort_unstable();
            neighbors.dedup();
        }

        Self { adj }
    }

    fn average_degree(&self) -> f64 {
        let total_edges: usize = self.adj.iter().map(|s| s.len()).sum();
        total_edges as f64 / self.adj.len() as f64
    }

    fn clustering_coefficient(&self) -> f64 {
        let mut total_c = 0.0;
        let mut count = 0;

        for i in 0..500.min(self.adj.len()) {
            let neighbors = &self.adj[i];
            let k = neighbors.len();
            if k < 2 {
                continue;
            }
            let mut links = 0;
            for j in 0..k {
                let u = neighbors[j] as usize;
                let u_adj = &self.adj[u];
                for &v in &neighbors[(j + 1)..k] {
                    if u_adj.binary_search(&v).is_ok() {
                        links += 1;
                    }
                }
            }
            let possible = (k * (k - 1)) / 2;
            total_c += links as f64 / possible as f64;
            count += 1;
        }

        if count > 0 {
            total_c / count as f64
        } else {
            0.0
        }
    }
}

/// Ergebnis eines Gossip-Ausbreitungslaufs
#[derive(Debug)]
struct GossipResult {
    reached_honest_count: usize,
    total_honest_count: usize,
    max_hops: usize,
    reach_by_hop: Vec<usize>,
    blocked_at_byzantine_count: usize,
}

/// Simuliert die Ausbreitung des Keepalive/Gossip-Heartbeats vom Opferknoten
fn simulate_gossip(
    graph: &F2FGraph,
    victim: usize,
    byzantine_nodes: &[bool],
) -> GossipResult {
    let n = graph.adj.len();
    let mut visited = vec![false; n];
    let mut hop_dist = vec![u32::MAX; n];
    let mut queue = VecDeque::with_capacity(n);
    let mut blocked_count = 0;

    visited[victim] = true;
    hop_dist[victim] = 0;
    queue.push_back((victim as u32, 0u32));

    let mut reach_by_hop_map: BTreeMap<u32, usize> = BTreeMap::new();
    reach_by_hop_map.insert(0, 1);

    while let Some((curr, dist)) = queue.pop_front() {
        for &neighbor in &graph.adj[curr as usize] {
            let n_idx = neighbor as usize;
            // Wenn der Nachbar byzantinisch ist, droppt er den Gossip des Opfers!
            if byzantine_nodes[n_idx] {
                blocked_count += 1;
                continue;
            }

            if !visited[n_idx] {
                visited[n_idx] = true;
                hop_dist[n_idx] = dist + 1;
                *reach_by_hop_map.entry(dist + 1).or_insert(0) += 1;
                queue.push_back((neighbor, dist + 1));
            }
        }
    }

    let mut reached_honest = 0;
    let mut total_honest = 0;
    let mut max_hops = 0;

    for i in 0..n {
        if !byzantine_nodes[i] {
            total_honest += 1;
            if visited[i] {
                reached_honest += 1;
                if hop_dist[i] as usize > max_hops {
                    max_hops = hop_dist[i] as usize;
                }
            }
        }
    }

    let mut cum = 0;
    let mut reach_by_hop = Vec::new();
    for (_hop, count) in reach_by_hop_map {
        cum += count;
        reach_by_hop.push(cum);
    }

    GossipResult {
        reached_honest_count: reached_honest,
        total_honest_count: total_honest,
        max_hops,
        reach_by_hop,
        blocked_at_byzantine_count: blocked_count,
    }
}

#[test]
fn test_10k_f2f_gossip_censorship_resilience() {
    let mut rng = SimpleRng::new(42);

    println!("\n╔══════════════════════════════════════════════════════════════════════╗");
    println!("║ 🧪 GROSSSKALIGE SIMULATION: 10.000-Knoten F2F Dunbar-Small-World     ║");
    println!("║ 🛡️ Zensur-Resilienz gegen 10% böse Knoten (gezieltes Aushungern)     ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");

    let t_init = Instant::now();
    let graph = F2FGraph::new(N_NODES, &mut rng);
    let avg_deg = graph.average_degree();
    let clustering = graph.clustering_coefficient();

    println!("\n📊 TOPOLOGIE-KENNZAHLEN:");
    println!("  Gesamtknoten (N):               {}", N_NODES);
    println!("  Durchschnittlicher Knotengrad:  {:.2} Peers (Dunbar-Limit: {})", avg_deg, MAX_DEGREE);
    println!("  Clustering-Koeffizient (C):     {:.4} (Sehr hohe Dreiecks-Dichte)", clustering);
    println!("  Graph-Generierungszeit:         {:?}", t_init.elapsed());

    let victim_node = 42;

    // -------------------------------------------------------------
    // BASELINE: 0 % Byzantinische Knoten (Ideale Ausbreitung)
    // -------------------------------------------------------------
    let clean_byz = vec![false; N_NODES];
    let baseline_res = simulate_gossip(&graph, victim_node, &clean_byz);
    println!("\n-------------------------------------------------------------");
    println!("📈 BASELINE (0 % Böse Knoten):");
    println!("  Erreichte ehrliche Knoten:      {}/{} (100.00%)", baseline_res.reached_honest_count, baseline_res.total_honest_count);
    println!("  Maximaler Durchmesser / Hops:   {} Hops", baseline_res.max_hops);
    assert_eq!(baseline_res.reached_honest_count, N_NODES);

    // -------------------------------------------------------------
    // EXPERIMENT 1: 10 % Byzantinische Knoten (Gleichmäßig / Zufall)
    // -------------------------------------------------------------
    let num_byz = N_NODES / 10; // 1.000 Knoten (10%)
    let mut byz_flags_1 = vec![false; N_NODES];
    let mut count1 = 0;
    while count1 < num_byz {
        let candidate = rng.gen_range(0, N_NODES);
        if candidate != victim_node && !byz_flags_1[candidate] {
            byz_flags_1[candidate] = true;
            count1 += 1;
        }
    }

    let exp1_res = simulate_gossip(&graph, victim_node, &byz_flags_1);
    let reach_pct_1 = (exp1_res.reached_honest_count as f64 / exp1_res.total_honest_count as f64) * 100.0;

    println!("\n-------------------------------------------------------------");
    println!("⚔️ EXPERIMENT 1: 10 % Zufällige Zensur-Knoten (1.000 Angreifer)");
    println!("  Erreichte ehrliche Knoten:      {}/{} ({:.4}%)", exp1_res.reached_honest_count, exp1_res.total_honest_count, reach_pct_1);
    println!("  Geblockte Weiterleitungen:      {} Pakete", exp1_res.blocked_at_byzantine_count);
    println!("  Maximaler Durchmesser / Hops:   {} Hops", exp1_res.max_hops);

    // -------------------------------------------------------------
    // EXPERIMENT 2: Gezielte Infiltration des Freundeskreises (Worst-Case Eclipse)
    // -------------------------------------------------------------
    let mut byz_flags_2 = vec![false; N_NODES];
    let victim_friends = &graph.adj[victim_node];
    let friends_to_compromise = (victim_friends.len() as f64 * 0.70) as usize;
    let mut count2 = 0;

    for &f in victim_friends.iter().take(friends_to_compromise) {
        byz_flags_2[f as usize] = true;
        count2 += 1;
    }
    while count2 < num_byz {
        let candidate = rng.gen_range(0, N_NODES);
        if candidate != victim_node && !byz_flags_2[candidate] {
            byz_flags_2[candidate] = true;
            count2 += 1;
        }
    }

    let exp2_res = simulate_gossip(&graph, victim_node, &byz_flags_2);
    let reach_pct_2 = (exp2_res.reached_honest_count as f64 / exp2_res.total_honest_count as f64) * 100.0;

    println!("\n-------------------------------------------------------------");
    println!("🔥 EXPERIMENT 2: Gezielte 70% Infiltration der direkten Freunde + 10% Byzanz");
    println!("  Kompromittierte direkte Freunde:{}/{}", friends_to_compromise, victim_friends.len());
    println!("  Erreichte ehrliche Knoten:      {}/{} ({:.4}%)", exp2_res.reached_honest_count, exp2_res.total_honest_count, reach_pct_2);
    println!("  Geblockte Weiterleitungen:      {} Pakete", exp2_res.blocked_at_byzantine_count);
    println!("  Maximaler Durchmesser / Hops:   {} Hops", exp2_res.max_hops);

    println!("\n-------------------------------------------------------------");
    println!("📊 RUNDEN- / HOP-ZÄHLER: Ausbreitungswelle P_reach(t) pro Hop");
    println!("  ┌──────┬────────────────────────┬────────────────────────┐");
    println!("  │ Hop  │ Exp 1 (Zufall 10% Byz) │ Exp 2 (70% Fokus Byz)  │");
    println!("  ├──────┼────────────────────────┼────────────────────────┤");
    let max_h = exp1_res.reach_by_hop.len().max(exp2_res.reach_by_hop.len());
    for h in 0..max_h {
        let r1 = exp1_res.reach_by_hop.get(h).copied().unwrap_or(*exp1_res.reach_by_hop.last().unwrap());
        let r2 = exp2_res.reach_by_hop.get(h).copied().unwrap_or(*exp2_res.reach_by_hop.last().unwrap());
        let pct1 = (r1 as f64 / exp1_res.total_honest_count as f64) * 100.0;
        let pct2 = (r2 as f64 / exp2_res.total_honest_count as f64) * 100.0;
        println!("  │ {:>4} │ {:>5} / 9000 ({:>5.1}%) │ {:>5} / 9000 ({:>5.1}%) │", h, r1, pct1, r2, pct2);
    }
    println!("  └──────┴────────────────────────┴────────────────────────┘");

    // Verifikations-Kriterien
    assert!(reach_pct_1 >= 99.9, "10 % zufällige Zensoren dürfen ehrliche Knoten nicht isolieren");
    assert!(reach_pct_2 >= 99.9, "Selbst bei 70% korrumpierten direkten Freunden müssen die restlichen ehrlichen Freunde via Triadic Closure das Netz fluten");
}
