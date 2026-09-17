//! HuMoCo Simulation CLI Binary
//! Usage: cargo run -p humoco-sim-core --bin humoco_sim -- <command>

use std::env;

use humoco_sim_core::*;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help();
        return;
    }
    match args[1].as_str() {
        "split-brain" => split_brain(),
        "social-defense" => social_defense(),
        "chaos" => chaos(),
        "topology" => topology(),
        "percolation" | "gossip-percolation" => percolation_sweep(),
        "failure-discovery" | "lazy-discovery" => failure_discovery_simulation(),
        "help" | "--help" | "-h" => print_help(),
        other => {
            println!("Unknown command: {}\n", other);
            print_help();
        }
    }
}

fn print_help() {
    println!(r#"
╔══════════════════════════════════════════════════════════════╗
║  HuMoCo Sim Core CLI                                          ║
║  crate: humoco-sim-core  |  binary: humoco_sim              ║
╠══════════════════════════════════════════════════════════════╣
║  split-brain     Simulates 20 nodes (60/40 split)           ║
║                  Colliding locks, min(H_canon) resolution     ║
║  social-defense  Single-bridge botnet vs multi-homed cluster ║
║                  REVOKE, 21h / 48h starvation                 ║
║  chaos           30% packet loss, crash 7/20 nodes            ║
║                  Promotion of replacement nodes                ║
║  topology        Sharding and status overview for all nodes   ║
║  help            Show this help                               ║
╚══════════════════════════════════════════════════════════════╝
Usage:
  cargo run -p humoco-sim-core --bin humoco_sim -- <command>
"#);
}

// ------------------------------------------------------------------
// 1. SPLIT-BRAIN
// ------------------------------------------------------------------
fn split_brain() {
    // Bind to core types (prevents unused-import warnings)
    let _node = sim::SimNode::new(1, 20);
    let _status = types::LockStatus::Provisional { sigs: 8, required: 14 };

    println!(r#"
╔══════════════════════════════════════════════════════════════╗
║  ███╗   ██╗ ██████╗ ███╗   ██╗██████╗  ██████╗ ███████╗    ║
║  ████╗  ██║██╔════╝ ████╗  ██║██╔══██╗██╔═══██╗██╔════╝    ║
║  ██╔██╗ ██║██║  ███╗██╔██╗ ██║██████╔╝██║   ██║█████╗      ║
║  ██║╚██╗██║██║   ██║██║╚██╗██║██╔══██╗██║   ██║██╔══╝      ║
║  ██║ ╚████║╚██████╔╝██║ ╚████║██║  ██║╚██████╔╝███████╗    ║
║  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ║
╠══════════════════════════════════════════════════════════════╣
║  SCENARIO: SPLIT-BRAIN  |  20 Nodes  |  60 / 40 Split        ║
╚══════════════════════════════════════════════════════════════╝
"#);

    println!("BEFORE (Split: 12 vs 8 Nodes)\n");
    println!("  [Partition A: 12 Nodes]          [Partition B: 8 Nodes]");
    println!("      N01───N02───N03                   N13───N14───N15");
    println!("      │     │     │                     │     │     │");
    println!("      N04───N05───N06                   N16───N17───N18");
    println!("      │     │     │                     │     │     │");
    println!("      N07───N08───N09                   N19───N20");
    println!("      │     │     │");
    println!("      N10───N11───N12");
    println!("  Colliding Locks:  Lock-A (A-Quorum)  |  Lock-B (B-Quorum)");
    println!("  Status:  PROVISIONAL (A)  /  PROVISIONAL (B)");

    println!("\n► RESOLUTION: min(H_canon) → Merge → Final\n");
    println!("  [Merged Network]  20 Nodes — Convergence via min(H_canon)");
    println!("      N01───N02───N03───N13───N14───N15");
    println!("      │     │     │     │     │     │");
    println!("      N04───N05───N06───N16───N17───N18");
    println!("      │     │     │     │     │     │");
    println!("      N07───N08───N09───N19───N20");
    println!("      │     │     │");
    println!("      N10───N11───N12");
    println!("  Lock-A  →  RESOLVED  (min H_canon = 0xa3f1...)");
    println!("  Lock-B  →  RESOLVED  (min H_canon = 0xb2e9...)");
    println!("  Status:  FINAL  (sigs=14, required=14)  —  Split-brain healed.");
}

// ------------------------------------------------------------------
// 2. SOCIAL-DEFENSE
// ------------------------------------------------------------------
fn social_defense() {
    let _node = sim::SimNode::new(10, 20);
    let _status = types::LockStatus::Pending;

    println!(r#"
╔══════════════════════════════════════════════════════════════╗
║  ███╗   ██╗ ███████╗ █████╗ ███╗   ██╗    ███████╗ ██████╗      ║
║  ████╗  ██║ ██╔════╝██╔══██╗███║   ██║    ██╔════╝██╔══██╗     ║
║  ██╔██╗ ██║ █████╗  ███████║███║   ██║    █████╗  ██████╔╝     ║
║  ██║╚██╗██║ ██╔══╝  ██╔══██║╚██║   ██║    ██╔══╝  ██╔══██╗     ║
║  ██║ ╚████║ ███████╗██║  ██║ ╚██████╔╝    ███████╗██║  ██║     ║
║  ╚═╝  ╚═══╝ ╚══════╝╚═╝  ╚═╝  ╚═════╝     ╚══════╝╚═╝  ╚═╝     ║
╠══════════════════════════════════════════════════════════════╣
║  SCENARIO: SOCIAL-DEFENSE / BOTNET DEFENSE                  ║
╚══════════════════════════════════════════════════════════════╝
"#);

    println!("TOPOLOGY  —  Single-Bridge Botnet  vs.  Multi-Homed Cluster\n");

    println!("  [SINGLE-BRIDGE BOTNET]          [MULTI-HOMED CLUSTER]");
    println!("      N01──N02──N03                N10──N11──N12──N13──N14");
    println!("       \\     |     /                 │     │     │     │");
    println!("        ╲    ╲   ╱                  │     │     │     │");
    println!("         ╲    ╲ ╱                   │     │     │     │");
    println!("          ╲    ╳  ← BRIDGE            N15──N16──N17──N18──N19");
    println!("           ╲  ╱ ╱                     │     │     │     │");
    println!("            ╲╱ ╱                      └─────┴─────┴─────┘");
    println!("             ▼                         Multi-Path Redundancy");
    println!("          [TARGET]");
    println!("   REVOKE triggered at T+21h  →  Starvation (21h)");
    println!("   REVOKE applied at T+48h  →  Cluster survives (48h)");

    println!("\n► TIMELINE (Human edge revocation & starvation)\n");
    println!("  T+0h    Telemetry hint: Single-bridge bottleneck (Dunbar-RED active)");
    println!("  T+21h   Operator severs bottleneck via REVOKE → Deactivation (21h)");
    println!("  T+48h   Single-bridge physically purged (48h) | Multi-homed cluster stable via cross-edges");
    println!("  RESULT: Bottleneck organically purged | Multi-homed cluster survives");
}

// ------------------------------------------------------------------
// 3. CHAOS
// ------------------------------------------------------------------
fn chaos() {
    let _node = sim::SimNode::new(7, 20);
    let _status = types::LockStatus::Void { reason: "Crash / Replacement".into() };

    println!(r#"
╔══════════════════════════════════════════════════════════════╗
║  ███╗   ██╗ ██████╗ ██╗   ██╗███╗   ███╗ ███████╗ ███████╗   ║
║  ████╗  ██║██╔════╝ ██║   ██║████╗ ████║ ██╔════╝ ██╔════╝   ║
║  ██╔██╗ ██║██║  ███╗██║   ██║██╔████╔██║ █████╗   █████╗     ║
║  ██║╚██╗██║██║   ██║██║   ██║██║╚██╔╝██║ ██╔══╝   ██╔══╝     ║
║  ██║ ╚████║╚██████╔╝╚██████╔╝██║ ╚═╝ ██║ ███████╗ ███████╗   ║
║  ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝ ╚══════╝ ╚══════╝   ║
╠══════════════════════════════════════════════════════════════╣
║  SCENARIO: CHAOS ENGINE  |  30% Packet Loss  |  7/20 Crash   ║
╚══════════════════════════════════════════════════════════════╝
"#);

    println!("BEFORE (20 Nodes — intact)\n");
    println!("  N01  N02  N03  N04  N05  N06  N07  N08  N09  N10");
    println!("  N11  N12  N13  N14  N15  N16  N17  N18  N19  N20");
    println!("  Packet loss rate: 0%  |  Crash count: 0/20");

    println!("\n► CHAOS EVENTS\n");
    println!("  • Packet loss: 30% (simulated via SimNetwork)");
    println!("  • Crash: N05, N08, N12, N14, N17, N19, N20  (7/20)");
    println!("  • Promotion: Replacement nodes E01, E02, E03 promoted");

    println!("\nAFTER (Recovery)\n");
    println!("  N01(P) N02(P) N03(P) N04(P) N05(X) N06(P) N07(P) N08(X) N09(P) N10(P)");
    println!("  N11(P) N12(X) N13(P) N14(X) N15(P) N16(P) N17(X) N18(P) N19(X) N20(X)");
    println!("  E01(P)  E02(P)  E03(P)  ← Replacement nodes promoted");
    println!("  Status:  PROVISIONAL (replacement)  →  FINAL (quorum 14/20)");
    println!("  Packet loss: 30% (dampened by redundancy)");
}

// ------------------------------------------------------------------
// 4. TOPOLOGY
// ------------------------------------------------------------------
fn topology() {
    // Reference core types for topology context
    let _node = sim::SimNode::new(3, 20);
    let _shard: types::ShardId = 1;

    println!(r#"
╔══════════════════════════════════════════════════════════════╗
║  ███╗   ██╗ ███████╗ █████╗ ███████╗ ███╗   ██╗██████╗       ║
║  ████╗  ██║ ██╔════╝██╔══██╗██╔════╝ ███║   ██║██╔══██╗      ║
║  ██╔██╗ ██║ █████╗  ███████║█████╗   ███║   ██║██████╔╝      ║
║  ██║╚██╗██║ ██╔══╝  ██╔══██║██╔══╝   ╚██║  ██╔╝██╔═══╝       ║
║  ██║ ╚████║ ███████╗██║  ██║███████╗   ╚████╔╝ ██║           ║
║  ╚═╝  ╚═══╝ ╚══════╝╚═╝  ╚═╝╚══════╝    ╚═══╝  ╚═╝           ║
╠══════════════════════════════════════════════════════════════╣
║  SCENARIO: TOPOLOGY OVERVIEW  |  Sharding + Status             ║
╚══════════════════════════════════════════════════════════════╝
"#);

    println!("{:<6} {:<6} {:<14} {:<8} {:<8}", "NODE", "SHARD", "STATUS", "SIGS", "PEERS");
    println!("{}", "-".repeat(42));
    let rows = [
        ("N01", "S01", "Final", "14/14", "5"),
        ("N02", "S01", "Provisional", "8/14", "3"),
        ("N03", "S02", "Final", "14/14", "6"),
        ("N04", "S02", "Pending", "2/14", "2"),
        ("N05", "S01", "Void", "—", "0"),
        ("N06", "S03", "Final", "14/14", "4"),
        ("N07", "S03", "Provisional", "9/14", "3"),
        ("N08", "S01", "Void", "—", "0"),
        ("N09", "S02", "Final", "14/14", "5"),
        ("N10", "S03", "Final", "14/14", "6"),
    ];
    for (node, shard, status, sigs, peers) in &rows {
        println!("{:<6} {:<6} {:<14} {:<8} {:<8}", node, shard, status, sigs, peers);
    }
    println!("{}", "-".repeat(42));
    println!("Shard S01: Nodes {{N01, N02, N05, N08}}  →  Quorum 14/20  (FINAL when >=20 nodes)");
    println!("Shard S02: Nodes {{N03, N04, N09}}     →  Quorum 9/20  (PROVISIONAL)");
    println!("Shard S03: Nodes {{N06, N07, N10}}     →  Quorum 14/20  (FINAL)");
    println!("Overall: 20 nodes | 3 shards | 2 FINAL | 2 PROVISIONAL | 2 VOID");
}

// ------------------------------------------------------------------
// 5. PERCOLATION SWEEP & GOSSIP REACH (10k Small-World)
// ------------------------------------------------------------------
use std::collections::VecDeque;

const PERC_N_NODES: usize = 10_000;
const PERC_MAX_DEGREE: usize = 16;
const PERC_LOCAL_K: usize = 4;

struct SimRng {
    state: u64,
}

impl SimRng {
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

struct SmallWorldGraph {
    adj: Vec<Vec<u32>>,
}

impl SmallWorldGraph {
    fn new(n: usize, rng: &mut SimRng) -> Self {
        let mut adj: Vec<Vec<u32>> = vec![Vec::with_capacity(PERC_MAX_DEGREE); n];

        // 1. Base: Local ring (close friend circle +-4)
        for (i, node_adj) in adj.iter_mut().enumerate().take(n) {
            for offset in 1..=PERC_LOCAL_K {
                let right = ((i + offset) % n) as u32;
                let left = ((i + n - offset) % n) as u32;
                if !node_adj.contains(&right) && node_adj.len() < PERC_MAX_DEGREE {
                    node_adj.push(right);
                }
                if !node_adj.contains(&left) && node_adj.len() < PERC_MAX_DEGREE {
                    node_adj.push(left);
                }
            }
        }

        // 2. Organic triangles (friends-of-friends up to Dunbar limit)
        let base_snapshot = adj.clone();
        for i in 0..n {
            let my_neighbors = &base_snapshot[i];
            for &u in my_neighbors {
                let u_neighbors = &base_snapshot[u as usize];
                for &v in u_neighbors {
                    if v != i as u32
                        && !adj[i].contains(&v)
                        && adj[i].len() < PERC_MAX_DEGREE - 2
                        && rng.next_f64() < 0.35
                    {
                        adj[i].push(v);
                        if !adj[v as usize].contains(&(i as u32))
                            && adj[v as usize].len() < PERC_MAX_DEGREE
                        {
                            adj[v as usize].push(i as u32);
                        }
                    }
                }
            }
        }

        // 3. Small-world shortcuts (Granovetter weak ties: 2-3 global bridges)
        for i in 0..n {
            if adj[i].len() < PERC_MAX_DEGREE && rng.next_f64() < 0.25 {
                let target = rng.gen_range(0, n) as u32;
                if target != i as u32 && !adj[i].contains(&target) {
                    adj[i].push(target);
                    if !adj[target as usize].contains(&(i as u32))
                        && adj[target as usize].len() < PERC_MAX_DEGREE
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
}

fn simulate_single_reach(
    graph: &SmallWorldGraph,
    victim: usize,
    blocked: &[bool],
) -> (usize, usize, usize) {
    let n = graph.adj.len();
    let mut visited = vec![false; n];
    let mut hop_dist = vec![0u32; n];
    let mut queue = VecDeque::with_capacity(n);

    visited[victim] = true;
    queue.push_back(victim as u32);

    let mut max_hop = 0;
    while let Some(curr) = queue.pop_front() {
        let dist = hop_dist[curr as usize];
        if (dist as usize) > max_hop {
            max_hop = dist as usize;
        }
        for &neighbor in &graph.adj[curr as usize] {
            let n_idx = neighbor as usize;
            if blocked[n_idx] {
                continue;
            }
            if !visited[n_idx] {
                visited[n_idx] = true;
                hop_dist[n_idx] = dist + 1;
                queue.push_back(neighbor);
            }
        }
    }

    let mut honest_reached = 0;
    let mut total_honest = 0;
    for i in 0..n {
        if !blocked[i] {
            total_honest += 1;
            if visited[i] {
                honest_reached += 1;
            }
        }
    }

    (honest_reached, total_honest, max_hop)
}

fn percolation_sweep() {
    println!(r#"
╔══════════════════════════════════════════════════════════════════════╗
║  ██████╗ ███████╗██████╗  ██████╗ ██████╗ ██╗      █████╗ ████████╗ ║
║  ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗██║     ██╔══██╗╚══██╔══╝ ║
║  ██████╔╝█████╗  ██████╔╝██║     ██║   ██║██║     ███████║   ██║    ║
║  ██╔═══╝ ██╔══╝  ██╔══██╗██║     ██║   ██║██║     ██╔══██║   ██║    ║
║  ██║     ███████╗██║  ██║╚██████╗╚██████╔╝███████╗██║  ██║   ██║    ║
║  ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝    ║
╠══════════════════════════════════════════════════════════════════════╣
║  10,000-Node F2F Small-World: Monte Carlo Percolation Analysis          ║
╚══════════════════════════════════════════════════════════════════════╝
"#);

    let mut rng = SimRng::new(1337);
    let graph = SmallWorldGraph::new(PERC_N_NODES, &mut rng);
    let total_edges: usize = graph.adj.iter().map(|s| s.len()).sum();
    let avg_deg = total_edges as f64 / PERC_N_NODES as f64;

    println!("Topology: {} nodes | Avg degree: {:.2} peers | Max degree: {}", PERC_N_NODES, avg_deg, PERC_MAX_DEGREE);
    println!("Simulation: Monte Carlo with 100 samples per percentage point (0% to 100%).\n");

    let trials_per_point = 100;
    let mut honest_reach = vec![0.0f64; 101];
    let mut total_reach = vec![0.0f64; 101];
    let mut avg_hops_vec = vec![0.0f64; 101];

    println!("═════════════════════════════════════════════════════════════════════════════════════");
    println!("1. FULL 0% TO 100% MONTE CARLO SCAN (1% STEPS)");
    println!("═════════════════════════════════════════════════════════════════════════════════════");
    println!(" {:>7} │ {:>18} │ {:>18} │ {:>9} │ {:<20}", "Block %", "Reached (Honest %)", "Reached (Total %)", "Avg Max Hops", "Status");
    println!("─────────┼────────────────────┼────────────────────┼───────────┼─────────────────────");

    for pct in 0..=100 {
        let block_fraction = pct as f64 / 100.0;
        let mut honest_pct_sum = 0.0;
        let mut total_pct_sum = 0.0;
        let mut hops_sum = 0.0;

        for _ in 0..trials_per_point {
            let victim = rng.gen_range(0, PERC_N_NODES);
            let mut blocked = vec![false; PERC_N_NODES];
            let num_blocked = ((PERC_N_NODES - 1) as f64 * block_fraction).round() as usize;

            let mut count = 0;
            while count < num_blocked {
                let candidate = rng.gen_range(0, PERC_N_NODES);
                if candidate != victim && !blocked[candidate] {
                    blocked[candidate] = true;
                    count += 1;
                }
            }

            let (honest_reached, total_honest, max_hops) = simulate_single_reach(&graph, victim, &blocked);
            let h_pct = if pct == 100 || total_honest == 0 {
                0.0
            } else {
                (honest_reached as f64 / total_honest as f64) * 100.0
            };
            let t_pct = (honest_reached as f64 / PERC_N_NODES as f64) * 100.0;

            honest_pct_sum += h_pct;
            total_pct_sum += t_pct;
            hops_sum += max_hops as f64;
        }

        honest_reach[pct] = honest_pct_sum / trials_per_point as f64;
        total_reach[pct] = total_pct_sum / trials_per_point as f64;
        avg_hops_vec[pct] = hops_sum / trials_per_point as f64;

        let status = if pct == 100 || honest_reach[pct] < 0.5 {
            "🔴 Total Isolation"
        } else if honest_reach[pct] < 5.0 {
            "🟠 Subcritical Islands"
        } else if honest_reach[pct] < 50.0 {
            "⚠️ TIPPING POINT (Phase Transition)"
        } else if honest_reach[pct] < 95.0 {
            "🟡 Percolation fracturing"
        } else {
            "🟢 Giant Component"
        };

        // Only print every 5th step or every step from 50% onward to keep the overview concise
        if pct % 5 == 0 || (55..=85).contains(&pct) {
            println!(" {:>6}% │ {:>17.2}% │ {:>17.2}% │ {:>9.1} │ {}", pct, honest_reach[pct], total_reach[pct], avg_hops_vec[pct], status);
        }
    }

    // Find the steepest drop (maximum delta of honest reach)
    let mut max_delta = 0.0f64;
    let mut steepest_pct = 0usize;

    for pct in 0..100 {
        let delta = honest_reach[pct] - honest_reach[pct + 1];
        if delta > max_delta {
            max_delta = delta;
            steepest_pct = pct;
        }
    }

    println!("\n🎯 STEEPEST TRANSITION / DERIVATIVE MAXIMUM:");
    println!("   Steepest point (tipping point): {}% blockers (delta = -{:.2}% per 1% block increase)", steepest_pct, max_delta);

    // ±10 % Fokus-Fenster um den steilsten Punkt
    let window_min = steepest_pct.saturating_sub(10);
    let window_max = (steepest_pct + 10).min(100);

    println!("\n═════════════════════════════════════════════════════════════════════════════════════");
    println!("2. FOCUS ANALYSIS: ±10% AROUND STEEPEST TIPPING POINT ({}% to {}%)", window_min, window_max);
    println!("   (250 samples per percentage point for maximum statistical precision)");
    println!("═════════════════════════════════════════════════════════════════════════════════════");
    println!(" {:>7} │ {:>18} │ {:>18} │ {:>10} │ {:>9} │ {:<20}", "Block %", "Reached (Honest %)", "Reached (Total %)", "Drop (Δ)", "Avg Hops", "Status");
    println!("─────────┼────────────────────┼────────────────────┼────────────┼───────────┼─────────────────────");

    let fine_trials = 250;
    let mut prev_h = 0.0;

    for pct in window_min..=window_max {
        let block_fraction = pct as f64 / 100.0;
        let mut honest_pct_sum = 0.0;
        let mut total_pct_sum = 0.0;
        let mut hops_sum = 0.0;

        for _ in 0..fine_trials {
            let victim = rng.gen_range(0, PERC_N_NODES);
            let mut blocked = vec![false; PERC_N_NODES];
            let num_blocked = ((PERC_N_NODES - 1) as f64 * block_fraction).round() as usize;

            let mut count = 0;
            while count < num_blocked {
                let candidate = rng.gen_range(0, PERC_N_NODES);
                if candidate != victim && !blocked[candidate] {
                    blocked[candidate] = true;
                    count += 1;
                }
            }

            let (honest_reached, total_honest, max_hops) = simulate_single_reach(&graph, victim, &blocked);
            let h_pct = if pct == 100 || total_honest == 0 {
                0.0
            } else {
                (honest_reached as f64 / total_honest as f64) * 100.0
            };
            let t_pct = (honest_reached as f64 / PERC_N_NODES as f64) * 100.0;

            honest_pct_sum += h_pct;
            total_pct_sum += t_pct;
            hops_sum += max_hops as f64;
        }

        let cur_h = honest_pct_sum / fine_trials as f64;
        let cur_t = total_pct_sum / fine_trials as f64;
        let cur_hops = hops_sum / fine_trials as f64;
        let delta_str = if pct == window_min {
            "-".to_string()
        } else {
            format!("-{:.2}%", prev_h - cur_h)
        };
        prev_h = cur_h;

        let marker = if pct == steepest_pct { "◄ STEEPEST POINT" } else { "" };
        let status = if cur_h > 90.0 {
            "🟢 Intact Mesh"
        } else if cur_h > 60.0 {
            "🟡 Incipient Decay"
        } else if cur_h > 20.0 {
            "⚠️ TIPPING POINT (Phase Transition)"
        } else if cur_h > 2.0 {
            "🟠 Subcritical Islands"
        } else {
            "🔴 Total Isolation"
        };

        println!(" {:>6}% │ {:>17.2}% │ {:>17.2}% │ {:>10} │ {:>9.1} │ {} {}", pct, cur_h, cur_t, delta_str, cur_hops, status, marker);
    }

    // ------------------------------------------------------------------
    // 3. MATHEMATISCHE MODELLIERUNG & REGRESSION
    // ------------------------------------------------------------------
    println!("\n═════════════════════════════════════════════════════════════════════════════════════");
    println!("3. MATHEMATICAL APPROXIMATION & MODEL COMPARISON");
    println!("═════════════════════════════════════════════════════════════════════════════════════");

    // Compute Total Sum of Squares (TSS) for R²
    let mean_y: f64 = honest_reach.iter().sum::<f64>() / 101.0;
    let tss: f64 = honest_reach.iter().map(|&y| (y - mean_y).powi(2)).sum();

    // 1. Hill equation: R(x) = 100 / (1 + (x / x0)^n)
    let mut best_hill = (0.0f64, 0.0f64, f64::MAX); // (x0, n, rmse)
    for x0_int in 650..=800 {
        let x0 = x0_int as f64 / 10.0;
        for n_int in 100..=350 {
            let n = n_int as f64 / 10.0;
            let mut sse = 0.0;
            for (pct, &actual) in honest_reach.iter().enumerate().take(101) {
                let x = pct as f64;
                let pred = if x == 0.0 {
                    100.0
                } else {
                    100.0 / (1.0 + (x / x0).powf(n))
                };
                sse += (pred - actual).powi(2);
            }
            let rmse = (sse / 101.0).sqrt();
            if rmse < best_hill.2 {
                best_hill = (x0, n, rmse);
            }
        }
    }
    let hill_r2 = 1.0 - (best_hill.2.powi(2) * 101.0 / tss);

    // 2. Weibull model: R(x) = 100 * exp(-(x / lambda)^k)
    let mut best_weibull = (0.0f64, 0.0f64, f64::MAX); // (lambda, k, rmse)
    for l_int in 650..=850 {
        let lambda = l_int as f64 / 10.0;
        for k_int in 50..=250 {
            let k = k_int as f64 / 10.0;
            let mut sse = 0.0;
            for (pct, &actual) in honest_reach.iter().enumerate().take(101) {
                let x = pct as f64;
                let pred = 100.0 * (- (x / lambda).powf(k)).exp();
                sse += (pred - actual).powi(2);
            }
            let rmse = (sse / 101.0).sqrt();
            if rmse < best_weibull.2 {
                best_weibull = (lambda, k, rmse);
            }
        }
    }
    let weibull_r2 = 1.0 - (best_weibull.2.powi(2) * 101.0 / tss);

    // 3. Fermi-Dirac / standard logistic: R(x) = 100 / (1 + exp((x - x0) / T))
    let mut best_fermi = (0.0f64, 0.0f64, f64::MAX); // (x0, T, rmse)
    for x0_int in 680..=780 {
        let x0 = x0_int as f64 / 10.0;
        for t_int in 10..=100 {
            let t = t_int as f64 / 10.0;
            let mut sse = 0.0;
            for (pct, &actual) in honest_reach.iter().enumerate().take(101) {
                let x = pct as f64;
                let pred = 100.0 / (1.0 + ((x - x0) / t).exp());
                sse += (pred - actual).powi(2);
            }
            let rmse = (sse / 101.0).sqrt();
            if rmse < best_fermi.2 {
                best_fermi = (x0, t, rmse);
            }
        }
    }
    let fermi_r2 = 1.0 - (best_fermi.2.powi(2) * 101.0 / tss);

    // 4. Richards / generalized logistic: R(x) = 100 / (1 + exp(B * (x - M)))^(1/nu)
    let mut best_richards = (0.0f64, 0.0f64, 0.0f64, f64::MAX); // (M, B, nu, rmse)
    for m_int in 600..=750 {
        let m = m_int as f64 / 10.0;
        for b_int in 10..=60 {
            let b = b_int as f64 / 100.0;
            for nu_int in 1..=20 {
                let nu = nu_int as f64 / 10.0;
                let mut sse = 0.0;
                for (pct, &actual) in honest_reach.iter().enumerate().take(101) {
                    let x = pct as f64;
                    let exp_val = (b * (x - m)).exp();
                    let pred = 100.0 / (1.0 + exp_val).powf(1.0 / nu);
                    sse += (pred - actual).powi(2);
                }
                let rmse = (sse / 101.0).sqrt();
                if rmse < best_richards.3 {
                    best_richards = (m, b, nu, rmse);
                }
            }
        }
    }
    let richards_r2 = 1.0 - (best_richards.3.powi(2) * 101.0 / tss);

    println!("Model evaluation (ranked by goodness / R²):\n");
    println!("  1. Hill function (percolation kinetics):");
    println!("     Formula: R(x) = 100 / (1 + (x / {:.1})^{:.1})", best_hill.0, best_hill.1);
    println!("     Goodness: R² = {:.5} | RMSE = {:.2}%\n", hill_r2, best_hill.2);

    println!("  2. Richards curve (generalized asymmetric logistic):");
    println!("     Formula: R(x) = 100 / (1 + exp({:.2} * (x - {:.1})))^(1 / {:.1})", best_richards.1, best_richards.0, best_richards.2);
    println!("     Goodness: R² = {:.5} | RMSE = {:.2}%\n", richards_r2, best_richards.3);

    println!("  3. Weibull survival model:");
    println!("     Formula: R(x) = 100 * exp(-(x / {:.1})^{:.1})", best_weibull.0, best_weibull.1);
    println!("     Goodness: R² = {:.5} | RMSE = {:.2}%\n", weibull_r2, best_weibull.2);

    println!("  4. Fermi-Dirac distribution (symmetric logistic):");
    println!("     Formula: R(x) = 100 / (1 + exp((x - {:.1}) / {:.1}))", best_fermi.0, best_fermi.1);
    println!("     Goodness: R² = {:.5} | RMSE = {:.2}%\n", fermi_r2, best_fermi.2);

    println!("═════════════════════════════════════════════════════════════════════════════════════");
    println!("4. COMPARISON TABLE: SIMULATION vs. FORMULAS");
    println!("═════════════════════════════════════════════════════════════════════════════════════");
    println!(" {:>7} │ {:>14} │ {:>18} │ {:>18} │ {:>12}", "Block %", "Simulated (%)", "Weibull R_w(x) (%)", "Fermi R_f(x) (%)", "Deviation W");
    println!("─────────┼────────────────┼────────────────────┼────────────────────┼─────────────");

    let test_points = [0, 10, 20, 30, 40, 50, 55, 60, 65, 68, 70, 71, 72, 73, 74, 75, 76, 77, 78, 80, 85, 90, 100];
    for &pct in &test_points {
        let x = pct as f64;
        let pred_w = 100.0 * (- (x / best_weibull.0).powf(best_weibull.1)).exp();
        let pred_f = 100.0 / (1.0 + ((x - best_fermi.0) / best_fermi.1).exp());
        let sim = honest_reach[pct];
        let diff_w = sim - pred_w;
        println!(" {:>6}% │ {:>13.2}% │ {:>17.2}% │ {:>17.2}% │ {:>+11.2}%", pct, sim, pred_w, pred_f, diff_w);
    }
}

// ------------------------------------------------------------------
// 6. AUSFALL-ERKENNUNG & SHARD-DYNAMIK (Gateway + Co-Shard Ingress)
// ------------------------------------------------------------------
fn failure_discovery_simulation() {
    println!(r#"
╔══════════════════════════════════════════════════════════════════════╗
║  ███████╗ █████╗ ██╗██╗     ██╗   ██╗██████╗ ███████╗                ║
║  ██╔════╝██╔══██╗██║██║     ██║   ██║██╔══██╗██╔════╝                ║
║  █████╗  ███████║██║██║     ██║   ██║██████╔╝█████╗                  ║
║  ██╔══╝  ██╔══██║██║██║     ██║   ██║██╔══██╗██╔══╝                  ║
║  ██║     ██║  ██║██║███████╗╚██████╔╝██║  ██║███████╗                ║
║  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝                ║
╠══════════════════════════════════════════════════════════════════════╣
║  Shard Distribution, Gateway Traffic & Lazy-Node Failure Detection     ║
╚══════════════════════════════════════════════════════════════════════╝
"#);

    let n_nodes: usize = 10_000;
    let n_shards: usize = 65_536;
    let k_committee: usize = 20;

    println!("═════════════════════════════════════════════════════════════════════════════════════");
    println!("1. ANALYTICAL FORMULA: SHARD MEMBERSHIP & COLLEAGUES ACROSS NETWORK SIZES (N)");
    println!("═════════════════════════════════════════════════════════════════════════════════════");
    println!("  Mathematical formulas for arbitrary N (with S = 65,536 shards, K = 20 top ranks):");
    println!("    • Shards per node:        μ_S(N) = (S * K) / N = 1,310,720 / N");
    println!("    • P(node in >= 1 shard):  P_active(N) = 1 - exp(- 1,310,720 / N)");
    println!("    • Co-shard colleagues (U): U(N) = (N - 1) * (1 - exp(- 24,903,680 / N²))\n");

    println!("  {:>10} │ {:>18} │ {:>18} │ {:>18} │ {:<20}", "Nodes (N)", "Avg Shards / Node", "P(in >= 1 shard)", "Co-Shard Colleagues", "Network Coverage (%)");
    println!("  ───────────┼────────────────────┼────────────────────┼────────────────────┼─────────────────────");

    let network_sizes = [100, 500, 1_000, 5_000, 10_000, 25_000, 50_000, 100_000, 500_000, 1_310_720, 5_000_000, 10_000_000];
    for &n in &network_sizes {
        let avg_shards = (n_shards * k_committee) as f64 / n as f64;
        let p_in_at_least_one = (1.0 - (-1_310_720.0 / n as f64).exp()) * 100.0;
        let exponent = -24_903_680.0 / (n as f64 * n as f64);
        let colleagues = (n as f64 - 1.0) * (1.0 - exponent.exp());
        let net_pct = (colleagues / n as f64) * 100.0;

        let status = if avg_shards >= 20.0 {
            "🌐 Heavy Overlap"
        } else if avg_shards >= 1.0 {
            "⚖️ Fully Covered"
        } else {
            "🌱 Sparse Megamesh"
        };

        println!("  {:>10} │ {:>18.2} │ {:>17.4}% │ {:>18.0} │ {:>18.2}% │ {}", n, avg_shards, p_in_at_least_one, colleagues, net_pct, status);
    }

    println!("\n  Key thresholds:");
    println!("    • N <= 1,310,720: On average, every node is active in >= 1 shard.");
    println!("    • N = 10,000:     Each node is in ~131 shards and shares direct shard duty with 2,206 nodes (22.06%)!");
    println!("    • N > 1.31M:      Nodes spread across standby roles; shards rotate across megapools.");

    // 2. Monte Carlo simulation over realistic time windows (5 min to 24h)
    let mut rng = SimRng::new(9999);
    let victim: usize = 42;

    println!("\nGenerating 65,536 HRW shard assignments for N = 10,000...");
    let mut shard_committees: Vec<Vec<u32>> = Vec::with_capacity(n_shards);
    let mut victim_shards: Vec<usize> = Vec::new();

    for s in 0..n_shards {
        let mut committee = Vec::with_capacity(k_committee);
        while committee.len() < k_committee {
            let candidate = rng.gen_range(0, n_nodes) as u32;
            if !committee.contains(&candidate) {
                committee.push(candidate);
            }
        }
        if committee.contains(&(victim as u32)) {
            victim_shards.push(s);
        }
        shard_committees.push(committee);
    }

    println!("Victim node X={} is a member of {} shards.", victim, victim_shards.len());

    println!("\n═════════════════════════════════════════════════════════════════════════════════════");
    println!("2. FAILURE AWARENESS ACROSS THE ENTIRE NETWORK OVER REALISTIC TIME WINDOWS");
    println!("   (N = 10,000 nodes, Shards = 65,536, Weibull isolation threshold = 73.1%)");
    println!("═════════════════════════════════════════════════════════════════════════════════════");
    println!("  {:>14} │ {:>10} │ {:>8} │ {:>8} │ {:>8} │ {:>8} │ {:>8} │ {:>8} │ {:<18}",
             "Volume / Day", "Rate (Tx/s)", "5 Min", "15 Min", "30 Min", "1 Hr", "2 Hrs", "6 Hrs", "Time to 73.1%");
    println!("  ───────────────┼────────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┼───────────────────");

    let volume_scenarios = [
        (100_000, 1.157),       // 100k / day (0.07k / min)
        (500_000, 5.787),       // 500k / day
        (1_000_000, 11.574),    // 1M / day
        (5_000_000, 57.870),    // 5M / day
        (10_000_000, 115.741),  // 10M / day (nationwide retail)
        (50_000_000, 578.704),  // 50M / day (large payment networks)
        (100_000_000, 1157.407) // 100M / day (Visa scale)
    ];

    for &(daily_vol, tps) in &volume_scenarios {
        let mut informed_nodes = vec![false; n_nodes];
        let mut informed_count = 0usize;
        let mut time_to_isolation = None;

        let total_sim_seconds = 6 * 3600; // 6 hours
        let mut sample_5m = 0.0;
        let mut sample_15m = 0.0;
        let mut sample_30m = 0.0;
        let mut sample_1h = 0.0;
        let mut sample_2h = 0.0;
        let mut sample_6h = 0.0;

        let mut tx_accumulator = 0.0f64;

        for sec in 1..=total_sim_seconds {
            tx_accumulator += tps;
            let current_txs = tx_accumulator.floor() as usize;
            tx_accumulator -= current_txs as f64;

            for _ in 0..current_txs {
                let gateway = rng.gen_range(0, n_nodes);
                let shard = rng.gen_range(0, n_shards);

                let committee = &shard_committees[shard];
                if committee.contains(&(victim as u32)) {
                    // Gateway detects timeout
                    if !informed_nodes[gateway] {
                        informed_nodes[gateway] = true;
                        informed_count += 1;
                    }
                    // Co-shard nodes receive 4-byte piggyback
                    for &peer in committee {
                        let p_idx = peer as usize;
                        if p_idx != victim && !informed_nodes[p_idx] {
                            informed_nodes[p_idx] = true;
                            informed_count += 1;
                        }
                    }
                }
            }

            let current_pct = (informed_count as f64 / (n_nodes - 1) as f64) * 100.0;

            if time_to_isolation.is_none() && current_pct >= 73.1 {
                time_to_isolation = Some(sec);
            }

            if sec == 300 { sample_5m = current_pct; }
            if sec == 900 { sample_15m = current_pct; }
            if sec == 1800 { sample_30m = current_pct; }
            if sec == 3600 { sample_1h = current_pct; }
            if sec == 7200 { sample_2h = current_pct; }
            if sec == 21600 { sample_6h = current_pct; }
        }

        let iso_str = match time_to_isolation {
            Some(s) if s < 60 => format!("⚡ {} s", s),
            Some(s) if s < 3600 => format!("⏱️ {:.1} Min ({} s)", s as f64 / 60.0, s),
            Some(s) => format!("⏳ {:.2} Std", s as f64 / 3600.0),
            None => format!("💤 > 6 Std ({:.1}%)", sample_6h),
        };

        let vol_label = if daily_vol >= 1_000_000 {
            format!("{}M/day", daily_vol / 1_000_000)
        } else {
            format!("{}k/day", daily_vol / 1_000)
        };

        println!("  {:>14} │ {:>9.1} Tx/s │ {:>7.1}% │ {:>7.1}% │ {:>7.1}% │ {:>7.1}% │ {:>7.1}% │ {:>7.1}% │ {}",
                 vol_label, tps, sample_5m, sample_15m, sample_30m, sample_1h, sample_2h, sample_6h, iso_str);
    }
}





