#![forbid(unsafe_code)]
//! Isolated research: actual HRW-score experiments and authenticated source transfer.
//! Neither a new membership protocol nor daemon receiver enforcement.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use humoco_sim_core::types::hrw_score_32;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Instant;

type Hash = [u8; 32];
const PAGE: usize = 32;
const MAX_RECORDS: u64 = 4096;

fn digest(domain: &[u8], fields: &[&[u8]]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[domain.len() as u8]);
    h.update(domain);
    for field in fields {
        h.update(field);
    }
    *h.finalize().as_bytes()
}
fn check(ok: bool, why: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(why.to_owned())
    }
}
fn ticket(id: u64, trial: u64) -> Hash {
    digest(
        b"RESEARCH_ENVELOPE_TICKET",
        &[&id.to_le_bytes(), &trial.to_le_bytes()],
    )
}

// Exact sampling-without-replacement probability for a non-adaptive uniform
// twenty-member subset. No shard independence or actual attacker fraction claimed.
fn choose(n: u64, k: u64) -> f64 {
    if k > n {
        return 0.0;
    }
    let k = k.min(n - k);
    (0..k).fold(1.0, |acc, i| acc * (n - i) as f64 / (i + 1) as f64)
}
fn hypergeom_tail(n: u64, bad: u64, minimum: u64) -> f64 {
    if minimum > bad {
        return 0.0;
    }
    (minimum..=20.min(bad))
        .map(|k| choose(bad, k) * choose(n - bad, 20 - k) / choose(n, 20))
        .sum()
}

fn committee(tickets: &[Hash], shard: u16) -> Vec<usize> {
    // O(N log 20), fixed heap of twenty best full scores. Actual production
    // selector additionally clones/deduplicates/sorts; this is a favorable floor.
    let mut selected = std::collections::BinaryHeap::new();
    for (i, t) in tickets.iter().enumerate() {
        selected.push(std::cmp::Reverse((hrw_score_32(t, shard), i)));
        if selected.len() > 20 {
            selected.pop();
        }
    }
    selected
        .into_iter()
        .map(|std::cmp::Reverse((_, i))| i)
        .collect()
}

fn risk_and_scaling() -> Result<(), String> {
    // Necessary quorum inequalities, not a proposed change to selected 14/20.
    for unavailable in 0..=6 {
        let available = 20 - 6 - unavailable;
        println!("{{\"kind\":\"fault_envelope\",\"n\":20,\"q\":14,\"byzantine_withholding\":6,\"honest_unavailable\":{unavailable},\"correct_responses\":{available},\"quorum_possible\":{}}}", available>=14);
    }
    let feasible: Vec<_> = (14..=25)
        .flat_map(|n| (1..=n).map(move |q| (n, q)))
        .filter(|(n, q)| 2 * q > n + 6 && *q < n - 6)
        .collect();
    check(
        feasible.first() == Some(&(21, 14)),
        "minimum fault margin arithmetic",
    )?;
    println!("{{\"kind\":\"minimum_extra_outage_alternative\",\"byzantine\":6,\"unavailable_correct\":1,\"minimum_n\":21,\"q\":14,\"violates_selected_max20\":true}}");
    for n in [20, 30, 100, 1000, 10_000, 1_000_000] {
        for percent in [5, 10, 20, 30] {
            let bad = n * percent / 100;
            let p7 = hypergeom_tail(n, bad, 7);
            let p8 = hypergeom_tail(n, bad, 8);
            println!("{{\"kind\":\"hypergeometric\",\"n\":{n},\"bad\":{bad},\"p_ge7\":{p7:.12},\"p_ge8\":{p8:.12},\"expected_ge7_shards\":{:.8},\"union_bound_ge7_65536\":{:.8}}}", 65536.0*p7, (65536.0*p7).min(1.0));
        }
    }
    // All 65,536 shards, actual independent domain-separated test tickets, full
    // production BLAKE3 HRW scores. Fixed non-grinding ten-percent attacker.
    for n in [100usize, 1000] {
        let tickets: Vec<_> = (0..n).map(|i| ticket(i as u64, 0)).collect();
        let started = Instant::now();
        let mut hist = [0usize; 21];
        for shard in 0..=u16::MAX {
            let bad = committee(&tickets, shard)
                .iter()
                .filter(|i| **i < n / 10)
                .count();
            hist[bad] += 1;
        }
        check(hist.iter().sum::<usize>() == 65_536, "shards omitted")?;
        println!("{{\"kind\":\"actual_hrw_all_shards\",\"n\":{n},\"bad\":{},\"histogram\":{hist:?},\"elapsed_ms\":{}}}",n/10, started.elapsed().as_millis());
    }

    // Targeted ticket search: each trial is an ideal independently valid ticket,
    // NOT an Argon2 computation and NOT a work-ratchet implementation. This gives
    // selection leverage per usable attempt, not a dollar/time attack cost.
    let shard = 17;
    let honest: Vec<_> = (0..1000).map(|i| ticket(i, 0)).collect();
    for trials in [1u64, 16, 256, 4096] {
        let mut active = honest.clone();
        for id in 1000..1008 {
            let best = (0..trials)
                .map(|t| ticket(id, t))
                .max_by_key(|t| hrw_score_32(t, shard))
                .ok_or("zero trials")?;
            active.push(best);
        }
        let bad = committee(&active, shard)
            .into_iter()
            .filter(|i| *i >= 1000)
            .count();
        println!("{{\"kind\":\"ideal_valid_ticket_grinding\",\"shard\":17,\"honest\":1000,\"attacker_identities\":8,\"usable_trials_each\":{trials},\"selected_attacker\":{bad}}}");
    }

    for n in [20usize, 30, 100, 1000, 10_000, 1_000_000] {
        let start = Instant::now();
        let catalog: Vec<_> = (0..n).map(|id| ticket(id as u64, 0)).collect();
        let build_us = start.elapsed().as_micros();
        let start = Instant::now();
        let chosen = committee(&catalog, 17);
        check(chosen.len() == 20, "HRW progress absent")?;
        println!("{{\"kind\":\"single_catalog_scan\",\"n\":{n},\"ticket_bytes\":{},\"build_us\":{build_us},\"scan_us\":{},\"abstraction\":\"one catalog, not N simulated nodes\"}}", catalog.len()*32, start.elapsed().as_micros());
    }
    Ok(())
}

// Optimistic upper bound: perfect per-edge delivery, no RED, every friend
// forwards. If this cannot reach an identity, limited fan-out cannot do so either.
fn reachable(
    graph: &[BTreeSet<usize>],
    origin: usize,
    ttl: usize,
    dropped: Option<usize>,
) -> BTreeSet<usize> {
    let mut known = BTreeSet::from([origin]);
    let mut queue = VecDeque::from([(origin, 0)]);
    while let Some((at, depth)) = queue.pop_front() {
        if depth == ttl || Some(at) == dropped {
            continue;
        }
        for next in &graph[at] {
            if known.insert(*next) {
                queue.push_back((*next, depth + 1));
            }
        }
    }
    known
}
fn discovery_checks() -> Result<(), String> {
    let mut chain = vec![BTreeSet::new(); 36];
    for i in 0..35 {
        chain[i].insert(i + 1);
        chain[i + 1].insert(i);
    }
    let seen = reachable(&chain, 0, 16, None);
    check(!seen.contains(&35), "TTL counterexample missing")?;
    println!("{{\"kind\":\"connected_ttl_cut\",\"n\":36,\"ttl\":16,\"optimistic_reached\":{},\"hours_do_not_accumulate_ttl\":true}}",seen.len());

    let mut bridge = vec![BTreeSet::new(); 39];
    for side in [1..20, 20..39] {
        let ids: Vec<_> = side.collect();
        for i in &ids {
            bridge[*i].insert(0);
            bridge[0].insert(*i);
            for j in &ids {
                if i != j {
                    bridge[*i].insert(*j);
                }
            }
        }
    }
    check(
        reachable(&bridge, 1, 16, None).len() == 39,
        "honest bridge cannot heal",
    )?;
    check(
        reachable(&bridge, 1, 16, Some(0)).len() == 20,
        "malicious bridge leaked",
    )?;
    println!("{{\"kind\":\"one_organic_network_bridge\",\"n\":39,\"honest_bridge_reached\":39,\"withholding_bridge_reached\":20,\"byzantine_identities\":1}}");
    for n in [20usize, 30, 100, 1000, 10_000] {
        // A bidirectional ring has no permanently privileged bridge. Its long
        // distance is a legitimate topology that the present rules do not reject.
        let mut ring = vec![BTreeSet::new(); n];
        for (i, adjacent) in ring.iter_mut().enumerate() {
            adjacent.insert((i + 1) % n);
            adjacent.insert((i + n - 1) % n);
        }
        let count = reachable(&ring, 0, 16, None).len();
        println!("{{\"kind\":\"ttl_ring_upper_bound\",\"n\":{n},\"reached\":{count},\"delivery\":\"perfect, full fanout, no RED\"}}");
    }
    // Same ticket, differing honest observation times; no shared activation time.
    let day = 24 * 3600;
    let first_a = 0;
    let first_b = 6 * 3600;
    check(
        25 * 3600 - first_a >= day && 25 * 3600 - first_b < day,
        "incubation divergence absent",
    )?;
    println!("{{\"kind\":\"local_incubation\",\"at_hour\":25,\"first_seen_hours\":[0,6],\"mature\":[true,false]}}");
    Ok(())
}

#[derive(Clone)]
struct Item {
    seq: u64,
    slot: u64,
    value: u8,
    until: u64,
}
impl Item {
    fn hash_after(&self, previous: &Hash) -> Hash {
        digest(
            b"RESEARCH_TRANSFER_ITEM",
            &[
                previous,
                &self.seq.to_le_bytes(),
                &self.slot.to_le_bytes(),
                &[self.value],
                &self.until.to_le_bytes(),
            ],
        )
    }
}
#[derive(Clone)]
struct Seal {
    context: Hash,
    count: u64,
    root: Hash,
    signature: Signature,
}
impl Seal {
    fn bytes(&self) -> Hash {
        digest(
            b"RESEARCH_TRANSFER_SEAL",
            &[&self.context, &self.count.to_le_bytes(), &self.root],
        )
    }
}
fn seed(context: &Hash) -> Hash {
    digest(b"RESEARCH_TRANSFER_BEGIN", &[context])
}
fn make_seal(key: &SigningKey, context: Hash, items: &[Item]) -> Seal {
    let root = items
        .iter()
        .fold(seed(&context), |h, item| item.hash_after(&h));
    let mut s = Seal {
        context,
        count: items.len() as u64,
        root,
        signature: key.sign(&[]),
    };
    s.signature = key.sign(&s.bytes());
    s
}
struct Receiver {
    key: VerifyingKey,
    seal: Seal,
    next: u64,
    root: Hash,
    staging: BTreeMap<u64, BTreeSet<u8>>,
    installed: Option<BTreeMap<u64, BTreeSet<u8>>>,
    commit_ready: bool,
}
impl Receiver {
    fn begin(key: VerifyingKey, expected: Hash, seal: Seal) -> Result<Self, String> {
        check(
            seal.context == expected && seal.count <= MAX_RECORDS,
            "invalid transfer context/count",
        )?;
        key.verify_strict(&seal.bytes(), &seal.signature)
            .map_err(|_| "bad source seal")?;
        Ok(Self {
            key,
            root: seed(&expected),
            seal,
            next: 1,
            staging: BTreeMap::new(),
            installed: None,
            commit_ready: false,
        })
    }
    fn page(&mut self, page: &[Item]) -> Result<(), String> {
        check(
            !page.is_empty() && page.len() <= PAGE && !self.commit_ready,
            "invalid page size/state",
        )?;
        // Validate every sequence before mutation; retransmitting a page is a
        // recognized duplicate/retry response, never counted twice as progress.
        for (offset, item) in page.iter().enumerate() {
            check(
                item.seq == self.next + offset as u64 && item.seq <= self.seal.count,
                "noncontiguous source range",
            )?;
        }
        for item in page {
            self.root = item.hash_after(&self.root);
            self.next += 1;
            self.staging
                .entry(item.slot)
                .or_default()
                .insert(item.value);
        }
        Ok(())
    }
    fn complete(&mut self) -> Result<(), String> {
        check(
            self.next == self.seal.count + 1 && self.root == self.seal.root,
            "incomplete/corrupted range",
        )?;
        self.key
            .verify_strict(&self.seal.bytes(), &self.seal.signature)
            .map_err(|_| "bad seal")?;
        self.commit_ready = true;
        Ok(())
    }
    fn durable_install(&mut self) -> Result<(), String> {
        check(self.commit_ready, "install before verified completion")?;
        // Scripted atomic durability abstraction; the real redb probe is separate.
        self.installed = Some(self.staging.clone());
        Ok(())
    }
    fn crash(&mut self) {
        self.staging.clear();
        self.commit_ready = false;
        // The progress cursor authenticates the volatile staging contents.
        // Keeping it while dropping those contents allows an empty reinstall.
        self.next = 1;
        self.root = seed(&self.seal.context);
    }
    fn can_vote(&self, slot: u64, value: u8) -> bool {
        self.installed.as_ref().is_some_and(|state| {
            state
                .get(&slot)
                .is_none_or(|v| *v == BTreeSet::from([value]))
        })
    }
}
fn transfer_checks() -> Result<(), String> {
    let k = SigningKey::from_bytes(&[93; 32]);
    let context = ticket(99, 3);
    let mut items: Vec<_> = (1..=80)
        .map(|seq| Item {
            seq,
            slot: seq,
            value: 1,
            until: 1000,
        })
        .collect();
    // Two concurrent deltas, one creates an authentic partial conflict.
    items.push(Item {
        seq: 81,
        slot: 1,
        value: 2,
        until: 1000,
    });
    items.push(Item {
        seq: 82,
        slot: 83,
        value: 1,
        until: 1000,
    });
    let seal = make_seal(&k, context, &items);
    let begin = || Receiver::begin(k.verifying_key(), context, seal.clone());
    let mut r = begin()?;
    for page in items.chunks(PAGE) {
        r.page(page)?;
    }
    r.complete()?;
    check(!r.can_vote(500, 1), "download alone activated")?;
    r.durable_install()?;
    check(
        r.can_vote(500, 1) && !r.can_vote(1, 1) && !r.can_vote(1, 2),
        "fresh progress/conflict gate",
    )?;
    r.crash();
    check(
        r.can_vote(500, 1) && !r.can_vote(1, 2),
        "durable install lost",
    )?;
    check(
        r.complete().is_err(),
        "lost staging reused old verified cursor",
    )?;
    check(
        r.durable_install().is_err(),
        "crash replaced durable state with empty staging",
    )?;
    check(
        !r.can_vote(1, 2),
        "crash/reinstall erased inherited conflict",
    )?;
    let mut count = 6;
    for omitted in [0, 31, 32, 80, 81] {
        let mut r = begin()?;
        let changed: Vec<_> = items
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != omitted)
            .map(|(_, v)| v.clone())
            .collect();
        let mut failed = false;
        for page in changed.chunks(PAGE) {
            if r.page(page).is_err() {
                failed = true;
                break;
            }
        }
        check(failed || r.complete().is_err(), "omission accepted")?;
        count += 1;
    }
    let mut r = begin()?;
    r.page(&items[..32])?;
    check(r.page(&items[..32]).is_err(), "duplicate advanced range")?;
    count += 1;
    let mut changed = items.clone();
    changed[11].value = 2;
    let mut r = begin()?;
    for p in changed.chunks(PAGE) {
        r.page(p)?;
    }
    check(r.complete().is_err(), "payload mutation accepted")?;
    count += 1;
    check(
        Receiver::begin(k.verifying_key(), ticket(99, 4), seal.clone()).is_err(),
        "stale context accepted",
    )?;
    count += 1;
    let mut forged = seal.clone();
    forged.count -= 1;
    check(
        Receiver::begin(k.verifying_key(), context, forged).is_err(),
        "forged count accepted",
    )?;
    count += 1;
    let mut oversized = seal.clone();
    oversized.count = MAX_RECORDS + 1;
    check(
        Receiver::begin(k.verifying_key(), context, oversized).is_err(),
        "resource cap bypass",
    )?;
    count += 1;
    let mut r = begin()?;
    r.page(&items[..32])?;
    r.crash();
    check(
        !r.can_vote(500, 1) && r.durable_install().is_err(),
        "crash activated staging",
    )?;
    count += 1;
    check(
        begin()?.page(&items[..33]).is_err(),
        "oversized page accepted",
    )?;
    count += 1;
    // A Byzantine source can genuinely sign an omitted record stream. Source
    // completeness does not establish distributed inclusion/closure membership.
    let bad_items = &items[1..];
    let renumbered: Vec<_> = bad_items
        .iter()
        .enumerate()
        .map(|(i, v)| Item {
            seq: i as u64 + 1,
            ..v.clone()
        })
        .collect();
    let authentic_omission = make_seal(&k, context, &renumbered);
    let mut r = Receiver::begin(k.verifying_key(), context, authentic_omission)?;
    for page in renumbered.chunks(PAGE) {
        r.page(page)?;
    }
    r.complete()?;
    println!("{{\"kind\":\"transfer_predicates\",\"checks\":{count},\"records\":82,\"max_page\":32,\"source_authenticated\":true,\"byzantine_resigned_omission_accepted\":true,\"activation_is_not_distributed_closure\":true}}");
    Ok(())
}
fn run() -> Result<(), String> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "all".into());
    if mode == "all" || mode == "risk" {
        risk_and_scaling()?;
    }
    if mode == "all" || mode == "discovery" {
        discovery_checks()?;
    }
    if mode == "all" || mode == "transfer" {
        transfer_checks()?;
    }
    check(
        ["all", "risk", "discovery", "transfer"].contains(&mode.as_str()),
        "unknown mode",
    )
}
fn main() {
    if let Err(e) = run() {
        eprintln!("FAIL {e}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn transfer_and_attacks() -> Result<(), String> {
        super::transfer_checks()
    }
    #[test]
    fn discovery_limits() -> Result<(), String> {
        super::discovery_checks()
    }
    #[test]
    fn exact_risk_arithmetic() {
        assert_eq!(super::hypergeom_tail(20, 6, 7), 0.0);
        assert!((super::hypergeom_tail(20, 7, 7) - 1.0).abs() < 1e-12);
        assert!((super::hypergeom_tail(30, 6, 0) - 1.0).abs() < 1e-12);
    }
}
