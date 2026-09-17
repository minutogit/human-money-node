//! # Spec 09: Netzwerk-Thermometer, Byte-Jahre & Dynamische Quotas
//!
//! Spezifikationstests für:
//! - [INV-0901] Byte-Jahre Verrechnungseinheit (Speicher-Zeit-Produkt)
//! - [INV-0902] Hard Floor Baseline (960.000 BJ/Tag = 1.000 5-Jahres-Locks)
//! - [INV-0903] 28-Tage Slotted Median-Glättung gegen Botnetz-Spikes
//! - [INV-0904] 24h-Tagesbudget & Epochen-Reset
//! - [INV-0905] Wal-Bremse (K <= 5.0) & Sandbox-Gating (K = 0.05)
//! - [INV-0906] Silent Dropping bei Quota-Überschreitung

use humoco_sim_core::quota::{
    evaluate_quota_exceeded_claim, ByteYears, NetworkThermometer, QuartileStats,
    QuotaPlausibilityVerdict, SlottedMedianRingBuffer, HARD_FLOOR_BASELINE_DAILY,
    MAX_WHALE_MULTIPLIER, SANDBOX_K_MULTIPLIER, STANDARD_K_MULTIPLIER,
    HARD_FLOOR_READ_BASELINE_DAILY, READ_TO_WRITE_RATIO,
};

/// [INV-0902] [INV-0904]
/// Test 1: Verifiziert, dass ein Kaltstart-Knoten (N < 4 oder leeres Netz)
/// exakt 1.000 Fünf-Jahres-Locks (je 960 Byte-Jahre) innerhalb eines Tages einspeisen kann.
#[test]
fn test_spec_09_hard_floor_baseline_1000_locks_guarantee() {
    let mut thermometer = NetworkThermometer::new();
    let node_id = 42;
    let epoch_day = 0;

    // Hard-Floor Baseline ist aktiv (keine History vorhanden)
    let ncb_eff = thermometer.effective_ncb();
    assert_eq!(ncb_eff, HARD_FLOOR_BASELINE_DAILY); // 960.000 Byte-Jahre

    // Vollwertiger Knoten (K = 1.0, Spread_Damper = 1.0)
    let quota = thermometer.calculate_daily_quota(STANDARD_K_MULTIPLIER, 1.0);
    assert_eq!(quota, 960_000);

    // 1 Lock mit 5 Jahren Gültigkeit = 960 Byte-Jahre
    let lock_5y_footprint = ByteYears::from_ttl_years(5.0);
    assert_eq!(lock_5y_footprint, 960);

    // 1.000 Locks einspeisen -> alle müssen erfolgreich akzeptiert werden
    for i in 0..1000 {
        let accepted = thermometer.try_accept_lock(epoch_day, node_id, lock_5y_footprint, quota);
        assert!(accepted, "Lock {} von 1.000 muss innerhalb des Tageskontingents akzeptiert werden", i + 1);
    }

    assert_eq!(thermometer.get_node_usage(node_id), 960_000);

    // Der 1.001 Lock am selben Tag übersteigt das Budget und wird lautlos abgewiesen (Silent Dropping)
    let lock_1001_accepted = thermometer.try_accept_lock(epoch_day, node_id, lock_5y_footprint, quota);
    assert!(!lock_1001_accepted, "Lock 1.001 muss durch Silent Dropping abgewiesen werden");

    // Am nächsten Tag (neue 24h-Epoche) wird das Budget zurückgesetzt
    let next_day = epoch_day + 1;
    let next_day_lock_accepted = thermometer.try_accept_lock(next_day, node_id, lock_5y_footprint, quota);
    assert!(next_day_lock_accepted, "Am nächsten Tag muss das Budget wieder voll zur Verfügung stehen");
    assert_eq!(thermometer.get_node_usage(node_id), 960);
}

/// [INV-0901]
/// Test 2: Quartilsberechnung (Q1, Median, Q3) und Zipf-Spread-Dämpfer
    #[test]
    fn test_quartile_distribution_and_spread_damper() {
        // 10 repräsentative Knoten im Mesh
        let samples = vec![
            300_000, 320_000, // Kleine Dorfknoten (Q1)
            500_000, 600_000, 700_000, // Mittlere Knoten
            800_000, 900_000, // Normalnull (Median)
            1_000_000, 1_200_000, 1_500_000, // Händler-Gateways (Q3)
        ];

        let stats = QuartileStats::calculate(&samples);
        assert_eq!(stats.q1, 500_000);
        assert_eq!(stats.median, 750_000);
        assert_eq!(stats.q3, 1_000_000);

        let damper = stats.spread_damper();
        // Q1 / Q3 = 500k / 1M = 0.5 -> (1 - 0.5) / 0.66 = 0.5 / 0.66 = 0.757
        assert!((0.7..=0.8).contains(&damper), "Spread-Dämpfer sollte ca. 0.757 sein, ist: {}", damper);

        // Extremfall 1: Alle Nodes identisch (Q1 == Q3) -> minimale Dämpfung (0.5)
        let equal_samples = vec![1_000_000; 8];
        let equal_stats = QuartileStats::calculate(&equal_samples);
        assert_eq!(equal_stats.spread_damper(), 0.5);

        // Extremfall 2: Gesunde Spreizung (Q1 / Q3 <= 0.34) -> voller Durchsatz (1.0)
        let natural_samples = vec![100_000, 200_000, 300_000, 400_000, 500_000, 600_000, 1_000_000, 2_000_000];
        let natural_stats = QuartileStats::calculate(&natural_samples);
        assert_eq!(natural_stats.spread_damper(), 1.0);
    }

    /// [INV-0910]
    /// Test 9: Garantie der Hard Floor Baseline für Lesevorgänge: 50.000 Reads / Tag
    #[test]
    fn test_spec_09_read_hard_floor_baseline_50000_reads_guarantee() {
        let mut thermometer = NetworkThermometer::new();
        let node_id = 42;
        let epoch_day = 0;

        let ncb_eff = thermometer.effective_ncb();
        assert_eq!(ncb_eff, HARD_FLOOR_BASELINE_DAILY);
        assert_eq!(READ_TO_WRITE_RATIO, 5);

        let spread_damper = 1.0;
        let daily_read_quota = thermometer.calculate_daily_read_quota(1.0, spread_damper);
        assert_eq!(daily_read_quota, HARD_FLOOR_READ_BASELINE_DAILY);

        let one_read_credit = 1;
        // Teste 50.000 Reads (unter Verwendung von Chunks zur Performance-Optimierung im Test)
        for i in 0..50 {
            let accepted = thermometer.try_accept_read(epoch_day, node_id, one_read_credit * 1000, daily_read_quota);
            assert!(accepted, "Chunk {} von 50.000 Reads muss innerhalb des Tagesbudgets akzeptiert werden", i + 1);
        }

        assert_eq!(thermometer.get_node_read_usage(node_id), 50_000);

        let read_over_budget_accepted = thermometer.try_accept_read(epoch_day, node_id, one_read_credit, daily_read_quota);
        assert!(!read_over_budget_accepted, "Read 50.001 muss durch Silent Dropping abgewiesen werden");

        let next_day = epoch_day + 1;
        let next_day_read_accepted = thermometer.try_accept_read(next_day, node_id, one_read_credit, daily_read_quota);
        assert!(next_day_read_accepted, "Am nächsten Tag muss das Budget wieder voll zur Verfügung stehen");
        assert_eq!(thermometer.get_node_read_usage(node_id), 1);
    }

    /// [INV-0911]
    /// Test 10: 28-Tage Slotted Median-Inertie gegen Scraping-Spike
    #[test]
    fn test_spec_09_read_28_day_slotted_median_inertia_against_scraping_spike() {
        let mut read_buffer = SlottedMedianRingBuffer::new();

        for _ in 0..28 {
            read_buffer.push_daily_median(5_000);
        }
        assert_eq!(read_buffer.moving_average_median(), 5_000);
        assert_eq!(read_buffer.days_recorded(), 28);

        read_buffer.push_daily_median(500_000);
        read_buffer.push_daily_median(500_000);

        let smoothed_median = read_buffer.moving_average_median();
        let expected = (26 * 5_000 + 2 * 500_000) / 28;
        assert_eq!(smoothed_median, expected);

        for _ in 0..28 {
            read_buffer.push_daily_median(5_000);
        }

        assert_eq!(read_buffer.moving_average_median(), 5_000);
    }

    /// [INV-0912] [INV-0913]
    /// Test 11: Whale Brake (K <= 5.0) und Sandbox-Limits für Lesevorgänge
    #[test]
    fn test_spec_09_read_whale_brake_and_sandbox_limits() {
        let mut thermometer = NetworkThermometer::new();
        for _ in 0..28 {
            thermometer.record_daily_read_median(60_000);
        }
        let ncb_read_eff = thermometer.effective_read_ncb();
        assert_eq!(ncb_read_eff, 60_000);

        let spread_damper = 1.0;

        let standard_read_quota = thermometer.calculate_daily_read_quota(STANDARD_K_MULTIPLIER, spread_damper);
        assert_eq!(standard_read_quota, 60_000);

        let sandbox_read_quota = thermometer.calculate_daily_read_quota(SANDBOX_K_MULTIPLIER, spread_damper);
        assert_eq!(sandbox_read_quota, 3_000);

        let whale_read_quota = thermometer.calculate_daily_read_quota(100.0, spread_damper);
        let max_allowed = ((ncb_read_eff as f64) * MAX_WHALE_MULTIPLIER * spread_damper) as u64;
        assert_eq!(whale_read_quota, max_allowed);
        assert_eq!(whale_read_quota, 300_000);
    }

/// [INV-0914]
/// Test 12: Berechnung der Sync-Read-Credits
#[test]
fn test_spec_09_calculate_sync_read_credits() {
    assert_eq!(NetworkThermometer::calculate_sync_read_credits(0), 1);
    assert_eq!(NetworkThermometer::calculate_sync_read_credits(1), 2);
    assert_eq!(NetworkThermometer::calculate_sync_read_credits(5), 2);
    assert_eq!(NetworkThermometer::calculate_sync_read_credits(10), 2);
    assert_eq!(NetworkThermometer::calculate_sync_read_credits(11), 3);
    assert_eq!(NetworkThermometer::calculate_sync_read_credits(20), 3);
    assert_eq!(NetworkThermometer::calculate_sync_read_credits(21), 4);
}

/// [INV-0918]
/// Test 13: Evaluierung der Quota-Read für Neuknoten beim Beitritt
#[test]
fn test_spec_09_read_quota_evaluation_on_join() {
    let mut thermometer = NetworkThermometer::new();
    let node_id = 42;
    let epoch_day = 0;

    // Beim Kaltstart ist der effektive NCB_Read_Eff = Hard-Floor-Read-Baseline
    assert_eq!(thermometer.effective_read_ncb(), HARD_FLOOR_READ_BASELINE_DAILY);

    let spread_damper = 1.0;
    let daily_read_quota = thermometer.calculate_daily_read_quota(1.0, spread_damper);
    assert_eq!(daily_read_quota, HARD_FLOOR_READ_BASELINE_DAILY);

    // Nehmen wir an, der Knoten erhält ein Peer-Read-Median von 100.000
    // Seed-Initialisierung: Alle 28 Slots werden mit 100.000 gefüllt
    thermometer.seed_read_from_peers(100_000);

    // Nach der Seed-Initialisierung ist der NCB_Read_Eff = max(100.000, 50.000) = 100.000
    assert_eq!(thermometer.effective_read_ncb(), 100_000);

    let daily_read_quota_after_seed = thermometer.calculate_daily_read_quota(1.0, spread_damper);
    assert_eq!(daily_read_quota_after_seed, 100_000);

    // Knoten verbraucht 30.000 Reads
    let one_read = 1;
    let accepted1 = thermometer.try_accept_read(epoch_day, node_id, one_read * 30_000, daily_read_quota_after_seed);
    assert!(accepted1);
    assert_eq!(thermometer.get_node_read_usage(node_id), 30_000);

    // Knoten verbraucht weitere 70.000 Reads, Gesamt 100.000 -> Akzeptiert
    let accepted2 = thermometer.try_accept_read(epoch_day, node_id, one_read * 70_000, daily_read_quota_after_seed);
    assert!(accepted2);
    assert_eq!(thermometer.get_node_read_usage(node_id), 100_000);

    // Knoten versucht, weitere 1 Read zu verbrauchen -> Silent Dropping
    let accepted3 = thermometer.try_accept_read(epoch_day, node_id, one_read, daily_read_quota_after_seed);
    assert!(!accepted3);
    assert_eq!(thermometer.get_node_read_usage(node_id), 100_000);
}

/// [INV-0903]
/// Test 3: 28-Tage Slotted-Ringpuffer fängt kurzzeitige Botnetz-Spikes träge ab
#[test]
fn test_spec_09_28_day_slotted_median_inertia_against_botnet_spike() {
    let mut ring_buffer = SlottedMedianRingBuffer::new();

    // 28 Tage stabiler Normalbetrieb mit 1.000.000 Byte-Jahren/Tag
    for _ in 0..28 {
        ring_buffer.push_daily_median(1_000_000);
    }
    assert_eq!(ring_buffer.moving_average_median(), 1_000_000);
    assert_eq!(ring_buffer.days_recorded(), 28);

    // Tag 29 & 30: Massiver 2-Tage-Botnetz-Angriff (50.000.000 Byte-Jahre/Tag)
    ring_buffer.push_daily_median(50_000_000);
    ring_buffer.push_daily_median(50_000_000);

    // Der gleitende 28-Tage-Median darf nicht explodieren:
    // (26 * 1.000.000 + 2 * 50.000.000) / 28 = (26M + 100M) / 28 = 126M / 28 = 4.500.000
    let smoothed_median = ring_buffer.moving_average_median();
    assert_eq!(smoothed_median, 4_500_000);

    // Nach Abklingen des Angriffs: Nach weiteren 28 Tagen sind alle Slots wieder Normalbetrieb
    for _ in 0..28 {
        ring_buffer.push_daily_median(1_000_000);
    }
    // Nun sind die 2 Spike-Tage vollständig aus dem 28-Tage-Fenster herausgefallen
    assert_eq!(ring_buffer.moving_average_median(), 1_000_000);
}

/// [INV-0905]
/// Test 4: Wal-Bremse (K <= 5.0) und Sandbox-Gating (K = 0.05)
#[test]
fn test_spec_09_whale_brake_and_sandbox_limits() {
    let mut thermometer = NetworkThermometer::new();
    // 28 Tage mit je 2.000.000 Byte-Jahren
    for _ in 0..28 {
        thermometer.record_daily_median(2_000_000);
    }
    let ncb_eff = thermometer.effective_ncb();
    assert_eq!(ncb_eff, 2_000_000);

    let spread_damper = 1.0;

    // 1. Vollwertiger Knoten (K = 1.0)
    let standard_quota = thermometer.calculate_daily_quota(STANDARD_K_MULTIPLIER, spread_damper);
    assert_eq!(standard_quota, 2_000_000);

    // 2. Sandbox-Knoten (K = 0.05 -> 5%)
    let sandbox_quota = thermometer.calculate_daily_quota(SANDBOX_K_MULTIPLIER, spread_damper);
    assert_eq!(sandbox_quota, 100_000);

    // 3. Wal-Versuch (K = 100.0) -> Wird strikt auf K = 5.0 (10.000.000) gedeckelt
    let whale_quota = thermometer.calculate_daily_quota(100.0, spread_damper);
    let max_allowed = ((ncb_eff as f64) * MAX_WHALE_MULTIPLIER * spread_damper) as u64;
    assert_eq!(whale_quota, max_allowed);
    assert_eq!(whale_quota, 10_000_000);
}

/// [INV-0906]
/// Test 5: Organisches Netzwachstum & Silent Dropping
#[test]
fn test_spec_09_organic_network_growth_and_silent_dropping() {
    let mut thermometer = NetworkThermometer::new();

    // Start-Tag mit Hard Floor
    assert_eq!(thermometer.effective_ncb(), HARD_FLOOR_BASELINE_DAILY);

    // Simuliere 15 Nodes über mehrere Tage mit steigendem Transaktionsvolumen
    let mut daily_samples = vec![
        600_000, 700_000, 800_000, 900_000, 1_000_000,
        1_100_000, 1_200_000, 1_300_000, 1_400_000, 1_500_000,
        1_600_000, 1_700_000, 1_800_000, 1_900_000, 2_000_000,
    ];

    for day in 0..14 {
        let stats = QuartileStats::calculate(&daily_samples);
        thermometer.record_daily_median(stats.median);

        // Volumen wächst organisch um 5% pro Tag
        for sample in &mut daily_samples {
            *sample = (*sample as f64 * 1.05) as u64;
        }

        // Überprüfe Ingress für Node 10
        let node_id = 10;
        let quota = thermometer.calculate_daily_quota(STANDARD_K_MULTIPLIER, stats.spread_damper());
        let lock_1y = ByteYears::from_ttl_years(1.0); // 192 Byte-Jahre

        // Node schreibt 100 Locks
        for _ in 0..100 {
            let ok = thermometer.try_accept_lock(day, node_id, lock_1y, quota);
            assert!(ok);
        }
    }

    // Das Thermometer ist organisch mitgewachsen und liegt nun über dem Hard Floor
    assert!(thermometer.effective_ncb() > HARD_FLOOR_BASELINE_DAILY);
}

/// [INV-0907]
/// Test 6: Neuknoten-Seed verhindert Kaltstart-Deadlock in gewachsenem Großnetz
#[test]
fn test_spec_09_new_node_seed_prevents_coldstart_deadlock() {
    let mut new_node_thermometer = NetworkThermometer::new();

    // Ohne Seed: Neuer Node startet bei Hard Floor (960k)
    assert_eq!(new_node_thermometer.effective_ncb(), HARD_FLOOR_BASELINE_DAILY);

    // Das Großnetz hat einen aktuellen Tages-Median von 50.000.000 Byte-Jahren
    let active_network_median = 50_000_000;

    // Neuknoten joint via F2F & initialisiert (seeded) seinen Puffer mit dem Peer-Median
    new_node_thermometer.seed_from_peers(active_network_median);

    // Verifiziere: Ab Sekunde 1 operiert der Neuknoten auf der realen Skala des Großnetzes
    assert_eq!(new_node_thermometer.effective_ncb(), 50_000_000);

    // Tagesquota bei K=1.0 ist sofort 50M Byte-Jahre
    let daily_quota = new_node_thermometer.calculate_daily_quota(STANDARD_K_MULTIPLIER, 1.0);
    assert_eq!(daily_quota, 50_000_000);

    // Regulärer Traffic (z. B. 10.000.000 Byte-Jahre) wird problemlos akzeptiert und löst keinen Fehlalarm aus
    let accepted = new_node_thermometer.try_accept_lock(0, 42, 10_000_000, daily_quota);
    assert!(accepted, "Neuknoten darf normalen Großnetz-Traffic nicht fälschlich abweisen");
}

/// [INV-0908]
/// Test 7: Fast-Re-Seed bei Netzwerk-Merge (Dorfnetz trifft Weltnetz)
#[test]
fn test_spec_09_merge_fast_reseed_and_scale_jump() {
    let mut village_node_thermometer = NetworkThermometer::new();

    // 28 Tage Dorf-Betrieb bei Minimal-Volumen (Hard Floor 960k)
    for _ in 0..28 {
        village_node_thermometer.record_daily_median(HARD_FLOOR_BASELINE_DAILY);
    }
    assert_eq!(village_node_thermometer.effective_ncb(), HARD_FLOOR_BASELINE_DAILY);

    // Merge-Ereignis: Dorf dockt an Weltnetz an (Globaler Median: 100.000.000 Byte-Jahre)
    let global_world_median = 100_000_000;
    village_node_thermometer.fast_reseed_on_merge(global_world_median);

    // Verifiziere: Der Dorfknoten schwingt in < 1ms auf die Welt-Skala ein (kein 28-Tage-Verzug)
    assert_eq!(village_node_thermometer.effective_ncb(), 100_000_000);

    let world_quota = village_node_thermometer.calculate_daily_quota(STANDARD_K_MULTIPLIER, 1.0);
    assert_eq!(world_quota, 100_000_000);
}

/// [INV-0909]
/// Test 8: 3-Zonen-Plausibilitätsprüfung für 429 QuotaExceeded (Ehrlicher Vorreiter vs. Betrug)
#[test]
fn test_spec_09_three_zone_quota_exceeded_plausibility_and_malus() {
    let quota_limit = 10_000_000; // 10M Byte-Jahre (z. B. 5x Limit)

    // Fall 1: Eindeutige Betrugszone (< 75% des Limits, z. B. 2.000.000 Byte-Jahre verbraucht)
    // Ein Shard-Node, der hier schon 429 QuotaExceeded behauptet, verweigert die Arbeit -> Malus +8!
    let fraud_verdict = evaluate_quota_exceeded_claim(2_000_000, quota_limit);
    assert_eq!(
        fraud_verdict,
        QuotaPlausibilityVerdict::FraudulentRejection { malus_increment: 8 }
    );
    assert_eq!(fraud_verdict.malus(), 8);

    // Fall 2: Toleranter Grenzbereich (75% bis 125% des Limits, z. B. 8.000.000 Byte-Jahre)
    // Shard-Node ist ein ehrlicher Vorreiter, der als Erster am Limit anstößt -> Kein Malus (0)!
    let boundary_verdict = evaluate_quota_exceeded_claim(8_000_000, quota_limit);
    assert_eq!(
        boundary_verdict,
        QuotaPlausibilityVerdict::BoundaryCutoff { malus_increment: 0 }
    );
    assert_eq!(boundary_verdict.malus(), 0);

    // Fall 3: Exakt am 100% Limit (10.000.000 Byte-Jahre) -> Kein Malus (0)!
    let exact_verdict = evaluate_quota_exceeded_claim(10_000_000, quota_limit);
    assert_eq!(
        exact_verdict,
        QuotaPlausibilityVerdict::BoundaryCutoff { malus_increment: 0 }
    );
    assert_eq!(exact_verdict.malus(), 0);

    // Fall 4: Echte Überlast-Zone (> 125% des Limits, z. B. 15.000.000 Byte-Jahre)
    // Sender ist meilenweit über dem Limit -> Regulärer Rate-Limit-Schutz -> Kein Malus (0)!
    let overload_verdict = evaluate_quota_exceeded_claim(15_000_000, quota_limit);
    assert_eq!(
        overload_verdict,
        QuotaPlausibilityVerdict::LegitimateOverload { malus_increment: 0 }
    );
    assert_eq!(overload_verdict.malus(), 0);
}

