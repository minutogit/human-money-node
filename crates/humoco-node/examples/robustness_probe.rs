//! Isolated cost probe, NOT the HuMoCo protocol or a membership implementation.
//! One authenticated owner, one hot durable replica, fixed bounded wire messages.
#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use redb::{Database, Durability, ReadableTable, TableDefinition};
use serde_json::json;
use std::{
    error::Error,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};

type AnyError = Box<dyn Error + Send + Sync>;
const CHOICES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("probe_choices");
const CONTEXT: &[u8; 8] = b"RPROBE01";
const PAYLOAD: usize = 88;
const WIRE: usize = PAYLOAD + 64;
const QUEUE: usize = 64;
static QUEUE_PEAK: AtomicUsize = AtomicUsize::new(0);
const BATCH: usize = 32;
const CLIENT_LIMIT: usize = 512;
type Server = (
    quinn::Endpoint,
    quinn::Connection,
    tokio::task::JoinHandle<Result<(), AnyError>>,
    SigningKey,
    VerifyingKey,
);
type TimedReply = Result<Result<(u8, f64), AnyError>, tokio::time::error::Elapsed>;
type CatalogRow = ([u8; 32], [u8; 32], [u8; 16], u64, u64);

struct Job {
    payload: Vec<u8>,
    reply: oneshot::Sender<u8>,
}

fn quantiles(mut samples: Vec<f64>) -> [f64; 3] {
    if samples.is_empty() {
        return [0.0; 3];
    }
    samples.sort_by(f64::total_cmp);
    [0.50, 0.95, 0.99].map(|p| samples[((samples.len() - 1) as f64 * p) as usize])
}

fn request(seq: u64, key: &SigningKey) -> Vec<u8> {
    let mut payload = Vec::with_capacity(WIRE);
    payload.extend_from_slice(CONTEXT);
    payload.extend_from_slice(&seq.to_le_bytes());
    payload.extend_from_slice(&probe_hash(b"HUMOCO_RESEARCH_PARENT", &seq.to_le_bytes()));
    payload.extend_from_slice(&probe_hash(b"HUMOCO_RESEARCH_VALUE", &seq.to_le_bytes()));
    payload.extend_from_slice(&86400u64.to_le_bytes());
    let signature = key.sign(&payload);
    payload.extend_from_slice(&signature.to_bytes());
    payload
}

fn probe_hash(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[domain.len() as u8]);
    hasher.update(domain);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

fn authenticated(payload: &[u8]) -> Vec<u8> {
    // Probe response domains are independent of production wire formats.
    [b"robustness_probe_response".as_slice(), payload].concat()
}

fn storage_worker(
    db: Arc<Database>,
    mut rx: mpsc::Receiver<Job>,
    delay_ms: u64,
) -> Result<(), AnyError> {
    while let Some(first) = rx.blocking_recv() {
        let mut batch = vec![first];
        // Explicit group-commit delay; measured as part of request latency.
        std::thread::sleep(Duration::from_millis(1 + delay_ms));
        while batch.len() < BATCH {
            match rx.try_recv() {
                Ok(job) => batch.push(job),
                Err(_) => break,
            }
        }
        let mut tx = db.begin_write()?;
        tx.set_durability(Durability::Immediate);
        let mut statuses = Vec::with_capacity(batch.len());
        {
            let mut table = tx.open_table(CHOICES)?;
            for job in &batch {
                let parent = &job.payload[16..48];
                let value = &job.payload[48..80];
                let existing = table.get(parent)?.map(|v| v.value().to_vec());
                let status = match existing {
                    Some(old) if old == value => 2,
                    Some(_) => 3,
                    None => {
                        table.insert(parent, value)?;
                        1
                    }
                };
                statuses.push(status);
            }
        }
        tx.commit()?;
        for (job, status) in batch.into_iter().zip(statuses) {
            let _ = job.reply.send(status);
        }
    }
    Ok(())
}

async fn start_server(
    path: &std::path::Path,
    delay_ms: u64,
    identity: u8,
) -> Result<Server, AnyError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
    let cert_der = cert.cert.der().clone();
    let key_der = rustls_pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut server_config =
        quinn::ServerConfig::with_single_cert(vec![cert_der.clone()], key_der.into())?;
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(128u32.into());
    transport.max_concurrent_uni_streams(0u32.into());
    transport.stream_receive_window(1024u32.into());
    transport.receive_window(131072u32.into());
    server_config.transport_config(Arc::new(transport));
    let server = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let addr = server.local_addr()?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der)?;
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    client.set_default_client_config(quinn::ClientConfig::with_root_certificates(Arc::new(
        roots,
    ))?);
    let owner = SigningKey::from_bytes(&[19; 32]);
    let owner_pub = owner.verifying_key();
    let replica = SigningKey::from_bytes(&[identity; 32]);
    let replica_pub = replica.verifying_key();
    let db = Arc::new(Database::create(path)?);
    {
        let tx = db.begin_write()?;
        {
            tx.open_table(CHOICES)?;
        }
        tx.commit()?;
    }
    let (tx, rx) = mpsc::channel::<Job>(QUEUE);
    let writer = tokio::task::spawn_blocking(move || storage_worker(db, rx, delay_ms));
    let server_copy = server.clone();
    tokio::spawn(async move {
        while let Some(incoming) = server_copy.accept().await {
            let tx = tx.clone();
            let replica = replica.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let tx = tx.clone();
                    let replica = replica.clone();
                    tokio::spawn(async move {
                        let input = match tokio::time::timeout(
                            Duration::from_secs(2),
                            recv.read_to_end(WIRE),
                        )
                        .await
                        {
                            Ok(Ok(input)) => input,
                            _ => {
                                let _ = send.write_all(&[4]).await;
                                let _ = send.finish();
                                return;
                            }
                        };
                        let status = if input.len() != WIRE || &input[..8] != CONTEXT {
                            4
                        } else {
                            // Capacity is checked before asymmetric verification and mutation.
                            match tx.try_reserve() {
                                Ok(permit) => {
                                    QUEUE_PEAK.fetch_max(QUEUE - tx.capacity(), Ordering::Relaxed);
                                    if Signature::from_slice(&input[PAYLOAD..]).ok().is_some_and(
                                        |signature| {
                                            owner_pub.verify(&input[..PAYLOAD], &signature).is_ok()
                                        },
                                    ) {
                                        let (reply, answer) = oneshot::channel();
                                        permit.send(Job {
                                            payload: input[..PAYLOAD].to_vec(),
                                            reply,
                                        });
                                        answer.await.unwrap_or(7)
                                    } else {
                                        5
                                    }
                                }
                                Err(_) => 6,
                            }
                        };
                        let mut response = vec![status];
                        if matches!(status, 1..=3) {
                            let payload = [input[..PAYLOAD].as_ref(), &[status]].concat();
                            response.extend_from_slice(
                                &replica.sign(&authenticated(&payload)).to_bytes(),
                            );
                        }
                        let _ = send.write_all(&response).await;
                        let _ = send.finish();
                    });
                }
            });
        }
    });
    let connection = client.connect(addr, "localhost")?.await?;
    // Keep client endpoint alive through the connection's internal endpoint reference.
    Ok((server, connection, writer, owner, replica_pub))
}

async fn roundtrip(
    conn: quinn::Connection,
    input: Vec<u8>,
    replica: VerifyingKey,
    rtt_ms: u64,
) -> Result<(u8, f64), AnyError> {
    let start = Instant::now();
    if rtt_ms > 0 {
        tokio::time::sleep(Duration::from_millis(rtt_ms)).await;
    }
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&input).await?;
    send.finish()?;
    let output = recv.read_to_end(65).await?;
    let status = *output.first().ok_or("empty reply")?;
    if matches!(status, 1..=3) {
        let signature = Signature::from_slice(&output[1..])?;
        let payload = [input[..PAYLOAD].as_ref(), &[status]].concat();
        replica.verify(&authenticated(&payload), &signature)?;
    }
    Ok((status, start.elapsed().as_secs_f64() * 1000.0))
}

fn microbench(path: &std::path::Path) -> Result<serde_json::Value, AnyError> {
    let key = SigningKey::from_bytes(&[41; 32]);
    let public = key.verifying_key();
    let payload = [11u8; PAYLOAD];
    let signature = key.sign(&payload);
    let mut signs = Vec::new();
    let mut verifies = Vec::new();
    for _ in 0..5000 {
        let at = Instant::now();
        std::hint::black_box(key.sign(std::hint::black_box(&payload)));
        signs.push(at.elapsed().as_secs_f64() * 1e6);
        let at = Instant::now();
        public.verify(
            std::hint::black_box(&payload),
            std::hint::black_box(&signature),
        )?;
        verifies.push(at.elapsed().as_secs_f64() * 1e6);
    }
    let db = Database::create(path)?;
    let mut commits = Vec::new();
    for i in 0u64..200 {
        let at = Instant::now();
        let mut tx = db.begin_write()?;
        tx.set_durability(Durability::Immediate);
        {
            let mut table = tx.open_table(CHOICES)?;
            table.insert(i.to_le_bytes().as_slice(), payload.as_slice())?;
        }
        tx.commit()?;
        commits.push(at.elapsed().as_secs_f64() * 1000.0);
    }
    Ok(
        json!({"kind":"microbench", "sign_us_p50_p95_p99":quantiles(signs), "verify_us_p50_p95_p99":quantiles(verifies), "immediate_commit_ms_p50_p95_p99":quantiles(commits), "crypto_n":5000, "commit_n":200}),
    )
}

fn catalog_probe() -> serde_json::Value {
    // Compact synthetic rows: identity, ticket, address, eligibility, epoch.
    let at = Instant::now();
    let catalog: Vec<CatalogRow> = (0u64..1_000_000)
        .map(|i| {
            let identity = probe_hash(b"HUMOCO_RESEARCH_CATALOG", &i.to_le_bytes());
            (identity, identity, [0; 16], 86400, 0)
        })
        .collect();
    let construction_ms = at.elapsed().as_secs_f64() * 1000.0;
    let at = Instant::now();
    let mut top = std::collections::BinaryHeap::new();
    for row in &catalog {
        let score = probe_hash(
            b"HUMOCO_RESEARCH_HRW",
            &[row.1.as_slice(), &17u16.to_le_bytes()].concat(),
        );
        top.push(std::cmp::Reverse((score, row.0)));
        if top.len() > 20 {
            top.pop();
        }
    }
    std::hint::black_box(top);
    json!({"kind":"catalog", "rows":catalog.len(),"row_bytes":std::mem::size_of_val(&catalog[0]),"compact_bytes":std::mem::size_of_val(catalog.as_slice()),"construction_ms":construction_ms,"single_shard_top20_ms":at.elapsed().as_secs_f64()*1000.0,"excludes":"maps, F2F rows, certificates, histories, allocator overhead"})
}

async fn committee_probe(dir: &std::path::Path) -> Result<(), AnyError> {
    let mut servers = Vec::new();
    for i in 0..20 {
        servers.push(start_server(&dir.join(format!("committee-{i}.redb")), 0, 50 + i).await?);
    }
    for available in [20, 14, 13] {
        let mut samples = Vec::new();
        let mut success = 0;
        for seq in 0..5 {
            let at = Instant::now();
            let mut tasks = tokio::task::JoinSet::new();
            for (i, (_, conn, _, owner, replica)) in servers.iter().enumerate() {
                let input = request(800000000 + available * 100 + seq, owner);
                let conn = conn.clone();
                let replica = *replica;
                tasks.spawn(async move {
                    if i >= available as usize {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                    roundtrip(conn, input, replica, 0).await
                });
            }
            let mut votes = 0;
            let completed = tokio::time::timeout(Duration::from_millis(800), async {
                while let Some(result) = tasks.join_next().await {
                    if let Ok(Ok((1 | 2, _))) = result {
                        votes += 1;
                    }
                    if votes >= 14 {
                        return true;
                    }
                }
                false
            })
            .await
            .unwrap_or(false);
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            success += usize::from(completed);
            samples.push(at.elapsed().as_secs_f64() * 1000.0);
        }
        println!(
            "{}",
            json!({"kind":"committee_smoke", "distinct_replica_keys":20,"distinct_quic_endpoints":20,"separate_redb_databases":20,"available":available,"trials":5,"success":success,"latency_ms_p50_p95_p99":quantiles(samples),"deadline_ms":800,"same_process_same_host":true,"membership_justification":false})
        );
        if (available >= 14 && success != 5) || (available == 13 && success != 0) {
            return Err("unexpected committee progress result".into());
        }
    }
    for (endpoint, conn, writer, _, _) in servers {
        conn.close(0u32.into(), b"done");
        endpoint.close(0u32.into(), b"done");
        tokio::time::timeout(Duration::from_secs(2), writer).await???;
    }
    Ok(())
}

async fn wire_tests(
    conn: &quinn::Connection,
    owner: &SigningKey,
    replica: VerifyingKey,
) -> Result<serde_json::Value, AnyError> {
    let base = request(9999999, owner);
    let created = roundtrip(conn.clone(), base.clone(), replica, 0).await?.0;
    let idem = roundtrip(conn.clone(), base.clone(), replica, 0).await?.0;
    let mut bad = base.clone();
    bad[48] ^= 1;
    let tampered = roundtrip(conn.clone(), bad, replica, 0).await?.0;
    let mut conflict = base.clone();
    conflict[48] ^= 1;
    let sig = owner.sign(&conflict[..PAYLOAD]);
    conflict[PAYLOAD..].copy_from_slice(&sig.to_bytes());
    let collision = roundtrip(conn.clone(), conflict, replica, 0).await?.0;
    let mut stale = base.clone();
    stale[7] ^= 1;
    let sig = owner.sign(&stale[..PAYLOAD]);
    stale[PAYLOAD..].copy_from_slice(&sig.to_bytes());
    let stale_context = roundtrip(conn.clone(), stale, replica, 0).await?.0;
    let malformed = roundtrip(conn.clone(), vec![0u8; 4], replica, 0).await?.0;
    let oversized = roundtrip(conn.clone(), vec![0u8; WIRE + 1], replica, 0)
        .await?
        .0;
    if [
        created,
        idem,
        tampered,
        collision,
        stale_context,
        malformed,
        oversized,
    ] != [1, 2, 5, 3, 4, 4, 4]
    {
        return Err("wire rejection mismatch".into());
    }
    Ok(
        json!({"kind":"receiver_wire_tests", "created":created,"exact_retry":idem,"tampered":tampered,"owner_authorized_conflict":collision,"stale_context":stale_context,"short":malformed,"oversized":oversized,"pass":true}),
    )
}

async fn load(
    conn: &quinn::Connection,
    owner: &SigningKey,
    replica: VerifyingKey,
    rate: u64,
    seconds: u64,
    repetition: u64,
    rtt_ms: u64,
) -> Result<serde_json::Value, AnyError> {
    QUEUE_PEAK.store(0, Ordering::Relaxed);
    let total = rate * seconds;
    let mut tasks: tokio::task::JoinSet<TimedReply> = tokio::task::JoinSet::new();
    let mut latency = Vec::new();
    let mut counts = [0u64; 9];
    let mut dropped = 0;
    // Preparation is intentionally measured separately: runtime offered load excludes owner signing.
    let prep_at = Instant::now();
    let inputs: Vec<Vec<u8>> = (0..total)
        .map(|i| request(repetition * 10_000_000_000 + rate * 1_000_000 + i, owner))
        .collect();
    let preparation_ms = prep_at.elapsed().as_secs_f64() * 1000.0;
    let start = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / rate as f64));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    for input in inputs {
        tick.tick().await;
        while let Some(result) = tasks.try_join_next() {
            match result? {
                Ok(Ok((status, ms))) => {
                    counts[status.min(8) as usize] += 1;
                    if matches!(status, 1 | 2) {
                        latency.push(ms);
                    }
                }
                _ => counts[8] += 1,
            }
        }
        if tasks.len() >= CLIENT_LIMIT {
            dropped += 1;
            continue;
        }
        tasks.spawn(tokio::time::timeout(
            Duration::from_millis(800),
            roundtrip(conn.clone(), input, replica, rtt_ms),
        ));
    }
    while let Some(result) = tasks.join_next().await {
        match result? {
            Ok(Ok((status, ms))) => {
                counts[status.min(8) as usize] += 1;
                if matches!(status, 1 | 2) {
                    latency.push(ms);
                }
            }
            _ => counts[8] += 1,
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    Ok(
        json!({"kind":"hot_replica_load","offered_per_s":rate,"duration_target_s":seconds,"repetition":repetition,"injected_application_delay_ms":rtt_ms,"offered":total,"client_capacity_drop":dropped,"status_counts":counts,"useful_per_s":(counts[1]+counts[2]) as f64/elapsed,"elapsed_s":elapsed,"useful_latency_ms_p50_p95_p99":quantiles(latency),"owner_preparation_ms":preparation_ms,"deadline_ms":800,"queue_capacity":QUEUE,"receiver_queue_peak":QUEUE_PEAK.load(Ordering::Relaxed),"batch_max":BATCH,"client_inflight_cap":CLIENT_LIMIT}),
    )
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), AnyError> {
    let dir = tempfile::tempdir()?;
    println!("{}", microbench(&dir.path().join("micro.redb"))?);
    println!("{}", catalog_probe());
    let delay_ms = std::env::var("PROBE_STORAGE_DELAY_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let seconds = std::env::var("PROBE_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let (endpoint, conn, writer, owner, replica) =
        start_server(&dir.path().join("replica.redb"), delay_ms, 29).await?;
    println!("{}", wire_tests(&conn, &owner, replica).await?);
    for repetition in 1..=3 {
        for rate in [1000, 10000] {
            println!(
                "{}",
                load(&conn, &owner, replica, rate, seconds, repetition, 0).await?
            );
        }
    }
    println!(
        "{}",
        load(&conn, &owner, replica, 1000, seconds, 10, 50).await?
    );
    conn.close(0u32.into(), b"probe complete");
    endpoint.close(0u32.into(), b"probe complete");
    tokio::time::timeout(Duration::from_secs(2), writer).await???;
    {
        let reopened = Database::open(dir.path().join("replica.redb"))?;
        let tx = reopened.begin_read()?;
        let table = tx.open_table(CHOICES)?;
        let input = request(9999999, &owner);
        let saved = table
            .get(&input[16..48])?
            .ok_or("acknowledged choice missing after reopen")?;
        if saved.value() != &input[48..80] {
            return Err("reopen changed choice".into());
        }
        println!(
            "{}",
            json!({"kind":"graceful_reopen", "durable_choices":table.iter()?.count(),"original_ack_preserved":true,"power_failure_test":false})
        );
    }
    committee_probe(dir.path()).await?;
    println!(
        "{}",
        json!({"kind":"scope","transport":"real loopback QUIC","replicas":1,"durability":"redb Immediate before signed reply","storage_delay_ms":delay_ms,"membership":false,"handoff":false,"quorum":false,"thermal_control":false,"process_memory_sample":"external /usr/bin/time -v","profile":"record command flags"})
    );
    Ok(())
}
