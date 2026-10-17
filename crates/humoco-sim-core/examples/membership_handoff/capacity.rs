//! Virtual capacity experiments, not measurements of the node or QUIC stack.
//!
//! Rates describe useful, validated records after deduplication. Evidence bytes,
//! disk latency and transport overhead must be measured before choosing rates.

use std::collections::VecDeque;

#[derive(Clone, Copy, Debug)]
struct Parameters {
    arrivals_per_second: u64,
    durable_records_per_second: u64,
    transfer_records_per_second: u64,
    queue_capacity: usize,
    snapshot_records: u64,
    pre_copy_ms: u64,
    install_ms: u64,
    event_limit_ms: u64,
}

#[derive(Debug)]
struct Outcome {
    admitted: u64,
    rejected: u64,
    committed: u64,
    max_queue: usize,
    tail_at_fence: u64,
    copied: u64,
    seal_ms: Option<u64>,
    activation_ms: Option<u64>,
    last_commit_sequence: u64,
    installed_sequence: Option<u64>,
}

fn check(condition: bool, detail: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(format!("capacity model: {detail}"))
    }
}

/// One tick represents a millisecond. Arrival and service budgets carry their
/// fractional remainder, so a configured rate is independent of event count.
fn simulate(p: Parameters) -> Result<Outcome, String> {
    check(p.queue_capacity > 0, "zero queue capacity")?;
    let mut pending = VecDeque::new();
    let mut arrival_credit = 0_u64;
    let mut durable_credit = 0_u64;
    let mut transfer_credit = 0_u64;
    let mut backlog = p.snapshot_records;
    let mut result = Outcome {
        admitted: 0,
        rejected: 0,
        committed: 0,
        max_queue: 0,
        tail_at_fence: 0,
        copied: 0,
        seal_ms: None,
        activation_ms: None,
        last_commit_sequence: 0,
        installed_sequence: None,
    };
    let mut installation_started = None;

    for now in 0..p.event_limit_ms {
        // Fence stops admission. Already reserved writes still drain and extend
        // the final change sequence; a request timestamp cannot bypass this.
        if now < p.pre_copy_ms {
            arrival_credit = arrival_credit.saturating_add(p.arrivals_per_second);
            let arrivals = arrival_credit / 1_000;
            arrival_credit %= 1_000;
            for _ in 0..arrivals {
                if pending.len() == p.queue_capacity {
                    result.rejected += 1;
                } else {
                    result.admitted += 1;
                    pending.push_back(result.admitted);
                }
            }
            result.max_queue = result.max_queue.max(pending.len());
        }

        durable_credit = durable_credit.saturating_add(p.durable_records_per_second);
        let available_commits = durable_credit / 1_000;
        durable_credit %= 1_000;
        for _ in 0..available_commits.min(pending.len() as u64) {
            let Some(sequence) = pending.pop_front() else {
                return Err("capacity model: missing reserved write".into());
            };
            result.committed += 1;
            result.last_commit_sequence = sequence;
            backlog += 1;
        }
        // Service capacity cannot be banked while idle. Only a fractional tick
        // remainder carries forward; otherwise idle time would fake burst speed.
        if now == p.pre_copy_ms {
            result.tail_at_fence = backlog;
        }
        if now >= p.pre_copy_ms && pending.is_empty() && result.seal_ms.is_none() {
            result.seal_ms = Some(now);
        }

        transfer_credit = transfer_credit.saturating_add(p.transfer_records_per_second);
        let available_copy = transfer_credit / 1_000;
        transfer_credit %= 1_000;
        let copied = available_copy.min(backlog);
        backlog -= copied;
        result.copied += copied;

        if result.seal_ms.is_some() && backlog == 0 {
            let started = *installation_started.get_or_insert(now);
            if now.saturating_sub(started) >= p.install_ms {
                result.installed_sequence = Some(result.last_commit_sequence);
                result.activation_ms = Some(now);
                break;
            }
        }
    }
    check(
        result.max_queue <= p.queue_capacity,
        "queue exceeded reservation limit",
    )?;
    check(
        result.committed <= result.admitted,
        "unreserved durable write",
    )?;
    if let Some(activation) = result.activation_ms {
        check(
            result.seal_ms.is_some_and(|seal| seal <= activation),
            "activation before seal",
        )?;
        check(
            result.committed == result.admitted,
            "activation before write drain",
        )?;
        check(
            result.installed_sequence == Some(result.last_commit_sequence),
            "missing final delta",
        )?;
        check(
            result.copied == p.snapshot_records + result.committed,
            "copy coverage mismatch",
        )?;
    }
    Ok(result)
}

pub fn run_checks() -> Result<usize, String> {
    println!("CAPACITY: virtual records/s; no CPU, disk, network or signature benchmark");
    let common = Parameters {
        arrivals_per_second: 1_000,
        durable_records_per_second: 20_000,
        transfer_records_per_second: 40_000,
        queue_capacity: 1_000,
        snapshot_records: 100_000,
        pre_copy_ms: 5_000,
        install_ms: 5,
        event_limit_ms: 120_000,
    };
    for offered in [1_000, 10_000] {
        let p = Parameters {
            arrivals_per_second: offered,
            ..common
        };
        let result = simulate(p)?;
        check(
            result.rejected == 0,
            "stable offered load unexpectedly rejected",
        )?;
        check(result.activation_ms.is_some(), "stable load did not finish")?;
        println!(
            "CAPACITY offered={offered} commit={} transfer={} snapshot={} admitted={} rejected={} tail={} pause_ms={} assumption=effective_useful_record_rates",
            p.durable_records_per_second, p.transfer_records_per_second,
            p.snapshot_records, result.admitted, result.rejected, result.tail_at_fence,
            result.activation_ms.map(|time| time.saturating_sub(p.pre_copy_ms)).unwrap_or_default()
        );
    }
    let slow = simulate(Parameters {
        arrivals_per_second: 10_000,
        transfer_records_per_second: 5_000,
        ..common
    })?;
    check(
        slow.tail_at_fence > common.snapshot_records,
        "slow transfer appeared to catch up live",
    )?;
    check(
        slow.activation_ms.is_some(),
        "paused finite tail did not drain",
    )?;
    println!(
        "CAPACITY transfer_below_arrivals tail={} pause_ms={} result=longer_pause_not_impossible_handoff",
        slow.tail_at_fence,
        slow.activation_ms.map(|time| time.saturating_sub(common.pre_copy_ms)).unwrap_or_default()
    );

    let saturated = simulate(Parameters {
        arrivals_per_second: 10_000,
        durable_records_per_second: 2_000,
        queue_capacity: 100,
        ..common
    })?;
    check(
        saturated.rejected > 0,
        "saturation did not exercise rejection",
    )?;
    check(
        saturated.activation_ms.is_some(),
        "admitted bounded backlog failed to drain",
    )?;
    println!(
        "CAPACITY saturation admitted={} rejected={} max_queue={} result=bounded_reservation_before_mutation",
        saturated.admitted, saturated.rejected, saturated.max_queue
    );

    let bounded = simulate(Parameters {
        event_limit_ms: 10,
        ..common
    })?;
    check(
        bounded.activation_ms.is_none(),
        "event-limit fixture accidentally activated",
    )?;
    println!("CAPACITY bounded_run=INCONCLUSIVE (required progress was not reached)");

    // Live offset pagination can omit a still-live record when an earlier entry
    // expires between pages. This is a deliberate mutant, not an acceptable sync.
    let snapshot = [10_u64, 20, 30];
    let first_page = snapshot[..1].to_vec();
    let live_after_expiry = [20_u64, 30];
    let mut unsafe_download = first_page.clone();
    unsafe_download.extend_from_slice(&live_after_expiry[1..]);
    check(
        !unsafe_download.contains(&20),
        "offset-pagination mutant failed to omit record",
    )?;
    let mut bound_download = first_page;
    bound_download.extend_from_slice(&snapshot[1..]);
    // A source-local post-snapshot durable sequence is replayed before closure.
    let delta = [(1_u64, 40_u64), (2, 50)];
    let mut last_sequence = 0;
    for (sequence, record) in delta {
        check(sequence == last_sequence + 1, "noncontiguous change feed")?;
        bound_download.push(record);
        last_sequence = sequence;
    }
    check(
        bound_download == [10, 20, 30, 40, 50],
        "snapshot/delta coverage failed",
    )?;
    check(last_sequence == 2, "closure endpoint not reached")?;
    println!("TRANSFER live_offset_mutant=record_20_omitted snapshot_plus_contiguous_deltas=PASS (abstract records)");
    Ok(6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_capacity_checks() -> Result<(), String> {
        run_checks().map(|_| ())
    }
}
