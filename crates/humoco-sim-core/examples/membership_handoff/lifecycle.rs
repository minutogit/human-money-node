//! Exhaustive finite lifecycle model for one vote and one handoff boundary.
//! This checks local ordering, not a quorum protocol or the storage engine.

use std::collections::{BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
struct State {
    pending: bool,
    durable_choice: bool,
    fence_requested: bool,
    durable_fence: bool,
    snapshot: Option<bool>,
    response_released: bool,
    installed: bool,
    conflicting_successor_vote: bool,
    crashed: bool,
}

#[derive(Clone, Copy, Debug)]
enum Action {
    Admit,
    Commit,
    RequestFence,
    FinishFence,
    Snapshot,
    Release,
    Crash,
    Restart,
    Install,
    SuccessorVote,
}

const ACTIONS: [Action; 10] = [
    Action::Admit,
    Action::Commit,
    Action::RequestFence,
    Action::FinishFence,
    Action::Snapshot,
    Action::Release,
    Action::Crash,
    Action::Restart,
    Action::Install,
    Action::SuccessorVote,
];

fn step(mut s: State, action: Action, early_snapshot_mutant: bool) -> Option<State> {
    if s.crashed && !matches!(action, Action::Restart) {
        return None;
    }
    match action {
        Action::Admit if !s.fence_requested && !s.pending && !s.durable_choice => {
            s.pending = true;
        }
        Action::Commit if s.pending && !s.durable_fence => {
            s.durable_choice = true;
            s.pending = false;
        }
        Action::RequestFence if !s.fence_requested => s.fence_requested = true,
        Action::FinishFence if s.fence_requested && !s.pending && !s.durable_fence => {
            s.durable_fence = true;
        }
        Action::Snapshot
            if s.snapshot.is_none()
                && (s.durable_fence || (early_snapshot_mutant && s.fence_requested)) =>
        {
            s.snapshot = Some(s.durable_choice);
        }
        Action::Release if s.durable_choice && !s.response_released => {
            s.response_released = true;
        }
        Action::Crash => {
            s.crashed = true;
            // An uncommitted request may be lost; no vote could have escaped.
            s.pending = false;
            // A durable fence survives. An admission stop without committed
            // fence is conservatively kept here; this cannot reopen writes.
        }
        Action::Restart if s.crashed => s.crashed = false,
        Action::Install if s.snapshot.is_some() && !s.installed => s.installed = true,
        Action::SuccessorVote
            if s.installed && s.snapshot == Some(false) && !s.conflicting_successor_vote =>
        {
            s.conflicting_successor_vote = true;
        }
        _ => return None,
    }
    Some(s)
}

struct Explored {
    states: usize,
    edges: usize,
    old_vote_seen: bool,
    successor_vote_seen: bool,
    trace: Option<Vec<Action>>,
}

fn explore(mutant: bool) -> Result<Explored, String> {
    let mut visited = BTreeSet::from([State::default()]);
    let mut work = VecDeque::from([(State::default(), Vec::<Action>::new())]);
    let mut result = Explored {
        states: 1,
        edges: 0,
        old_vote_seen: false,
        successor_vote_seen: false,
        trace: None,
    };
    while let Some((state, trace)) = work.pop_front() {
        result.old_vote_seen |= state.response_released;
        result.successor_vote_seen |= state.conflicting_successor_vote;
        if state.response_released && state.conflicting_successor_vote {
            result.trace = Some(trace);
            break;
        }
        if state.response_released && !state.durable_choice {
            return Err("lifecycle emitted an undurable vote".into());
        }
        for action in ACTIONS {
            if let Some(next) = step(state, action, mutant) {
                result.edges += 1;
                if visited.insert(next) {
                    if visited.len() > 10_000 {
                        return Err("INCONCLUSIVE: lifecycle state bound reached".into());
                    }
                    let mut next_trace = trace.clone();
                    next_trace.push(action);
                    work.push_back((next, next_trace));
                }
            }
        }
    }
    result.states = visited.len();
    Ok(result)
}

pub fn run_checks() -> Result<usize, String> {
    let safe = explore(false)?;
    if safe.trace.is_some() || !safe.old_vote_seen || !safe.successor_vote_seen {
        return Err("lifecycle safety or non-vacuity failed".into());
    }
    println!(
        "LIFECYCLE exhaustive_finite states={} edges={} released_old_vote=true fresh_successor_vote=true conflict=false",
        safe.states, safe.edges
    );
    let mutant = explore(true)?;
    let trace = mutant
        .trace
        .ok_or("early snapshot mutant did not expose pending vote")?;
    println!("LIFECYCLE EXPECTED-UNSAFE snapshot_before_drain trace={trace:?}");
    Ok(2)
}

#[cfg(test)]
mod tests {
    #[test]
    fn exhaustive_local_lifecycle_and_mutant() -> Result<(), String> {
        super::run_checks().map(|_| ())
    }
}
