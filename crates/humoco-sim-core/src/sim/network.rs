use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use crate::sim::node::SimNode;
use crate::types::{Attestation, Hash256, LockRecord, NodeId, SimTime};

/// Message types within the discrete simulation network
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimMessage {
    /// Request to lock a balance
    LockRequest(LockRecord),
    /// Signed attestation from a node
    LockAttestation(Attestation),
    /// Gossip for forwarding a lock
    GossipLock { lock: LockRecord, hops: u8 },
    /// Gossip for attestation (receipt)
    GossipReceipt {
        lock_id: Hash256,
        attestation: Attestation,
        hops: u8,
    },
    /// Fraud proof (pillars 1..3) – priority-0 emergency alert
    FraudProof(crate::fraud::FraudProofPayload),
    /// Heartbeat for presence / pillar 3 detector
    Heartbeat(crate::fraud::Heartbeat),
}

/// Scheduled discrete event in the priority queue
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduledEvent {
    pub deliver_at: SimTime,
    pub event_id: u64,
    pub from: NodeId,
    pub to: NodeId,
    pub msg: SimMessage,
}

impl Ord for ScheduledEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        // Min-heap based on deliver_at (earliest time first)
        other
            .deliver_at
            .cmp(&self.deliver_at)
            .then_with(|| other.event_id.cmp(&self.event_id))
    }
}

impl PartialOrd for ScheduledEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Discrete-event simulation network (zero-I/O, 100% deterministic)
pub struct SimNetwork {
    pub current_time: SimTime,
    pub nodes: BTreeMap<NodeId, SimNode>,
    pub events: BinaryHeap<ScheduledEvent>,
    pub partitions: Vec<BTreeSet<NodeId>>,
    pub min_latency_ms: u64,
    pub max_latency_ms: u64,
    pub packet_drop_rate: f64,
    next_event_id: u64,
    prng_state: u64,
}

impl Default for SimNetwork {
    fn default() -> Self {
        Self::new()
    }
}

impl SimNetwork {
    pub fn new() -> Self {
        Self {
            current_time: SimTime::ZERO,
            nodes: BTreeMap::new(),
            events: BinaryHeap::new(),
            partitions: Vec::new(),
            min_latency_ms: 10,
            max_latency_ms: 30,
            packet_drop_rate: 0.0,
            next_event_id: 0,
            prng_state: 123456789,
        }
    }

    /// Deterministic pseudo-random generator (Xorshift64) for deterministic latencies
    fn next_prng(&mut self) -> u64 {
        let mut x = self.prng_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.prng_state = x;
        x
    }

    pub fn add_node(&mut self, node: SimNode) {
        self.nodes.insert(node.id, node);
    }

    pub fn set_latency(&mut self, min_ms: u64, max_ms: u64) {
        self.min_latency_ms = min_ms;
        self.max_latency_ms = max_ms;
    }

    pub fn set_packet_drop_rate(&mut self, drop_rate: f64) {
        self.packet_drop_rate = drop_rate;
    }

    /// Creates network partitions. Nodes can only communicate within the same group.
    pub fn partition(&mut self, groups: Vec<Vec<NodeId>>) {
        self.partitions = groups
            .into_iter()
            .map(|g| g.into_iter().collect())
            .collect();
    }

    /// Heals all network partitions (full connectivity restored)
    pub fn heal_partition(&mut self) {
        self.partitions.clear();
    }

    /// Checks whether two nodes can communicate with each other
    pub fn can_communicate(&self, from: NodeId, to: NodeId) -> bool {
        if self.partitions.is_empty() {
            return true;
        }
        for group in &self.partitions {
            if group.contains(&from) && group.contains(&to) {
                return true;
            }
        }
        false
    }

    /// Schedules an event at a specific time
    pub fn schedule(&mut self, deliver_at: SimTime, from: NodeId, to: NodeId, msg: SimMessage) {
        let event_id = self.next_event_id;
        self.next_event_id += 1;
        self.events.push(ScheduledEvent {
            deliver_at,
            event_id,
            from,
            to,
            msg,
        });
    }

    /// Sends a message with computed deterministic latency
    pub fn send_message(&mut self, from: NodeId, to: NodeId, msg: SimMessage) {
        // Packet drop check
        if self.packet_drop_rate > 0.0 {
            let rnd = (self.next_prng() % 10_000) as f64 / 10_000.0;
            if rnd < self.packet_drop_rate {
                return; // packet dropped
            }
        }

        let latency = if self.max_latency_ms > self.min_latency_ms {
            self.min_latency_ms
                + (self.next_prng() % (self.max_latency_ms - self.min_latency_ms + 1))
        } else {
            self.min_latency_ms
        };

        let deliver_at = self.current_time + latency;
        self.schedule(deliver_at, from, to, msg);
    }

    /// Executes a single simulation step
    pub fn step(&mut self) -> bool {
        let event = match self.events.pop() {
            Some(e) => e,
            None => return false,
        };

        self.current_time = event.deliver_at;

        // Partition filter: if partitioned, packet is dropped in transit
        if !self.can_communicate(event.from, event.to) {
            return true;
        }

        // Delivery to the destination node
        if let Some(node) = self.nodes.get_mut(&event.to) {
            let outgoing = node.handle_message(event.from, event.msg, self.current_time);
            for (dest, out_msg) in outgoing {
                self.send_message(event.to, dest, out_msg);
            }
        }

        true
    }

    /// Runs the simulation until a time limit is reached
    pub fn run_until(&mut self, time_limit: SimTime) {
        while let Some(next_event) = self.events.peek() {
            if next_event.deliver_at > time_limit {
                self.current_time = time_limit;
                break;
            }
            self.step();
        }
        if self.current_time < time_limit {
            self.current_time = time_limit;
        }
    }

    /// Runs the simulation until all events have been processed
    pub fn run_all(&mut self) {
        while self.step() {}
    }
}
