//! F2F Operator Dialogue and Hop-2 Topology Sensorics Module
//!
//! Provides bounded local persistence for operator conversations between direct F2F friends,
//! 1-slot reconnect outbox queues, inbound rate limiting, and Hop-2 mutual-consent neighbor
//! roster tracking (INV-1701 & Dunbar Bubble Diagnostics).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::network::framing::{
    F2fNeighborRosterPayload, F2fOperatorMessagePayload, MAX_VISIBLE_F2F_NEIGHBORS,
};

pub const MAX_STORED_MESSAGES_PER_FRIEND: usize = 20;
pub const MAX_INBOUND_PER_HOUR: usize = 10;
pub const INBOUND_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(3600);
pub const F2F_INBOX_FILE_NAME: &str = "f2f_inbox.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum F2fMessageDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct F2fStoredMessage {
    pub msg_id: u64,
    pub peer_pubkey: [u8; 32],
    pub direction: F2fMessageDirection,
    pub timestamp_ms: u64,
    pub text: String,
    pub trace_pubkeys: Vec<[u8; 32]>,
    pub reply_to_msg_id: Option<u64>,
    pub delivered: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct F2fDiskSchema {
    messages: HashMap<String, Vec<F2fStoredMessage>>,
    #[serde(default)]
    pending_outbox: HashMap<String, F2fOperatorMessagePayload>,
}

#[derive(Debug)]
pub struct F2fInboxStore {
    data_dir: Option<PathBuf>,
    messages: HashMap<[u8; 32], Vec<F2fStoredMessage>>,
    pending_outbox: HashMap<[u8; 32], F2fOperatorMessagePayload>,
    inbound_timestamps: HashMap<[u8; 32], Vec<Instant>>,
}

impl F2fInboxStore {
    pub fn new(data_dir: Option<PathBuf>) -> Self {
        let mut store = Self {
            data_dir: data_dir.clone(),
            messages: HashMap::new(),
            pending_outbox: HashMap::new(),
            inbound_timestamps: HashMap::new(),
        };

        if let Some(ref dir) = data_dir {
            let path = dir.join(F2F_INBOX_FILE_NAME);
            store.load_from_path(&path);
        }

        store
    }

    fn load_from_path(&mut self, path: &Path) {
        if !path.exists() {
            return;
        }
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        let Ok(schema) = serde_json::from_slice::<F2fDiskSchema>(&bytes) else {
            return;
        };

        for (pk_hex, msgs) in schema.messages {
            let Ok(pk_bytes) = hex::decode(&pk_hex) else {
                continue;
            };
            if let Ok(pk) = <[u8; 32]>::try_from(pk_bytes.as_slice()) {
                let mut trimmed = msgs;
                if trimmed.len() > MAX_STORED_MESSAGES_PER_FRIEND {
                    let keep_from = trimmed.len() - MAX_STORED_MESSAGES_PER_FRIEND;
                    trimmed = trimmed.split_off(keep_from);
                }
                self.messages.insert(pk, trimmed);
            }
        }

        for (pk_hex, payload) in schema.pending_outbox {
            let Ok(pk_bytes) = hex::decode(&pk_hex) else {
                continue;
            };
            if let Ok(pk) = <[u8; 32]>::try_from(pk_bytes.as_slice()) {
                self.pending_outbox.insert(pk, payload);
            }
        }
    }

    pub fn save_to_disk(&self) {
        let Some(ref dir) = self.data_dir else {
            return;
        };
        let target_path = dir.join(F2F_INBOX_FILE_NAME);
        let tmp_path = dir.join(format!("{}.tmp", F2F_INBOX_FILE_NAME));

        let mut schema = F2fDiskSchema {
            messages: HashMap::new(),
            pending_outbox: HashMap::new(),
        };

        for (pk, msgs) in &self.messages {
            schema.messages.insert(hex::encode(pk), msgs.clone());
        }
        for (pk, payload) in &self.pending_outbox {
            schema.pending_outbox.insert(hex::encode(pk), payload.clone());
        }

        let Ok(json_bytes) = serde_json::to_vec_pretty(&schema) else {
            return;
        };

        let _ = std::fs::create_dir_all(dir);
        if std::fs::write(&tmp_path, json_bytes).is_ok() {
            let _ = std::fs::rename(&tmp_path, &target_path);
        }
    }

    /// Records an authentic inbound message from a direct F2F friend.
    /// Rejects if the peer exceeds the rate limit (max 10 messages / hour).
    pub fn record_inbound(
        &mut self,
        payload: F2fOperatorMessagePayload,
        now: Instant,
    ) -> Result<F2fStoredMessage, &'static str> {
        let sender = payload.sender_pubkey;

        // Rate limit check
        let timestamps = self.inbound_timestamps.entry(sender).or_default();
        timestamps.retain(|&t| now.duration_since(t) < INBOUND_RATE_LIMIT_WINDOW);
        if timestamps.len() >= MAX_INBOUND_PER_HOUR {
            return Err("Inbound F2F message rate limit exceeded (max 10/hour)");
        }
        timestamps.push(now);

        // Check for duplicate message ID
        let friend_msgs = self.messages.entry(sender).or_default();
        if let Some(existing) = friend_msgs.iter().find(|m| m.msg_id == payload.msg_id) {
            return Ok(existing.clone());
        }

        let stored = F2fStoredMessage {
            msg_id: payload.msg_id,
            peer_pubkey: sender,
            direction: F2fMessageDirection::Inbound,
            timestamp_ms: payload.timestamp_ms,
            text: payload.text,
            trace_pubkeys: payload.trace_pubkeys,
            reply_to_msg_id: payload.reply_to_msg_id,
            delivered: true,
        };

        friend_msgs.push(stored.clone());
        if friend_msgs.len() > MAX_STORED_MESSAGES_PER_FRIEND {
            friend_msgs.remove(0);
        }

        self.save_to_disk();
        Ok(stored)
    }

    /// Queues or records an outbound message to a direct F2F friend.
    /// If not delivered, stores in the 1-slot reconnect outbox.
    pub fn queue_outbound(
        &mut self,
        friend_pk: [u8; 32],
        payload: F2fOperatorMessagePayload,
        delivered: bool,
    ) -> F2fStoredMessage {
        if !delivered {
            self.pending_outbox.insert(friend_pk, payload.clone());
        } else {
            self.pending_outbox.remove(&friend_pk);
        }

        let stored = F2fStoredMessage {
            msg_id: payload.msg_id,
            peer_pubkey: friend_pk,
            direction: F2fMessageDirection::Outbound,
            timestamp_ms: payload.timestamp_ms,
            text: payload.text,
            trace_pubkeys: payload.trace_pubkeys,
            reply_to_msg_id: payload.reply_to_msg_id,
            delivered,
        };

        let friend_msgs = self.messages.entry(friend_pk).or_default();
        friend_msgs.push(stored.clone());
        if friend_msgs.len() > MAX_STORED_MESSAGES_PER_FRIEND {
            friend_msgs.remove(0);
        }

        self.save_to_disk();
        stored
    }

    /// Handles delivery ack from friend, clears pending outbox and updates stored message status.
    pub fn on_ack_received(&mut self, friend_pk: [u8; 32], msg_id: u64) -> bool {
        let removed_outbox = if let Some(pending) = self.pending_outbox.get(&friend_pk) {
            if pending.msg_id == msg_id {
                self.pending_outbox.remove(&friend_pk);
                true
            } else {
                false
            }
        } else {
            false
        };

        let mut marked_delivered = false;
        if let Some(list) = self.messages.get_mut(&friend_pk) {
            for msg in list.iter_mut() {
                if msg.msg_id == msg_id && msg.direction == F2fMessageDirection::Outbound {
                    msg.delivered = true;
                    marked_delivered = true;
                }
            }
        }

        if removed_outbox || marked_delivered {
            self.save_to_disk();
            true
        } else {
            false
        }
    }

    pub fn get_pending_outbox(&self, friend_pk: &[u8; 32]) -> Option<&F2fOperatorMessagePayload> {
        self.pending_outbox.get(friend_pk)
    }

    pub fn list_pending_outbox(&self) -> Vec<([u8; 32], F2fOperatorMessagePayload)> {
        self.pending_outbox.iter().map(|(&k, v)| (k, v.clone())).collect()
    }

    pub fn list_messages_for_friend(&self, friend_pk: &[u8; 32]) -> Vec<F2fStoredMessage> {
        self.messages.get(friend_pk).cloned().unwrap_or_default()
    }

    pub fn get_message(&self, friend_pk: &[u8; 32], msg_id: u64) -> Option<F2fStoredMessage> {
        self.messages
            .get(friend_pk)
            .and_then(|list| list.iter().find(|m| m.msg_id == msg_id).cloned())
    }

    pub fn list_all_messages(&self) -> HashMap<[u8; 32], Vec<F2fStoredMessage>> {
        self.messages.clone()
    }
}

/// Tracks neighbor rosters received from direct F2F friends and constructs our local roster.
#[derive(Debug)]
pub struct F2fRosterTracker {
    share_neighbor_roster: bool,
    friend_rosters: HashMap<[u8; 32], F2fNeighborRosterPayload>,
}

impl F2fRosterTracker {
    pub fn new(share_neighbor_roster: bool) -> Self {
        Self {
            share_neighbor_roster,
            friend_rosters: HashMap::new(),
        }
    }

    pub fn share_neighbor_roster(&self) -> bool {
        self.share_neighbor_roster
    }

    pub fn set_share_neighbor_roster(&mut self, val: bool) {
        self.share_neighbor_roster = val;
    }

    pub fn record_roster(&mut self, payload: F2fNeighborRosterPayload) {
        self.friend_rosters.insert(payload.sender_pubkey, payload);
    }

    pub fn get_roster(&self, friend_pk: &[u8; 32]) -> Option<&F2fNeighborRosterPayload> {
        self.friend_rosters.get(friend_pk)
    }

    pub fn friend_rosters(&self) -> &HashMap<[u8; 32], F2fNeighborRosterPayload> {
        &self.friend_rosters
    }

    /// Constructs the canonical local roster obeying mutual consent.
    ///
    /// If local `share_neighbor_roster` is false, zero neighbors are shared and all are counted as hidden.
    /// If true, friends who explicitly opted out (`shares_roster == false`) are excluded from `visible_neighbors`
    /// and counted as hidden. All other friends (up to [`MAX_VISIBLE_F2F_NEIGHBORS`]) are visible.
    pub fn build_local_roster(
        &self,
        self_pubkey: &[u8; 32],
        f2f_friend_pubkeys: &[[u8; 32]],
        now_ms: u64,
    ) -> F2fNeighborRosterPayload {
        if !self.share_neighbor_roster {
            let mut hidden: u16 = 0;
            for friend in f2f_friend_pubkeys {
                if friend != self_pubkey {
                    hidden = hidden.saturating_add(1);
                }
            }
            return F2fNeighborRosterPayload {
                sender_pubkey: *self_pubkey,
                timestamp_ms: now_ms,
                shares_roster: false,
                visible_neighbors: Vec::new(),
                hidden_neighbor_count: hidden,
            };
        }

        let mut visible = Vec::new();
        let mut hidden: u16 = 0;

        for friend in f2f_friend_pubkeys {
            if friend == self_pubkey {
                continue;
            }
            let friend_shares = self
                .friend_rosters
                .get(friend)
                .map(|r| r.shares_roster)
                .unwrap_or(true);

            if !friend_shares {
                hidden = hidden.saturating_add(1);
            } else if visible.len() < MAX_VISIBLE_F2F_NEIGHBORS {
                visible.push(*friend);
            } else {
                hidden = hidden.saturating_add(1);
            }
        }

        F2fNeighborRosterPayload {
            sender_pubkey: *self_pubkey,
            timestamp_ms: now_ms,
            shares_roster: true,
            visible_neighbors: visible,
            hidden_neighbor_count: hidden,
        }
    }

    /// Evaluates if local node is trapped in an isolated closed triangle bubble:
    /// At least 2 direct friends share non-empty rosters, and 100% of their visible neighbors
    /// are either ourselves or our direct friends (0 external Hop-2 bridges).
    pub fn is_closed_triangle_bubble(
        &self,
        self_pubkey: &[u8; 32],
        my_friends: &[[u8; 32]],
    ) -> bool {
        let friends_with_rosters: Vec<&[u8; 32]> = my_friends
            .iter()
            .filter(|f| {
                self.friend_rosters
                    .get(*f)
                    .is_some_and(|r| r.shares_roster && !r.visible_neighbors.is_empty())
            })
            .collect();

        if friends_with_rosters.len() < 2 {
            return false;
        }

        for &friend in &friends_with_rosters {
            if let Some(roster) = self.friend_rosters.get(friend) {
                for neighbor in &roster.visible_neighbors {
                    if neighbor != self_pubkey && !my_friends.contains(neighbor) {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Evaluates whether a peer claims an abnormally high neighbor count (> 32).
    pub fn is_mega_hub(&self, friend_pk: &[u8; 32]) -> bool {
        if let Some(roster) = self.friend_rosters.get(friend_pk) {
            roster.visible_neighbors.len().saturating_add(roster.hidden_neighbor_count as usize) > 32
        } else {
            false
        }
    }
}

/// Unified coordinator for F2F collaboration features.
#[derive(Debug)]
pub struct F2fCollabManager {
    inbox: F2fInboxStore,
    roster: F2fRosterTracker,
}

impl F2fCollabManager {
    pub fn new(data_dir: Option<PathBuf>, share_neighbor_roster: bool) -> Self {
        Self {
            inbox: F2fInboxStore::new(data_dir),
            roster: F2fRosterTracker::new(share_neighbor_roster),
        }
    }

    pub fn inbox(&self) -> &F2fInboxStore {
        &self.inbox
    }

    pub fn inbox_mut(&mut self) -> &mut F2fInboxStore {
        &mut self.inbox
    }

    pub fn roster(&self) -> &F2fRosterTracker {
        &self.roster
    }

    pub fn roster_mut(&mut self) -> &mut F2fRosterTracker {
        &mut self.roster
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_f2f_inbox_roundtrip_and_ring_buffer() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut inbox = F2fInboxStore::new(Some(temp_dir.path().to_path_buf()));
        let friend = [42u8; 32];
        let now = Instant::now();

        // Push 25 messages -> verify bounded at 20
        for i in 0..25 {
            let payload = F2fOperatorMessagePayload {
                msg_id: i as u64,
                sender_pubkey: friend,
                timestamp_ms: 1000 + i as u64,
                text: format!("msg {}", i),
                trace_pubkeys: vec![],
                reply_to_msg_id: None,
            };
            // Reset timestamps to bypass rate limiting for ring buffer test
            inbox.inbound_timestamps.clear();
            inbox.record_inbound(payload, now).unwrap();
        }

        let msgs = inbox.list_messages_for_friend(&friend);
        assert_eq!(msgs.len(), 20);
        assert_eq!(msgs[0].msg_id, 5);
        assert_eq!(msgs[19].msg_id, 24);

        // Reload from disk to verify persistence
        let reloaded = F2fInboxStore::new(Some(temp_dir.path().to_path_buf()));
        let reloaded_msgs = reloaded.list_messages_for_friend(&friend);
        assert_eq!(reloaded_msgs.len(), 20);
        assert_eq!(reloaded_msgs[0].msg_id, 5);
        assert_eq!(reloaded_msgs[19].msg_id, 24);
    }

    #[test]
    fn test_f2f_inbox_rate_limiting() {
        let mut inbox = F2fInboxStore::new(None);
        let friend = [7u8; 32];
        let now = Instant::now();

        for i in 0..10 {
            let payload = F2fOperatorMessagePayload {
                msg_id: i,
                sender_pubkey: friend,
                timestamp_ms: 1000,
                text: "test".into(),
                trace_pubkeys: vec![],
                reply_to_msg_id: None,
            };
            assert!(inbox.record_inbound(payload, now).is_ok());
        }

        // 11th message within 1 hour is rejected
        let eleventh = F2fOperatorMessagePayload {
            msg_id: 11,
            sender_pubkey: friend,
            timestamp_ms: 1000,
            text: "overflow".into(),
            trace_pubkeys: vec![],
            reply_to_msg_id: None,
        };
        assert!(inbox.record_inbound(eleventh, now).is_err());

        // After 1 hour + 1 second, rate limit resets
        let later = now + Duration::from_secs(3601);
        let allowed = F2fOperatorMessagePayload {
            msg_id: 12,
            sender_pubkey: friend,
            timestamp_ms: 1000,
            text: "allowed".into(),
            trace_pubkeys: vec![],
            reply_to_msg_id: None,
        };
        assert!(inbox.record_inbound(allowed, later).is_ok());
    }

    #[test]
    fn test_f2f_outbox_queue_and_ack() {
        let mut inbox = F2fInboxStore::new(None);
        let friend = [99u8; 32];
        let payload = F2fOperatorMessagePayload {
            msg_id: 555,
            sender_pubkey: [1u8; 32],
            timestamp_ms: 5000,
            text: "Are you seeing node X down?".into(),
            trace_pubkeys: vec![[88u8; 32]],
            reply_to_msg_id: None,
        };

        // Outbound send queued as undelivered
        let stored = inbox.queue_outbound(friend, payload.clone(), false);
        assert!(!stored.delivered);
        assert!(inbox.get_pending_outbox(&friend).is_some());

        // Ack arrives matching msg_id
        assert!(inbox.on_ack_received(friend, 555));
        assert!(inbox.get_pending_outbox(&friend).is_none());
        let msgs = inbox.list_messages_for_friend(&friend);
        assert!(msgs[0].delivered);
    }

    #[test]
    fn test_mutual_consent_roster_builder() {
        let mut tracker = F2fRosterTracker::new(true);
        let me = [0u8; 32];
        let friend_alice = [1u8; 32];
        let friend_bob = [2u8; 32]; // Bob opts out of roster sharing

        tracker.record_roster(F2fNeighborRosterPayload {
            sender_pubkey: friend_bob,
            timestamp_ms: 1000,
            shares_roster: false,
            visible_neighbors: vec![],
            hidden_neighbor_count: 5,
        });

        let friends = vec![friend_alice, friend_bob];
        let roster = tracker.build_local_roster(&me, &friends, 2000);

        assert!(roster.shares_roster);
        assert_eq!(roster.visible_neighbors, vec![friend_alice]);
        assert_eq!(roster.hidden_neighbor_count, 1); // Bob is masked out

        // If local node sets share_neighbor_roster = false:
        tracker.set_share_neighbor_roster(false);
        let hidden_roster = tracker.build_local_roster(&me, &friends, 3000);
        assert!(!hidden_roster.shares_roster);
        assert!(hidden_roster.visible_neighbors.is_empty());
        assert_eq!(hidden_roster.hidden_neighbor_count, 2);
    }

    #[test]
    fn test_closed_triangle_bubble_and_mega_hub() {
        let mut tracker = F2fRosterTracker::new(true);
        let me = [0u8; 32];
        let f1 = [1u8; 32];
        let f2 = [2u8; 32];

        // f1 and f2 only see each other and me
        tracker.record_roster(F2fNeighborRosterPayload {
            sender_pubkey: f1,
            timestamp_ms: 1000,
            shares_roster: true,
            visible_neighbors: vec![me, f2],
            hidden_neighbor_count: 0,
        });
        tracker.record_roster(F2fNeighborRosterPayload {
            sender_pubkey: f2,
            timestamp_ms: 1000,
            shares_roster: true,
            visible_neighbors: vec![me, f1],
            hidden_neighbor_count: 0,
        });

        assert!(tracker.is_closed_triangle_bubble(&me, &[f1, f2]));

        // Add external neighbor to f2 -> bubble broken!
        let external = [99u8; 32];
        tracker.record_roster(F2fNeighborRosterPayload {
            sender_pubkey: f2,
            timestamp_ms: 1001,
            shares_roster: true,
            visible_neighbors: vec![me, f1, external],
            hidden_neighbor_count: 0,
        });
        assert!(!tracker.is_closed_triangle_bubble(&me, &[f1, f2]));

        // Test mega hub detection
        assert!(!tracker.is_mega_hub(&f1));
        tracker.record_roster(F2fNeighborRosterPayload {
            sender_pubkey: f1,
            timestamp_ms: 1002,
            shares_roster: true,
            visible_neighbors: vec![[5u8; 32]; 30],
            hidden_neighbor_count: 5, // 35 total > 32
        });
        assert!(tracker.is_mega_hub(&f1));
    }

    #[test]
    fn test_s04_18_roster_builder_payload_ceiling_and_mutual_consent_boundary() {
        let mut tracker = F2fRosterTracker::new(true);
        let me = [0xAAu8; 32];
        let now_ms = 1_700_000_000_000u64;

        // Test 62, 63, 64, 65 candidate friends
        for total_candidates in [62usize, 63, 64, 65] {
            let candidates: Vec<[u8; 32]> = (1..=total_candidates)
                .map(|i| {
                    let mut pk = [0u8; 32];
                    pk[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    pk
                })
                .collect();

            let roster = tracker.build_local_roster(&me, &candidates, now_ms);

            // Invariant 1: Visible neighbors must NEVER exceed 62
            assert!(
                roster.visible_neighbors.len() <= 62,
                "Visible neighbors must never exceed 62, got {}",
                roster.visible_neighbors.len()
            );

            // Invariant 2: Total candidate accounting must be preserved
            let total_accounted = roster
                .visible_neighbors
                .len()
                .saturating_add(roster.hidden_neighbor_count as usize);
            assert_eq!(
                total_accounted, total_candidates,
                "Total accounted friends (visible + hidden) must match total candidates"
            );

            // Invariant 3: Expected split
            let expected_visible = total_candidates.min(62);
            let expected_hidden = total_candidates.saturating_sub(62) as u16;
            assert_eq!(roster.visible_neighbors.len(), expected_visible);
            assert_eq!(roster.hidden_neighbor_count, expected_hidden);

            // Invariant 4: Validation and serialization must succeed and fit <= 2048 bytes
            assert!(
                roster.validate().is_ok(),
                "Builder output must pass validation for {} candidates",
                total_candidates
            );
            let bytes = roster
                .to_bytes()
                .expect("Builder output must serialize within payload ceiling");
            assert!(
                bytes.len() <= crate::network::framing::MAX_F2F_FRAME_PAYLOAD_LEN,
                "Encoded bytes {} must be <= 2048",
                bytes.len()
            );

            // Invariant 5: Round-trip decode
            let decoded = crate::network::framing::F2fNeighborRosterPayload::from_bytes(&bytes)
                .expect("Roundtrip decode must succeed");
            assert_eq!(decoded, roster);
        }

        // Mixed test: opt-out friends and overflow friends
        // 70 candidates: 65 willing, 5 opted-out
        let willing: Vec<[u8; 32]> = (1..=65)
            .map(|i| {
                let mut pk = [1u8; 32];
                pk[..8].copy_from_slice(&(i as u64).to_le_bytes());
                pk
            })
            .collect();
        let opted_out: Vec<[u8; 32]> = (66..=70)
            .map(|i| {
                let mut pk = [2u8; 32];
                pk[..8].copy_from_slice(&(i as u64).to_le_bytes());
                pk
            })
            .collect();

        for friend in &opted_out {
            tracker.record_roster(F2fNeighborRosterPayload {
                sender_pubkey: *friend,
                timestamp_ms: now_ms,
                shares_roster: false,
                visible_neighbors: vec![],
                hidden_neighbor_count: 0,
            });
        }

        let mut all_70 = willing.clone();
        all_70.extend(opted_out);

        let roster_70 = tracker.build_local_roster(&me, &all_70, now_ms);
        // 65 willing -> 62 visible, 3 overflow hidden
        // 5 opted out -> 5 hidden
        // total hidden = 8
        assert_eq!(roster_70.visible_neighbors.len(), 62);
        assert_eq!(roster_70.hidden_neighbor_count, 8);
        assert_eq!(
            roster_70.visible_neighbors.len() + roster_70.hidden_neighbor_count as usize,
            70
        );
        let bytes_70 = roster_70.to_bytes().expect("roster_70 encodes");
        assert!(bytes_70.len() <= crate::network::framing::MAX_F2F_FRAME_PAYLOAD_LEN);
    }
}
