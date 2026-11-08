//! # Proof-Gate G4 / G5: Fail-Closed Monotonic Signing History & Clock Slot Integrity
//!
//! Architectural Invariants: INV-1402, G5 Local Signing Latch, Audit 23 Concurrency Hardening
//!
//! - FAIL-CLOSED SIGNING LATCH: Local signing history integrity is guarded by atomic commit metadata
//!   (generation, row count, XOR slot fingerprint). Any row loss, metadata corruption, or generation
//!   rollback latches `FAIL_CLOSED_CORRUPT` durably and halts further signature releases.
//! - MONOTONIC ADVANCEMENT IN SAME TRANSACTION: Generation and row fingerprints advance with checked
//!   arithmetic in the exact same redb transaction as the original approval / record change.
//! - REAL-TIME CHECKPOINT VALIDATION: QUIC heartbeats carry signed checkpoints; observing a newer
//!   generation or conflicting fingerprint for our own identity latches the node immediately.
//! - CLOCK SLOT COMPOSITION (Contract G4): Signing decisions bind strictly to slot-bound roots and
//!   median network time offsets; replay across slots or after root TTL grace expiry is prevented.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

pub const TABLE_SIGNING_STATE: TableDefinition<u8, &[u8]> =
    TableDefinition::new("signing_commit_state");

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub(super) struct SigningState {
    pub generation: u64,
    pub count: u64,
    pub fingerprint: [u8; 32],
    pub corrupt: bool,
}

pub(super) fn fingerprint(slot: &str, bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    let domain = b"HUMOCO_V1_OWN_CHOICE_STORAGE";
    h.update(&[domain.len() as u8]);
    h.update(domain);
    h.update(&(slot.len() as u64).to_le_bytes());
    h.update(slot.as_bytes());
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(bytes);
    *h.finalize().as_bytes()
}
fn xor(dst: &mut [u8; 32], value: [u8; 32]) {
    for (a, b) in dst.iter_mut().zip(value) {
        *a ^= b;
    }
}
pub(super) fn read(txn: &redb::WriteTransaction) -> Result<SigningState, StorageError> {
    let table = txn.open_table(TABLE_SIGNING_STATE)?;
    let bytes = table.get(0)?.ok_or(StorageError::SigningHistoryCorrupt)?;
    serde_json::from_slice(bytes.value()).map_err(|_| StorageError::SigningHistoryCorrupt)
}
fn write(txn: &redb::WriteTransaction, state: &SigningState) -> Result<(), StorageError> {
    let bytes = serde_json::to_vec(state)?;
    txn.open_table(TABLE_SIGNING_STATE)?
        .insert(0, bytes.as_slice())?;
    Ok(())
}

/// Streams startup validation without repairing incomplete signing histories.
pub(super) fn initialize(
    txn: &redb::WriteTransaction,
    new_database: bool,
) -> Result<bool, StorageError> {
    let stored = {
        let table = txn.open_table(TABLE_SIGNING_STATE)?;
        let result = table
            .get(0)?
            .map(|v| serde_json::from_slice::<SigningState>(v.value()))
            .transpose();
        result
    };
    let mut measured = SigningState::default();
    let choices = txn.open_table(TABLE_OWN_CHOICES)?;
    let ttl = txn.open_table(TABLE_OWN_CHOICE_TTL)?;
    let commitments = txn.open_table(TABLE_OWN_CHOICE_COMMITMENTS)?;

    let mut valid_roots = std::collections::HashMap::new();
    let roots_table = txn.open_table(roots::TABLE_VOUCHER_ROOTS)?;
    for item in roots_table.iter()? {
        let (key, value) = item?;
        match serde_json::from_slice::<crate::api::hmc::L2LockEntry>(value.value()) {
            Ok(root_entry) => {
                if key.value() != root_entry.layer2_voucher_id.as_str() {
                    measured.corrupt = true;
                } else {
                    match roots::root_valid_until(&root_entry) {
                        Ok(valid_until) => {
                            valid_roots.insert(root_entry.layer2_voucher_id, valid_until);
                        }
                        Err(_) => {
                            measured.corrupt = true;
                        }
                    }
                }
            }
            Err(_) => {
                measured.corrupt = true;
            }
        }
    }
    let hmc_locks = txn.open_table(TABLE_HMC_LOCKS)?;
    let prov_hmc_locks = txn.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?;

    for item in choices.iter()? {
        let (slot, value) = item?;
        measured.count = measured
            .count
            .checked_add(1)
            .ok_or(StorageError::SigningHistoryCorrupt)?;
        let fp = fingerprint(slot.value(), value.value());
        xor(&mut measured.fingerprint, fp);
        let existing_fp = commitments.get(slot.value())?.map(|guard| *guard.value());
        match existing_fp {
            Some(stored_fp) => {
                if stored_fp != fp {
                    measured.corrupt = true;
                }
            }
            None => {
                measured.corrupt = true;
            }
        }
        match serde_json::from_slice::<OwnSigningChoice>(value.value()) {
            Ok(choice) => {
                measured.generation = measured.generation.max(choice.generation);
                let expiry = super::grace_expiry_bucket_sec(choice.valid_until_ms);
                if ttl.get(&(expiry, slot.value()))?.is_none() {
                    measured.corrupt = true;
                }
                let key = slot.value();
                if let Some((_, rest)) = key.split_once(':') {
                    if !rest.starts_with("native:") {
                        let raw_entry = if let Some(guard) = hmc_locks.get(rest)? {
                            Some(guard.value().to_vec())
                        } else {
                            prov_hmc_locks
                                .get(rest)?
                                .map(|guard| guard.value().to_vec())
                        };
                        if let Some(raw_bytes) = raw_entry {
                            if let Ok(hmc_entry) =
                                serde_json::from_slice::<crate::api::hmc::L2LockEntry>(&raw_bytes)
                            {
                                if let Some(&root_ttl) =
                                    valid_roots.get(&hmc_entry.layer2_voucher_id)
                                {
                                    if root_ttl != choice.valid_until_ms {
                                        measured.corrupt = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => measured.corrupt = true,
        }
    }
    if commitments.len()? != measured.count {
        measured.corrupt = true;
    }
    let state = match stored {
        Ok(Some(mut state)) => {
            state.corrupt |= measured.corrupt
                || state.count != measured.count
                || state.fingerprint != measured.fingerprint
                || measured.generation > state.generation;
            state
        }
        Ok(None) => {
            measured.corrupt |=
                !new_database || measured.count != 0 || commitments.len()? != 0 || ttl.len()? != 0;
            measured
        }
        Err(_) => {
            measured.corrupt = true;
            measured
        }
    };
    // A corrupt latch is never cleared by startup, sync or ordinary pruning.
    if state.corrupt {
        tracing::error!("FAIL_CLOSED_CORRUPT: signing history integrity check failed");
    }
    let corrupt = state.corrupt;
    write(txn, &state)?;
    Ok(corrupt)
}

pub(super) fn put_choice(
    txn: &redb::WriteTransaction,
    slot: &str,
    choice: &mut OwnSigningChoice,
) -> Result<(), StorageError> {
    let mut state = read(txn)?;
    if state.corrupt {
        return Err(StorageError::SigningHistoryCorrupt);
    }
    let mut choices = txn.open_table(TABLE_OWN_CHOICES)?;
    let actual_len = choices.len()?;
    if actual_len != state.count {
        return Err(StorageError::SigningHistoryCorrupt);
    }
    let mut commitments = txn.open_table(TABLE_OWN_CHOICE_COMMITMENTS)?;
    if commitments.len()? != state.count {
        return Err(StorageError::SigningHistoryCorrupt);
    }
    let old = choices.get(slot)?.map(|v| v.value().to_vec());
    let candidate = serde_json::to_vec(choice)?;
    if old.as_deref() == Some(candidate.as_slice()) {
        let fp = fingerprint(slot, &candidate);
        let stored_fp = commitments.get(slot)?.map(|guard| *guard.value());
        match stored_fp {
            Some(stored) if stored == fp => return Ok(()),
            _ => return Err(StorageError::SigningHistoryCorrupt),
        }
    }
    state.generation = state
        .generation
        .checked_add(1)
        .ok_or(StorageError::SigningHistoryCorrupt)?;
    choice.generation = state.generation;
    let bytes = serde_json::to_vec(choice)?;
    let new_fp = fingerprint(slot, &bytes);
    if let Some(old) = old {
        let expected_old_fp = fingerprint(slot, &old);
        let stored_fp = commitments.get(slot)?.map(|guard| *guard.value());
        match stored_fp {
            Some(stored) if stored == expected_old_fp => {}
            _ => return Err(StorageError::SigningHistoryCorrupt),
        }
        xor(&mut state.fingerprint, expected_old_fp);
    } else {
        if commitments.get(slot)?.is_some() {
            return Err(StorageError::SigningHistoryCorrupt);
        }
        state.count = state
            .count
            .checked_add(1)
            .ok_or(StorageError::SigningHistoryCorrupt)?;
    }
    xor(&mut state.fingerprint, new_fp);
    commitments.insert(slot, &new_fp)?;
    choices.insert(slot, bytes.as_slice())?;
    write(txn, &state)
}

pub(super) fn remove_choice(txn: &redb::WriteTransaction, slot: &str) -> Result<(), StorageError> {
    let mut state = read(txn)?;
    if state.corrupt {
        return Err(StorageError::SigningHistoryCorrupt);
    }
    let mut choices = txn.open_table(TABLE_OWN_CHOICES)?;
    let actual_len = choices.len()?;
    if actual_len != state.count {
        return Err(StorageError::SigningHistoryCorrupt);
    }
    let mut commitments = txn.open_table(TABLE_OWN_CHOICE_COMMITMENTS)?;
    if commitments.len()? != state.count {
        return Err(StorageError::SigningHistoryCorrupt);
    }
    let old = choices
        .get(slot)?
        .map(|v| v.value().to_vec())
        .ok_or(StorageError::SigningHistoryCorrupt)?;
    let expected_fp = fingerprint(slot, &old);
    let stored_fp = commitments
        .get(slot)?
        .map(|guard| *guard.value())
        .ok_or(StorageError::SigningHistoryCorrupt)?;
    if stored_fp != expected_fp {
        return Err(StorageError::SigningHistoryCorrupt);
    }

    choices.remove(slot)?;
    commitments.remove(slot)?;

    state.generation = state
        .generation
        .checked_add(1)
        .ok_or(StorageError::SigningHistoryCorrupt)?;
    state.count = state
        .count
        .checked_sub(1)
        .ok_or(StorageError::SigningHistoryCorrupt)?;
    xor(&mut state.fingerprint, expected_fp);
    write(txn, &state)?;
    Ok(())
}

pub(super) fn latch_corruption_in_txn(txn: &redb::WriteTransaction, signing_corrupt: &AtomicBool) {
    signing_corrupt.store(true, Ordering::Release);
    let state = {
        let table = txn.open_table(TABLE_SIGNING_STATE);
        match table {
            Ok(table) => match table.get(0) {
                Ok(Some(bytes)) => {
                    let mut s: SigningState =
                        serde_json::from_slice(bytes.value()).unwrap_or_default();
                    s.corrupt = true;
                    s
                }
                _ => SigningState {
                    corrupt: true,
                    ..Default::default()
                },
            },
            _ => SigningState {
                corrupt: true,
                ..Default::default()
            },
        }
    };
    if let Ok(mut table) = txn.open_table(TABLE_SIGNING_STATE) {
        if let Ok(bytes) = serde_json::to_vec(&state) {
            let _ = table.insert(0, bytes.as_slice());
        }
    }
    tracing::error!(
        "FAIL_CLOSED_CORRUPT: signing history corruption latched in-memory and marked in txn"
    );
}

impl RedbStorage {
    pub fn is_signing_history_healthy(&self) -> bool {
        !self.signing_corrupt.load(Ordering::Acquire)
    }

    /// Latches corruption in an existing write transaction without deadlocking begin_write.
    pub fn latch_corruption_in_txn(&self, txn: &redb::WriteTransaction) {
        latch_corruption_in_txn(txn, &self.signing_corrupt);
    }

    /// Latches corruption both in memory and durably on disk across reopen/backups.
    pub fn latch_corruption(&self) {
        self.signing_corrupt.store(true, Ordering::Release);
        if let Ok(mut txn) = self.db.begin_write() {
            txn.set_durability(redb::Durability::Immediate);
            latch_corruption_in_txn(&txn, &self.signing_corrupt);
            let _ = txn.commit();
        }
        tracing::error!(
            "FAIL_CLOSED_CORRUPT: signing history corruption latched in-memory and persisted"
        );
    }

    /// Read in a blocking worker; never required on the checkout path.
    pub fn signing_checkpoint(&self) -> Result<(u64, [u8; 32]), StorageError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(TABLE_SIGNING_STATE)?;
        let value = match table.get(0)? {
            Some(v) => v,
            None => {
                drop(table);
                drop(txn);
                self.latch_corruption();
                return Err(StorageError::SigningHistoryCorrupt);
            }
        };
        let state: SigningState = match serde_json::from_slice(value.value()) {
            Ok(s) => s,
            Err(_) => {
                drop(table);
                drop(txn);
                self.latch_corruption();
                return Err(StorageError::SigningHistoryCorrupt);
            }
        };
        if state.corrupt {
            self.signing_corrupt.store(true, Ordering::Release);
            return Err(StorageError::SigningHistoryCorrupt);
        }
        Ok((state.generation, state.fingerprint))
    }

    /// Caller first verifies an actual self-signature and network context. A peer
    /// hint by itself is never evidence. The latch also blocks already queued votes.
    pub fn observe_verified_own_checkpoint(
        &self,
        generation: u64,
        fingerprint: [u8; 32],
    ) -> Result<bool, StorageError> {
        let mut txn = self.db.begin_write()?;
        txn.set_durability(redb::Durability::Immediate);
        let state = match read(&txn) {
            Ok(s) => s,
            Err(_) => {
                latch_corruption_in_txn(&txn, &self.signing_corrupt);
                let _ = txn.commit();
                return Err(StorageError::SigningHistoryCorrupt);
            }
        };
        if state.corrupt {
            latch_corruption_in_txn(&txn, &self.signing_corrupt);
            let _ = txn.commit();
            return Err(StorageError::SigningHistoryCorrupt);
        }
        if generation > state.generation
            || (generation == state.generation && fingerprint != state.fingerprint)
        {
            latch_corruption_in_txn(&txn, &self.signing_corrupt);
            let _ = txn.commit();
            tracing::error!(
                generation,
                "FAIL_CLOSED_CORRUPT: verified own checkpoint contradicts local signing history"
            );
            return Ok(true);
        }
        Ok(false)
    }
}

pub(super) fn latch(corrupt: bool) -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(corrupt))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lock(parent: u8) -> (String, crate::api::hmc::L2LockEntry) {
        let entry = crate::api::hmc::L2LockEntry {
            causal_output: None,
            layer2_voucher_id: format!("voucher-{parent}"),
            t_id: [2; 32],
            sender_ephemeral_pub: [7; 32],
            layer2_signature: [0; 64],
            trap_r: None,
            trap_s: None,
            encrypted_timestamp: 1,
            created_at_ms: 1_000,
            deletable_at: Some("50000".into()),
            privacy_guard: None,
        };
        (format!("spend-{parent}"), entry)
    }
    #[test]
    fn premature_extra_ttl_index_preserves_choice_and_latches_durably() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ttl-corrupt.redb");
        let (tag, entry) = lock(1);
        {
            let db = RedbStorage::open(&path).unwrap();
            db.commit_original_approval(&tag, &entry, &[7; 32], b"original", 0, 50_000)
                .unwrap();
            let txn = db.db.begin_write().unwrap();
            let slot = {
                let choices = txn.open_table(TABLE_OWN_CHOICES).unwrap();
                let slot = choices
                    .iter()
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap()
                    .0
                    .value()
                    .to_string();
                slot
            };
            txn.open_table(TABLE_OWN_CHOICE_TTL)
                .unwrap()
                .insert((1, slot.as_str()), ())
                .unwrap();
            txn.commit().unwrap();
            assert!(matches!(
                db.prune_expired_buckets(1),
                Err(StorageError::SigningHistoryCorrupt)
            ));
            // Repeated prune markers must still commit the first corruption latch and return Err.
            assert!(matches!(
                db.apply_flush_batch_atomic(&[], &[], &[], &[], &[1, 81]),
                Err(StorageError::SigningHistoryCorrupt)
            ));
            assert!(!db.is_signing_history_healthy());
            let txn = db.db.begin_read().unwrap();
            assert_eq!(txn.open_table(TABLE_OWN_CHOICES).unwrap().len().unwrap(), 1);
        }
        assert!(!RedbStorage::open(&path)
            .unwrap()
            .is_signing_history_healthy());
    }
    #[test]
    fn missing_integrity_metadata_is_never_reconstructed_at_startup() {
        for remove_state in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("incomplete.redb");
            let (tag, entry) = lock(1);
            {
                let db = RedbStorage::open(&path).unwrap();
                db.commit_original_approval(&tag, &entry, &[7; 32], b"original", 0, 50_000)
                    .unwrap();
                let txn = db.db.begin_write().unwrap();
                if remove_state {
                    txn.open_table(TABLE_SIGNING_STATE)
                        .unwrap()
                        .remove(0)
                        .unwrap();
                } else {
                    txn.open_table(TABLE_OWN_CHOICE_COMMITMENTS)
                        .unwrap()
                        .retain(|_, _| false)
                        .unwrap();
                }
                txn.commit().unwrap();
            }
            let db = RedbStorage::open(&path).unwrap();
            assert!(!db.is_signing_history_healthy());
            if !remove_state {
                let txn = db.db.begin_read().unwrap();
                assert_eq!(
                    txn.open_table(TABLE_OWN_CHOICE_COMMITMENTS)
                        .unwrap()
                        .len()
                        .unwrap(),
                    0
                );
            }
        }
    }

    #[test]
    fn existing_empty_history_with_missing_state_stays_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty-incomplete.redb");
        {
            let db = RedbStorage::open(&path).unwrap();
            let txn = db.db.begin_write().unwrap();
            txn.open_table(TABLE_SIGNING_STATE)
                .unwrap()
                .remove(0)
                .unwrap();
            txn.commit().unwrap();
        }
        assert!(!RedbStorage::open(&path)
            .unwrap()
            .is_signing_history_healthy());
    }

    #[test]
    fn rolled_back_prune_marker_is_persisted_on_retry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("retry.redb");
        {
            let db = RedbStorage::open(&path).unwrap();
            // Model a write/commit failure after setting the RAM latch: redb
            // atomically rolls back this transaction while RAM remains latched.
            let txn = db.db.begin_write().unwrap();
            db.latch_corruption_in_txn(&txn);
            txn.abort().unwrap();
            let _ = db.prune_expired_buckets(1);
        }
        assert!(!RedbStorage::open(&path)
            .unwrap()
            .is_signing_history_healthy());
    }
    #[test]
    fn intact_restart_retry_expiry_and_backup_keep_monotonic_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.redb");
        let backup = dir.path().join("backup.redb");
        let (tag, first) = lock(1);
        {
            let db = RedbStorage::open(&path).unwrap();
            assert_eq!(db.signing_checkpoint().unwrap().0, 0);
            db.commit_original_approval(&tag, &first, &[7; 32], b"original", 0, 50_000)
                .unwrap();
            assert_eq!(db.signing_checkpoint().unwrap().0, 1);
            db.commit_original_approval(&tag, &first, &[7; 32], b"retry bytes ignored", 0, 50_000)
                .unwrap();
            assert_eq!(
                db.signing_checkpoint().unwrap().0,
                1,
                "an exact retained retry adds no decision"
            );
            db.create_backup(&backup).unwrap();
        }
        let db = RedbStorage::open(&path).unwrap();
        assert!(db.is_signing_history_healthy());
        assert_eq!(db.signing_checkpoint().unwrap().0, 1);
        let restored = RedbStorage::open(&backup).unwrap();
        assert_eq!(
            restored.signing_checkpoint().unwrap(),
            db.signing_checkpoint().unwrap()
        );
        db.prune_expired_buckets(81).unwrap();
        let checkpoint = db.signing_checkpoint().unwrap();
        assert_eq!(checkpoint.0, 2);
        assert_eq!(
            checkpoint.1, [0; 32],
            "expiry removes all active choice commitment"
        );
        drop(db);
        let db = RedbStorage::open(&path).unwrap();
        assert!(db.is_signing_history_healthy());
        assert_eq!(db.signing_checkpoint().unwrap(), checkpoint);
    }
    #[test]
    fn deleted_history_is_detected_and_latch_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("truncated.redb");
        let (tag, record) = lock(1);
        {
            let db = RedbStorage::open(&path).unwrap();
            db.commit_original_approval(&tag, &record, &[7; 32], b"original", 0, 50_000)
                .unwrap();
            // Simulate a damaged history independently of the normal writer.
            let txn = db.db.begin_write().unwrap();
            txn.open_table(TABLE_OWN_CHOICES)
                .unwrap()
                .remove(format!("{}:{}", hex::encode([7; 32]), tag).as_str())
                .unwrap();
            txn.commit().unwrap();
        }
        for _ in 0..2 {
            let db = RedbStorage::open(&path).unwrap();
            assert!(!db.is_signing_history_healthy());
            let (tag2, record2) = lock(2);
            assert!(matches!(
                db.commit_original_approval(&tag2, &record2, &[7; 32], b"new", 0, 50_000),
                Err(StorageError::SigningHistoryCorrupt)
            ));
        }
    }

    #[test]
    fn test_missing_state_key_zero_in_open_session_latches_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s02_11_missing_key0.redb");
        let (tag, record) = lock(1);
        let db = RedbStorage::open(&path).unwrap();
        assert!(db.is_signing_history_healthy());
        db.commit_original_approval(&tag, &record, &[7; 32], b"original", 0, 50_000)
            .unwrap();
        assert!(db.is_signing_history_healthy());
        assert_eq!(db.signing_checkpoint().unwrap().0, 1);

        // Remove signing-state key 0 during an open session
        {
            let txn = db.db.begin_write().unwrap();
            txn.open_table(TABLE_SIGNING_STATE).unwrap().remove(0).unwrap();
            txn.commit().unwrap();
        }

        // Before calling signing_checkpoint(), RAM health is still true
        assert!(db.is_signing_history_healthy());

        // Calling signing_checkpoint() must return SigningHistoryCorrupt
        let res = db.signing_checkpoint();
        assert!(
            matches!(res, Err(StorageError::SigningHistoryCorrupt)),
            "must return SigningHistoryCorrupt, got: {res:?}"
        );

        // Must latch corruption immediately in-memory
        assert!(
            !db.is_signing_history_healthy(),
            "immediate unhealthy state required"
        );

        // Retained choices must still be preserved in the database
        assert!(
            db.own_signing_choice(&[7; 32], &tag).unwrap().is_some(),
            "retained choices must be preserved"
        );

        // Durable corruption persistence after reopen
        drop(db);
        let reopened = RedbStorage::open(&path).unwrap();
        assert!(
            !reopened.is_signing_history_healthy(),
            "corruption must persist durably after reopen"
        );
        assert!(
            reopened.own_signing_choice(&[7; 32], &tag).unwrap().is_some(),
            "retained choices must be preserved after reopen"
        );
    }
}
