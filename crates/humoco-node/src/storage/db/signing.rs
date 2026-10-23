//! Local signing-history integrity. No independent hardware or remote authority.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) const TABLE_SIGNING_STATE: TableDefinition<u8, &[u8]> =
    TableDefinition::new("signing_commit_state");

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub(super) struct SigningState {
    pub generation: u64,
    pub count: u64,
    pub fingerprint: [u8; 32],
    pub corrupt: bool,
}

fn fingerprint(slot: &str, bytes: &[u8]) -> [u8; 32] {
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
fn read(txn: &redb::WriteTransaction) -> Result<SigningState, StorageError> {
    let table = txn.open_table(TABLE_SIGNING_STATE)?;
    let bytes = table.get(0)?.ok_or(StorageError::SigningHistoryCorrupt)?;
    serde_json::from_slice(bytes.value()).map_err(StorageError::from)
}
fn write(txn: &redb::WriteTransaction, state: &SigningState) -> Result<(), StorageError> {
    let bytes = serde_json::to_vec(state)?;
    txn.open_table(TABLE_SIGNING_STATE)?
        .insert(0, bytes.as_slice())?;
    Ok(())
}

/// Streams startup validation without cloning the history. Legacy rows have no
/// generation; migrating them cannot retroactively establish preexisting integrity.
pub(super) fn initialize(txn: &redb::WriteTransaction) -> Result<bool, StorageError> {
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
    for item in choices.iter()? {
        let (slot, value) = item?;
        measured.count = measured
            .count
            .checked_add(1)
            .ok_or(StorageError::SigningHistoryCorrupt)?;
        xor(
            &mut measured.fingerprint,
            fingerprint(slot.value(), value.value()),
        );
        match serde_json::from_slice::<OwnSigningChoice>(value.value()) {
            Ok(choice) => {
                measured.generation = measured.generation.max(choice.generation);
                let expiry = choice.valid_until_ms.saturating_add(30_999) / 1_000;
                if ttl.get(&(expiry, slot.value()))?.is_none() {
                    measured.corrupt = true;
                }
            }
            Err(_) => measured.corrupt = true,
        }
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
            measured.corrupt |= measured.generation != 0;
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
    let old = choices.get(slot)?.map(|v| v.value().to_vec());
    let candidate = serde_json::to_vec(choice)?;
    if old.as_deref() == Some(candidate.as_slice()) {
        return Ok(());
    }
    state.generation = state
        .generation
        .checked_add(1)
        .ok_or(StorageError::SigningHistoryCorrupt)?;
    choice.generation = state.generation;
    let bytes = serde_json::to_vec(choice)?;
    if let Some(old) = old {
        xor(&mut state.fingerprint, fingerprint(slot, &old));
    } else {
        state.count = state
            .count
            .checked_add(1)
            .ok_or(StorageError::SigningHistoryCorrupt)?;
    }
    xor(&mut state.fingerprint, fingerprint(slot, &bytes));
    choices.insert(slot, bytes.as_slice())?;
    write(txn, &state)
}

pub(super) fn remove_choice(txn: &redb::WriteTransaction, slot: &str) -> Result<(), StorageError> {
    let mut choices = txn.open_table(TABLE_OWN_CHOICES)?;
    let old = choices.remove(slot)?.map(|v| v.value().to_vec());
    if let Some(old) = old {
        let mut state = read(txn)?;
        if state.corrupt {
            return Err(StorageError::SigningHistoryCorrupt);
        }
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(StorageError::SigningHistoryCorrupt)?;
        state.count = state
            .count
            .checked_sub(1)
            .ok_or(StorageError::SigningHistoryCorrupt)?;
        xor(&mut state.fingerprint, fingerprint(slot, &old));
        write(txn, &state)?;
    }
    Ok(())
}

impl RedbStorage {
    pub fn is_signing_history_healthy(&self) -> bool {
        !self.signing_corrupt.load(Ordering::Acquire)
    }

    /// Read in a blocking worker; never required on the checkout path.
    pub(crate) fn signing_checkpoint(&self) -> Result<(u64, [u8; 32]), StorageError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(TABLE_SIGNING_STATE)?;
        let value = table.get(0)?.ok_or(StorageError::SigningHistoryCorrupt)?;
        let state: SigningState = serde_json::from_slice(value.value())?;
        if state.corrupt {
            return Err(StorageError::SigningHistoryCorrupt);
        }
        Ok((state.generation, state.fingerprint))
    }

    /// Caller first verifies an actual self-signature and network context. A peer
    /// hint by itself is never evidence. The latch also blocks already queued votes.
    pub(crate) fn observe_verified_own_checkpoint(
        &self,
        generation: u64,
        fingerprint: [u8; 32],
    ) -> Result<bool, StorageError> {
        let mut txn = self.db.begin_write()?;
        txn.set_durability(redb::Durability::Immediate);
        let mut state = read(&txn)?;
        if generation > state.generation
            || (generation == state.generation && fingerprint != state.fingerprint)
        {
            self.signing_corrupt.store(true, Ordering::Release);
            state.corrupt = true;
            write(&txn, &state)?;
            txn.commit()?;
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
    fn lock(parent: u8) -> LockRecord {
        LockRecord::new(
            [parent; 32],
            [2; 32],
            vec![3],
            SimTime(1_000),
            SimTime(50_000),
        )
    }
    #[test]
    fn intact_restart_retry_expiry_and_backup_keep_monotonic_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.redb");
        let backup = dir.path().join("backup.redb");
        let first = lock(1);
        {
            let db = RedbStorage::open(&path).unwrap();
            assert_eq!(db.signing_checkpoint().unwrap().0, 0);
            db.commit_original_record_approval(&first, 50_000, &[7; 32], b"original", 0)
                .unwrap();
            assert_eq!(db.signing_checkpoint().unwrap().0, 1);
            db.commit_original_record_approval(&first, 50_000, &[7; 32], b"retry bytes ignored", 0)
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
        let record = lock(1);
        {
            let db = RedbStorage::open(&path).unwrap();
            db.commit_original_record_approval(&record, 50_000, &[7; 32], b"original", 0)
                .unwrap();
            // Simulate a damaged history independently of the normal writer.
            let txn = db.db.begin_write().unwrap();
            txn.open_table(TABLE_OWN_CHOICES)
                .unwrap()
                .remove(
                    format!(
                        "{}:{}",
                        hex::encode([7; 32]),
                        hex::encode(record.parent_lock)
                    )
                    .as_str(),
                )
                .unwrap();
            txn.commit().unwrap();
        }
        for _ in 0..2 {
            let db = RedbStorage::open(&path).unwrap();
            assert!(!db.is_signing_history_healthy());
            assert!(matches!(
                db.commit_original_record_approval(&lock(2), 50_000, &[7; 32], b"new", 0),
                Err(StorageError::SigningHistoryCorrupt)
            ));
        }
    }
}
