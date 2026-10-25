
#[cfg(test)]
mod audit23_runtime_probes {
 use super::*;
 #[test]
 fn missing_runtime_choice_must_fail_closed_before_conflicting_approval() {
  let dir=tempfile::tempdir().unwrap(); let path=dir.path().join("runtime.redb");
  let db=RedbStorage::open(&path).unwrap(); let node=[7;32];
  let a=LockRecord::new([1;32],[2;32],vec![3],SimTime(1_000),SimTime(50_000));
  let b=LockRecord::new([1;32],[4;32],vec![3],SimTime(1_000),SimTime(50_000));
  db.commit_original_record_approval(&a,50_000,&node,b"original A",0).unwrap();
  // Model loss of one logical choice, without changing the independent fingerprint.
  // This is fault injection, not a remote API available to a peer.
  let tx=db.db.begin_write().unwrap();
  let slot=format!("{}:{}",hex::encode(node),hex::encode(a.parent_lock));
  tx.open_table(TABLE_OWN_CHOICES).unwrap().remove(slot.as_str()).unwrap();
  tx.commit().unwrap();
  // Lawful canonical replacement is separate from the retained original A choice.
  db.put_lock(&b,50_000).unwrap();
  let result=db.commit_original_record_approval(&b,50_000,&node,b"original B",0);
  assert!(matches!(result,Err(StorageError::SigningHistoryCorrupt)),
   "missing retained history must reject contradictory original approval, got {result:?}");
  assert!(!db.is_signing_history_healthy(),"detected corruption must latch");
 }
 #[test]
 fn malformed_runtime_state_must_latch_across_reopen() {
  let dir=tempfile::tempdir().unwrap(); let path=dir.path().join("malformed.redb");
  let db=RedbStorage::open(&path).unwrap();
  let tx=db.db.begin_write().unwrap();
  tx.open_table(TABLE_SIGNING_STATE).unwrap().insert(0,b"invalid json".as_slice()).unwrap();tx.commit().unwrap();
  let a=LockRecord::new([1;32],[2;32],vec![3],SimTime(1_000),SimTime(50_000));
  assert!(db.commit_original_record_approval(&a,50_000,&[7;32],b"A",0).is_err());
  assert!(!db.is_signing_history_healthy(),"runtime parse failure must set signing-corrupt latch");
 }
}
