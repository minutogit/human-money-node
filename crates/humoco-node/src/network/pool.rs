//! Bounded outbound shard sessions. A returned lease pins its session until dropped.
//!
//! `Deref` supports the existing trusted transport helpers. Callers must retain the
//! lease while using a borrowed connection and must not clone the raw Quinn handle
//! to bypass ownership. This is an internal ownership contract, not a boundary
//! against untrusted Rust callers.
use crate::NodeError;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Orderly local resource turnover; connection handlers never score close events.
pub const LOCAL_POOL_ROTATION_CODE: u32 = 0x4850;
const CAPACITY: usize = 256;

/// Recognizes a peer's orderly resource turnover across Quinn's error wrappers.
/// This affects diagnostics only; it never grants authorization or proof validity.
pub(crate) fn is_pool_rotation_error(error: &NodeError) -> bool {
    let connection_error = match error {
        NodeError::QuinnConnection(error)
        | NodeError::QuinnWrite(quinn::WriteError::ConnectionLost(error))
        | NodeError::QuinnRead(quinn::ReadError::ConnectionLost(error))
        | NodeError::QuinnReadToEnd(quinn::ReadToEndError::Read(
            quinn::ReadError::ConnectionLost(error),
        )) => error,
        _ => return false,
    };
    matches!(connection_error, quinn::ConnectionError::ApplicationClosed(close)
        if close.error_code == LOCAL_POOL_ROTATION_CODE.into())
}

struct Entry {
    connection: quinn::Connection,
    active: usize,
    last_used: Instant,
    _permit: OwnedSemaphorePermit,
}

#[derive(Clone)]
pub(crate) struct ShardConnectionPool {
    entries: Arc<Mutex<HashMap<usize, Entry>>>,
    slots: Arc<Semaphore>,
}

impl ShardConnectionPool {
    pub(crate) fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            slots: Arc::new(Semaphore::new(CAPACITY)),
        }
    }

    fn entries(&self) -> MutexGuard<'_, HashMap<usize, Entry>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn reserve(&self) -> Result<ShardReservation, NodeError> {
        let mut entries = self.entries();
        entries.retain(|_, entry| entry.connection.close_reason().is_none());
        let permit = match self.slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let victim = entries
                    .iter()
                    .filter(|(_, entry)| entry.active == 0)
                    .min_by_key(|(id, entry)| (entry.last_used, **id))
                    .map(|(id, _)| *id);
                if let Some(id) = victim {
                    if let Some(entry) = entries.remove(&id) {
                        entry.connection.close(
                            LOCAL_POOL_ROTATION_CODE.into(),
                            b"local shard pool turnover",
                        );
                        drop(entry);
                    }
                }
                self.slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| NodeError::LocalCapacity("outbound shard connections"))?
            }
        };
        Ok(ShardReservation {
            pool: self.clone(),
            permit,
        })
    }

    pub(crate) fn lease(
        &self,
        connection: quinn::Connection,
    ) -> Result<PeerConnectionLease, NodeError> {
        let mut entries = self.entries();
        if connection.close_reason().is_some() {
            return Err(NodeError::LocalCapacity("closed shard connection"));
        }
        let pool = if let Some(entry) = entries.get_mut(&connection.stable_id()) {
            entry.active += 1;
            Some(self.clone())
        } else {
            None
        };
        Ok(PeerConnectionLease { connection, pool })
    }

    #[cfg(test)]
    pub(crate) fn occupy_all(&self) -> OwnedSemaphorePermit {
        self.slots
            .clone()
            .try_acquire_many_owned(CAPACITY as u32)
            .expect("test fixture starts with all outbound slots available")
    }
}

pub(crate) struct ShardReservation {
    pool: ShardConnectionPool,
    permit: OwnedSemaphorePermit,
}
impl ShardReservation {
    pub(crate) fn commit(self, connection: quinn::Connection) -> PeerConnectionLease {
        self.pool.entries().insert(
            connection.stable_id(),
            Entry {
                connection: connection.clone(),
                active: 1,
                last_used: Instant::now(),
                _permit: self.permit,
            },
        );
        PeerConnectionLease {
            connection,
            pool: Some(self.pool),
        }
    }
}

/// Owned use of a connection, protecting shard sessions from idle LRU eviction.
#[derive(Debug)]
pub struct PeerConnectionLease {
    connection: quinn::Connection,
    pool: Option<ShardConnectionPool>,
}
impl Deref for PeerConnectionLease {
    type Target = quinn::Connection;
    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}
impl Clone for PeerConnectionLease {
    fn clone(&self) -> Self {
        if let Some(pool) = &self.pool {
            if let Some(entry) = pool.entries().get_mut(&self.connection.stable_id()) {
                entry.active += 1;
            }
        }
        Self {
            connection: self.connection.clone(),
            pool: self.pool.clone(),
        }
    }
}
impl Drop for PeerConnectionLease {
    fn drop(&mut self) {
        if let Some(pool) = &self.pool {
            if let Some(entry) = pool.entries().get_mut(&self.connection.stable_id()) {
                entry.active = entry.active.saturating_sub(1);
                entry.last_used = Instant::now();
            }
        }
    }
}
impl std::fmt::Debug for ShardConnectionPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardConnectionPool")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pending_reservations_release_capacity_on_task_abort() {
        let pool = ShardConnectionPool::new();
        let reservations: Vec<_> = (0..CAPACITY - 1).map(|_| pool.reserve().unwrap()).collect();
        let held = Arc::new(tokio::sync::Notify::new());
        let task_pool = pool.clone();
        let task_held = held.clone();
        let task = tokio::spawn(async move {
            let _reservation = task_pool.reserve().unwrap();
            task_held.notify_one();
            std::future::pending::<()>().await;
        });
        held.notified().await;
        assert!(matches!(pool.reserve(), Err(NodeError::LocalCapacity(_))));
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let recovered = pool.reserve().unwrap();
        drop((recovered, reservations));
        assert_eq!(pool.slots.available_permits(), CAPACITY);
    }
}
