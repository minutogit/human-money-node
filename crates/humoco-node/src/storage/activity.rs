//! Per-shard admission fencing. No RAM index guard crosses persistence.
use std::sync::{Arc, atomic::{AtomicU32, Ordering}};
const CLOSED: u32 = 1 << 31;
#[derive(Clone)]
pub(crate) struct ShardActivity(Arc<[AtomicU32]>);
impl Default for ShardActivity {
    fn default() -> Self { Self((0..=u16::MAX).map(|_| AtomicU32::new(0)).collect()) }
}
pub(crate) struct Lease { state: ShardActivity, shard: u16, closed: bool }
impl ShardActivity {
    pub fn enter(&self, shard: u16) -> Option<Lease> {
        self.0[shard as usize].fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |n| (n < CLOSED - 1).then_some(n + 1)).ok()?;
        Some(Lease { state: self.clone(), shard, closed: false })
    }
    pub async fn close(&self, shard: u16) -> Option<Lease> {
        let slot = &self.0[shard as usize];
        let old = slot.fetch_or(CLOSED, Ordering::AcqRel);
        if old & CLOSED != 0 { return None; }
        // Construct first: cancellation must reopen admission, even while draining.
        let lease = Lease { state: self.clone(), shard, closed: true };
        while slot.load(Ordering::Acquire) != CLOSED { tokio::task::yield_now().await; }
        Some(lease)
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let slot = &self.state.0[self.shard as usize];
        if self.closed { slot.fetch_and(!CLOSED, Ordering::Release); }
        else { slot.fetch_sub(1, Ordering::Release); }
    }
}
