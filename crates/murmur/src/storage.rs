//! Where a swarm persists its entries, and (optionally) reads old ones back. See ADR 0002.

use std::sync::Arc;

use crate::entry::Entry;
use crate::id::PeerId;
use crate::vector::Vector;

/// Where accepted entries are persisted. `append` is called once per accepted batch (including
/// our own entries), in order per author.
///
/// A storage may also read its entries back (`can_read` true). The swarm then keeps only about
/// [`crate::Config::ram_window`] bytes of each author's newest entries in memory and reads older
/// ones through [`Storage::read`] when it needs them. The default methods can't read, so a storage
/// that only implements `append` behaves as before: the swarm keeps every entry in memory.
/// Reads are synchronous, so browsers (where storage is async) keep the default.
pub trait Storage: Send {
    fn append(&mut self, entries: &[Arc<Entry>]) -> Result<(), String>;

    /// Whether [`Storage::heads`] and [`Storage::read`] work. Must not change while the swarm
    /// uses this storage.
    fn can_read(&self) -> bool {
        false
    }

    /// For each author, the highest seq `n` such that this storage holds all of `1..=n`.
    fn heads(&self) -> Result<Vector, String> {
        Err("this storage can't read".into())
    }

    /// Up to `max` entries of `author` starting at seq `from`, in order and without gaps: the
    /// entries passed to `append` before. Fewer than `max` only at the end of what it holds;
    /// empty if it doesn't hold `from`. An error means the storage can't tell (I/O, damage).
    fn read(&self, author: &PeerId, from: u64, max: usize) -> Result<Vec<Entry>, String> {
        let _ = (author, from, max);
        Err("this storage can't read".into())
    }
}
