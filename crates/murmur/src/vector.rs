//! Version vectors: author → highest contiguous seq held.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::id::PeerId;

/// What a peer holds: for each author, the highest `seq` it has (it then has all of `1..=seq`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vector(BTreeMap<PeerId, u64>);

impl Vector {
    pub fn new() -> Vector {
        Vector::default()
    }

    pub fn get(&self, author: &PeerId) -> u64 {
        self.0.get(author).copied().unwrap_or(0)
    }

    /// Raises `author` to `seq` (never lowers it).
    pub fn raise(&mut self, author: PeerId, seq: u64) {
        if seq == 0 {
            return;
        }
        let e = self.0.entry(author).or_insert(0);
        if *e < seq {
            *e = seq;
        }
    }

    /// Raises every author to at least `other`'s value.
    pub fn merge(&mut self, other: &Vector) {
        for (a, s) in &other.0 {
            self.raise(*a, *s);
        }
    }

    /// Whether `other` holds something this vector doesn't.
    pub fn lacks_from(&self, other: &Vector) -> bool {
        other.0.iter().any(|(a, s)| self.get(a) < *s)
    }

    /// Whether this vector holds everything in `other`.
    pub fn covers(&self, other: &Vector) -> bool {
        !self.lacks_from(other)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PeerId, &u64)> {
        self.0.iter()
    }

    pub fn authors(&self) -> impl Iterator<Item = &PeerId> {
        self.0.keys()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Total number of entries this vector stands for.
    pub fn total(&self) -> u64 {
        self.0.values().fold(0u64, |a, b| a.saturating_add(*b))
    }

    /// A short digest of the whole vector, to check cheaply whether two peers are in sync.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key("murmur vector digest v1");
        for (a, s) in &self.0 {
            if *s > 0 {
                h.update(&a.0);
                h.update(&s.to_be_bytes());
            }
        }
        *h.finalize().as_bytes()
    }
}

impl FromIterator<(PeerId, u64)> for Vector {
    fn from_iter<T: IntoIterator<Item = (PeerId, u64)>>(iter: T) -> Self {
        let mut v = Vector::new();
        for (a, s) in iter {
            v.raise(a, s);
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(n: u8) -> PeerId {
        PeerId([n; 32])
    }

    #[test]
    fn raise_merge_and_cover() {
        let mut a: Vector = [(p(1), 3), (p(2), 1)].into_iter().collect();
        let b: Vector = [(p(1), 2), (p(3), 4)].into_iter().collect();
        assert!(a.lacks_from(&b));
        assert!(b.lacks_from(&a));
        a.raise(p(1), 1);
        assert_eq!(a.get(&p(1)), 3, "never lowers");
        a.merge(&b);
        assert!(a.covers(&b));
        assert_eq!(a.total(), 3 + 1 + 4);
    }

    #[test]
    fn digest_ignores_zero_entries_and_order() {
        let a: Vector = [(p(1), 3), (p(2), 1)].into_iter().collect();
        let mut b: Vector = [(p(2), 1), (p(1), 3)].into_iter().collect();
        assert_eq!(a.digest(), b.digest());
        b.0.insert(p(9), 0);
        assert_eq!(a.digest(), b.digest());
        b.raise(p(9), 1);
        assert_ne!(a.digest(), b.digest());
    }
}
