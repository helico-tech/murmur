//! Entries (stored, replicated) and flashes (flooded, not stored).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::id::{Identity, PeerId, SwarmId, verify};

/// One signed entry in an author's log.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub author: PeerId,
    /// 1, 2, 3… per author, without gaps.
    pub seq: u64,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: [u8; 64],
}

impl Entry {
    /// Signs a new entry. The caller picks `seq` (the swarm does this in `publish`).
    pub fn sign(swarm: &SwarmId, me: &Identity, seq: u64, payload: Vec<u8>) -> Entry {
        let author = me.id();
        let sig = me.sign(&Self::signed_bytes(swarm, &author, seq, &payload));
        Entry { author, seq, payload, sig }
    }

    /// Whether the signature is the author's, over this swarm. `seq` 0 is never valid.
    pub fn verify(&self, swarm: &SwarmId) -> bool {
        self.seq > 0 && verify(&self.author, &Self::signed_bytes(swarm, &self.author, self.seq, &self.payload), &self.sig)
    }

    fn signed_bytes(swarm: &SwarmId, author: &PeerId, seq: u64, payload: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(16 + 32 + 32 + 16 + payload.len());
        m.extend_from_slice(b"murmur entry v1\0");
        m.extend_from_slice(&swarm.0);
        m.extend_from_slice(&author.0);
        m.extend_from_slice(&seq.to_be_bytes());
        m.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        m.extend_from_slice(payload);
        m
    }

    /// Roughly how many bytes this takes on the wire.
    pub fn wire_size(&self) -> usize {
        32 + 10 + 5 + self.payload.len() + 64
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Entry({}:{}, {} bytes)", self.author.short(), self.seq, self.payload.len())
    }
}

/// What a flash is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FlashKind {
    /// "I'm online." Sent by the swarm itself every `presence_interval`.
    Presence,
    /// An application signal (e.g. "typing…"), delivered as [`crate::Event::Flash`].
    App,
}

/// A signed message that is flooded to every online peer but not stored. `stamp` must grow per
/// author and kind; older or repeated flashes are dropped, which also stops replays.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flash {
    pub author: PeerId,
    pub kind: FlashKind,
    /// The author's clock in ms, made strictly increasing by the sender.
    pub stamp: u64,
    /// Hops left. Not signed: each hop lowers it.
    pub ttl: u8,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: [u8; 64],
}

impl Flash {
    pub fn sign(swarm: &SwarmId, me: &Identity, kind: FlashKind, stamp: u64, ttl: u8, payload: Vec<u8>) -> Flash {
        let author = me.id();
        let sig = me.sign(&Self::signed_bytes(swarm, &author, kind, stamp, &payload));
        Flash { author, kind, stamp, ttl, payload, sig }
    }

    pub fn verify(&self, swarm: &SwarmId) -> bool {
        verify(&self.author, &Self::signed_bytes(swarm, &self.author, self.kind, self.stamp, &self.payload), &self.sig)
    }

    fn signed_bytes(swarm: &SwarmId, author: &PeerId, kind: FlashKind, stamp: u64, payload: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(16 + 32 + 32 + 1 + 16 + payload.len());
        m.extend_from_slice(b"murmur flash v1\0");
        m.extend_from_slice(&swarm.0);
        m.extend_from_slice(&author.0);
        m.push(match kind {
            FlashKind::Presence => 0,
            FlashKind::App => 1,
        });
        m.extend_from_slice(&stamp.to_be_bytes());
        m.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        m.extend_from_slice(payload);
        m
    }
}

impl fmt::Debug for Flash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flash({} {:?} @{} ttl {})", self.author.short(), self.kind, self.stamp, self.ttl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_bound_to_swarm_author_seq_and_payload() {
        let me = Identity::from_secret([3; 32]);
        let (s1, s2) = (SwarmId([1; 32]), SwarmId([2; 32]));
        let e = Entry::sign(&s1, &me, 1, b"hello".to_vec());
        assert!(e.verify(&s1));
        assert!(!e.verify(&s2));
        let mut t = e.clone();
        t.seq = 2;
        assert!(!t.verify(&s1));
        let mut t = e.clone();
        t.payload.push(b'!');
        assert!(!t.verify(&s1));
        let mut t = e.clone();
        t.author = Identity::from_secret([4; 32]).id();
        assert!(!t.verify(&s1));
        let zero = Entry::sign(&s1, &me, 0, vec![]);
        assert!(!zero.verify(&s1), "seq 0 is never valid");
    }

    #[test]
    fn flash_ttl_is_not_signed_but_the_rest_is() {
        let me = Identity::from_secret([3; 32]);
        let s = SwarmId([1; 32]);
        let f = Flash::sign(&s, &me, FlashKind::App, 10, 5, b"typing".to_vec());
        let mut g = f.clone();
        g.ttl = 1;
        assert!(g.verify(&s));
        g.stamp = 11;
        assert!(!g.verify(&s));
        let mut g = f.clone();
        g.kind = FlashKind::Presence;
        assert!(!g.verify(&s));
    }
}
