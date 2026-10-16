//! Messages between two peers on one connection, and their binary encoding (postcard).
//!
//! A transport carries each encoded message as one frame (murmur-iroh: a 4-byte big-endian length
//! and the bytes). [`decode`] never panics and rejects anything over the [`crate::limits`].

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::entry::{Entry, Flash};
use crate::id::PeerId;
use crate::limits;
use crate::vector::Vector;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    /// First message each side sends: protocol version, proof of the swarm secret (bound to the
    /// sender's and receiver's ids), and how to reach the sender (opaque to murmur).
    Hello {
        version: u16,
        proof: [u8; 32],
        #[serde(with = "serde_bytes")]
        hint: Vec<u8>,
    },
    /// "This is everything I hold; send me up to `want` bytes of what I lack." A peer catching
    /// up pulls full windows from one neighbour and only small probes from the others.
    Have { vector: Vector, want: u32 },
    /// "My vector hashes to this." Sent every `ae_interval`; a mismatch triggers `Have`.
    Digest { hash: [u8; 32] },
    /// Entries, oldest first per author.
    Entries { entries: Vec<Arc<Entry>> },
    /// Peers the sender knows, with their address hints.
    Peers { peers: Vec<PeerHint> },
    /// A flooded, unstored signal (presence, typing…).
    Flash(Flash),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerHint {
    pub peer: PeerId,
    #[serde(with = "serde_bytes")]
    pub hint: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("message too large ({0} bytes)")]
    TooLarge(usize),
    #[error("malformed message: {0}")]
    Malformed(String),
    #[error("message over limits: {0}")]
    OverLimit(&'static str),
}

pub fn encode(msg: &Message) -> Vec<u8> {
    // Encoding plain data into a Vec can't fail; an empty frame would be rejected by the peer.
    postcard::to_stdvec(msg).unwrap_or_default()
}

pub fn decode(bytes: &[u8]) -> Result<Message, WireError> {
    if bytes.len() > limits::MAX_MESSAGE {
        return Err(WireError::TooLarge(bytes.len()));
    }
    let msg: Message = postcard::from_bytes(bytes).map_err(|e| WireError::Malformed(e.to_string()))?;
    check(&msg)?;
    Ok(msg)
}

/// Checks a decoded message against the limits.
pub fn check(msg: &Message) -> Result<(), WireError> {
    match msg {
        Message::Hello { hint, .. } if hint.len() > limits::MAX_HINT => Err(WireError::OverLimit("hint")),
        Message::Have { vector, .. } if vector.len() > limits::MAX_VECTOR => Err(WireError::OverLimit("vector")),
        Message::Entries { entries } if entries.len() > limits::MAX_ENTRIES_PER_MESSAGE => Err(WireError::OverLimit("entries")),
        Message::Entries { entries } if entries.iter().any(|e| e.payload.len() > limits::MAX_PAYLOAD) => Err(WireError::OverLimit("payload")),
        Message::Peers { peers } if peers.len() > limits::MAX_PEERS_PER_MESSAGE || peers.iter().any(|p| p.hint.len() > limits::MAX_HINT) => {
            Err(WireError::OverLimit("peers"))
        }
        Message::Flash(f) if f.payload.len() > limits::MAX_PAYLOAD => Err(WireError::OverLimit("flash payload")),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::FlashKind;
    use crate::id::{Identity, SwarmId};
    use crate::rng::Rng;

    fn samples() -> Vec<Message> {
        let me = Identity::from_secret([5; 32]);
        let s = SwarmId([1; 32]);
        vec![
            Message::Hello { version: 1, proof: [9; 32], hint: b"relay".to_vec() },
            Message::Have { vector: [(me.id(), 3)].into_iter().collect(), want: 1 << 20 },
            Message::Digest { hash: [4; 32] },
            Message::Entries { entries: vec![Arc::new(Entry::sign(&s, &me, 1, b"x".to_vec())), Arc::new(Entry::sign(&s, &me, 2, vec![]))] },
            Message::Peers { peers: vec![PeerHint { peer: me.id(), hint: vec![] }] },
            Message::Flash(Flash::sign(&s, &me, FlashKind::Presence, 7, 3, vec![])),
        ]
    }

    #[test]
    fn round_trip() {
        for m in samples() {
            assert_eq!(decode(&encode(&m)), Ok(m));
        }
    }

    #[test]
    fn junk_never_panics() {
        let mut rng = Rng::new(42);
        for _ in 0..20_000 {
            let len = rng.below(200) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
            let _ = decode(&bytes);
        }
        // Mutated valid messages, too.
        for m in samples() {
            let good = encode(&m);
            for _ in 0..5_000 {
                let mut b = good.clone();
                let n = 1 + rng.below(4);
                for _ in 0..n {
                    if b.is_empty() {
                        break;
                    }
                    let i = rng.below(b.len() as u64) as usize;
                    b[i] = rng.next_u64() as u8;
                }
                if rng.below(4) == 0 {
                    b.truncate(rng.below(b.len() as u64 + 1) as usize);
                }
                let _ = decode(&b);
            }
        }
    }

    #[test]
    fn limits_are_enforced() {
        assert!(matches!(decode(&vec![0u8; limits::MAX_MESSAGE + 1]), Err(WireError::TooLarge(_))));
        let big = Message::Hello { version: 1, proof: [0; 32], hint: vec![0; limits::MAX_HINT + 1] };
        assert_eq!(decode(&encode(&big)), Err(WireError::OverLimit("hint")));
        let peers = Message::Peers { peers: (0..65).map(|i| PeerHint { peer: PeerId([i as u8; 32]), hint: vec![] }).collect() };
        assert_eq!(decode(&encode(&peers)), Err(WireError::OverLimit("peers")));
    }

    #[test]
    fn a_huge_length_prefix_does_not_allocate_wildly() {
        // Variant 4 (Peers) followed by a varint length of ~2^63.
        let bytes = [4u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
        assert!(decode(&bytes).is_err());
    }
}
