//! The entries a peer holds: one contiguous log per author, plus a bounded buffer for entries
//! that arrived ahead of a gap (they came by a faster path than the ones before them).
//!
//! Logs are packed to save memory: an author's entries sit back to back in byte chunks of about
//! [`CHUNK`] bytes, each as `payload ‖ signature`, with a 2-byte start offset per entry. The author
//! and seq are implicit. Entries are decoded into an `Entry` when someone asks for them.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

use crate::entry::Entry;
use crate::id::PeerId;
use crate::vector::Vector;

/// Fewest entries one answer carries (when there are that many to send).
pub(crate) const MIN_BATCH: usize = 16;

/// Most entries held back waiting for a gap to fill, over all authors.
pub(crate) const PENDING_LIMIT: usize = 8192;

/// Target size of one chunk of a packed log. An entry bigger than this gets a chunk of its own.
/// Must stay at most 65 536, so start offsets fit in a `u16`.
pub(crate) const CHUNK: usize = 32 * 1024;

const SIG: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Insert {
    /// Appended, together with buffered entries it unblocked (in order).
    Appended(Vec<Arc<Entry>>),
    /// Already held (same content).
    Duplicate,
    /// Already held with different content: the author signed two entries with one seq.
    Conflict,
    /// Ahead of a gap; kept until the gap fills.
    Buffered,
    /// Ahead of a gap, but the buffer is full.
    Dropped,
}

/// A run of one author's entries: `payload ‖ signature` back to back.
#[derive(Debug, Default)]
struct Chunk {
    /// Seq of the first entry.
    first: u64,
    data: Vec<u8>,
    /// Where each entry starts in `data`; it ends where the next one starts.
    starts: Vec<u16>,
}

impl Chunk {
    /// Payload and signature of entry `i` of this chunk.
    fn record(&self, i: usize) -> Option<(&[u8], &[u8; 64])> {
        let start = usize::from(*self.starts.get(i)?);
        let end = self.starts.get(i + 1).map_or(self.data.len(), |s| usize::from(*s));
        let rec = self.data.get(start..end)?;
        let (payload, sig) = rec.split_at_checked(rec.len().checked_sub(SIG)?)?;
        Some((payload, sig.try_into().ok()?))
    }
}

/// One author's log in memory.
#[derive(Debug, Default)]
struct Log {
    chunks: VecDeque<Chunk>,
}

impl Log {
    fn push(&mut self, seq: u64, payload: &[u8], sig: &[u8; 64]) {
        let size = payload.len() + SIG;
        let start = match self.chunks.back() {
            Some(c) if !c.starts.is_empty() && c.data.len() + size <= CHUNK => u16::try_from(c.data.len()).ok(),
            _ => None,
        };
        let start = match start {
            Some(s) => s,
            None => {
                if let Some(full) = self.chunks.back_mut() {
                    full.data.shrink_to_fit();
                    full.starts.shrink_to_fit();
                }
                // A busy author gets a full chunk at once; a first chunk grows as needed, so
                // many quiet authors don't cost a chunk each.
                let cap = if self.chunks.is_empty() { size } else { CHUNK.max(size) };
                self.chunks.push_back(Chunk { first: seq, data: Vec::with_capacity(cap), starts: Vec::new() });
                0
            }
        };
        if let Some(c) = self.chunks.back_mut() {
            c.starts.push(start);
            c.data.extend_from_slice(payload);
            c.data.extend_from_slice(sig);
        }
    }

    fn record(&self, seq: u64) -> Option<(&[u8], &[u8; 64])> {
        let k = self.chunks.partition_point(|c| c.first <= seq).checked_sub(1)?;
        let c = self.chunks.get(k)?;
        c.record(usize::try_from(seq - c.first).ok()?)
    }

    /// Bytes of entry data held (payloads and signatures).
    fn ram(&self) -> usize {
        self.chunks.iter().map(|c| c.data.len()).sum()
    }
}

#[derive(Default)]
pub(crate) struct Logs {
    logs: HashMap<PeerId, Log>,
    vector: Vector,
    pending: BTreeMap<PeerId, BTreeMap<u64, Arc<Entry>>>,
    pending_count: usize,
    bytes: usize,
}

impl Logs {
    pub fn vector(&self) -> &Vector {
        &self.vector
    }

    pub fn get(&self, author: &PeerId, seq: u64) -> Option<Arc<Entry>> {
        let (payload, sig) = self.logs.get(author)?.record(seq)?;
        Some(Arc::new(Entry { author: *author, seq, payload: payload.to_vec(), sig: *sig }))
    }

    pub fn len(&self) -> u64 {
        self.vector.total()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Bytes of entry data held in memory (payloads and signatures, not the waiting buffer).
    pub fn ram(&self) -> usize {
        self.logs.values().map(Log::ram).sum()
    }

    pub fn pending(&self) -> usize {
        self.pending_count
    }

    /// The highest seq buffered for `author`, if any.
    pub fn pending_max(&self, author: &PeerId) -> u64 {
        self.pending.get(author).and_then(|p| p.keys().next_back().copied()).unwrap_or(0)
    }

    /// Whether we hold `e` itself (`Some(true)`), another entry with its seq (`Some(false)`), or
    /// nothing with its seq (`None`).
    fn holds(&self, e: &Entry) -> Option<bool> {
        let (payload, sig) = self.logs.get(&e.author)?.record(e.seq)?;
        Some(payload == e.payload.as_slice() && sig == &e.sig)
    }

    /// Inserts an entry whose signature was already checked.
    pub fn insert(&mut self, e: Arc<Entry>) -> Insert {
        let have = self.vector.get(&e.author);
        if e.seq <= have {
            return match self.holds(&e) {
                Some(true) => Insert::Duplicate,
                _ => Insert::Conflict,
            };
        }
        if e.seq > have + 1 {
            let p = self.pending.entry(e.author).or_default();
            if let Some(old) = p.get(&e.seq) {
                return if **old == *e { Insert::Duplicate } else { Insert::Conflict };
            }
            if self.pending_count >= PENDING_LIMIT {
                // Make room only by dropping something further ahead than this entry.
                let Some((&far_author, &far_seq)) =
                    self.pending.iter().filter_map(|(a, m)| m.keys().next_back().map(|s| (a, s))).max_by_key(|(_, s)| **s)
                else {
                    return Insert::Dropped;
                };
                if far_seq <= e.seq {
                    return Insert::Dropped;
                }
                if let Some(m) = self.pending.get_mut(&far_author) {
                    m.remove(&far_seq);
                    self.pending_count -= 1;
                    if m.is_empty() {
                        self.pending.remove(&far_author);
                    }
                }
            }
            self.pending.entry(e.author).or_default().insert(e.seq, e);
            self.pending_count += 1;
            return Insert::Buffered;
        }
        let author = e.author;
        self.push(&e);
        let mut added = vec![e];
        // Drain buffered entries that are now next in line.
        if let Some(mut p) = self.pending.remove(&author) {
            loop {
                let next = self.vector.get(&author) + 1;
                // Drop anything at or below what we now hold.
                while let Some((&s, _)) = p.first_key_value() {
                    if s < next {
                        p.remove(&s);
                        self.pending_count -= 1;
                    } else {
                        break;
                    }
                }
                let Some(e) = p.remove(&next) else { break };
                self.pending_count -= 1;
                self.push(&e);
                added.push(e);
            }
            if !p.is_empty() {
                self.pending.insert(author, p);
            }
        }
        Insert::Appended(added)
    }

    fn push(&mut self, e: &Entry) {
        self.bytes += e.payload.len();
        self.logs.entry(e.author).or_default().push(e.seq, &e.payload, &e.sig);
        self.vector.raise(e.author, e.seq);
    }

    /// Entries the holder of `known` lacks, oldest first per author, until `budget` bytes or
    /// `max` entries. Authors are visited round-robin from the one after `start`, so one big
    /// log doesn't starve the others.
    pub fn since(&self, known: &Vector, budget: usize, max: usize) -> Vec<Arc<Entry>> {
        let mut out = Vec::new();
        let mut used = 0usize;
        let mut cursors: Vec<(PeerId, u64, u64)> =
            self.vector.iter().filter(|(a, have)| known.get(a) < **have).map(|(a, &have)| (*a, known.get(a) + 1, have)).collect();
        while !cursors.is_empty() {
            let mut i = 0;
            while i < cursors.len() {
                let (a, next, have) = cursors[i];
                if let Some(e) = self.get(&a, next) {
                    let size = e.wire_size();
                    // At least MIN_BATCH entries go out whatever the byte budget, so catch-up over
                    // slow, high-latency links still moves a fair amount per round trip.
                    if (used + size > budget && out.len() >= MIN_BATCH.min(max)) || out.len() >= max {
                        return out;
                    }
                    used += size;
                    out.push(e);
                }
                if next >= have {
                    cursors.swap_remove(i);
                } else {
                    cursors[i].1 = next + 1;
                    i += 1;
                }
            }
        }
        out
    }

    /// Entries `from..=to` of one author (what we hold of them).
    pub fn range(&self, author: &PeerId, from: u64, to: u64) -> Vec<Arc<Entry>> {
        let to = to.min(self.vector.get(author));
        (from.max(1)..=to).filter_map(|s| self.get(author, s)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{Identity, SwarmId};

    fn entries(n: u64, who: u8) -> Vec<Arc<Entry>> {
        let me = Identity::from_secret([who; 32]);
        (1..=n).map(|s| Arc::new(Entry::sign(&SwarmId([0; 32]), &me, s, vec![who; 10]))).collect()
    }

    #[test]
    fn in_order_out_of_order_and_duplicates() {
        let es = entries(5, 1);
        let mut l = Logs::default();
        assert_eq!(l.insert(es[0].clone()), Insert::Appended(vec![es[0].clone()]));
        assert_eq!(l.insert(es[3].clone()), Insert::Buffered);
        assert_eq!(l.insert(es[2].clone()), Insert::Buffered);
        assert_eq!(l.insert(es[3].clone()), Insert::Duplicate);
        assert_eq!(l.pending(), 2);
        assert_eq!(l.insert(es[1].clone()), Insert::Appended(vec![es[1].clone(), es[2].clone(), es[3].clone()]));
        assert_eq!(l.pending(), 0);
        assert_eq!(l.vector().get(&es[0].author), 4);
        assert_eq!(l.insert(es[0].clone()), Insert::Duplicate);
    }

    #[test]
    fn conflicting_entries_are_reported_and_first_wins() {
        let me = Identity::from_secret([1; 32]);
        let s = SwarmId([0; 32]);
        let mut l = Logs::default();
        let a = Arc::new(Entry::sign(&s, &me, 1, b"a".to_vec()));
        let b = Arc::new(Entry::sign(&s, &me, 1, b"b".to_vec()));
        assert!(matches!(l.insert(a.clone()), Insert::Appended(_)));
        assert_eq!(l.insert(b), Insert::Conflict);
        assert_eq!(l.get(&a.author, 1), Some(a));
    }

    #[test]
    fn since_is_fair_and_respects_budget() {
        let mut l = Logs::default();
        for e in entries(100, 1).into_iter().chain(entries(3, 2)) {
            l.insert(e);
        }
        let got = l.since(&Vector::new(), usize::MAX, 6);
        // Round robin: both authors appear in the first batch.
        assert!(got.iter().any(|e| e.payload[0] == 2));
        assert_eq!(got.len(), 6);
        let small = l.since(&Vector::new(), 1, 100);
        assert_eq!(small.len(), MIN_BATCH, "a minimum batch, so progress is made");
        let all = l.since(&Vector::new(), usize::MAX, usize::MAX);
        assert_eq!(all.len(), 103);
        // Per author the order is ascending.
        let mut last = HashMap::new();
        for e in &all {
            let prev = last.insert(e.author, e.seq).unwrap_or(0);
            assert_eq!(e.seq, prev + 1);
        }
        let known: Vector = [(entries(1, 1)[0].author, 99)].into_iter().collect();
        assert_eq!(l.since(&known, usize::MAX, usize::MAX).len(), 1 + 3);
    }

    #[test]
    fn pending_buffer_is_bounded_and_keeps_the_nearest() {
        let es = entries(PENDING_LIMIT as u64 + 10, 1);
        let mut l = Logs::default();
        // Everything from seq 3 on, far end first: the nearest ones must survive.
        for e in es.iter().skip(2).rev() {
            l.insert(e.clone());
        }
        assert_eq!(l.pending(), PENDING_LIMIT);
        l.insert(es[0].clone());
        l.insert(es[1].clone());
        assert_eq!(l.vector().get(&es[0].author), PENDING_LIMIT as u64 + 2);
        assert_eq!(l.pending(), 0);
    }

    #[test]
    fn range_clamps() {
        let mut l = Logs::default();
        for e in entries(5, 1) {
            l.insert(e);
        }
        let a = entries(1, 1)[0].author;
        assert_eq!(l.range(&a, 0, 2).len(), 2);
        assert_eq!(l.range(&a, 4, 99).len(), 2);
        assert!(l.range(&a, 6, 9).is_empty());
        assert!(l.range(&PeerId([9; 32]), 1, 9).is_empty());
    }

    fn signed(who: u8, seq: u64, payload: Vec<u8>) -> Arc<Entry> {
        Arc::new(Entry::sign(&SwarmId([0; 32]), &Identity::from_secret([who; 32]), seq, payload))
    }

    #[test]
    fn packed_logs_round_trip_across_chunks_and_authors() {
        let mut l = Logs::default();
        let mut all = Vec::new();
        // 40 authors, payloads from empty to a few KiB, so chunks fill unevenly.
        for seq in 1..=60u64 {
            for who in 1..=40u8 {
                let len = (seq as usize * 97 + who as usize * 31) % 3000;
                let e = signed(who, seq, (0..len).map(|i| (i as u8) ^ who).collect());
                assert!(matches!(l.insert(e.clone()), Insert::Appended(_)));
                all.push(e);
            }
        }
        for e in &all {
            assert_eq!(l.get(&e.author, e.seq).as_ref(), Some(e));
            assert_eq!(l.insert(e.clone()), Insert::Duplicate);
        }
        assert_eq!(l.len(), all.len() as u64);
        let payload: usize = all.iter().map(|e| e.payload.len()).sum();
        assert_eq!(l.bytes(), payload);
        assert_eq!(l.ram(), payload + 64 * all.len(), "payload and signature, nothing else");
        assert!(l.logs.values().any(|g| g.chunks.len() > 1), "some logs span chunks");
        for g in l.logs.values() {
            // Sealed chunks are full but for less than one entry.
            for c in g.chunks.iter().rev().skip(1) {
                assert!(c.data.len() > CHUNK - 3000 - 64 && c.data.len() <= CHUNK);
            }
        }
        let back = l.since(&Vector::new(), usize::MAX, usize::MAX);
        assert_eq!(back.len(), all.len());
        let mut sorted = back.clone();
        sorted.sort_by_key(|e| (e.author, e.seq));
        let mut want = all.clone();
        want.sort_by_key(|e| (e.author, e.seq));
        assert_eq!(sorted, want);
        assert!(l.get(&all[0].author, 0).is_none());
        assert!(l.get(&all[0].author, 61).is_none());
    }

    #[test]
    fn stored_bytes_decide_duplicates_and_conflicts() {
        let mut l = Logs::default();
        let a = signed(1, 1, b"same".to_vec());
        l.insert(a.clone());
        // Same seq, other payload: a conflict.
        assert_eq!(l.insert(signed(1, 1, b"other".to_vec())), Insert::Conflict);
        // Same payload, another signature (not valid, but the bytes differ): a conflict too.
        let mut forged = (*a).clone();
        forged.sig[0] ^= 1;
        assert_eq!(l.insert(Arc::new(forged)), Insert::Conflict);
        // A payload that is a prefix of the stored one is not the same entry.
        let b = signed(1, 2, b"abcdef".to_vec());
        l.insert(b.clone());
        assert_eq!(l.insert(signed(1, 2, b"abc".to_vec())), Insert::Conflict);
        assert_eq!(l.insert(b), Insert::Duplicate);
        assert_eq!(l.get(&a.author, 1), Some(a));
    }

    #[test]
    fn gaps_wait_and_then_pack_in_order() {
        let mut l = Logs::default();
        let es: Vec<Arc<Entry>> = (1..=200).map(|s| signed(3, s, vec![s as u8; 500])).collect();
        for e in es.iter().skip(1).rev() {
            assert_eq!(l.insert(e.clone()), Insert::Buffered);
        }
        assert_eq!(l.vector().get(&es[0].author), 0);
        assert_eq!(l.ram(), 0);
        let Insert::Appended(v) = l.insert(es[0].clone()) else { panic!("not appended") };
        assert_eq!(v, es);
        assert_eq!(l.pending(), 0);
        for e in &es {
            assert_eq!(l.get(&e.author, e.seq).as_ref(), Some(e));
        }
    }

    #[test]
    fn payloads_at_the_limit_get_chunks_of_their_own() {
        let mut l = Logs::default();
        let max = crate::limits::MAX_PAYLOAD;
        let sizes = [max, 10, max, max, 0, 1, max - 1, 5000];
        let es: Vec<Arc<Entry>> = sizes.iter().enumerate().map(|(i, n)| signed(4, i as u64 + 1, vec![i as u8; *n])).collect();
        for e in &es {
            assert!(matches!(l.insert(e.clone()), Insert::Appended(_)));
        }
        for e in &es {
            assert_eq!(l.get(&e.author, e.seq).as_ref(), Some(e));
        }
        let log = &l.logs[&es[0].author];
        assert!(log.chunks.iter().all(|c| c.starts.len() == 1 || c.data.len() <= CHUNK));
        assert_eq!(l.range(&es[0].author, 2, 4), es[1..4].to_vec());
    }
}
