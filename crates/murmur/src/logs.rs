//! The entries a peer holds: one contiguous log per author, plus a bounded buffer for entries
//! that arrived ahead of a gap (they came by a faster path than the ones before them).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::entry::Entry;
use crate::id::PeerId;
use crate::vector::Vector;

/// Fewest entries one answer carries (when there are that many to send).
pub(crate) const MIN_BATCH: usize = 16;

/// Most entries held back waiting for a gap to fill, over all authors.
pub(crate) const PENDING_LIMIT: usize = 8192;

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

#[derive(Default)]
pub(crate) struct Logs {
    logs: HashMap<PeerId, Vec<Arc<Entry>>>,
    vector: Vector,
    pending: BTreeMap<PeerId, BTreeMap<u64, Arc<Entry>>>,
    pending_count: usize,
    bytes: usize,
}

impl Logs {
    pub fn vector(&self) -> &Vector {
        &self.vector
    }

    pub fn get(&self, author: &PeerId, seq: u64) -> Option<&Arc<Entry>> {
        let i = usize::try_from(seq.checked_sub(1)?).ok()?;
        self.logs.get(author)?.get(i)
    }

    pub fn len(&self) -> u64 {
        self.vector.total()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn pending(&self) -> usize {
        self.pending_count
    }

    /// The highest seq buffered for `author`, if any.
    pub fn pending_max(&self, author: &PeerId) -> u64 {
        self.pending.get(author).and_then(|p| p.keys().next_back().copied()).unwrap_or(0)
    }

    /// Inserts an entry whose signature was already checked.
    pub fn insert(&mut self, e: Arc<Entry>) -> Insert {
        let have = self.vector.get(&e.author);
        if e.seq <= have {
            return match self.get(&e.author, e.seq) {
                Some(old) if **old == *e => Insert::Duplicate,
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
        let mut added = vec![e.clone()];
        self.push(e);
        // Drain buffered entries that are now next in line.
        if let Some(p) = self.pending.get_mut(&author) {
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
                added.push(e.clone());
                let log = self.logs.entry(author).or_default();
                self.bytes += e.payload.len();
                log.push(e);
                self.vector.raise(author, next);
            }
            if p.is_empty() {
                self.pending.remove(&author);
            }
        }
        Insert::Appended(added)
    }

    fn push(&mut self, e: Arc<Entry>) {
        let author = e.author;
        let seq = e.seq;
        self.bytes += e.payload.len();
        self.logs.entry(author).or_default().push(e);
        self.vector.raise(author, seq);
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
                    out.push(e.clone());
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
        let Some(log) = self.logs.get(author) else { return Vec::new() };
        let from = from.max(1);
        let to = to.min(log.len() as u64);
        if from > to {
            return Vec::new();
        }
        log.get((from - 1) as usize..to as usize).map(|s| s.to_vec()).unwrap_or_default()
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
        assert_eq!(l.get(&a.author, 1), Some(&a));
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
}
