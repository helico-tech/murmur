//! The entries a peer holds: one contiguous log per author, plus a bounded buffer for entries
//! that arrived ahead of a gap (they came by a faster path than the ones before them).
//!
//! Logs are packed to save memory: an author's entries sit back to back in byte chunks, each as
//! `payload ‖ signature`, with a 2-byte start offset per entry. The author and seq are implicit.
//! Entries are decoded into an `Entry` when someone asks for them.
//!
//! With a storage that can read (ADR 0002), whole old chunks leave memory once the storage holds
//! them; those entries are read back through the storage when needed.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

use crate::entry::Entry;
use crate::id::PeerId;
use crate::storage::Storage;
use crate::vector::Vector;

/// Fewest entries one answer carries (when there are that many to send).
pub(crate) const MIN_BATCH: usize = 16;

/// Most entries held back waiting for a gap to fill, over all authors.
pub(crate) const PENDING_LIMIT: usize = 8192;

/// Largest target size of one chunk of a packed log. An entry bigger than the target gets a
/// chunk of its own. At most 65 536, so start offsets fit in a `u16`.
pub(crate) const CHUNK: usize = 32 * 1024;

/// Smallest target chunk size (with a tiny `ram_window`).
const MIN_CHUNK: usize = 256;

/// Entries read from storage at once when answering peers, and when replaying.
const READ_BATCH: u64 = 64;
const REPLAY_BATCH: u64 = 1024;

const SIG: usize = 64;

/// The chunk size for a `ram_window`: a window holds about eight chunks.
pub(crate) fn chunk_for(window: usize) -> usize {
    (window / 8).clamp(MIN_CHUNK, CHUNK)
}

/// Where old entries are read from: the app's storage, if any.
pub(crate) type Reader<'a> = Option<&'a dyn Storage>;

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
    /// Already held, but reading our copy back from storage failed, so we can't tell whether it
    /// is the same. Nothing changed.
    Unread(String),
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

    fn last(&self) -> u64 {
        self.first + (self.starts.len() as u64).saturating_sub(1)
    }
}

/// One author's log in memory.
#[derive(Debug, Default)]
struct Log {
    /// Seqs `1..=base` are not in memory; they are read through the storage.
    base: u64,
    /// The storage holds `1..=durable` for sure (only entries up to here may leave memory).
    durable: u64,
    chunks: VecDeque<Chunk>,
}

impl Log {
    fn push(&mut self, seq: u64, payload: &[u8], sig: &[u8; 64], chunk: usize) {
        let size = payload.len() + SIG;
        let start = match self.chunks.back() {
            Some(c) if !c.starts.is_empty() && c.data.len() + size <= chunk => u16::try_from(c.data.len()).ok(),
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
                let cap = if self.chunks.is_empty() { size } else { chunk.max(size) };
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

    /// Drops whole old chunks that the storage holds, keeping at least `window` bytes and the
    /// newest chunk.
    fn evict(&mut self, window: usize) {
        let mut ram = self.ram();
        while self.chunks.len() > 1 {
            let Some(c) = self.chunks.front() else { break };
            if c.last() > self.durable || ram - c.data.len() < window {
                break;
            }
            ram -= c.data.len();
            self.base = c.last();
            self.chunks.pop_front();
        }
    }
}

/// Entries `from..=to` of `author`, read from the storage and checked to be exactly those.
fn read_old(store: Reader, author: &PeerId, from: u64, to: u64) -> Result<Vec<Entry>, String> {
    let Some(st) = store else {
        return Err(format!("{}:{from} is not in memory and there is no storage to read it from", author.short()));
    };
    let mut out = Vec::new();
    let mut next = from;
    while next <= to {
        let want = usize::try_from(to - next + 1).unwrap_or(usize::MAX);
        let got = st.read(author, next, want)?;
        if got.is_empty() {
            return Err(format!("the storage lacks {}:{next}", author.short()));
        }
        for e in got.into_iter().take(want) {
            if e.author != *author || e.seq != next {
                return Err(format!("the storage returned {}:{} for {}:{next}", e.author.short(), e.seq, author.short()));
            }
            out.push(e);
            next += 1;
        }
    }
    Ok(out)
}

/// Reads `from..=to` of `author` into `buf` (kept out of the hot loop of `since`).
#[cold]
#[inline(never)]
fn refill(buf: &mut VecDeque<Entry>, store: Reader, author: &PeerId, from: u64, to: u64) -> Result<(), String> {
    buf.extend(read_old(store, author, from, to)?);
    Ok(())
}

pub(crate) struct Logs {
    logs: HashMap<PeerId, Log>,
    vector: Vector,
    pending: BTreeMap<PeerId, BTreeMap<u64, Arc<Entry>>>,
    pending_count: usize,
    bytes: usize,
    /// Target chunk size.
    chunk: usize,
}

impl Default for Logs {
    fn default() -> Self {
        Logs::new(CHUNK)
    }
}

impl Logs {
    pub fn new(chunk: usize) -> Logs {
        Logs { logs: HashMap::new(), vector: Vector::new(), pending: BTreeMap::new(), pending_count: 0, bytes: 0, chunk: chunk.clamp(1, CHUNK) }
    }

    pub fn vector(&self) -> &Vector {
        &self.vector
    }

    /// Entry `seq` of `author`, from memory or (if it left memory) from the storage.
    pub fn get(&self, author: &PeerId, seq: u64, store: Reader) -> Result<Option<Arc<Entry>>, String> {
        if seq == 0 || seq > self.vector.get(author) {
            return Ok(None);
        }
        match self.logs.get(author) {
            Some(log) if seq <= log.base => Ok(read_old(store, author, seq, seq)?.pop().map(Arc::new)),
            _ => Ok(self.decode(author, seq)),
        }
    }

    /// Entry `seq` of `author` if it is in memory.
    fn decode(&self, author: &PeerId, seq: u64) -> Option<Arc<Entry>> {
        let (payload, sig) = self.logs.get(author)?.record(seq)?;
        Some(Arc::new(Entry { author: *author, seq, payload: payload.to_vec(), sig: *sig }))
    }

    pub fn len(&self) -> u64 {
        self.vector.total()
    }

    /// Holds nothing at all (not even waiting entries).
    pub fn is_empty(&self) -> bool {
        self.vector.is_empty() && self.pending_count == 0
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
    fn holds(&self, e: &Entry, store: Reader) -> Result<Option<bool>, String> {
        let Some(log) = self.logs.get(&e.author) else { return Ok(None) };
        if e.seq <= log.base {
            let old = read_old(store, &e.author, e.seq, e.seq)?;
            return Ok(old.first().map(|o| o.payload == e.payload && o.sig == e.sig));
        }
        Ok(log.record(e.seq).map(|(payload, sig)| payload == e.payload.as_slice() && sig == &e.sig))
    }

    /// Inserts an entry whose signature was already checked.
    pub fn insert(&mut self, e: Arc<Entry>, store: Reader) -> Insert {
        let have = self.vector.get(&e.author);
        if e.seq <= have {
            return match self.holds(&e, store) {
                Ok(Some(true)) => Insert::Duplicate,
                Ok(_) => Insert::Conflict,
                Err(err) => Insert::Unread(err),
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
        let chunk = self.chunk;
        self.logs.entry(e.author).or_default().push(e.seq, &e.payload, &e.sig, chunk);
        self.vector.raise(e.author, e.seq);
    }

    /// Takes a storage's `heads` as the logs, all of them out of memory. Only on empty logs.
    pub fn load(&mut self, heads: &Vector) {
        for (a, &h) in heads.iter() {
            if h > 0 && self.vector.get(a) == 0 {
                self.logs.insert(*a, Log { base: h, durable: h, chunks: VecDeque::new() });
                self.vector.raise(*a, h);
            }
        }
    }

    /// The storage accepted `added` (in order per author): move the durable marks.
    pub fn stored(&mut self, added: &[Arc<Entry>]) {
        for e in added {
            if let Some(log) = self.logs.get_mut(&e.author)
                && e.seq == log.durable + 1
            {
                log.durable = e.seq;
            }
        }
    }

    /// A new storage: nothing in memory is known to be in it.
    pub fn forget_durable(&mut self) {
        for log in self.logs.values_mut() {
            log.durable = log.base;
        }
    }

    /// Lets old chunks of these authors leave memory, keeping about `window` bytes each.
    pub fn evict<'a>(&mut self, authors: impl IntoIterator<Item = &'a PeerId>, window: usize) {
        for a in authors {
            if let Some(log) = self.logs.get_mut(a) {
                log.evict(window);
            }
        }
    }

    /// Entries the holder of `known` lacks, oldest first per author, until `budget` bytes or
    /// `max` entries. Authors are visited round-robin, so one big log doesn't starve the others.
    /// If reading old entries fails, returns what it has so far and the error.
    pub fn since(&self, known: &Vector, budget: usize, max: usize, store: Reader) -> (Vec<Arc<Entry>>, Option<String>) {
        struct Cursor {
            author: PeerId,
            next: u64,
            have: u64,
            base: u64,
            /// Old entries read from storage, not sent yet.
            read: VecDeque<Entry>,
        }
        let mut out = Vec::new();
        let mut used = 0usize;
        let mut cursors: Vec<Cursor> = self
            .vector
            .iter()
            .filter(|(a, have)| known.get(a) < **have)
            .map(|(a, &have)| Cursor {
                author: *a,
                next: known.get(a) + 1,
                have,
                base: self.logs.get(a).map_or(0, |l| l.base),
                read: VecDeque::new(),
            })
            .collect();
        while !cursors.is_empty() {
            let mut i = 0;
            while i < cursors.len() {
                let c = &mut cursors[i];
                let e = if c.next <= c.base {
                    if c.read.is_empty() {
                        let room = (max.saturating_sub(out.len()) as u64).clamp(1, READ_BATCH);
                        if let Err(err) = refill(&mut c.read, store, &c.author, c.next, c.base.min(c.next.saturating_add(room - 1))) {
                            return (out, Some(err));
                        }
                    }
                    c.read.pop_front().map(Arc::new)
                } else {
                    self.decode(&c.author, c.next)
                };
                if let Some(e) = e {
                    let size = e.wire_size();
                    // At least MIN_BATCH entries go out whatever the byte budget, so catch-up over
                    // slow, high-latency links still moves a fair amount per round trip.
                    if (used + size > budget && out.len() >= MIN_BATCH.min(max)) || out.len() >= max {
                        return (out, None);
                    }
                    used += size;
                    out.push(e);
                }
                if c.next >= c.have {
                    cursors.swap_remove(i);
                } else {
                    c.next += 1;
                    i += 1;
                }
            }
        }
        (out, None)
    }

    /// Entries `from..=to` of one author (what we hold of them).
    pub fn range(&self, author: &PeerId, from: u64, to: u64, store: Reader) -> Result<Vec<Arc<Entry>>, String> {
        let from = from.max(1);
        let to = to.min(self.vector.get(author));
        let Some(log) = self.logs.get(author) else { return Ok(Vec::new()) };
        let mut out = Vec::new();
        if from > to {
            return Ok(out);
        }
        if from <= log.base {
            out.extend(read_old(store, author, from, to.min(log.base))?.into_iter().map(Arc::new));
        }
        out.extend((from.max(log.base + 1)..=to).filter_map(|s| self.decode(author, s)));
        Ok(out)
    }

    /// Calls `f` with every entry the holder of `from` lacks: author by author, oldest first,
    /// without holding them all. Returns how many there were.
    pub fn replay(&self, from: &Vector, mut f: impl FnMut(&Entry), store: Reader) -> Result<u64, String> {
        let mut n = 0u64;
        let mut scratch = Entry { author: PeerId([0; 32]), seq: 0, payload: Vec::new(), sig: [0; 64] };
        for (a, &have) in self.vector.iter() {
            let Some(log) = self.logs.get(a) else { continue };
            let mut next = from.get(a) + 1;
            while next <= have.min(log.base) {
                let to = have.min(log.base).min(next.saturating_add(REPLAY_BATCH - 1));
                for e in read_old(store, a, next, to)? {
                    f(&e);
                    n += 1;
                }
                next = to + 1;
            }
            for seq in next..=have {
                let Some((payload, sig)) = log.record(seq) else {
                    return Err(format!("{}:{seq} is missing from memory", a.short()));
                };
                scratch.author = *a;
                scratch.seq = seq;
                scratch.payload.clear();
                scratch.payload.extend_from_slice(payload);
                scratch.sig = *sig;
                f(&scratch);
                n += 1;
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{Identity, SwarmId};
    use crate::storage::Storage;

    fn entries(n: u64, who: u8) -> Vec<Arc<Entry>> {
        let me = Identity::from_secret([who; 32]);
        (1..=n).map(|s| Arc::new(Entry::sign(&SwarmId([0; 32]), &me, s, vec![who; 10]))).collect()
    }

    #[test]
    fn in_order_out_of_order_and_duplicates() {
        let es = entries(5, 1);
        let mut l = Logs::default();
        assert_eq!(l.insert(es[0].clone(), None), Insert::Appended(vec![es[0].clone()]));
        assert_eq!(l.insert(es[3].clone(), None), Insert::Buffered);
        assert_eq!(l.insert(es[2].clone(), None), Insert::Buffered);
        assert_eq!(l.insert(es[3].clone(), None), Insert::Duplicate);
        assert_eq!(l.pending(), 2);
        assert_eq!(l.insert(es[1].clone(), None), Insert::Appended(vec![es[1].clone(), es[2].clone(), es[3].clone()]));
        assert_eq!(l.pending(), 0);
        assert_eq!(l.vector().get(&es[0].author), 4);
        assert_eq!(l.insert(es[0].clone(), None), Insert::Duplicate);
    }

    #[test]
    fn conflicting_entries_are_reported_and_first_wins() {
        let me = Identity::from_secret([1; 32]);
        let s = SwarmId([0; 32]);
        let mut l = Logs::default();
        let a = Arc::new(Entry::sign(&s, &me, 1, b"a".to_vec()));
        let b = Arc::new(Entry::sign(&s, &me, 1, b"b".to_vec()));
        assert!(matches!(l.insert(a.clone(), None), Insert::Appended(_)));
        assert_eq!(l.insert(b, None), Insert::Conflict);
        assert_eq!(l.get(&a.author, 1, None).unwrap(), Some(a));
    }

    #[test]
    fn since_is_fair_and_respects_budget() {
        let mut l = Logs::default();
        for e in entries(100, 1).into_iter().chain(entries(3, 2)) {
            l.insert(e, None);
        }
        let got = l.since(&Vector::new(), usize::MAX, 6, None).0;
        // Round robin: both authors appear in the first batch.
        assert!(got.iter().any(|e| e.payload[0] == 2));
        assert_eq!(got.len(), 6);
        let small = l.since(&Vector::new(), 1, 100, None).0;
        assert_eq!(small.len(), MIN_BATCH, "a minimum batch, so progress is made");
        let all = l.since(&Vector::new(), usize::MAX, usize::MAX, None).0;
        assert_eq!(all.len(), 103);
        // Per author the order is ascending.
        let mut last = HashMap::new();
        for e in &all {
            let prev = last.insert(e.author, e.seq).unwrap_or(0);
            assert_eq!(e.seq, prev + 1);
        }
        let known: Vector = [(entries(1, 1)[0].author, 99)].into_iter().collect();
        assert_eq!(l.since(&known, usize::MAX, usize::MAX, None).0.len(), 1 + 3);
    }

    #[test]
    fn pending_buffer_is_bounded_and_keeps_the_nearest() {
        let es = entries(PENDING_LIMIT as u64 + 10, 1);
        let mut l = Logs::default();
        // Everything from seq 3 on, far end first: the nearest ones must survive.
        for e in es.iter().skip(2).rev() {
            l.insert(e.clone(), None);
        }
        assert_eq!(l.pending(), PENDING_LIMIT);
        l.insert(es[0].clone(), None);
        l.insert(es[1].clone(), None);
        assert_eq!(l.vector().get(&es[0].author), PENDING_LIMIT as u64 + 2);
        assert_eq!(l.pending(), 0);
    }

    #[test]
    fn range_clamps() {
        let mut l = Logs::default();
        for e in entries(5, 1) {
            l.insert(e, None);
        }
        let a = entries(1, 1)[0].author;
        assert_eq!(l.range(&a, 0, 2, None).unwrap().len(), 2);
        assert_eq!(l.range(&a, 4, 99, None).unwrap().len(), 2);
        assert!(l.range(&a, 6, 9, None).unwrap().is_empty());
        assert!(l.range(&PeerId([9; 32]), 1, 9, None).unwrap().is_empty());
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
                assert!(matches!(l.insert(e.clone(), None), Insert::Appended(_)));
                all.push(e);
            }
        }
        for e in &all {
            assert_eq!(l.get(&e.author, e.seq, None).unwrap().as_ref(), Some(e));
            assert_eq!(l.insert(e.clone(), None), Insert::Duplicate);
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
        let back = l.since(&Vector::new(), usize::MAX, usize::MAX, None).0;
        assert_eq!(back.len(), all.len());
        let mut sorted = back.clone();
        sorted.sort_by_key(|e| (e.author, e.seq));
        let mut want = all.clone();
        want.sort_by_key(|e| (e.author, e.seq));
        assert_eq!(sorted, want);
        assert!(l.get(&all[0].author, 0, None).unwrap().is_none());
        assert!(l.get(&all[0].author, 61, None).unwrap().is_none());
    }

    #[test]
    fn stored_bytes_decide_duplicates_and_conflicts() {
        let mut l = Logs::default();
        let a = signed(1, 1, b"same".to_vec());
        l.insert(a.clone(), None);
        // Same seq, other payload: a conflict.
        assert_eq!(l.insert(signed(1, 1, b"other".to_vec()), None), Insert::Conflict);
        // Same payload, another signature (not valid, but the bytes differ): a conflict too.
        let mut forged = (*a).clone();
        forged.sig[0] ^= 1;
        assert_eq!(l.insert(Arc::new(forged), None), Insert::Conflict);
        // A payload that is a prefix of the stored one is not the same entry.
        let b = signed(1, 2, b"abcdef".to_vec());
        l.insert(b.clone(), None);
        assert_eq!(l.insert(signed(1, 2, b"abc".to_vec()), None), Insert::Conflict);
        assert_eq!(l.insert(b, None), Insert::Duplicate);
        assert_eq!(l.get(&a.author, 1, None).unwrap(), Some(a));
    }

    #[test]
    fn gaps_wait_and_then_pack_in_order() {
        let mut l = Logs::default();
        let es: Vec<Arc<Entry>> = (1..=200).map(|s| signed(3, s, vec![s as u8; 500])).collect();
        for e in es.iter().skip(1).rev() {
            assert_eq!(l.insert(e.clone(), None), Insert::Buffered);
        }
        assert_eq!(l.vector().get(&es[0].author), 0);
        assert_eq!(l.ram(), 0);
        let Insert::Appended(v) = l.insert(es[0].clone(), None) else { panic!("not appended") };
        assert_eq!(v, es);
        assert_eq!(l.pending(), 0);
        for e in &es {
            assert_eq!(l.get(&e.author, e.seq, None).unwrap().as_ref(), Some(e));
        }
    }

    #[test]
    fn payloads_at_the_limit_get_chunks_of_their_own() {
        let mut l = Logs::default();
        let max = crate::limits::MAX_PAYLOAD;
        let sizes = [max, 10, max, max, 0, 1, max - 1, 5000];
        let es: Vec<Arc<Entry>> = sizes.iter().enumerate().map(|(i, n)| signed(4, i as u64 + 1, vec![i as u8; *n])).collect();
        for e in &es {
            assert!(matches!(l.insert(e.clone(), None), Insert::Appended(_)));
        }
        for e in &es {
            assert_eq!(l.get(&e.author, e.seq, None).unwrap().as_ref(), Some(e));
        }
        let log = &l.logs[&es[0].author];
        assert!(log.chunks.iter().all(|c| c.starts.len() == 1 || c.data.len() <= CHUNK));
        assert_eq!(l.range(&es[0].author, 2, 4, None).unwrap(), es[1..4].to_vec());
    }

    /// A storage that reads back, and can be told to fail.
    #[derive(Default)]
    struct Store {
        logs: HashMap<PeerId, Vec<Entry>>,
        broken: std::sync::atomic::AtomicBool,
    }

    impl Storage for Store {
        fn append(&mut self, entries: &[Arc<Entry>]) -> Result<(), String> {
            for e in entries {
                let log = self.logs.entry(e.author).or_default();
                if e.seq == log.len() as u64 + 1 {
                    log.push((**e).clone());
                }
            }
            Ok(())
        }
        fn can_read(&self) -> bool {
            true
        }
        fn heads(&self) -> Result<Vector, String> {
            Ok(self.logs.iter().map(|(a, v)| (*a, v.len() as u64)).collect())
        }
        fn read(&self, author: &PeerId, from: u64, max: usize) -> Result<Vec<Entry>, String> {
            if self.broken.load(std::sync::atomic::Ordering::Relaxed) {
                return Err("disk on fire".into());
            }
            let log = self.logs.get(author).map(Vec::as_slice).unwrap_or_default();
            Ok(log.iter().skip(from.max(1) as usize - 1).take(max).cloned().collect())
        }
    }

    /// Inserts entries as the swarm does with a reading storage: append, mark stored, evict.
    fn feed(l: &mut Logs, st: &mut Store, es: &[Arc<Entry>], window: usize) {
        for e in es {
            if let Insert::Appended(v) = l.insert(e.clone(), Some(&*st)) {
                st.append(&v).unwrap();
                l.stored(&v);
                l.evict(&[e.author], window);
            }
        }
    }

    #[test]
    fn old_chunks_leave_memory_and_read_back_across_the_boundary() {
        let window = 2_000;
        let mut l = Logs::new(chunk_for(window));
        let mut st = Store::default();
        let es: Vec<Arc<Entry>> = (1..=300u64).flat_map(|s| (1..=3u8).map(move |w| signed(w, s, vec![w; (s % 90) as usize]))).collect();
        feed(&mut l, &mut st, &es, window);
        let a = es[0].author;
        let base = l.logs[&a].base;
        assert!(base > 200, "old entries left memory (base {base})");
        assert!(l.ram() <= 3 * (window + chunk_for(window) + 90 + 64), "ram {}", l.ram());
        assert_eq!(l.len(), 900);
        // Single entries on both sides of the boundary, and ranges across it.
        for seq in [1, base - 1, base, base + 1, 300] {
            assert_eq!(l.get(&a, seq, Some(&st)).unwrap().map(|e| e.seq), Some(seq));
        }
        let r = l.range(&a, base - 5, base + 5, Some(&st)).unwrap();
        assert_eq!(r.iter().map(|e| e.seq).collect::<Vec<_>>(), (base - 5..=base + 5).collect::<Vec<_>>());
        // Everything, in order per author, through since and replay.
        let mut want = es.clone();
        want.sort_by_key(|e| (e.author, e.seq));
        let (mut got, err) = l.since(&Vector::new(), usize::MAX, usize::MAX, Some(&st));
        assert!(err.is_none());
        got.sort_by_key(|e| (e.author, e.seq));
        assert_eq!(got, want);
        let mut seen = Vec::new();
        assert_eq!(l.replay(&Vector::new(), |e| seen.push(Arc::new(e.clone())), Some(&st)), Ok(900));
        seen.sort_by_key(|e| (e.author, e.seq));
        assert_eq!(seen, want);
        let from: Vector = [(a, base + 2)].into_iter().collect();
        assert_eq!(l.replay(&from, |_| {}, Some(&st)), Ok(900 - base - 2));
        // A budget still applies to old entries, and the minimum batch too.
        let (small, _) = l.since(&Vector::new(), 1, usize::MAX, Some(&st));
        assert_eq!(small.len(), MIN_BATCH);
        // Duplicates and conflicts of entries that left memory are checked against the storage.
        assert_eq!(l.insert(es[0].clone(), Some(&st)), Insert::Duplicate);
        assert_eq!(l.insert(signed(1, 1, b"not the first".to_vec()), Some(&st)), Insert::Conflict);
    }

    #[test]
    fn failed_reads_are_errors_not_short_answers() {
        let mut l = Logs::new(chunk_for(0));
        let mut st = Store::default();
        let es: Vec<Arc<Entry>> = (1..=100).map(|s| signed(1, s, vec![1; 40])).collect();
        feed(&mut l, &mut st, &es, 0);
        let a = es[0].author;
        assert!(l.logs[&a].base > 50);
        assert!(l.get(&a, 1, None).is_err(), "no storage to read from");
        assert!(l.range(&a, 1, 100, None).is_err());
        st.broken.store(true, std::sync::atomic::Ordering::Relaxed);
        let (got, err) = l.since(&Vector::new(), usize::MAX, usize::MAX, Some(&st));
        assert!(got.is_empty() && err.is_some());
        assert!(l.replay(&Vector::new(), |_| {}, Some(&st)).is_err());
        assert!(matches!(l.insert(es[0].clone(), Some(&st)), Insert::Unread(_)));
        // What is still in memory reads fine.
        assert_eq!(l.get(&a, 100, Some(&st)).unwrap().as_deref(), Some(&*es[99]));
        let known: Vector = [(a, 99)].into_iter().collect();
        assert_eq!(l.since(&known, usize::MAX, usize::MAX, Some(&st)).0.len(), 1);
        // A storage that returns the wrong entries is caught.
        st.broken.store(false, std::sync::atomic::Ordering::Relaxed);
        if let Some(v) = st.logs.get_mut(&a) {
            v.remove(3);
        }
        assert!(l.range(&a, 1, 10, Some(&st)).is_err());
    }

    #[test]
    fn only_entries_the_storage_confirmed_leave_memory() {
        let mut l = Logs::new(chunk_for(0));
        let es: Vec<Arc<Entry>> = (1..=200).map(|s| signed(1, s, vec![1; 40])).collect();
        for e in &es {
            l.insert(e.clone(), None);
        }
        l.stored(&es[..50]);
        l.stored(&es[60..]); // Doesn't continue the mark: ignored.
        l.evict(&[es[0].author], 0);
        let base = l.logs[&es[0].author].base;
        assert!(base > 0 && base <= 50, "base {base}");
        l.forget_durable();
        l.stored(&es[150..]);
        l.evict(&[es[0].author], 0);
        assert_eq!(l.logs[&es[0].author].base, base, "a new storage confirms only runs that continue what left memory");
    }

    #[test]
    fn load_takes_the_storage_heads_without_reading() {
        let mut st = Store::default();
        let es: Vec<Arc<Entry>> = (1..=50).flat_map(|s| [signed(1, s, vec![1; 9]), signed(2, s, vec![2; 9])]).collect();
        st.append(&es).unwrap();
        let mut l = Logs::new(chunk_for(0));
        l.load(&st.heads().unwrap());
        assert_eq!((l.len(), l.ram()), (100, 0));
        assert_eq!(l.get(&es[0].author, 7, Some(&st)).unwrap().map(|e| e.seq), Some(7));
        assert_eq!(l.insert(es[4].clone(), Some(&st)), Insert::Duplicate);
        let next = signed(1, 51, b"new".to_vec());
        assert!(matches!(l.insert(next.clone(), Some(&st)), Insert::Appended(_)));
        let mut n = 0;
        assert_eq!(l.replay(&Vector::new(), |_| n += 1, Some(&st)), Ok(101));
        assert_eq!(n, 101);
        assert_eq!(l.range(&next.author, 49, 51, Some(&st)).unwrap().len(), 3);
    }
}
