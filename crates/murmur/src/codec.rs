//! A compact binary form for stored entries, and an append-only log file of them.
//!
//! An entry: author (32 bytes) | seq (varint) | payload length (varint) | payload | signature
//! (64 bytes). About 100 bytes of overhead per entry, against ~250 for JSON with hex and base64.
//!
//! A log file: the 4-byte magic [`LOG_MAGIC`], then one record per entry: its length (u32,
//! little-endian) | the entry | a check (the first 4 bytes of the entry's BLAKE3 hash). Reading
//! stops at the first record that is torn (the app stopped mid-write) or fails its check, and
//! says how many bytes were good, so the store can cut the file there; peers send what was lost.

use crate::entry::Entry;
use crate::id::PeerId;
use crate::limits::MAX_PAYLOAD;

/// The first bytes of a murmur log file (format 1).
pub const LOG_MAGIC: &[u8; 4] = b"MRL1";

/// Largest encoded entry.
const MAX_ENTRY: usize = 32 + 10 + 10 + MAX_PAYLOAD + 64;

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn get_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v: u64 = 0;
    for shift in (0..64).step_by(7) {
        let b = *buf.get(*pos)?;
        *pos += 1;
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// Appends the binary form of `e` to `out`.
pub fn encode_entry(e: &Entry, out: &mut Vec<u8>) {
    out.extend_from_slice(&e.author.0);
    put_varint(out, e.seq);
    put_varint(out, e.payload.len() as u64);
    out.extend_from_slice(&e.payload);
    out.extend_from_slice(&e.sig);
}

/// Reads one entry that fills all of `buf`. `None` for anything malformed or over the limits.
/// The signature isn't checked (see `Entry::verify`).
pub fn decode_entry(buf: &[u8]) -> Option<Entry> {
    let author = PeerId(<[u8; 32]>::try_from(buf.get(..32)?).ok()?);
    let mut pos = 32;
    let seq = get_varint(buf, &mut pos)?;
    let len = usize::try_from(get_varint(buf, &mut pos)?).ok()?;
    if seq == 0 || len > MAX_PAYLOAD {
        return None;
    }
    let payload = buf.get(pos..pos.checked_add(len)?)?.to_vec();
    pos += len;
    let sig = <[u8; 64]>::try_from(buf.get(pos..pos + 64)?).ok()?;
    (pos + 64 == buf.len()).then_some(Entry { author, seq, payload, sig })
}

fn check(body: &[u8]) -> [u8; 4] {
    let h = blake3::hash(body);
    let mut c = [0u8; 4];
    c.copy_from_slice(&h.as_bytes()[..4]);
    c
}

/// A new, empty log file.
pub fn new_log() -> Vec<u8> {
    LOG_MAGIC.to_vec()
}

/// Log records for `entries`, to append to a log file.
pub fn log_records<'a>(entries: impl IntoIterator<Item = &'a Entry>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut body = Vec::new();
    for e in entries {
        body.clear();
        encode_entry(e, &mut body);
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&check(&body));
    }
    out
}

/// What [`parse_log`] found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedLog {
    pub entries: Vec<Entry>,
    /// Bytes that form whole, good records (with the magic): cut the file here if it is longer.
    pub good_len: usize,
    /// The file went on after the good part (torn or damaged).
    pub damaged: bool,
}

/// Reads a log file. `None` if it isn't one (wrong magic); an empty file is an empty log.
pub fn parse_log(bytes: &[u8]) -> Option<ParsedLog> {
    if bytes.is_empty() {
        return Some(ParsedLog::default());
    }
    if bytes.get(..4)? != LOG_MAGIC {
        return None;
    }
    let mut out = ParsedLog { entries: Vec::new(), good_len: 4, damaged: false };
    let mut pos = 4;
    while pos < bytes.len() {
        let record = (|| {
            let len = u32::from_le_bytes(bytes.get(pos..pos + 4)?.try_into().ok()?) as usize;
            if len > MAX_ENTRY {
                return None;
            }
            let body = bytes.get(pos + 4..pos + 4 + len)?;
            let sum = bytes.get(pos + 4 + len..pos + 8 + len)?;
            (sum == check(body)).then_some(())?;
            Some((decode_entry(body)?, 8 + len))
        })();
        match record {
            Some((e, n)) => {
                out.entries.push(e);
                pos += n;
                out.good_len = pos;
            }
            None => {
                out.damaged = true;
                break;
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{Identity, SwarmKey};

    fn entries(n: u64) -> Vec<Entry> {
        let swarm = SwarmKey::from_secret(&[1; 32]).id();
        let me = Identity::from_secret([2; 32]);
        (1..=n).map(|s| Entry::sign(&swarm, &me, s, format!("payload {s}").repeat(s as usize % 7).into_bytes())).collect()
    }

    #[test]
    fn entries_round_trip_and_junk_is_refused() {
        for e in entries(300) {
            let mut b = Vec::new();
            encode_entry(&e, &mut b);
            assert_eq!(decode_entry(&b).as_ref(), Some(&e));
            assert_eq!(decode_entry(&b[..b.len() - 1]), None, "short");
            let mut long = b.clone();
            long.push(0);
            assert_eq!(decode_entry(&long), None, "trailing bytes");
        }
        assert_eq!(decode_entry(&[]), None);
        assert_eq!(decode_entry(&[0xff; 200]), None);
    }

    #[test]
    fn a_log_reads_back_and_a_torn_or_damaged_tail_is_cut() {
        let es = entries(50);
        let mut log = new_log();
        log.extend(log_records(&es));
        let p = parse_log(&log).unwrap_or_default();
        assert_eq!(p.entries, es);
        assert_eq!(p.good_len, log.len());
        assert!(!p.damaged);
        // Torn: the app stopped in the middle of the last record.
        let torn = &log[..log.len() - 3];
        let p = parse_log(torn).unwrap_or_default();
        assert_eq!(p.entries.len(), 49);
        assert!(p.damaged && p.good_len < torn.len());
        // A flipped byte in record 10: records before it survive.
        let mut bad = log.clone();
        let at = 4
            + (0..10)
                .map(|i| {
                    let mut b = Vec::new();
                    encode_entry(&es[i], &mut b);
                    b.len() + 8
                })
                .sum::<usize>()
            + 40;
        bad[at] ^= 0x55;
        let p = parse_log(&bad).unwrap_or_default();
        assert_eq!(p.entries.len(), 10);
        assert!(p.damaged);
        assert_eq!(parse_log(b"{\"a\":1}\n"), None, "not a murmur log");
        assert_eq!(parse_log(&[]), Some(ParsedLog::default()));
    }
}
