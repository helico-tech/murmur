//! A log file a swarm can read back from (native only): see [`FileStorage`].

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

use crate::codec::{self, LOG_MAGIC, MAX_ENTRY};
use crate::entry::Entry;
use crate::id::PeerId;
use crate::storage::Storage;
use crate::vector::Vector;

/// Keeps a swarm's entries in one append-only log file (the [`codec`] format) and reads them
/// back, so the swarm can keep only recent entries in memory (see [`Storage::can_read`]).
///
/// [`FileStorage::open`] scans the file once and builds an index author/seq → file offset and
/// length (8 bytes of memory per entry), so a read is one positioned read. A torn or damaged tail is cut off there; peers send what was
/// lost. An entry that doesn't continue its author's log (a gap) is kept in the file but not
/// indexed, so reads and [`Storage::heads`] always see unbroken logs. Appends are not synced
/// to disk one by one: a crash of the machine (not of the app) can lose the newest entries,
/// which peers send again.
///
/// ```no_run
/// # fn main() -> Result<(), String> {
/// # let (key, me) = (murmur::SwarmKey::from_secret(&[1; 32]), murmur::Identity::from_secret([2; 32]));
/// let mut swarm = murmur::Swarm::new(key, me, murmur::Config::default(), 7);
/// let file = murmur::file::FileStorage::open("team.log").map_err(|e| e.to_string())?;
/// swarm.set_storage(Box::new(file));
/// swarm.load()?;
/// swarm.replay(&murmur::Vector::new(), |e| { /* fold e into the app's state */ })?;
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct FileStorage {
    file: File,
    /// Length of the good part of the file; appends go here.
    len: u64,
    /// Per author, where the record of seq 1, 2, 3… is (see [`pack`]).
    index: HashMap<PeerId, Vec<u64>>,
    repaired: bool,
}

impl FileStorage {
    /// Opens (or creates) a log file, indexes it and cuts off a torn or damaged tail. Fails if
    /// the file isn't a murmur log.
    pub fn open(path: impl AsRef<Path>) -> io::Result<FileStorage> {
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        let size = file.metadata()?.len();
        let mut s = FileStorage { file, len: 0, index: HashMap::new(), repaired: false };
        if size == 0 {
            s.file.write_all(LOG_MAGIC)?;
            s.len = LOG_MAGIC.len() as u64;
            return Ok(s);
        }
        let mut magic = [0u8; 4];
        s.file.seek(SeekFrom::Start(0))?;
        if s.file.read_exact(&mut magic).is_err() || &magic != LOG_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not a murmur log file"));
        }
        let mut pos = LOG_MAGIC.len() as u64;
        {
            let mut r = BufReader::with_capacity(1 << 20, &s.file);
            let mut body = Vec::new();
            loop {
                let mut head = [0u8; 4];
                if r.read_exact(&mut head).is_err() {
                    break;
                }
                let len = u32::from_le_bytes(head) as usize;
                if len > MAX_ENTRY {
                    break;
                }
                body.resize(len + 4, 0);
                if r.read_exact(&mut body).is_err() {
                    break;
                }
                let (entry, sum) = body.split_at(len);
                if sum != codec::check(entry) {
                    break;
                }
                let Some((author, seq, _, _)) = codec::decode_parts(entry) else { break };
                index_record(&mut s.index, author, seq, pos, len);
                pos += 8 + len as u64;
            }
        }
        if pos < size {
            s.file.set_len(pos)?;
            s.repaired = true;
        }
        s.len = pos;
        Ok(s)
    }

    /// Whether [`FileStorage::open`] cut off a torn or damaged tail.
    pub fn repaired(&self) -> bool {
        self.repaired
    }

    /// Number of indexed entries.
    pub fn len(&self) -> u64 {
        self.index.values().map(|v| v.len() as u64).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    fn head(&self, author: &PeerId) -> u64 {
        self.index.get(author).map_or(0, |v| v.len() as u64)
    }

    /// Reads the record indexed as `packed`: one positioned read of its body and check.
    fn read_record(&self, packed: u64) -> Result<Entry, String> {
        let (at, len) = unpack(packed);
        let mut body = vec![0u8; len + 4];
        self.read_at(at + 4, &mut body).map_err(|e| format!("log file read at {at}: {e}"))?;
        let (entry, sum) = body.split_at(len);
        if sum != codec::check(entry) {
            return Err(format!("log file damaged at {at}"));
        }
        codec::decode_entry(entry).ok_or_else(|| format!("log file damaged at {at}"))
    }

    #[cfg(unix)]
    fn read_at(&self, at: u64, buf: &mut [u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        self.file.read_exact_at(buf, at)
    }

    #[cfg(not(unix))]
    fn read_at(&self, at: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut f = &self.file;
        f.seek(SeekFrom::Start(at))?;
        f.read_exact(buf)
    }
}

/// Bits for a record's body length in an index slot (an entry is at most `MAX_ENTRY` < 2^17
/// bytes); the file offset gets the other 47 (128 TiB).
const LEN_BITS: u32 = 17;

/// A record's offset and body length in one index slot.
fn pack(at: u64, len: usize) -> u64 {
    at << LEN_BITS | len as u64
}

fn unpack(packed: u64) -> (u64, usize) {
    (packed >> LEN_BITS, (packed & ((1 << LEN_BITS) - 1)) as usize)
}

/// Indexes a record if it continues its author's log.
fn index_record(index: &mut HashMap<PeerId, Vec<u64>>, author: PeerId, seq: u64, at: u64, len: usize) {
    let have = index.get(&author).map_or(0, |v| v.len() as u64);
    if seq == have + 1 {
        index.entry(author).or_default().push(pack(at, len));
    }
}

impl Storage for FileStorage {
    fn append(&mut self, entries: &[Arc<Entry>]) -> Result<(), String> {
        let mut out = Vec::new();
        let mut body = Vec::new();
        let mut added: Vec<(PeerId, u64, u64, usize)> = Vec::new();
        let mut heads: HashMap<PeerId, u64> = HashMap::new();
        for e in entries {
            let head = *heads.entry(e.author).or_insert_with(|| self.head(&e.author));
            if e.seq <= head {
                continue; // Already stored.
            }
            if e.seq == head + 1 {
                heads.insert(e.author, e.seq);
            }
            body.clear();
            codec::encode_entry(e, &mut body);
            added.push((e.author, e.seq, self.len + out.len() as u64, body.len()));
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&body);
            out.extend_from_slice(&codec::check(&body));
        }
        if out.is_empty() {
            return Ok(());
        }
        if self.len + out.len() as u64 >= 1 << (64 - LEN_BITS) {
            return Err("log file full".into());
        }
        let written = self.file.seek(SeekFrom::Start(self.len)).and_then(|_| self.file.write_all(&out));
        if let Err(e) = written {
            // Don't leave half a record for the next append to follow.
            let _ = self.file.set_len(self.len);
            return Err(format!("log file write: {e}"));
        }
        self.len += out.len() as u64;
        for (author, seq, at, len) in added {
            index_record(&mut self.index, author, seq, at, len);
        }
        Ok(())
    }

    fn can_read(&self) -> bool {
        true
    }

    fn heads(&self) -> Result<Vector, String> {
        Ok(self.index.iter().map(|(a, v)| (*a, v.len() as u64)).collect())
    }

    fn read(&self, author: &PeerId, from: u64, max: usize) -> Result<Vec<Entry>, String> {
        let Some(offsets) = self.index.get(author) else { return Ok(Vec::new()) };
        let Ok(start) = usize::try_from(from.max(1) - 1) else { return Ok(Vec::new()) };
        let Some(offsets) = offsets.get(start..) else { return Ok(Vec::new()) };
        let mut out = Vec::with_capacity(max.min(offsets.len()).min(1024));
        for (i, packed) in offsets.iter().take(max).enumerate() {
            let e = self.read_record(*packed)?;
            if e.author != *author || e.seq != from.max(1) + i as u64 {
                return Err(format!("log file index is off at {}", unpack(*packed).0));
            }
            out.push(e);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{Identity, SwarmId};

    fn entry(who: u8, seq: u64, len: usize) -> Arc<Entry> {
        Arc::new(Entry::sign(&SwarmId([0; 32]), &Identity::from_secret([who; 32]), seq, vec![seq as u8; len]))
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("murmur-file-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join(name);
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn appends_read_back_and_survive_a_reopen() {
        let path = temp("reopen.log");
        let mut f = FileStorage::open(&path).unwrap();
        assert!(f.is_empty() && f.can_read());
        let a: Vec<Arc<Entry>> = (1..=50).map(|s| entry(1, s, s as usize * 10)).collect();
        let b: Vec<Arc<Entry>> = (1..=20).map(|s| entry(2, s, 3)).collect();
        f.append(&a[..30]).unwrap();
        f.append(&b).unwrap();
        f.append(&a[25..]).unwrap(); // Overlaps: the stored ones are skipped.
        let check = |f: &FileStorage| {
            assert_eq!(f.len(), 70);
            let heads = f.heads().unwrap();
            assert_eq!((heads.get(&a[0].author), heads.get(&b[0].author)), (50, 20));
            let got = f.read(&a[0].author, 1, usize::MAX).unwrap();
            assert_eq!(got, a.iter().map(|e| (**e).clone()).collect::<Vec<_>>());
            assert_eq!(f.read(&a[0].author, 48, 10).unwrap().len(), 3);
            assert_eq!(f.read(&b[0].author, 5, 2).unwrap(), vec![(*b[4]).clone(), (*b[5]).clone()]);
            assert!(f.read(&b[0].author, 21, 5).unwrap().is_empty());
            assert!(f.read(&PeerId([9; 32]), 1, 5).unwrap().is_empty());
        };
        check(&f);
        drop(f);
        let f = FileStorage::open(&path).unwrap();
        assert!(!f.repaired());
        check(&f);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_torn_tail_is_cut_at_open_and_appends_continue() {
        let path = temp("torn.log");
        let mut f = FileStorage::open(&path).unwrap();
        let a: Vec<Arc<Entry>> = (1..=10).map(|s| entry(1, s, 100)).collect();
        f.append(&a).unwrap();
        drop(f);
        let full = std::fs::metadata(&path).unwrap().len();
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(full - 7).unwrap();
        drop(file);
        let mut f = FileStorage::open(&path).unwrap();
        assert!(f.repaired());
        assert_eq!(f.heads().unwrap().get(&a[0].author), 9);
        f.append(&a[9..]).unwrap();
        f.append(&[entry(1, 11, 5)]).unwrap();
        drop(f);
        let f = FileStorage::open(&path).unwrap();
        assert!(!f.repaired());
        assert_eq!(f.read(&a[0].author, 1, 100).unwrap().len(), 11);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn gaps_are_kept_but_not_indexed_and_junk_is_refused() {
        let path = temp("gap.log");
        let mut f = FileStorage::open(&path).unwrap();
        f.append(&[entry(1, 1, 5), entry(1, 3, 5)]).unwrap();
        assert_eq!(f.heads().unwrap().get(&entry(1, 1, 0).author), 1);
        f.append(&[entry(1, 2, 5), entry(1, 3, 5)]).unwrap();
        assert_eq!(f.read(&entry(1, 1, 0).author, 1, 9).unwrap().len(), 3);
        drop(f);
        let f = FileStorage::open(&path).unwrap();
        assert_eq!(f.len(), 3);
        drop(f);
        let junk = temp("junk.log");
        std::fs::write(&junk, b"{\"not\":\"a log\"}").unwrap();
        assert!(FileStorage::open(&junk).is_err());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&junk);
    }
}
