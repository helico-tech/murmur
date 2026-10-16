//! Swarms on `FileStorage`: a small window in memory, old entries read from the file, restarts
//! with `load`, and a torn file healed by a peer.
#![cfg(not(target_family = "wasm"))]

use std::path::PathBuf;

use murmur::file::FileStorage;
use murmur::{Action, Config, Event, Identity, Storage, Swarm, SwarmKey, Vector, wire};

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("murmur-file-swarm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let p = dir.join(name);
    let _ = std::fs::remove_file(&p);
    p
}

fn cfg() -> Config {
    Config { presence_interval: None, ram_window: 0, ..Config::default() }
}

fn swarm(n: u8) -> Swarm {
    Swarm::new(SwarmKey::from_secret(&[42; 32]), Identity::from_secret([n; 32]), cfg(), n as u64)
}

fn on_file(n: u8, path: &PathBuf) -> Swarm {
    let mut s = swarm(n);
    s.set_storage(Box::new(FileStorage::open(path).expect("open")));
    s.load().expect("load");
    s
}

/// Connects two swarms and delivers messages until both are quiet.
fn sync(a: &mut Swarm, b: &mut Swarm) {
    let now = 1_000;
    a.on_connected(1, b.id(), true, now);
    b.on_connected(2, a.id(), false, now);
    for _ in 0..100_000 {
        let mut moved = false;
        while let Some(act) = a.poll_action() {
            moved = true;
            if let Action::Send { conn: 1, msg } = act {
                b.on_bytes(2, &wire::encode(&msg), now);
            }
        }
        while let Some(act) = b.poll_action() {
            moved = true;
            if let Action::Send { conn: 2, msg } = act {
                a.on_bytes(1, &wire::encode(&msg), now);
            }
        }
        if !moved {
            break;
        }
    }
    a.on_disconnected(1, now);
    b.on_disconnected(2, now);
}

fn no_failures(s: &mut Swarm) {
    while let Some(e) = s.poll_event() {
        assert!(!matches!(e, Event::StorageFailed(_) | Event::Conflict { .. } | Event::Misbehaved { .. }), "{e:?}");
    }
}

#[test]
fn a_file_backed_swarm_keeps_a_window_and_reads_the_rest_back() {
    let path = temp("window.log");
    let mut a = on_file(1, &path);
    a.assume_fresh();
    let mut published = Vec::new();
    for i in 0..1_000 {
        published.push(a.publish(format!("entry {i} {}", "x".repeat(i % 120)).into_bytes(), 0).expect("publish"));
    }
    assert!(a.ram_bytes() < 2 * 32 * 1024, "window plus a chunk: {}", a.ram_bytes());
    // Reads across the window boundary.
    let all = a.try_since(&Vector::new(), usize::MAX).expect("since");
    assert_eq!(all, published);
    assert_eq!(a.since(&Vector::new(), 3), published[..3].to_vec());
    assert_eq!(a.get(&a.id(), 1), Some(published[0].clone()));
    let mid: Vector = [(a.id(), 400)].into_iter().collect();
    assert_eq!(a.since(&mid, 5), published[400..405].to_vec());

    // Restart: load reads nothing, replay walks everything from the file.
    drop(a);
    let mut a = on_file(1, &path);
    assert_eq!((a.len(), a.ram_bytes()), (1_000, 0));
    let mut seen = Vec::new();
    assert_eq!(a.replay(&Vector::new(), |e| seen.push(e.clone())), Ok(1_000));
    assert_eq!(seen, published.iter().map(|e| (**e).clone()).collect::<Vec<_>>());
    let e = a.publish(b"after restart".to_vec(), 0).expect("publish");
    assert_eq!(e.seq, 1_001);

    // A peer with nothing gets the whole log; every old entry comes from the file.
    let mut b = swarm(2);
    sync(&mut a, &mut b);
    assert_eq!(b.len(), 1_001);
    assert_eq!(b.since(&Vector::new(), usize::MAX), a.since(&Vector::new(), usize::MAX));
    no_failures(&mut a);
    no_failures(&mut b);

    // The app stopped mid-write: the torn record is cut at open, and the peer sends it again.
    drop(a);
    let len = std::fs::metadata(&path).expect("meta").len();
    std::fs::OpenOptions::new().write(true).open(&path).expect("open").set_len(len - 5).expect("cut");
    let file = FileStorage::open(&path).expect("open");
    assert!(file.repaired());
    assert_eq!(file.heads().expect("heads").get(&b.since(&Vector::new(), 1)[0].author), 1_000);
    drop(file);
    let mut a = on_file(1, &path);
    assert_eq!(a.len(), 1_000);
    sync(&mut a, &mut b);
    assert_eq!(a.len(), 1_001);
    assert_eq!(a.publish(b"healed".to_vec(), 0).expect("publish").seq, 1_002);
    no_failures(&mut a);
    drop(a);
    assert_eq!(FileStorage::open(&path).expect("open").len(), 1_002);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn load_refuses_without_a_reading_storage_and_restore_keeps_everything() {
    let mut s = swarm(3);
    assert!(s.load().is_err(), "no storage");
    s.set_storage(Box::new(murmur::sim::MemStorage::default()));
    assert!(s.load().is_err(), "can't read");
    // A storage that can't read: restore keeps every entry in memory, as before.
    let mut src = swarm(4);
    src.assume_fresh();
    for i in 0..500 {
        src.publish(vec![i as u8; 100], 0).expect("publish");
    }
    let entries: Vec<_> = src.since(&Vector::new(), usize::MAX).into_iter().map(|e| (*e).clone()).collect();
    s.restore(entries, false);
    assert_eq!(s.ram_bytes(), 500 * (100 + 64));
    // With a reading storage, restored entries still stay: the storage never confirmed them.
    let path = temp("restore.log");
    let mut t = swarm(5);
    t.set_storage(Box::new(FileStorage::open(&path).expect("open")));
    t.restore(src.since(&Vector::new(), usize::MAX).into_iter().map(|e| (*e).clone()), false);
    assert_eq!(t.ram_bytes(), 500 * (100 + 64));
    assert!(t.load().is_err(), "load needs an empty swarm");
    let _ = std::fs::remove_file(&path);
}
