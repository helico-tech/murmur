//! How big and how slow do logs get? `cargo run --release -p murmur --example bench --
//! [--entries N] [--payload BYTES] [--authors N]`
//!
//! Makes N signed entries (payloads of about BYTES, from N authors), then measures for the
//! JSON-lines store format the apps used first (hex author, base64 payload and signature) and for
//! the binary log ([`murmur::codec`]): bytes on disk, time to parse, and then the time and memory
//! (resident set) to restore a `Swarm` and read everything back with `since`.

use std::time::Instant;

use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use murmur::{Config, Entry, Identity, Rng, Swarm, SwarmKey, Vector, codec};

fn arg(name: &str, default: usize) -> usize {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Resident memory of this process in MB (via `ps`; 0 if that fails).
fn rss_mb() -> f64 {
    let out = std::process::Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output();
    out.ok().and_then(|o| String::from_utf8(o.stdout).ok()).and_then(|s| s.trim().parse::<f64>().ok()).map_or(0.0, |kb| kb / 1024.0)
}

fn json_line(e: &Entry) -> String {
    serde_json::json!({ "a": HEXLOWER.encode(&e.author.0), "q": e.seq, "p": BASE64URL_NOPAD.encode(&e.payload), "s": BASE64URL_NOPAD.encode(&e.sig) })
        .to_string()
}

fn main() {
    let n = arg("--entries", 100_000);
    let payload = arg("--payload", 200);
    let authors = arg("--authors", 20).max(1);
    let key = SwarmKey::from_secret(&[7; 32]);
    let ids: Vec<Identity> = (0..authors).map(|i| Identity::from_secret([i as u8 + 1; 32])).collect();
    let mut rng = Rng::new(1);
    let mut seqs = vec![0u64; authors];
    let t = Instant::now();
    let entries: Vec<Entry> = (0..n)
        .map(|_| {
            let a = (rng.next_u64() % authors as u64) as usize;
            seqs[a] += 1;
            let len = payload / 2 + (rng.next_u64() % payload.max(1) as u64) as usize;
            let body: Vec<u8> = (0..len).map(|i| b"abcdefghijklmnopqrstuvwxyz \"{}:,0123456789"[(i * 7 + a) % 42]).collect();
            Entry::sign(&key.id(), &ids[a], seqs[a], body)
        })
        .collect();
    println!("{n} entries, payload ~{payload} B, {authors} authors (made and signed in {:.1} s)", t.elapsed().as_secs_f64());

    // On disk.
    let json: String = entries.iter().map(|e| json_line(e) + "\n").collect();
    let mut log = codec::new_log();
    log.extend(codec::log_records(&entries));
    let payload_bytes: usize = entries.iter().map(|e| e.payload.len()).sum();
    println!("\non disk               total MB   bytes/entry   overhead/entry");
    for (name, size) in [("JSON lines", json.len()), ("binary log", log.len())] {
        println!("{name:<20} {:>9.1} {:>13.0} {:>16.0}", size as f64 / 1e6, size as f64 / n as f64, (size - payload_bytes) as f64 / n as f64);
    }

    let payload_mb = payload_bytes as f64 / 1e6;
    drop(entries);
    let base = rss_mb();
    // Parse.
    let t = Instant::now();
    let parsed_json: usize = json.lines().filter(|l| serde_json::from_str::<serde_json::Value>(l).is_ok()).count();
    let json_ms = t.elapsed().as_secs_f64() * 1e3;
    let t = Instant::now();
    let parsed = codec::parse_log(&log).map(|p| p.entries).unwrap_or_default();
    let log_ms = t.elapsed().as_secs_f64() * 1e3;
    println!("\nparse                 ms");
    println!("JSON lines           {json_ms:>8.0}  ({parsed_json} lines)");
    println!("binary log           {log_ms:>8.0}  ({} entries)", parsed.len());
    drop(json);
    drop(log);

    // Restore and read back.
    let t = Instant::now();
    let mut swarm = Swarm::new(key.clone(), Identity::from_secret([99; 32]), Config::default(), 1);
    let r = swarm.restore(parsed, false);
    let restore_ms = t.elapsed().as_secs_f64() * 1e3;
    let t = Instant::now();
    let all = swarm.since(&Vector::new(), usize::MAX);
    let since_ms = t.elapsed().as_secs_f64() * 1e3;
    drop(all);
    let after = rss_mb();
    println!("\nrestore {} entries in {restore_ms:.0} ms ({} rejected); since() in {since_ms:.0} ms", swarm.len(), r.rejected);
    println!(
        "memory of the restored swarm: {:.0} MB resident ({:.0} B/entry; payloads alone {payload_mb:.0} MB)",
        after - base,
        (after - base) * 1e6 / n as f64
    );
}
