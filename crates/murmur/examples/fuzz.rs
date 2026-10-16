//! Long-running fuzzer for murmur, on the deterministic simulator.
//!
//! ```sh
//! cargo run --release -p murmur --features sim --example fuzz -- --minutes 60
//! cargo run --release -p murmur --features sim --example fuzz -- --seed 1234     # replay one
//! cargo run --release -p murmur --features sim --example fuzz -- --soak --minutes 600
//! ```
//!
//! **Scenario mode** (default): random scenarios, one per seed. Each picks a swarm size, config and
//! network (latency, bandwidth, slow peers, stalls, clock skew, NAT, failing dials, breaking
//! links, small send queues) and some dishonest peers, then runs a random storm of publishes
//! (small and large), app flashes, flaps, offline periods, restarts, partitions and newcomers.
//! While it runs, safety is checked (identical, correctly signed data everywhere; storage keeps
//! up; degrees and buffers bounded; honest peers never accuse each other). Then the storm stops
//! and liveness is checked: every honest online peer must converge, and see the others online.
//!
//! **Soak mode** (`--soak`): one swarm forever, in cycles of storm and calm, with members joining
//! and leaving; every calm must converge.
//!
//! Failures print a replay command and are appended to `target/murmur-fuzz-failures.txt`.

use std::io::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use murmur::sim::{Net, Sim};
use murmur::{Config, Event, PublishError, Rng};

struct Args {
    minutes: f64,
    seed: Option<u64>,
    start: u64,
    soak: bool,
    max_nodes: u64,
    stop: bool,
}

fn args() -> Args {
    let mut a = Args { minutes: 10.0, seed: None, start: 0, soak: false, max_nodes: 40, stop: false };
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < v.len() {
        let next = v.get(i + 1).cloned().unwrap_or_default();
        match v[i].as_str() {
            "--minutes" => a.minutes = next.parse().unwrap_or(a.minutes),
            "--seed" => a.seed = next.parse().ok(),
            "--start" => a.start = next.parse().unwrap_or(0),
            "--max-nodes" => a.max_nodes = next.parse().unwrap_or(a.max_nodes),
            "--soak" => {
                a.soak = true;
                i += 1;
                continue;
            }
            "--stop" => {
                a.stop = true;
                i += 1;
                continue;
            }
            other => {
                eprintln!("unknown argument {other}");
                std::process::exit(2);
            }
        }
        i += 2;
    }
    a
}

/// What one scenario looked like, for reports.
#[derive(Clone, Debug, Default)]
#[allow(dead_code)] // printed with Debug
struct Outcome {
    nodes: usize,
    entries: u64,
    converge_ms: u64,
    dup_ratio: f64,
    slow_closes: u64,
    messages: u64,
}

fn main() {
    let a = args();
    std::panic::set_hook(Box::new(|_| {}));
    if a.soak {
        soak(&a);
        return;
    }
    if let Some(seed) = a.seed {
        match catch_unwind(AssertUnwindSafe(|| scenario(seed, a.max_nodes, true))) {
            Ok(Ok(o)) => println!("seed {seed}: ok {o:?}"),
            Ok(Err(e)) => println!("seed {seed}: FAIL {e}"),
            Err(p) => println!("seed {seed}: PANIC {}", panic_text(&p)),
        }
        return;
    }
    let started = Instant::now();
    let budget = a.minutes * 60.0;
    let mut seed = a.start;
    let (mut runs, mut fails) = (0u64, 0u64);
    let mut converge: Vec<u64> = Vec::new();
    let mut dup = 0.0;
    let mut slow = 0u64;
    let mut last_report = Instant::now();
    println!("murmur fuzz: scenarios from seed {seed} for {} min (max {} nodes)", a.minutes, a.max_nodes);
    while started.elapsed().as_secs_f64() < budget {
        let r = catch_unwind(AssertUnwindSafe(|| scenario(seed, a.max_nodes, false)));
        runs += 1;
        match r {
            Ok(Ok(o)) => {
                converge.push(o.converge_ms);
                dup += o.dup_ratio;
                slow += o.slow_closes;
            }
            Ok(Err(e)) => {
                fails += 1;
                fail(seed, &e);
            }
            Err(p) => {
                fails += 1;
                fail(seed, &format!("panic: {}", panic_text(&p)));
            }
        }
        if fails > 0 && a.stop {
            break;
        }
        if last_report.elapsed().as_secs() >= 10 {
            report(runs, fails, &mut converge.clone(), dup, slow, started);
            last_report = Instant::now();
        }
        seed += 1;
    }
    report(runs, fails, &mut converge, dup, slow, started);
    println!("next unexplored seed: {seed}");
    if fails > 0 {
        std::process::exit(1);
    }
}

fn report(runs: u64, fails: u64, converge: &mut [u64], dup: f64, slow: u64, started: Instant) {
    converge.sort_unstable();
    let pct = |p: f64| converge.get(((converge.len() as f64 - 1.0) * p) as usize).copied().unwrap_or(0);
    let ok = converge.len().max(1) as f64;
    println!(
        "[{:>6.0}s] {runs} scenarios, {fails} failed | converge after storm: p50 {} ms, p95 {} ms, max {} ms | duplicates {:.1}% | slow-link closes {slow}",
        started.elapsed().as_secs_f64(),
        pct(0.5),
        pct(0.95),
        pct(1.0),
        100.0 * dup / ok
    );
}

fn fail(seed: u64, why: &str) {
    let line = format!("seed {seed}: {why}\n  replay: cargo run --release -p murmur --features sim --example fuzz -- --seed {seed}");
    println!("FAIL {line}");
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/murmur-fuzz-failures.txt");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{line}");
    }
}

fn panic_text(p: &Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_else(|| "?".into())
}

/// A random network for a scenario.
fn random_net(rng: &mut Rng) -> Net {
    let lo = rng.below(100);
    Net {
        latency: (lo, lo + 1 + rng.below(400)),
        dial_fail: rng.below(30) as f64 / 100.0,
        link_break: rng.below(10) as f64 / 1000.0,
        tick: 50 + rng.below(250),
        detect: 500 + rng.below(10_000),
        bandwidth: (20 + rng.below(2_000), 2_100 + rng.below(30_000)),
        slow: rng.below(40) as f64 / 100.0,
        spike: rng.below(5) as f64 / 100.0,
        spike_ms: 500 + rng.below(8_000),
        // Real transports queue thousands of frames (murmur-iroh: 4096); a small queue still
        // has to fit a catch-up window plus some eager pushes.
        queue_limit: [512usize, 1024, 4096][rng.below(3) as usize],
        skew: rng.below(120_000),
        nat: rng.below(40) as f64 / 100.0,
    }
}

fn random_config(rng: &mut Rng) -> Config {
    let target = 3 + rng.below(6) as usize;
    Config {
        target_degree: target,
        max_degree: target + rng.below(10) as usize,
        ae_interval: 300 + rng.below(5_000),
        presence_interval: Some(2_000 + rng.below(10_000)),
        presence_ttl: 30_000 + rng.below(30_000),
        known_limit: 16 + rng.below(200) as usize,
        catchup_window: 1 << (16 + rng.below(5)),
        probe_window: 1 << (12 + rng.below(5)),
        batch_bytes: 1 << (12 + rng.below(7)),
        eager_gap: rng.below(128),
        ..Config::default()
    }
}

/// Makes sure every NAT'd node knows a node it can dial, and there are at least two such nodes.
fn fix_reachability(sim: &mut Sim) {
    let n = sim.nodes.len();
    let open: Vec<usize> = (0..n).filter(|i| !sim.nodes[*i].profile.nat).collect();
    if open.len() < 2 {
        for i in 0..n.min(2) {
            sim.nodes[i].profile.nat = false;
        }
    }
    let open: Vec<usize> = (0..n).filter(|i| !sim.nodes[*i].profile.nat).collect();
    for i in 0..n {
        let knows_open = sim.nodes[i].bootstrap.iter().any(|p| sim.index(p).is_some_and(|j| !sim.nodes[j].profile.nat));
        if !knows_open && let Some(&j) = open.iter().find(|&&j| j != i) {
            sim.introduce(i, j);
        }
    }
}

/// Safety checks that must hold at every moment.
fn check_safety(sim: &Sim, deep: bool) -> Result<(), String> {
    for (i, n) in sim.nodes.iter().enumerate() {
        let active = n.swarm.neighbors().len();
        let max = n.swarm.config().max_degree;
        if active > max + 2 {
            return Err(format!("node {i} has {active} links (max {max})"));
        }
        if n.swarm.waiting() > 8192 {
            return Err(format!("node {i} buffers {} entries", n.swarm.waiting()));
        }
        if n.profile.evil {
            continue;
        }
        for e in &n.events {
            match e {
                Event::Misbehaved { peer, reason } if !sim.index(peer).is_some_and(|j| sim.is_evil(j)) => {
                    return Err(format!("honest node {i} accused honest peer {:?}: {reason}", sim.index(peer)));
                }
                Event::Conflict { author, seq } => return Err(format!("node {i} saw a conflict at {}:{seq}", author.short())),
                Event::StorageFailed(e) => return Err(format!("node {i} storage failed: {e}")),
                _ => {}
            }
        }
    }
    if deep {
        sim.check_integrity()?;
    }
    Ok(())
}

fn scenario(seed: u64, max_nodes: u64, verbose: bool) -> Result<Outcome, String> {
    let mut rng = Rng::new(seed.wrapping_mul(0x9E37_79B9).wrapping_add(17));
    let n = 2 + rng.below(max_nodes.max(3) - 1) as usize;
    let cfg = random_config(&mut rng);
    let net = random_net(&mut rng);
    if verbose {
        println!("n {n}\n{cfg:?}\n{net:?}");
    }
    let mut sim = Sim::new(n, cfg, net, seed);
    match rng.below(3) {
        0 => sim.bootstrap_star(),
        1 => sim.bootstrap_ring(),
        _ => {
            for i in 1..n {
                let j = rng.below(i as u64) as usize;
                sim.introduce(i, j);
            }
        }
    }
    let evil_count = if n >= 5 { rng.below(n as u64 / 5 + 1) as usize } else { 0 };
    for _ in 0..evil_count {
        let i = 1 + rng.below(n as u64 - 1) as usize;
        sim.make_evil(i);
    }
    fix_reachability(&mut sim);
    let steps = 100 + rng.below(500);
    for step in 0..steps {
        let count = sim.nodes.len();
        let i = rng.below(count as u64) as usize;
        match rng.below(100) {
            0..=49 => {
                if sim.nodes[i].online {
                    let size = if rng.below(20) == 0 { rng.below(60_000) } else { rng.below(300) } as usize;
                    let payload = vec![(step % 251) as u8; size];
                    match sim.publish(i, &payload) {
                        Ok(_) | Err(PublishError::NotSynced) | Err(PublishError::Behind { .. }) => {}
                        Err(e) => return Err(format!("publish failed: {e}")),
                    }
                }
            }
            50..=54 => {
                // A burst from one node.
                for k in 0..rng.below(200) {
                    let _ = sim.publish(i, format!("burst {step} {k}").as_bytes());
                }
            }
            55..=59 => sim.flash(i, b"typing"),
            60..=67 => sim.flap(i, rng.below(20_000)),
            68..=74 => {
                let online = sim.nodes[i].online;
                sim.set_online(i, !online);
            }
            75..=79 => sim.restart(i),
            80..=83 => {
                let parts = 2 + rng.below(3) as u32;
                let groups: Vec<u32> = (0..count).map(|_| rng.below(parts as u64) as u32).collect();
                sim.partition(&groups);
            }
            84..=88 => sim.heal(),
            89..=90 if count < (max_nodes as usize) * 2 => {
                // A newcomer, invited by a random member.
                let j = sim.add_node();
                let inviter = rng.below(j as u64) as usize;
                sim.introduce(j, inviter);
                fix_reachability(&mut sim);
            }
            _ => {}
        }
        sim.run_for(rng.below(2_000));
        check_safety(&sim, step % 50 == 0).map_err(|e| format!("during storm (step {step}): {e}"))?;
    }
    // Calm: everything heals, comes online, and stops breaking.
    sim.heal();
    for i in 0..sim.nodes.len() {
        sim.set_online(i, true);
    }
    sim.net.link_break = 0.0;
    sim.net.dial_fail = 0.0;
    let entries = sim.union().total();
    let messages = sim.messages;
    let limit = 600_000;
    let took = sim.run_until(limit, |s| s.converged());
    check_safety(&sim, true).map_err(|e| format!("after storm: {e}"))?;
    let Some(took) = took else {
        let union = sim.union();
        let behind: Vec<String> = sim
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, x)| !x.profile.evil && x.swarm.vector() != &union)
            .take(8)
            .map(|(i, x)| format!("{i}:{}/{} links {}", x.swarm.len(), union.total(), x.swarm.neighbors().len()))
            .collect();
        if verbose {
            dump(&sim);
            let union = sim.union();
            if let Some(lag) = (0..sim.nodes.len()).find(|&i| !sim.is_evil(i) && sim.nodes[i].swarm.vector() != &union) {
                println!("--- tracing node {lag} for 10 s");
                sim.trace = Some(lag);
                sim.run_for(10_000);
                sim.trace = None;
            }
        }
        return Err(format!("no convergence {} s after the storm ({} components): {behind:?}", limit / 1000, sim.components()));
    };
    // Presence: once calm, every honest peer sees every other honest peer online.
    let wait = sim.cfg.presence_interval.unwrap_or(0) * 3 + 5_000;
    sim.run_for(wait);
    let honest: Vec<usize> = (0..sim.nodes.len()).filter(|i| !sim.is_evil(*i)).collect();
    for &i in &honest {
        let online = sim.nodes[i].swarm.online(sim.clock(i));
        let missing = honest.iter().filter(|&&j| j != i && !online.contains(&sim.id(j))).count();
        if missing > 0 {
            return Err(format!("presence: node {i} doesn't see {missing} honest peers online after {wait} ms of calm"));
        }
    }
    let received: u64 = sim.nodes.iter().map(|x| x.swarm.stats().entries_received).sum();
    let dups: u64 = sim.nodes.iter().map(|x| x.swarm.stats().duplicates_received).sum();
    Ok(Outcome {
        nodes: sim.nodes.len(),
        entries,
        converge_ms: took,
        dup_ratio: if received == 0 { 0.0 } else { dups as f64 / received as f64 },
        slow_closes: sim.slow_closes,
        messages: sim.messages - messages,
    })
}

/// Prints the overlay and every lagging node's view of its peers (for `--seed` replays).
fn dump(sim: &Sim) {
    let union = sim.union();
    let n = sim.nodes.len();
    let now = sim.now;
    for i in 0..n {
        let x = &sim.nodes[i];
        let nb: Vec<usize> = x.swarm.neighbors().iter().filter_map(|p| sim.index(p)).collect();
        let lag = x.swarm.vector() != &union;
        println!(
            "node {i}{}{}{}: {} entries, links {nb:?}, known {}",
            if lag { " LAG" } else { "" },
            if x.profile.nat { " nat" } else { "" },
            if x.profile.evil { " evil" } else { "" },
            x.swarm.len(),
            x.swarm.known_peers().len()
        );
        if lag {
            for line in x.swarm.link_report(sim.clock(i)) {
                println!("  {line}");
            }
            println!(
                "  waiting {}, upload backlog {} ms, profile {:?}, stats {:?}",
                x.swarm.waiting(),
                sim.uplink_backlog(i),
                x.profile,
                x.swarm.stats()
            );
            for (a, s) in union.iter() {
                let have = x.swarm.vector().get(a);
                if have < *s {
                    print!("  lacks {}:{}..{}", sim.index(a).map(|j| j.to_string()).unwrap_or_default(), have + 1, s);
                    for p in x.swarm.neighbors() {
                        if let Some(j) = sim.index(&p) {
                            for (_, _, known) in sim.nodes[j].swarm.link_view_of(&x.swarm.id()) {
                                let k = known.iter().find(|(q, _)| q == a).map(|(_, s)| *s).unwrap_or(0);
                                print!(" [n{j} thinks {k}]");
                            }
                        }
                    }
                    println!();
                }
            }
            for j in 0..n {
                if let Some((f, t, b, d)) = x.swarm.peer_state(&sim.id(j)) {
                    print!("  {j}:f{f} t{} b{} d{} a{}", t as i64 - now as i64, (b > now) as u8, d as u8, x.swarm.is_allowed(&sim.id(j)) as u8);
                }
            }
            println!();
        }
    }
}

/// One swarm that never ends: storm, calm (must converge), repeat; members come and go.
fn soak(a: &Args) {
    let seed = a.seed.unwrap_or(1);
    let mut rng = Rng::new(seed);
    let cfg = Config::default();
    let net = Net { latency: (10, 200), dial_fail: 0.1, link_break: 0.002, slow: 0.2, spike: 0.02, skew: 60_000, nat: 0.2, ..Net::default() };
    let n = a.max_nodes.max(3) as usize;
    let mut sim = Sim::new(n, cfg, net.clone(), seed);
    sim.bootstrap_star();
    fix_reachability(&mut sim);
    let started = Instant::now();
    let mut cycle = 0u64;
    println!("murmur soak: seed {seed}, {n} nodes, {} min", a.minutes);
    while started.elapsed().as_secs_f64() < a.minutes * 60.0 {
        cycle += 1;
        sim.net = net.clone();
        for _ in 0..300 {
            let count = sim.nodes.len();
            let i = rng.below(count as u64) as usize;
            match rng.below(100) {
                0..=59 => {
                    let _ = sim.publish(i, format!("cycle {cycle}").as_bytes());
                }
                60..=69 => sim.flap(i, rng.below(30_000)),
                70..=74 => sim.restart(i),
                75..=77 => {
                    let groups: Vec<u32> = (0..count).map(|_| rng.below(2) as u32).collect();
                    sim.partition(&groups);
                }
                78..=82 => sim.heal(),
                83 => {
                    let j = sim.add_node();
                    let inviter = rng.below(j as u64) as usize;
                    sim.introduce(j, inviter);
                    fix_reachability(&mut sim);
                }
                _ => {}
            }
            sim.run_for(rng.below(3_000));
        }
        if let Err(e) = check_safety(&sim, true) {
            fail(seed, &format!("soak cycle {cycle}: {e}"));
            return;
        }
        sim.heal();
        for i in 0..sim.nodes.len() {
            sim.set_online(i, true);
        }
        sim.net.link_break = 0.0;
        sim.net.dial_fail = 0.0;
        match sim.run_until(600_000, |s| s.converged()) {
            Some(ms) => println!(
                "[{:>6.0}s] cycle {cycle}: {} nodes, {} entries, converged {ms} ms after the storm, virtual time {:.1} h",
                started.elapsed().as_secs_f64(),
                sim.nodes.len(),
                sim.union().total(),
                (sim.now - 1_000_000) as f64 / 3.6e6
            ),
            None => {
                fail(seed, &format!("soak cycle {cycle}: no convergence ({} components)", sim.components()));
                return;
            }
        }
    }
}
