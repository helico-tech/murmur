//! Whole-swarm behaviour in the deterministic simulator: convergence, speed, cost, and faults.

use murmur::sim::{Net, Sim};
use murmur::{Config, Event, PublishError, Rng};

fn cfg() -> Config {
    Config { presence_interval: None, ..Config::default() }
}

/// Publishes from a few nodes so every node has something.
fn seed_entries(sim: &mut Sim, per_node: usize) {
    for i in 0..sim.nodes.len() {
        for k in 0..per_node {
            sim.publish(i, format!("node {i} entry {k}").as_bytes()).expect("publish");
        }
    }
}

fn assert_converged(sim: &mut Sim, max_ms: u64, what: &str) -> u64 {
    let took = sim.run_until(max_ms, |s| s.converged());
    let union = sim.union();
    for (i, n) in sim.nodes.iter().enumerate() {
        if n.online && n.swarm.vector() != &union {
            panic!("{what}: node {i} has {} of {} entries after {max_ms} ms", n.swarm.len(), union.total());
        }
    }
    sim.check_integrity().unwrap_or_else(|e| panic!("{what}: {e}"));
    took.unwrap_or(max_ms)
}

#[test]
fn two_peers_sync_both_ways() {
    let mut sim = Sim::new(2, cfg(), Net::default(), 1);
    sim.introduce(1, 0);
    seed_entries(&mut sim, 3);
    assert_converged(&mut sim, 5_000, "two peers");
    assert_eq!(sim.nodes[0].swarm.len(), 6);
    // Live: a new entry arrives within a few latencies.
    let e = sim.publish(0, b"live").expect("publish");
    let took = sim.run_until(1_000, |s| s.everyone_has(&e.author, e.seq)).expect("delivered");
    assert!(took <= 200, "took {took} ms");
}

#[test]
fn a_star_bootstrap_turns_into_a_bounded_mesh_and_converges() {
    let c = Config { target_degree: 4, max_degree: 8, ..cfg() };
    let mut sim = Sim::new(40, c, Net::default(), 2);
    sim.bootstrap_star();
    seed_entries(&mut sim, 2);
    assert_converged(&mut sim, 30_000, "star");
    sim.run_for(10_000);
    for (i, n) in sim.nodes.iter().enumerate() {
        assert!(n.swarm.link_count() <= 8, "node {i} has {} links", n.swarm.link_count());
    }
    let avg: f64 = sim.nodes.iter().map(|n| n.swarm.link_count() as f64).sum::<f64>() / 40.0;
    assert!(avg >= 4.0, "average degree {avg}");
    // Everyone learned about everyone (peer exchange plus authors).
    assert!(sim.nodes.iter().all(|n| n.swarm.known_peers().len() >= 39));
}

#[test]
fn delivery_is_fast_in_a_big_swarm() {
    let mut sim = Sim::new(120, cfg(), Net { latency: (10, 60), ..Net::default() }, 3);
    sim.bootstrap_ring();
    seed_entries(&mut sim, 1);
    assert_converged(&mut sim, 60_000, "warm-up");
    // Link rotation mixes the ring into a random graph within seconds.
    sim.run_for(30_000);
    let (diameter, avg_path) = sim.overlay_paths();
    assert_eq!(sim.components(), 1);
    assert!(diameter <= 6, "diameter {diameter}");
    assert!(avg_path <= 3.5, "average path {avg_path:.2}");
    let mut rng = Rng::new(3);
    let mut worst = 0;
    let mut total = 0;
    for _ in 0..30 {
        let from = rng.below(120) as usize;
        let msgs = sim.messages;
        let e = sim.publish(from, b"breaking news").expect("publish");
        let took = sim.run_until(5_000, |s| s.everyone_has(&e.author, e.seq)).expect("delivered");
        worst = worst.max(took);
        total += took;
        // Cost: each node forwards to its neighbours at most once (plus background chatter).
        let per_publish = sim.messages - msgs;
        assert!(per_publish < 120 * 14, "{per_publish} messages for one publish");
    }
    // A few hops of at most 60 ms each.
    assert!(worst <= 300, "worst delivery {worst} ms");
    assert!(total / 30 <= 200, "average delivery {} ms", total / 30);
}

#[test]
fn background_traffic_is_small_when_idle() {
    let mut sim = Sim::new(30, cfg(), Net::default(), 4);
    sim.bootstrap_star();
    seed_entries(&mut sim, 5);
    assert_converged(&mut sim, 30_000, "warm-up");
    sim.run_for(10_000);
    let bytes = sim.bytes;
    sim.run_for(60_000);
    let per_node_per_s = (sim.bytes - bytes) as f64 / 30.0 / 60.0;
    // Digests every ~2 s on ~6 links: about 50 bytes each.
    assert!(per_node_per_s < 400.0, "{per_node_per_s:.0} bytes/s per node while idle");
}

#[test]
fn partitions_heal_and_both_sides_merge() {
    let mut sim = Sim::new(20, cfg(), Net::default(), 5);
    sim.bootstrap_star();
    seed_entries(&mut sim, 1);
    assert_converged(&mut sim, 20_000, "warm-up");
    let groups: Vec<u32> = (0..20).map(|i| (i % 2) as u32).collect();
    sim.partition(&groups);
    for round in 0..10 {
        for i in 0..20 {
            sim.publish(i, format!("split {round}").as_bytes()).expect("publish");
        }
        sim.run_for(500);
    }
    sim.run_for(5_000);
    // Each side converged on its own half.
    let evens: Vec<_> = (0..20).step_by(2).map(|i| sim.nodes[i].swarm.vector().clone()).collect();
    assert!(evens.windows(2).all(|w| w[0] == w[1]), "even side converged");
    assert!(!sim.converged());
    sim.heal();
    let took = assert_converged(&mut sim, 120_000, "after heal");
    assert!(took < 60_000, "healing took {took} ms");
}

#[test]
fn a_restarted_node_resumes_from_storage() {
    let mut sim = Sim::new(5, cfg(), Net::default(), 6);
    sim.bootstrap_star();
    seed_entries(&mut sim, 3);
    assert_converged(&mut sim, 10_000, "warm-up");
    sim.restart(3);
    assert_eq!(sim.nodes[3].swarm.len(), 15, "restored from storage");
    let e = sim.publish(3, b"after restart").expect("publish");
    assert_eq!(e.seq, 4);
    assert_converged(&mut sim, 10_000, "after restart");
}

#[test]
fn a_wiped_node_recovers_its_own_log_before_it_may_publish() {
    let mut sim = Sim::new(5, cfg(), Net::default(), 7);
    sim.bootstrap_star();
    seed_entries(&mut sim, 4);
    assert_converged(&mut sim, 10_000, "warm-up");
    sim.wipe(2);
    assert_eq!(sim.publish(2, b"too early"), Err(PublishError::NotSynced));
    assert_converged(&mut sim, 20_000, "recovery");
    let e = sim.publish(2, b"after recovery").expect("publish");
    assert_eq!(e.seq, 5, "continues its old log");
    assert_converged(&mut sim, 10_000, "after");
    for n in &sim.nodes {
        assert!(!n.events.iter().any(|e| matches!(e, Event::Conflict { .. })), "no conflicting entries");
    }
}

#[test]
fn a_node_that_was_offline_catches_up_a_big_backlog_in_windows() {
    let mut sim = Sim::new(3, cfg(), Net::default(), 8);
    sim.bootstrap_star();
    sim.run_for(3_000);
    sim.set_online(2, false);
    let payload = vec![7u8; 200];
    for _ in 0..12_000 {
        sim.publish(0, &payload).expect("publish");
    }
    for _ in 0..3_000 {
        sim.publish(1, &payload).expect("publish");
    }
    assert_converged(&mut sim, 20_000, "online part");
    sim.set_online(2, true);
    let took = assert_converged(&mut sim, 60_000, "backlog");
    let got = sim.nodes[2].swarm.stats().entries_received;
    assert!(got <= 15_000 * 21 / 20, "received {got} for 15000 entries");
    assert!(took < 20_000, "catch-up took {took} ms");
}

#[test]
fn simultaneous_dials_end_with_one_link() {
    for seed in 0..20 {
        let mut sim = Sim::new(2, cfg(), Net::default(), 100 + seed);
        sim.introduce(0, 1);
        sim.introduce(1, 0);
        sim.run_for(10_000);
        assert_eq!(sim.nodes[0].swarm.link_count(), 1, "seed {seed}");
        assert_eq!(sim.nodes[1].swarm.link_count(), 1, "seed {seed}");
        seed_entries(&mut sim, 1);
        assert_converged(&mut sim, 5_000, "two");
    }
}

#[test]
fn a_busy_bootstrap_hands_newcomers_to_others() {
    let c = Config { target_degree: 3, max_degree: 5, ..cfg() };
    let mut sim = Sim::new(25, c, Net::default(), 9);
    sim.bootstrap_star();
    seed_entries(&mut sim, 1);
    assert_converged(&mut sim, 60_000, "busy star");
    assert!(sim.nodes[0].swarm.link_count() <= 6);
}

#[test]
fn presence_spreads_and_expires() {
    let c = Config { target_degree: 3, max_degree: 6, presence_interval: Some(5_000), presence_ttl: 15_000, ..Config::default() };
    let mut sim = Sim::new(15, c, Net::default(), 10);
    sim.bootstrap_ring();
    sim.run_for(30_000);
    let now = sim.now;
    for (i, n) in sim.nodes.iter().enumerate() {
        assert_eq!(n.swarm.online(now).len(), 14, "node {i} sees everyone");
    }
    sim.set_online(7, false);
    let gone = sim.id(7);
    sim.run_for(25_000);
    let now = sim.now;
    for (i, n) in sim.nodes.iter().enumerate().filter(|(i, _)| *i != 7) {
        assert!(!n.swarm.online(now).contains(&gone), "node {i} still sees node 7");
        assert_eq!(n.swarm.online(now).len(), 13);
    }
}

#[test]
fn app_flashes_reach_everyone_once() {
    let c = Config { target_degree: 3, max_degree: 6, ..cfg() };
    let mut sim = Sim::new(20, c, Net::default(), 11);
    sim.bootstrap_star();
    sim.run_for(20_000);
    sim.flash(4, b"typing");
    sim.run_for(3_000);
    for (i, n) in sim.nodes.iter().enumerate().filter(|(i, _)| *i != 4) {
        let got = n.events.iter().filter(|e| matches!(e, Event::Flash { payload, .. } if payload == b"typing")).count();
        assert_eq!(got, 1, "node {i} got the flash {got} times");
    }
}

#[test]
fn same_seed_same_run() {
    let run = |seed| {
        let mut sim = Sim::new(15, cfg(), Net { dial_fail: 0.1, link_break: 0.01, ..Net::default() }, seed);
        sim.bootstrap_star();
        seed_entries(&mut sim, 2);
        sim.run_for(20_000);
        (sim.messages, sim.bytes, sim.nodes.iter().map(|n| n.swarm.vector().digest()).collect::<Vec<_>>())
    };
    assert_eq!(run(77), run(77));
    assert_ne!(run(77).0, run(78).0);
}

/// The big one: random publishes, churn, restarts, wipes, flaky links, failing dials and
/// partitions, for many seeds. After the chaos stops, everyone must converge.
#[test]
fn chaos_always_converges() {
    if let Some(one) = std::env::var("MURMUR_CHAOS_SEED").ok().and_then(|s| s.parse().ok()) {
        return chaos(one);
    }
    let seeds: u64 = std::env::var("MURMUR_CHAOS_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(24);
    for seed in 0..seeds {
        chaos(seed);
    }
}

pub fn chaos(seed: u64) {
    let salt: u64 = std::env::var("MURMUR_CHAOS_SALT").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let seed = seed + salt * 1_000_000;
    let mut rng = Rng::new(seed * 7919);
    let n = 8 + rng.below(25) as usize;
    let c = Config { target_degree: 3 + rng.below(4) as usize, max_degree: 8, presence_interval: Some(3_000), ..Config::default() };
    let net = Net {
        latency: (5, 5 + rng.below(200)),
        dial_fail: 0.15,
        link_break: 0.003,
        tick: 100,
        detect: 1_500,
        slow: 0.2,
        spike: 0.02,
        skew: 30_000,
        ..Net::default()
    };
    let mut sim = Sim::new(n, c, net, seed);
    if rng.below(2) == 0 {
        sim.bootstrap_star();
    } else {
        sim.bootstrap_ring();
    }
    for step in 0..400 {
        let i = rng.below(n as u64) as usize;
        match rng.below(100) {
            0..=59 => {
                if sim.nodes[i].online {
                    let r = sim.publish(i, format!("s{seed} step {step}").as_bytes());
                    assert!(matches!(r, Ok(_) | Err(PublishError::NotSynced) | Err(PublishError::Behind { .. })), "seed {seed}: {r:?}");
                }
            }
            60..=74 => sim.set_online(i, !sim.nodes[i].online),
            75..=79 => sim.restart(i),
            80..=81 => sim.restart(i),
            82..=86 => {
                let groups: Vec<u32> = (0..n).map(|_| rng.below(3) as u32).collect();
                sim.partition(&groups);
            }
            87..=89 => sim.heal(),
            90..=91 => sim.flap(i, rng.below(5_000)),
            92..=93 => sim.flash(i, b"hi"),
            _ => {}
        }
        sim.run_for(rng.below(400));
    }
    sim.heal();
    for i in 0..n {
        sim.set_online(i, true);
    }
    sim.net.link_break = 0.0;
    sim.net.dial_fail = 0.0;
    // Everyone must reach the union of everything still held anywhere.
    let took = sim.run_until(300_000, |s| s.converged());
    if took.is_none() {
        let union = sim.union();
        let lagging: Vec<String> = sim
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.swarm.vector() != &union)
            .map(|(i, n)| format!("{i}: {}/{} links {} waiting {}", n.swarm.len(), union.total(), n.swarm.link_count(), n.swarm.waiting()))
            .collect();
        let now = sim.now;
        let mut detail = String::new();
        let first = sim.nodes[0].swarm.vector().clone();
        let a = (0..n).find(|&i| sim.nodes[i].swarm.vector() == &first).unwrap_or(0);
        let b = (0..n).find(|&i| sim.nodes[i].swarm.vector() != &first).unwrap_or(0);
        for lag in [a, b] {
            let ls = &sim.nodes[lag].swarm;
            let states: Vec<String> =
                (0..n).map(|j| format!("{j}:{:?}", ls.peer_state(&sim.id(j)).map(|(f, t, b, d)| (f, t as i64 - now as i64, b > now, d)))).collect();
            let neighbors: Vec<usize> = ls.neighbors().iter().filter_map(|p| sim.index(p)).collect();
            detail += &format!(
                "\nnode {lag} neighbours {neighbors:?} target {} peers (fails, next_try-now, banned, dialing): {states:?}",
                sim.cfg.target_degree
            );
        }
        panic!("seed {seed} (n={n}) did not converge: {lagging:?}{detail}");
    }
    sim.check_integrity().unwrap_or_else(|e| panic!("seed {seed}: {e}"));
    for (i, node) in sim.nodes.iter().enumerate() {
        assert!(!node.events.iter().any(|e| matches!(e, Event::Conflict { .. })), "seed {seed}: node {i} saw a conflict");
        assert!(
            !node.events.iter().any(|e| matches!(e, Event::Misbehaved { .. })),
            "seed {seed}: node {i} saw misbehaviour: {:?}",
            node.events.iter().find(|e| matches!(e, Event::Misbehaved { .. }))
        );
    }
}

#[test]
fn a_restarted_peer_reconnects_before_the_old_link_times_out() {
    // The far side notices a dead connection only after 30 s (QUIC idle timeout).
    for seed in 0..10 {
        let mut sim = Sim::new(2, cfg(), Net { detect: 30_000, ..Net::default() }, 300 + seed);
        sim.introduce(0, 1);
        sim.introduce(1, 0);
        sim.run_for(15_000);
        assert_eq!(sim.nodes[0].swarm.neighbors().len(), 1);
        for who in [0, 1] {
            sim.restart(who);
            let other = 1 - who;
            let me = sim.id(who);
            let took = sim.run_until(20_000, |s| s.nodes[who].swarm.neighbors().len() == 1 && s.nodes[other].swarm.neighbors() == vec![me]);
            assert!(took.is_some_and(|t| t < 10_000), "seed {seed}: node {who} took {took:?} to reconnect");
            let ready = sim.run_until(2_000, |s| s.nodes[who].swarm.can_publish(s.clock(who)));
            assert!(ready.is_some(), "seed {seed}: node {who} never synced");
            let e = sim.publish(who, b"back").expect("publish");
            assert!(sim.run_until(2_000, |s| s.everyone_has(&e.author, e.seq)).is_some());
            sim.run_for(15_000);
        }
    }
}
