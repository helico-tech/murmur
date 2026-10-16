//! A deterministic network simulator for murmur swarms (feature `sim`).
//!
//! Virtual time, one event queue, a seeded random generator: the same seed gives the same run.
//! It models what the real transport does: connections are reliable and ordered while they
//! last; every message takes a random latency, plus the time to push its bytes through the
//! sender's upload (messages queue behind each other); some peers are on slow links; messages
//! sometimes stall (a lost packet being resent); dials take a round trip and can fail; peers
//! behind NAT can't be dialled; a connection whose send queue overflows is closed (as
//! murmur-iroh does); links break; peers' clocks are skewed; nodes go offline (and come back on
//! their own after a flap), restart from their storage, or lose it. Partitions split the nodes
//! into groups that can't reach each other. Dishonest nodes can corrupt what they send. Every
//! message is encoded and decoded, so the wire format is exercised too.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::sync::{Arc, Mutex};

use crate::entry::Entry;
use crate::id::{Identity, PeerId, SwarmKey};
use crate::rng::Rng;
use crate::swarm::{Action, Config, ConnId, Event, PublishError, Storage, Swarm};
use crate::vector::Vector;
use crate::wire;

/// How the simulated network behaves. Times in ms.
#[derive(Clone, Debug)]
pub struct Net {
    /// One-way latency range.
    pub latency: (u64, u64),
    /// Chance that a dial fails even though the peer is reachable.
    pub dial_fail: f64,
    /// Chance, per delivered message, that the connection breaks right after.
    pub link_break: f64,
    /// How often each node's `tick` runs.
    pub tick: u64,
    /// How long the far side takes to notice a connection died (QUIC idle timeout).
    pub detect: u64,
    /// Upload speed per node, bytes per ms (1 000 ≈ 8 Mbit/s). Drawn once per node.
    pub bandwidth: (u64, u64),
    /// Share of nodes on slow links (5× latency, 1/20 of the bandwidth).
    pub slow: f64,
    /// Chance that a message stalls for up to `spike_ms` (a lost packet being resent).
    pub spike: f64,
    pub spike_ms: u64,
    /// Frames waiting on one connection before the transport closes it as too slow.
    pub queue_limit: usize,
    /// Each node's clock is off by up to ± this many ms.
    pub skew: u64,
    /// Share of nodes that can't accept incoming connections (NAT, no relay).
    pub nat: f64,
}

impl Default for Net {
    fn default() -> Self {
        Net {
            latency: (10, 80),
            dial_fail: 0.0,
            link_break: 0.0,
            tick: 100,
            detect: 1_000,
            bandwidth: (2_000, 20_000),
            slow: 0.0,
            spike: 0.0,
            spike_ms: 2_000,
            queue_limit: 4096,
            skew: 0,
            nat: 0.0,
        }
    }
}

/// One node's network and character, drawn when it is added.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Upload speed, bytes per ms.
    pub bandwidth: u64,
    /// Latency multiplier (1 normally, 5 on a slow link).
    pub latency_x: u64,
    /// Clock offset in ms.
    pub skew: i64,
    /// Can't accept incoming connections.
    pub nat: bool,
    /// Corrupts some of what it sends (bad signatures, lying vectors).
    pub evil: bool,
}

/// Persists into a shared Vec, so the simulator can restart a node from it.
#[derive(Clone, Default)]
pub struct MemStorage(pub Arc<Mutex<Vec<Entry>>>);

impl Storage for MemStorage {
    fn append(&mut self, entries: &[Arc<Entry>]) -> Result<(), String> {
        let mut v = self.0.lock().map_err(|_| "poisoned".to_string())?;
        v.extend(entries.iter().map(|e| (**e).clone()));
        Ok(())
    }
}

pub struct Node {
    pub swarm: Swarm,
    pub online: bool,
    pub storage: MemStorage,
    /// Partition group (nodes only reach nodes in the same group).
    pub group: u32,
    /// Peers this node is told about at start and after restarts.
    pub bootstrap: Vec<PeerId>,
    /// Every event the swarm emitted.
    pub events: Vec<Event>,
    pub profile: Profile,
    secret: [u8; 32],
    restarts: u64,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Ev {
    Deliver { to: usize, conn: ConnId, bytes: Vec<u8> },
    DialDone { from: usize, to: PeerId },
    Gone { node: usize, conn: ConnId },
    Tick { node: usize, epoch: u64 },
    Online { node: usize },
}

struct End {
    node: usize,
    /// The other side's connection id.
    other: ConnId,
}

pub struct Sim {
    pub now: u64,
    pub nodes: Vec<Node>,
    pub net: Net,
    pub cfg: Config,
    pub rng: Rng,
    key: SwarmKey,
    queue: BinaryHeap<Reverse<(u64, u64, Ev)>>,
    order: u64,
    conns: BTreeMap<ConnId, End>,
    next_conn: ConnId,
    /// Latest delivery time per connection end, so messages on one connection stay in order.
    last_delivery: BTreeMap<ConnId, u64>,
    /// Frames on their way to each connection end.
    in_flight: BTreeMap<ConnId, usize>,
    /// When each node's upload is free again.
    uplink: Vec<u64>,
    /// Connections closed because their queue overflowed.
    pub slow_closes: u64,
    /// Print every message sent by or delivered to this node (debugging).
    pub trace: Option<usize>,
    ids: HashMap<PeerId, usize>,
    /// Messages and bytes put on the wire.
    pub messages: u64,
    pub bytes: u64,
    seed: u64,
}

impl Sim {
    /// `n` nodes in one swarm, all offline-free, no links yet (see [`Sim::bootstrap_ring`] and
    /// [`Sim::bootstrap_star`]).
    pub fn new(n: usize, cfg: Config, net: Net, seed: u64) -> Sim {
        let mut rng = Rng::new(seed);
        let mut secret = [0u8; 32];
        for b in secret.iter_mut() {
            *b = rng.next_u64() as u8;
        }
        let key = SwarmKey::from_secret(&secret);
        let mut sim = Sim {
            now: 1_000_000,
            nodes: Vec::new(),
            net,
            cfg,
            rng,
            key,
            queue: BinaryHeap::new(),
            order: 0,
            conns: BTreeMap::new(),
            next_conn: 1,
            last_delivery: BTreeMap::new(),
            in_flight: BTreeMap::new(),
            uplink: Vec::new(),
            slow_closes: 0,
            trace: None,
            ids: HashMap::new(),
            messages: 0,
            bytes: 0,
            seed,
        };
        for _ in 0..n {
            sim.add_node();
        }
        sim
    }

    /// Adds a node (online, knowing nobody). Returns its index.
    pub fn add_node(&mut self) -> usize {
        let mut secret = [0u8; 32];
        for b in secret.iter_mut() {
            *b = self.rng.next_u64() as u8;
        }
        let i = self.nodes.len();
        let slow = self.net.slow > 0.0 && self.rng.chance(self.net.slow);
        let (lo, hi) = self.net.bandwidth;
        let bandwidth = (lo + self.rng.below(hi.saturating_sub(lo) + 1)).max(1);
        let skew = if self.net.skew == 0 { 0 } else { self.rng.below(2 * self.net.skew + 1) as i64 - self.net.skew as i64 };
        let profile = Profile {
            bandwidth: if slow { (bandwidth / 20).max(1) } else { bandwidth },
            latency_x: if slow { 5 } else { 1 },
            skew,
            nat: self.net.nat > 0.0 && self.rng.chance(self.net.nat),
            evil: false,
        };
        let storage = MemStorage::default();
        let mut swarm = self.make_swarm(&secret, &storage, i as u64);
        swarm.assume_fresh();
        self.ids.insert(swarm.id(), i);
        self.nodes.push(Node { swarm, online: true, storage, group: 0, bootstrap: Vec::new(), events: Vec::new(), profile, secret, restarts: 0 });
        self.uplink.push(0);
        let jitter = self.rng.below(self.net.tick);
        self.schedule(self.now + jitter, Ev::Tick { node: i, epoch: 0 });
        i
    }

    fn make_swarm(&mut self, secret: &[u8; 32], storage: &MemStorage, salt: u64) -> Swarm {
        let mut s =
            Swarm::new(self.key.clone(), Identity::from_secret(*secret), self.cfg.clone(), self.seed ^ salt.wrapping_mul(0x51_7cc1_b727_220a));
        s.set_storage(Box::new(storage.clone()));
        s
    }

    /// A swarm with another secret but the same id space: an outsider for hostile tests.
    pub fn outsider_key() -> SwarmKey {
        SwarmKey::from_secret(&[0xEE; 32])
    }

    pub fn id(&self, i: usize) -> PeerId {
        self.nodes.get(i).map(|n| n.swarm.id()).unwrap_or(PeerId([0; 32]))
    }

    /// Node `i`'s clock (the simulation clock plus its skew).
    pub fn clock(&self, i: usize) -> u64 {
        let skew = self.nodes.get(i).map(|n| n.profile.skew).unwrap_or(0);
        (self.now as i64 + skew).max(0) as u64
    }

    /// How far behind node `i`'s upload is (ms of queued bytes).
    pub fn uplink_backlog(&self, i: usize) -> u64 {
        self.uplink.get(i).copied().unwrap_or(0).saturating_sub(self.now)
    }

    /// Makes node `i` dishonest: some of what it sends is corrupted.
    pub fn make_evil(&mut self, i: usize) {
        if let Some(n) = self.nodes.get_mut(i) {
            n.profile.evil = true;
        }
    }

    pub fn is_evil(&self, i: usize) -> bool {
        self.nodes.get(i).is_some_and(|n| n.profile.evil)
    }

    /// The index of a peer id.
    pub fn index(&self, peer: &PeerId) -> Option<usize> {
        self.ids.get(peer).copied()
    }

    /// Takes node `i` offline for `ms` (a network flap); it comes back by itself.
    pub fn flap(&mut self, i: usize, ms: u64) {
        self.set_online(i, false);
        self.schedule(self.now + ms.max(1), Ev::Online { node: i });
    }

    /// Tells node `i` about node `j`.
    pub fn introduce(&mut self, i: usize, j: usize) {
        let pj = self.id(j);
        if let Some(n) = self.nodes.get_mut(i) {
            n.swarm.add_peer(pj, Vec::new());
            n.bootstrap.push(pj);
        }
    }

    /// Every node knows only node 0 (an invite link from one person).
    pub fn bootstrap_star(&mut self) {
        for i in 1..self.nodes.len() {
            self.introduce(i, 0);
        }
    }

    /// Every node knows only the next one.
    pub fn bootstrap_ring(&mut self) {
        let n = self.nodes.len();
        for i in 0..n {
            self.introduce(i, (i + 1) % n);
        }
    }

    // ------------------------------------------------------------------ app actions

    pub fn publish(&mut self, i: usize, payload: &[u8]) -> Result<Arc<Entry>, PublishError> {
        let now = self.clock(i);
        let r = match self.nodes.get_mut(i) {
            Some(n) => n.swarm.publish(payload.to_vec(), now),
            None => return Err(PublishError::TooLarge(0)),
        };
        self.pump(i);
        r
    }

    pub fn flash(&mut self, i: usize, payload: &[u8]) {
        let now = self.clock(i);
        if let Some(n) = self.nodes.get_mut(i) {
            let _ = n.swarm.flash(payload.to_vec(), now);
        }
        self.pump(i);
    }

    // ------------------------------------------------------------------ faults

    /// Takes node `i` offline (its connections drop) or brings it back.
    pub fn set_online(&mut self, i: usize, online: bool) {
        let Some(n) = self.nodes.get(i) else { return };
        if n.online == online {
            return;
        }
        if online {
            let now = self.clock(i);
            if let Some(n) = self.nodes.get_mut(i) {
                n.online = true;
                n.restarts += 1;
                n.swarm.network_changed(now);
            }
            let epoch = self.nodes.get(i).map(|n| n.restarts).unwrap_or(0);
            self.schedule(self.now + 1, Ev::Tick { node: i, epoch });
        } else {
            self.drop_all(i);
            if let Some(n) = self.nodes.get_mut(i) {
                n.online = false;
            }
        }
    }

    /// Restarts node `i` from its storage (memory is lost, the identity and storage stay).
    pub fn restart(&mut self, i: usize) {
        self.restart_with(i, true);
    }

    /// Restarts node `i` with its storage wiped (same identity): it must recover its own log
    /// from the others before it may publish again.
    pub fn wipe(&mut self, i: usize) {
        self.restart_with(i, false);
    }

    fn restart_with(&mut self, i: usize, keep: bool) {
        let Some(n) = self.nodes.get(i) else { return };
        let was_online = n.online;
        let (secret, storage, bootstrap) = (n.secret, n.storage.clone(), n.bootstrap.clone());
        // Apps keep the address book with the data; a wipe loses both.
        let book = if keep { n.swarm.address_book(self.now) } else { Vec::new() };
        self.drop_all(i);
        if !keep && let Ok(mut v) = storage.0.lock() {
            v.clear();
        }
        let stored: Vec<Entry> = storage.0.lock().map(|v| v.clone()).unwrap_or_default();
        let salt = (i as u64) << 32 | self.rng.below(1 << 31);
        let mut swarm = self.make_swarm(&secret, &storage, salt);
        swarm.restore(stored, true);
        for p in &bootstrap {
            swarm.add_peer(*p, Vec::new());
        }
        for (p, h) in book {
            swarm.add_peer(p, h);
        }
        if let Some(n) = self.nodes.get_mut(i) {
            n.swarm = swarm;
            n.restarts += 1;
            n.online = was_online;
            let epoch = n.restarts;
            self.schedule(self.now + 1, Ev::Tick { node: i, epoch });
        }
    }

    /// Splits the nodes into groups (`groups[i]` for node `i`); links across groups break.
    pub fn partition(&mut self, groups: &[u32]) {
        for (i, g) in groups.iter().enumerate() {
            if let Some(n) = self.nodes.get_mut(i) {
                n.group = *g;
            }
        }
        let cross: Vec<ConnId> = self
            .conns
            .iter()
            .filter(|(c, e)| {
                let mine = self.conns.get(&e.other).map(|o| o.node);
                let a = self.nodes.get(e.node).map(|n| n.group);
                let b = mine.and_then(|m| self.nodes.get(m)).map(|n| n.group);
                a != b && **c < e.other
            })
            .map(|(c, _)| *c)
            .collect();
        for c in cross {
            self.break_conn(c, self.net.detect);
        }
    }

    pub fn heal(&mut self) {
        for n in &mut self.nodes {
            n.group = 0;
        }
    }

    /// Opens a raw connection from an outsider (wrong secret) to node `i` and sends its Hello.
    /// Returns what node `i` sent back before closing (decoded).
    pub fn outsider_hello(&mut self, i: usize) -> Vec<wire::Message> {
        let outsider = Identity::from_secret([0xAB; 32]);
        let key = Sim::outsider_key();
        let conn = 999_999;
        let now = self.now;
        let me = self.id(i);
        let Some(n) = self.nodes.get_mut(i) else { return Vec::new() };
        n.swarm.on_connected(conn, outsider.id(), false, now);
        let hello = wire::Message::Hello { version: crate::PROTOCOL_VERSION, proof: key.proof(&outsider.id(), &me), hint: vec![] };
        n.swarm.on_bytes(conn, &wire::encode(&hello), now);
        let mut out = Vec::new();
        while let Some(a) = n.swarm.poll_action() {
            if let Action::Send { conn: c, msg } = a
                && c == conn
            {
                out.push(msg);
            }
        }
        out
    }

    // ------------------------------------------------------------------ running

    /// Runs the simulation for `ms` of virtual time.
    pub fn run_for(&mut self, ms: u64) {
        let until = self.now + ms;
        while let Some(Reverse((at, _, _))) = self.queue.peek() {
            if *at > until {
                break;
            }
            let Some(Reverse((at, _, ev))) = self.queue.pop() else { break };
            self.now = at;
            self.handle(ev);
        }
        self.now = until;
    }

    /// Runs until `done` holds (checked every 10 ms of virtual time) or `max` ms pass. Returns
    /// the time it took, or `None` on timeout.
    pub fn run_until(&mut self, max: u64, mut done: impl FnMut(&Sim) -> bool) -> Option<u64> {
        let start = self.now;
        while self.now < start + max {
            if done(self) {
                return Some(self.now - start);
            }
            self.run_for(10);
        }
        done(self).then_some(self.now - start)
    }

    /// Whether every online node holds exactly the same entries.
    /// (Dishonest nodes are left out: honest peers may have banned them.)
    pub fn converged(&self) -> bool {
        let mut it = self.nodes.iter().filter(|n| n.online && !n.profile.evil);
        let Some(first) = it.next() else { return true };
        let d = first.swarm.vector().digest();
        it.all(|n| n.swarm.vector().digest() == d)
    }

    /// The union of all online honest nodes' vectors.
    pub fn union(&self) -> Vector {
        let mut v = Vector::new();
        for n in self.nodes.iter().filter(|n| n.online && !n.profile.evil) {
            v.merge(n.swarm.vector());
        }
        v
    }

    /// The overlay's diameter and average path length (in hops) over the working links between
    /// online nodes. Unreachable pairs are skipped; see [`Sim::components`].
    pub fn overlay_paths(&self) -> (usize, f64) {
        let adj = self.adjacency();
        let (mut max, mut sum, mut count) = (0usize, 0usize, 0usize);
        for s in 0..adj.len() {
            for d in Self::bfs(&adj, s).into_iter().flatten() {
                max = max.max(d);
                sum += d;
                count += 1;
            }
        }
        (max, if count == 0 { 0.0 } else { sum as f64 / count as f64 })
    }

    /// Number of connected groups among online nodes.
    pub fn components(&self) -> usize {
        let adj = self.adjacency();
        let mut seen = vec![false; adj.len()];
        let mut groups = 0;
        for s in 0..adj.len() {
            if seen.get(s) == Some(&true) || !self.nodes.get(s).is_some_and(|n| n.online) {
                continue;
            }
            groups += 1;
            for (i, d) in Self::bfs(&adj, s).into_iter().enumerate() {
                if d.is_some()
                    && let Some(x) = seen.get_mut(i)
                {
                    *x = true;
                }
            }
        }
        groups
    }

    fn adjacency(&self) -> Vec<Vec<usize>> {
        self.nodes
            .iter()
            .map(|n| if n.online { n.swarm.neighbors().iter().filter_map(|p| self.ids.get(p).copied()).collect() } else { Vec::new() })
            .collect()
    }

    fn bfs(adj: &[Vec<usize>], start: usize) -> Vec<Option<usize>> {
        let mut dist = vec![None; adj.len()];
        if let Some(d) = dist.get_mut(start) {
            *d = Some(0);
        }
        let mut queue = std::collections::VecDeque::from([start]);
        while let Some(u) = queue.pop_front() {
            let du = dist.get(u).copied().flatten().unwrap_or(0);
            for &v in adj.get(u).into_iter().flatten() {
                if let Some(d @ None) = dist.get_mut(v) {
                    *d = Some(du + 1);
                    queue.push_back(v);
                }
            }
        }
        dist
    }

    /// Whether every online node holds `author:seq`.
    pub fn everyone_has(&self, author: &PeerId, seq: u64) -> bool {
        self.nodes.iter().filter(|n| n.online && !n.profile.evil).all(|n| n.swarm.vector().get(author) >= seq)
    }

    /// Checks that all nodes that hold an entry hold the same bytes, and that every node's
    /// storage matches its memory. Returns a description of the first problem.
    pub fn check_integrity(&self) -> Result<(), String> {
        let mut seen: BTreeMap<(PeerId, u64), Vec<u8>> = BTreeMap::new();
        for (i, n) in self.nodes.iter().enumerate() {
            for e in n.swarm.since(&Vector::new(), usize::MAX) {
                match seen.get(&(e.author, e.seq)) {
                    Some(p) if *p != e.payload => return Err(format!("node {i} holds a different {}:{}", e.author.short(), e.seq)),
                    Some(_) => {}
                    None => {
                        seen.insert((e.author, e.seq), e.payload.clone());
                    }
                }
                if !e.verify(&self.key.id()) {
                    return Err(format!("node {i} holds an unsigned {}:{}", e.author.short(), e.seq));
                }
            }
            let stored = n.storage.0.lock().map(|v| v.len()).unwrap_or(0) as u64;
            if stored < n.swarm.len() {
                return Err(format!("node {i} stored {stored} of {} entries", n.swarm.len()));
            }
        }
        Ok(())
    }

    fn schedule(&mut self, at: u64, ev: Ev) {
        self.order += 1;
        self.queue.push(Reverse((at, self.order, ev)));
    }

    fn latency(&mut self) -> u64 {
        let (lo, hi) = self.net.latency;
        lo + self.rng.below(hi.saturating_sub(lo) + 1)
    }

    /// One-way latency between two nodes: the slower one's multiplier, plus a stall sometimes.
    fn path_latency(&mut self, a: usize, b: usize) -> u64 {
        let x = self.nodes.get(a).map(|n| n.profile.latency_x).unwrap_or(1).max(self.nodes.get(b).map(|n| n.profile.latency_x).unwrap_or(1));
        let mut lat = self.latency() * x;
        if self.net.spike > 0.0 && self.rng.chance(self.net.spike) {
            lat += self.rng.below(self.net.spike_ms + 1);
        }
        lat
    }

    fn handle(&mut self, ev: Ev) {
        match ev {
            Ev::Tick { node, epoch } => {
                let now = self.clock(node);
                let tick = self.net.tick;
                let Some(n) = self.nodes.get_mut(node) else { return };
                if !n.online || n.restarts != epoch {
                    return;
                }
                n.swarm.tick(now);
                self.schedule(self.now + tick, Ev::Tick { node, epoch });
                self.pump(node);
            }
            Ev::Deliver { to, conn, bytes } => {
                if let Some(f) = self.in_flight.get_mut(&conn) {
                    *f = f.saturating_sub(1);
                }
                if !self.conns.contains_key(&conn) {
                    return;
                }
                let now = self.clock(to);
                if let Some(n) = self.nodes.get_mut(to) {
                    n.swarm.on_bytes(conn, &bytes, now);
                }
                self.pump(to);
                if self.net.link_break > 0.0 && self.rng.chance(self.net.link_break) && self.conns.contains_key(&conn) {
                    self.break_conn(conn, self.net.detect);
                }
            }
            Ev::DialDone { from, to } => {
                let now = self.clock(from);
                let target = self.ids.get(&to).copied();
                let ok = match (self.nodes.get(from), target.and_then(|t| self.nodes.get(t))) {
                    (Some(a), Some(b)) => a.online && b.online && a.group == b.group && !b.profile.nat,
                    _ => false,
                };
                let fail = self.net.dial_fail > 0.0 && self.rng.chance(self.net.dial_fail);
                match target {
                    Some(t) if ok && !fail => {
                        let (ca, cb) = (self.next_conn, self.next_conn + 1);
                        self.next_conn += 2;
                        self.conns.insert(ca, End { node: from, other: cb });
                        self.conns.insert(cb, End { node: t, other: ca });
                        let (ia, ib) = (self.id(from), self.id(t));
                        let tnow = self.clock(t);
                        if let Some(n) = self.nodes.get_mut(t) {
                            n.swarm.on_connected(cb, ia, false, tnow);
                        }
                        if let Some(n) = self.nodes.get_mut(from) {
                            n.swarm.on_connected(ca, ib, true, now);
                        }
                        self.pump(t);
                        self.pump(from);
                    }
                    _ => {
                        if let Some(n) = self.nodes.get_mut(from)
                            && n.online
                        {
                            n.swarm.on_dial_failed(to, now);
                        }
                        self.pump(from);
                    }
                }
            }
            Ev::Online { node } => self.set_online(node, true),
            Ev::Gone { node, conn } => {
                let now = self.clock(node);
                self.conns.remove(&conn);
                if let Some(n) = self.nodes.get_mut(node) {
                    n.swarm.on_disconnected(conn, now);
                }
                self.pump(node);
            }
        }
    }

    /// Carries out node `i`'s actions and collects its events.
    fn pump(&mut self, i: usize) {
        loop {
            let Some(n) = self.nodes.get_mut(i) else { return };
            while let Some(e) = n.swarm.poll_event() {
                n.events.push(e);
            }
            let Some(action) = n.swarm.poll_action() else { return };
            match action {
                Action::Send { conn, msg } => {
                    let Some(end) = self.conns.get(&conn) else { continue };
                    let (to, other) = (self.conns.get(&end.other).map(|e| e.node), end.other);
                    let Some(to) = to else { continue };
                    let msg = if self.is_evil(i) { self.corrupt(msg) } else { msg };
                    if self.trace == Some(i) || self.trace == Some(to) {
                        let what = match &msg {
                            wire::Message::Hello { .. } => "Hello".to_string(),
                            wire::Message::Have { vector, want } => format!("Have total {} want {want}", vector.total()),
                            wire::Message::Digest { .. } => "Digest".to_string(),
                            wire::Message::Entries { entries } => format!("Entries {}", entries.len()),
                            wire::Message::Peers { peers } => format!("Peers {}", peers.len()),
                            wire::Message::Flash(_) => "Flash".to_string(),
                        };
                        if !what.starts_with("Flash") && !what.starts_with("Digest") {
                            println!("t={} {i}->{to} conn {conn}->{other} {what}", self.now);
                        }
                    }
                    let bytes = wire::encode(&msg);
                    self.messages += 1;
                    self.bytes += bytes.len() as u64 + 4;
                    // The transport gives up on a connection whose queue overflows.
                    let queued = self.in_flight.entry(other).or_insert(0);
                    *queued += 1;
                    if *queued > self.net.queue_limit {
                        self.slow_closes += 1;
                        self.break_conn(conn, self.net.detect);
                        continue;
                    }
                    // Bytes go out through the sender's upload one message after another.
                    let bw = self.nodes.get(i).map(|n| n.profile.bandwidth).unwrap_or(1).max(1);
                    let start = self.now.max(self.uplink.get(i).copied().unwrap_or(0));
                    let sent = start + (bytes.len() as u64 + 40) / bw;
                    if let Some(u) = self.uplink.get_mut(i) {
                        *u = sent;
                    }
                    let lat = self.path_latency(i, to);
                    let at = (sent + lat).max(self.last_delivery.get(&other).copied().unwrap_or(0));
                    self.last_delivery.insert(other, at);
                    self.schedule(at, Ev::Deliver { to, conn: other, bytes });
                }
                Action::Dial { peer, .. } => {
                    let to = self.ids.get(&peer).copied().unwrap_or(i);
                    let rtt = self.path_latency(i, to) + self.path_latency(to, i);
                    self.schedule(self.now + rtt, Ev::DialDone { from: i, to: peer });
                }
                Action::Close { conn, .. } => {
                    // The closing side already forgot it. The other side still gets what was
                    // already sent (a graceful QUIC close), then hears that it closed.
                    if let Some(end) = self.conns.remove(&conn) {
                        let other = end.other;
                        let at = (self.now + self.latency()).max(self.last_delivery.get(&other).copied().unwrap_or(0)) + 1;
                        if let Some(o) = self.conns.get(&other) {
                            let node = o.node;
                            self.schedule(at, Ev::Gone { node, conn: other });
                        }
                    }
                }
            }
        }
    }

    /// What a dishonest node does to a message it sends (sometimes).
    fn corrupt(&mut self, msg: wire::Message) -> wire::Message {
        if !self.rng.chance(0.2) {
            return msg;
        }
        match msg {
            wire::Message::Entries { mut entries } if !entries.is_empty() => {
                let k = self.rng.below(entries.len() as u64) as usize;
                if let Some(e) = entries.get_mut(k) {
                    let mut bad = (**e).clone();
                    bad.payload.push(b'!');
                    *e = Arc::new(bad);
                }
                wire::Message::Entries { entries }
            }
            wire::Message::Have { mut vector, want } => {
                let victim = self.rng.below(self.nodes.len() as u64) as usize;
                vector.raise(self.id(victim), 1 << 40);
                wire::Message::Have { vector, want }
            }
            wire::Message::Flash(mut f) => {
                f.stamp += 1;
                wire::Message::Flash(f)
            }
            other => other,
        }
    }

    /// Breaks connection `conn` (both ends): its node notices now, the other after `delay`.
    fn break_conn(&mut self, conn: ConnId, delay: u64) {
        let Some(end) = self.conns.remove(&conn) else { return };
        let other = self.conns.remove(&end.other);
        let now = self.clock(end.node);
        if let Some(n) = self.nodes.get_mut(end.node) {
            n.swarm.on_disconnected(conn, now);
        }
        self.pump(end.node);
        if let Some(o) = other {
            self.schedule(self.now + delay, Ev::Gone { node: o.node, conn: end.other });
        }
    }

    fn drop_all(&mut self, i: usize) {
        let mine: Vec<ConnId> = self.conns.iter().filter(|(_, e)| e.node == i).map(|(c, _)| *c).collect();
        for c in mine {
            self.break_conn(c, self.net.detect);
        }
    }
}
