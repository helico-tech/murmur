//! Hostile and broken peers, driven message by message against real swarms.

use std::sync::Arc;

use murmur::sim::{Net, Sim};
use murmur::wire::{self, PeerHint};
use murmur::{
    Action, CloseReason, Config, ConnId, Entry, Event, Flash, FlashKind, Identity, Message, PeerId, PublishError, Rng, Swarm, SwarmKey, Vector,
};

const SECRET: [u8; 32] = [42; 32];

fn swarm(n: u8, cfg: Config) -> Swarm {
    let mut s = Swarm::new(SwarmKey::from_secret(&SECRET), Identity::from_secret([n; 32]), cfg, n as u64);
    s.assume_fresh();
    s
}

fn quiet() -> Config {
    Config { presence_interval: None, ..Config::default() }
}

/// Two swarms joined by one connection: `a` uses conn 1, `b` conn 2. Messages go straight across.
struct Pair {
    a: Swarm,
    b: Swarm,
    now: u64,
    a_closed: Vec<CloseReason>,
    b_closed: Vec<CloseReason>,
}

impl Pair {
    fn new(a: Swarm, b: Swarm) -> Pair {
        let mut p = Pair { a, b, now: 1_000, a_closed: vec![], b_closed: vec![] };
        let (ia, ib) = (p.a.id(), p.b.id());
        p.a.on_connected(1, ib, true, p.now);
        p.b.on_connected(2, ia, false, p.now);
        p.run();
        p
    }

    /// Delivers everything until both are quiet. Only sends on the pair's connection cross.
    fn run(&mut self) {
        for _ in 0..10_000 {
            let mut moved = false;
            while let Some(act) = self.a.poll_action() {
                moved = true;
                match act {
                    Action::Send { conn: 1, msg } => self.b.on_bytes(2, &wire::encode(&msg), self.now),
                    Action::Close { conn: 1, reason } => {
                        self.a_closed.push(reason);
                        self.b.on_disconnected(2, self.now);
                    }
                    _ => {}
                }
            }
            while let Some(act) = self.b.poll_action() {
                moved = true;
                match act {
                    Action::Send { conn: 2, msg } => self.a.on_bytes(1, &wire::encode(&msg), self.now),
                    Action::Close { conn: 2, reason } => {
                        self.b_closed.push(reason);
                        self.a.on_disconnected(1, self.now);
                    }
                    _ => {}
                }
            }
            if !moved {
                return;
            }
        }
        panic!("pair never went quiet");
    }

    fn b_events(&mut self) -> Vec<Event> {
        std::iter::from_fn(|| self.b.poll_event()).collect()
    }
}

/// Sends a hand-made message from `a`'s side to `b`.
fn inject(p: &mut Pair, msg: Message) {
    p.b.on_message(2, msg, p.now);
    p.run();
}

#[test]
fn honest_pair_syncs() {
    let mut a = swarm(1, quiet());
    let mut b = swarm(2, quiet());
    a.publish(b"a1".to_vec(), 0).expect("publish");
    b.publish(b"b1".to_vec(), 0).expect("publish");
    let p = Pair::new(a, b);
    assert_eq!(p.a.vector(), p.b.vector());
    assert_eq!(p.a.len(), 2);
    assert_eq!(p.a.neighbors(), vec![p.b.id()]);
}

#[test]
fn an_outsider_without_the_secret_learns_nothing_and_is_banned() {
    let mut sim = Sim::new(3, quiet(), Net::default(), 1);
    sim.bootstrap_star();
    sim.publish(0, b"secret plans").expect("publish");
    sim.run_for(5_000);
    let replies = sim.outsider_hello(0);
    // Only our own Hello (sent on connect, before we know who it is) went out.
    assert!(replies.iter().all(|m| matches!(m, Message::Hello { .. })), "{replies:?}");
    assert!(sim.nodes[0].swarm.poll_event().is_some());
    // It is refused straight away next time.
    let again = sim.outsider_hello(0);
    assert!(again.is_empty(), "banned peers don't even get a Hello: {again:?}");
}

#[test]
fn forged_entries_are_dropped_and_the_sender_banned() {
    let mut p = Pair::new(swarm(1, quiet()), swarm(2, quiet()));
    let victim = Identity::from_secret([9; 32]);
    let swarm_id = SwarmKey::from_secret(&SECRET).id();
    let mut forged = Entry::sign(&swarm_id, &victim, 1, b"I owe you nothing".to_vec());
    forged.payload = b"I owe you 1000 euro".to_vec();
    inject(&mut p, Message::Entries { entries: vec![Arc::new(forged)] });
    assert_eq!(p.b.vector().get(&victim.id()), 0);
    assert_eq!(p.b_closed, vec![CloseReason::Misbehaved]);
    assert!(p.b_events().iter().any(|e| matches!(e, Event::Misbehaved { .. })));
}

#[test]
fn entries_signed_for_another_swarm_are_rejected() {
    let mut p = Pair::new(swarm(1, quiet()), swarm(2, quiet()));
    let other = SwarmKey::from_secret(&[1; 32]).id();
    let e = Entry::sign(&other, &Identity::from_secret([1; 32]), 1, b"wrong swarm".to_vec());
    inject(&mut p, Message::Entries { entries: vec![Arc::new(e)] });
    assert_eq!(p.b.len(), 0);
    assert_eq!(p.b_closed, vec![CloseReason::Misbehaved]);
}

#[test]
fn protocol_violations_close_the_link() {
    // A second Hello.
    let mut p = Pair::new(swarm(1, quiet()), swarm(2, quiet()));
    inject(&mut p, Message::Hello { version: 1, proof: [0; 32], hint: vec![] });
    assert_eq!(p.b_closed, vec![CloseReason::Misbehaved]);

    // Anything before Hello.
    let mut b = swarm(2, quiet());
    b.on_connected(7, Identity::from_secret([1; 32]).id(), false, 0);
    b.on_message(7, Message::Digest { hash: [0; 32] }, 0);
    let closes: Vec<_> = std::iter::from_fn(|| b.poll_action()).filter(|a| matches!(a, Action::Close { .. })).collect();
    assert_eq!(closes, vec![Action::Close { conn: 7, reason: CloseReason::Misbehaved }]);

    // Garbage bytes.
    let mut p = Pair::new(swarm(1, quiet()), swarm(2, quiet()));
    p.b.on_bytes(2, &[0xde, 0xad, 0xbe, 0xef, 0xff, 0xff], p.now);
    p.run();
    assert_eq!(p.b_closed, vec![CloseReason::Misbehaved]);

    // Over a limit (built by hand, so it skips the decoder).
    let mut p = Pair::new(swarm(1, quiet()), swarm(2, quiet()));
    let e = Entry::sign(&SwarmKey::from_secret(&SECRET).id(), &Identity::from_secret([1; 32]), 1, vec![0; murmur::limits::MAX_PAYLOAD + 1]);
    inject(&mut p, Message::Entries { entries: vec![Arc::new(e)] });
    assert_eq!(p.b_closed, vec![CloseReason::Misbehaved]);
}

#[test]
fn old_protocol_versions_are_refused_without_a_ban() {
    let mut b = swarm(2, quiet());
    let a = Identity::from_secret([1; 32]);
    b.on_connected(5, a.id(), false, 0);
    let proof = SwarmKey::from_secret(&SECRET).proof(&a.id(), &b.id());
    b.on_message(5, Message::Hello { version: 0, proof, hint: vec![] }, 0);
    let acts: Vec<_> = std::iter::from_fn(|| b.poll_action()).collect();
    assert!(acts.contains(&Action::Close { conn: 5, reason: CloseReason::Version }));
    assert!(!std::iter::from_fn(|| b.poll_event()).any(|e| matches!(e, Event::Misbehaved { .. })));
}

#[test]
fn a_lying_have_cannot_silence_a_peer_for_long() {
    let mut p = Pair::new(swarm(1, quiet()), swarm(2, quiet()));
    let me = p.b.id();
    let lie: Vector = [(me, 1_000_000)].into_iter().collect();
    inject(&mut p, Message::Have { vector: lie, want: 1 << 20 });
    assert!(matches!(p.b.publish(b"hi".to_vec(), p.now), Err(PublishError::Behind { .. })));
    let grace = p.b.config().claim_grace;
    assert!(p.b.publish(b"hi".to_vec(), p.now + grace).is_ok(), "an unproven claim expires");
}

#[test]
fn a_proven_loss_blocks_publishing_until_recovered() {
    // b published 3 entries, which a holds; b then lost its data (same key).
    let mut a = swarm(1, quiet());
    let mut old_b = swarm(2, quiet());
    for i in 0..3 {
        old_b.publish(vec![i], 0).expect("publish");
    }
    a.restore(old_b.since(&Vector::new(), 100).into_iter().map(|e| (*e).clone()), true);
    let fresh_b = Swarm::new(SwarmKey::from_secret(&SECRET), Identity::from_secret([2; 32]), quiet(), 9);
    let mut p = Pair::new(a, fresh_b);
    assert_eq!(p.b.vector().get(&p.b.id()), 3, "recovered from a");
    let e = p.b.publish(b"next".to_vec(), p.now).expect("publish");
    assert_eq!(e.seq, 4);
}

#[test]
fn conflicting_entries_keep_the_first_and_are_reported() {
    let mut p = Pair::new(swarm(1, quiet()), swarm(2, quiet()));
    let liar = Identity::from_secret([7; 32]);
    let id = SwarmKey::from_secret(&SECRET).id();
    inject(&mut p, Message::Entries { entries: vec![Arc::new(Entry::sign(&id, &liar, 1, b"one".to_vec()))] });
    inject(&mut p, Message::Entries { entries: vec![Arc::new(Entry::sign(&id, &liar, 1, b"two".to_vec()))] });
    assert_eq!(p.b.get(&liar.id(), 1).map(|e| e.payload.clone()), Some(b"one".to_vec()));
    assert!(p.b_events().iter().any(|e| matches!(e, Event::Conflict { seq: 1, .. })));
    assert!(p.b_closed.is_empty(), "a conflict is the author's fault, not the forwarder's");
}

#[test]
fn replayed_and_forged_flashes() {
    let mut p = Pair::new(swarm(1, quiet()), swarm(2, quiet()));
    let id = SwarmKey::from_secret(&SECRET).id();
    let other = Identity::from_secret([5; 32]);
    let f = Flash::sign(&id, &other, FlashKind::App, 100, 3, b"typing".to_vec());
    inject(&mut p, Message::Flash(f.clone()));
    inject(&mut p, Message::Flash(f.clone()));
    let older = Flash::sign(&id, &other, FlashKind::App, 99, 3, b"old".to_vec());
    inject(&mut p, Message::Flash(older));
    let flashes = p.b_events().into_iter().filter(|e| matches!(e, Event::Flash { .. })).count();
    assert_eq!(flashes, 1, "replays and older flashes are dropped");
    let mut forged = Flash::sign(&id, &other, FlashKind::App, 200, 3, b"x".to_vec());
    forged.payload = b"y".to_vec();
    inject(&mut p, Message::Flash(forged));
    assert_eq!(p.b_closed, vec![CloseReason::Misbehaved]);
}

#[test]
fn junk_peer_lists_and_vectors_stay_bounded() {
    let cfg = Config { known_limit: 50, ..quiet() };
    let mut p = Pair::new(swarm(1, cfg.clone()), swarm(2, cfg));
    let mut rng = Rng::new(1);
    let mut junk = || {
        let mut b = [0u8; 32];
        for x in b.iter_mut() {
            *x = rng.next_u64() as u8;
        }
        PeerId(b)
    };
    for _ in 0..20 {
        let peers = (0..64).map(|_| PeerHint { peer: junk(), hint: vec![1; 10] }).collect();
        inject(&mut p, Message::Peers { peers });
    }
    let vector: Vector = (0..10_000).map(|_| (junk(), 5)).collect();
    inject(&mut p, Message::Have { vector, want: 1 << 20 });
    assert!(p.b.known_peers().len() <= 50, "{} known", p.b.known_peers().len());
    assert!(p.b.known_peers().contains(&p.a.id()), "linked peers are never forgotten");
}

#[test]
fn self_connections_and_unknown_connections_are_harmless() {
    let mut s = swarm(1, quiet());
    let me = s.id();
    s.on_connected(1, me, true, 0);
    assert_eq!(s.poll_action(), Some(Action::Close { conn: 1, reason: CloseReason::SelfConnect }));
    s.on_message(99, Message::Digest { hash: [0; 32] }, 0);
    s.on_bytes(98, b"junk", 0);
    s.on_disconnected(97, 0);
    s.on_dial_failed(PeerId([3; 32]), 0);
    assert_eq!(s.poll_action(), None);
}

/// Random calls with random (mostly invalid) input: nothing panics, limits hold.
#[test]
fn random_abuse_never_panics() {
    let id = SwarmKey::from_secret(&SECRET).id();
    for seed in 0..40 {
        let mut rng = Rng::new(seed);
        let cfg = Config { known_limit: 64, max_degree: 4, ..Config::default() };
        let mut s = swarm(1, cfg);
        let others: Vec<Identity> = (2..8).map(|n| Identity::from_secret([n; 32])).collect();
        let mut now = 0u64;
        for _ in 0..3_000 {
            now += rng.below(500);
            let conn: ConnId = rng.below(12);
            let who = rng.pick(&others).map(|i| i.id()).unwrap_or(PeerId([0; 32]));
            match rng.below(14) {
                0 => s.on_connected(conn, who, rng.below(2) == 0, now),
                1 => s.on_disconnected(conn, now),
                2 => s.on_dial_failed(who, now),
                3 => s.tick(now),
                4 => {
                    let _ = s.publish(vec![rng.next_u64() as u8; rng.below(100) as usize], now);
                }
                5 => {
                    // A valid Hello from `who`, maybe.
                    let proof = SwarmKey::from_secret(&SECRET).proof(&who, &s.id());
                    s.on_message(conn, Message::Hello { version: 1, proof, hint: vec![] }, now);
                }
                6 => {
                    let author = rng.pick(&others).cloned().unwrap_or_else(|| Identity::from_secret([2; 32]));
                    let e = Entry::sign(&id, &author, 1 + rng.below(20), vec![1, 2, 3]);
                    s.on_message(conn, Message::Entries { entries: vec![Arc::new(e)] }, now);
                }
                7 => {
                    let v: Vector = (0..rng.below(20)).map(|i| (PeerId([i as u8; 32]), rng.below(1 << 40))).collect();
                    s.on_message(conn, Message::Have { vector: v, want: rng.below(1 << 21) as u32 }, now);
                }
                8 => s.on_message(conn, Message::Digest { hash: [rng.next_u64() as u8; 32] }, now),
                9 => {
                    let author = rng.pick(&others).cloned().unwrap_or_else(|| Identity::from_secret([2; 32]));
                    let f = Flash::sign(&id, &author, FlashKind::Presence, rng.below(10_000), rng.below(20) as u8, vec![]);
                    s.on_message(conn, Message::Flash(f), now);
                }
                10 => {
                    let len = rng.below(300) as usize;
                    let bytes: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
                    s.on_bytes(conn, &bytes, now);
                }
                11 => s.network_changed(now),
                12 => {
                    let _ = s.flash(vec![9], now);
                }
                _ => s.add_peer(PeerId([rng.next_u64() as u8; 32]), vec![]),
            }
            while s.poll_action().is_some() {}
            while s.poll_event().is_some() {}
            assert!(s.known_peers().len() <= 64 + 12, "known peers bounded");
            assert!(s.link_count() <= 12, "links bounded by connection ids");
        }
    }
}

#[test]
fn only_allowed_peers_get_in_even_with_the_secret() {
    let mut a = swarm(1, quiet());
    a.publish(b"members only".to_vec(), 0).expect("publish");
    let stranger = swarm(2, quiet());
    a.set_allowed(Some([Identity::from_secret([3; 32]).id()].into_iter().collect()));
    let mut p = Pair::new(a, stranger);
    assert_eq!(p.b.len(), 0, "nothing reached the stranger");
    assert_eq!(p.a_closed, vec![CloseReason::NotAllowed]);
    assert!(p.a.neighbors().is_empty());
    // Once admitted, it connects and syncs.
    let id = p.b.id();
    p.a.set_allowed(Some([id].into_iter().collect()));
    let (ia, ib) = (p.a.id(), p.b.id());
    p.a.on_connected(1, ib, true, p.now);
    p.b.on_connected(2, ia, false, p.now);
    p.run();
    assert_eq!(p.b.len(), 1);
    // And when it is removed again, the link closes.
    p.a.set_allowed(Some(Default::default()));
    p.run();
    assert!(p.a.neighbors().is_empty());
}
