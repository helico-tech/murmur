//! Real iroh endpoints on this machine (relays and address lookup off): murmur over QUIC.

use std::time::Duration;

use iroh::endpoint::presets;
use iroh::{Endpoint, RelayMode, SecretKey};
use murmur::{Config, Identity, Swarm, SwarmKey};
use murmur_iroh::{Node, SwarmHandle, encode_hint};

async fn node(n: u8) -> Node {
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[n; 32]))
        .relay_mode(RelayMode::Disabled)
        .bind_addr("127.0.0.1:0")
        .expect("addr")
        .bind()
        .await
        .expect("bind");
    Node::spawn(endpoint)
}

fn swarm(n: u8, secret: [u8; 32]) -> Swarm {
    let cfg = Config { presence_interval: Some(1_000), ..Config::default() };
    let mut s = Swarm::new(SwarmKey::from_secret(&secret), Identity::from_secret([n; 32]), cfg, n as u64);
    s.assume_fresh();
    s
}

async fn wait_until(what: &str, secs: u64, mut done: impl FnMut() -> bool) {
    for _ in 0..secs * 20 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

fn introduce(h: &SwarmHandle, to: &Node) {
    let (id, hint) = (to.peer_id(), encode_hint(&to.addr()));
    h.with(|s, _| s.add_peer(id, hint));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_nodes_sync_over_quic() {
    let secret = [7u8; 32];
    let nodes = [node(1).await, node(2).await, node(3).await];
    let handles: Vec<SwarmHandle> = nodes.iter().enumerate().map(|(i, n)| n.add(swarm(i as u8 + 1, secret))).collect();
    // Star: 2 and 3 only know 1.
    introduce(&handles[1], &nodes[0]);
    introduce(&handles[2], &nodes[0]);
    for (i, h) in handles.iter().enumerate() {
        for k in 0..20 {
            h.with(|s, now| s.publish(format!("node {i} msg {k}").into_bytes(), now)).expect("publish");
        }
    }
    wait_until("convergence", 20, || handles.iter().all(|h| h.read(|s| s.len()) == 60)).await;
    // 2 and 3 found each other through peer exchange.
    wait_until("a full mesh", 20, || handles[1].read(|s| s.neighbors().len()) == 2).await;
    // Live delivery.
    let start = std::time::Instant::now();
    let e = handles[2].with(|s, now| s.publish(b"live".to_vec(), now)).expect("publish");
    wait_until("live entry", 5, || handles.iter().all(|h| h.read(|s| s.vector().get(&e.author)) == e.seq)).await;
    assert!(start.elapsed() < Duration::from_secs(1), "took {:?}", start.elapsed());
    // Presence.
    let now = murmur_iroh::now_ms();
    wait_until("presence", 10, || handles[0].read(|s| s.online(now).len()) == 2).await;
    for n in nodes {
        n.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_without_the_swarm_gets_nothing() {
    let a = node(11).await;
    let b = node(12).await;
    let ha = a.add(swarm(11, [1; 32]));
    let hb = b.add(swarm(12, [2; 32])); // another swarm
    ha.with(|s, now| s.publish(b"private".to_vec(), now)).expect("publish");
    introduce(&hb, &a);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(hb.read(|s| s.len()), 0);
    assert!(hb.read(|s| s.neighbors().is_empty()));
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_big_backlog_streams_over() {
    let secret = [9u8; 32];
    let a = node(21).await;
    let b = node(22).await;
    let ha = a.add(swarm(21, secret));
    let payload = vec![1u8; 500];
    ha.with(|s, now| {
        for _ in 0..5_000 {
            s.publish(payload.clone(), now).expect("publish");
        }
    });
    let start = std::time::Instant::now();
    let hb = b.add(swarm(22, secret));
    introduce(&hb, &a);
    wait_until("backlog", 30, || hb.read(|s| s.len()) == 5_000).await;
    eprintln!("5000 entries (2.5 MB) in {:?}", start.elapsed());
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_node_reconnects() {
    let secret = [3u8; 32];
    let a = node(31).await;
    let ha = a.add(swarm(31, secret));
    let b = node(32).await;
    let hb = b.add(swarm(32, secret));
    introduce(&hb, &a);
    ha.with(|s, now| s.publish(b"one".to_vec(), now)).expect("publish");
    wait_until("first sync", 10, || hb.read(|s| s.len()) == 1).await;
    // b goes away; a keeps writing; b comes back on a new port with its data.
    let saved: Vec<murmur::Entry> = hb.read(|s| s.since(&murmur::Vector::new(), usize::MAX).into_iter().map(|e| (*e).clone()).collect());
    b.shutdown().await;
    ha.with(|s, now| s.publish(b"two".to_vec(), now)).expect("publish");
    let b = node(32).await;
    let mut s = Swarm::new(SwarmKey::from_secret(&secret), Identity::from_secret([32; 32]), Config::default(), 5);
    s.restore(saved, true);
    let hb = b.add(s);
    introduce(&hb, &a);
    wait_until("resync", 15, || hb.read(|s| s.len()) == 2).await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn knocks_are_answered_refused_or_withdrawn() {
    let member = node(41).await;
    let newcomer = node(42).await;
    let addr = || murmur_iroh::iroh::EndpointAddr::from_parts(member.endpoint().id(), member.addr().addrs);
    // Accepted.
    let ask = tokio::spawn({
        let ep = newcomer.endpoint().clone();
        let to = addr();
        async move {
            let n = Node::spawn(ep);
            let r = n.knock(to, b"let me in".to_vec(), Duration::from_secs(10)).await;
            (r, n)
        }
    });
    let mut req = None;
    wait_until("knock", 10, || {
        for e in member.take_knock_events() {
            if let murmur_iroh::KnockEvent::Arrived(r) = e {
                req = Some(r);
            }
        }
        req.is_some()
    })
    .await;
    let req = req.expect("knock");
    assert_eq!(req.peer, newcomer.peer_id(), "the knocker's id is authenticated");
    assert_eq!(req.body, b"let me in");
    member.answer_knock(req.id, Some(b"welcome".to_vec()));
    let (r, n) = ask.await.expect("task");
    assert_eq!(r, Ok(Some(b"welcome".to_vec())));
    // Refused.
    let to = addr();
    let refuse = tokio::spawn({
        let ep = n.endpoint().clone();
        async move { Node::spawn(ep).knock(to, b"again".to_vec(), Duration::from_secs(10)).await }
    });
    let mut id = None;
    wait_until("second knock", 10, || {
        for e in member.take_knock_events() {
            if let murmur_iroh::KnockEvent::Arrived(r) = e {
                id = Some(r.id);
            }
        }
        id.is_some()
    })
    .await;
    member.answer_knock(id.expect("id"), None);
    assert_eq!(refuse.await.expect("task"), Ok(None));
    // Withdrawn: the knocker gives up.
    let to = addr();
    let r = n.knock(to, b"impatient".to_vec(), Duration::from_millis(500)).await;
    assert!(r.is_err());
    wait_until("withdrawn", 10, || member.take_knock_events().iter().any(|e| matches!(e, murmur_iroh::KnockEvent::Withdrawn(_)))).await;
    member.shutdown().await;
}
