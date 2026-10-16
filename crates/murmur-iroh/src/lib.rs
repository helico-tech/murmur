#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]

//! Runs [murmur] swarms over [iroh]: QUIC connections between peers addressed by public key,
//! with hole punching and relay fallback. Works natively (tokio) and in browsers (wasm, through
//! relays only).
//!
//! One [`Node`] owns an iroh endpoint and hosts any number of swarms. Each murmur connection is
//! one QUIC connection with one bidirectional stream:
//!
//! - the dialler first writes a preface: `b"MUR1"` and the 32-byte swarm id;
//! - then both sides send frames: a 4-byte big-endian length and one encoded murmur message.
//!
//! Closing is graceful: the stream is finished and the peer gets everything already queued
//! (murmur relies on that, e.g. for the peer suggestions sent before a "busy" close).
//!
//! A second protocol, **knock** (ALPN `murmur-knock/1`, see [`knock`]), lets someone who is not
//! (yet) in a swarm ask a peer for something (an app can use it, e.g., to ask to be let in) and wait
//! for a person to answer.
//!
//! The application keeps a [`SwarmHandle`] per swarm: [`SwarmHandle::with`] gives it the
//! [`murmur::Swarm`] to publish or read, then carries out whatever the swarm asked for.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId, TransportAddr};
use murmur::{Action, ConnId, PeerId, Swarm, SwarmId, limits};
use n0_future::time::{sleep, timeout};
use tokio::sync::mpsc;

pub mod knock;

pub use iroh;
pub use knock::{KNOCK_ALPN, KnockEvent, KnockRequest};
pub use murmur;

/// The ALPN of the murmur protocol over iroh.
pub const ALPN: &[u8] = b"murmur/1";
const MAGIC: &[u8; 4] = b"MUR1";
/// How often each swarm's `tick` runs.
const TICK: Duration = Duration::from_millis(200);
/// How often our address hint is refreshed.
const HINT_EVERY: u64 = 10_000;
const PREFACE_TIMEOUT: Duration = Duration::from_secs(10);
const DIAL_TIMEOUT: Duration = Duration::from_secs(20);
const CLOSE_GRACE: Duration = Duration::from_secs(3);
/// Frames queued for one connection before it counts as too slow and is closed.
const LINK_QUEUE: usize = 4096;

/// Unix time in ms (works in browsers too).
pub fn now_ms() -> u64 {
    n0_future::time::SystemTime::now().duration_since(n0_future::time::SystemTime::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The murmur peer id of an iroh endpoint id (the same ed25519 key).
pub fn peer_id(id: EndpointId) -> PeerId {
    PeerId(*id.as_bytes())
}

/// The iroh endpoint id of a murmur peer, if the key is valid.
pub fn endpoint_id(peer: PeerId) -> Option<EndpointId> {
    EndpointId::from_bytes(&peer.0).ok()
}

/// Encodes how to reach an endpoint (relay first, then direct addresses) into a murmur hint.
pub fn encode_hint(addr: &EndpointAddr) -> Vec<u8> {
    let mut addrs: Vec<TransportAddr> = addr.addrs.iter().filter(|a| a.is_relay()).cloned().collect();
    addrs.extend(addr.addrs.iter().filter(|a| a.is_ip()).cloned());
    loop {
        let bytes = postcard::to_stdvec(&addrs).unwrap_or_default();
        if bytes.len() <= limits::MAX_HINT || addrs.is_empty() {
            return if addrs.is_empty() { Vec::new() } else { bytes };
        }
        addrs.pop();
    }
}

/// Decodes a hint; junk gives no addresses. Relay names lose a trailing dot (see [`relay_map`]).
pub fn decode_hint(hint: &[u8]) -> Vec<TransportAddr> {
    if hint.is_empty() || hint.len() > limits::MAX_HINT {
        return Vec::new();
    }
    let addrs: Vec<TransportAddr> = postcard::from_bytes(hint).unwrap_or_default();
    addrs
        .into_iter()
        .map(|a| match a {
            TransportAddr::Relay(url) => TransportAddr::Relay(undotted(&url)),
            other => other,
        })
        .collect()
}

/// n0's public relays (iroh's defaults), named without the trailing dot (see [`relay_map`]).
pub fn n0_relays() -> Vec<iroh::RelayUrl> {
    iroh::defaults::prod::default_relay_map().urls::<Vec<iroh::RelayUrl>>().iter().map(undotted).collect()
}

/// A relay map for an endpoint: `relays` (e.g. [`n0_relays`], or your own), named without a
/// trailing dot. iroh names n0's relays `…iroh.link.`; Safari's WebKit, which every iOS browser
/// uses, checks the relay's TLS certificate against the name with the dot and refuses it. Use the
/// same map for every endpoint of an app, so all peers name the same relays the same way.
pub fn relay_map(relays: &[iroh::RelayUrl]) -> iroh::RelayMap {
    iroh::RelayMap::from_iter(relays.iter().map(undotted))
}

/// A relay URL without a trailing dot in its host name.
pub fn undotted(url: &iroh::RelayUrl) -> iroh::RelayUrl {
    match url.host_str() {
        Some(h) if h.len() > 1 && h.ends_with('.') => {
            let mut u = (**url).clone();
            match u.set_host(Some(h.trim_end_matches('.'))) {
                Ok(()) => iroh::RelayUrl::from(u),
                Err(_) => url.clone(),
            }
        }
        _ => url.clone(),
    }
}

type OnChange = Arc<dyn Fn(SwarmId) + Send + Sync>;

/// Runs tasks on the runtime the node was started in, from any thread (a UI thread has no
/// tokio context of its own).
#[derive(Clone, Debug)]
pub struct Spawner {
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    rt: tokio::runtime::Handle,
}

impl Spawner {
    /// The current runtime. Natively this must be called inside tokio.
    pub fn current() -> Spawner {
        Spawner {
            #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
            rt: tokio::runtime::Handle::current(),
        }
    }

    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    pub fn spawn<F: std::future::Future<Output = ()> + Send + 'static>(&self, f: F) {
        self.rt.spawn(f);
    }

    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    pub fn spawn<F: std::future::Future<Output = ()> + 'static>(&self, f: F) {
        n0_future::task::spawn(f);
    }
}

struct Shared {
    endpoint: Endpoint,
    swarms: Mutex<HashMap<SwarmId, Arc<Slot>>>,
    next_conn: AtomicU64,
    on_change: Mutex<Option<OnChange>>,
    knocks: knock::Knocks,
    spawner: Spawner,
}

enum Out {
    Frame(Vec<u8>),
}

struct Slot {
    id: SwarmId,
    swarm: Mutex<Swarm>,
    links: Mutex<HashMap<ConnId, mpsc::Sender<Out>>>,
    closed: AtomicBool,
    shared: std::sync::Weak<Shared>,
}

/// The application's handle on one hosted swarm.
#[derive(Clone)]
pub struct SwarmHandle {
    slot: Arc<Slot>,
}

impl std::fmt::Debug for SwarmHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SwarmHandle({})", self.slot.id.short())
    }
}

impl SwarmHandle {
    pub fn id(&self) -> SwarmId {
        self.slot.id
    }

    /// Runs `f` on the swarm with the current time, then carries out what it asked for (sends,
    /// dials, closes). Use it to publish, flash, add peers.
    pub fn with<R>(&self, f: impl FnOnce(&mut Swarm, u64) -> R) -> R {
        let r = {
            let mut s = lock(&self.slot.swarm);
            f(&mut s, now_ms())
        };
        self.slot.pump();
        r
    }

    /// Reads the swarm (no actions follow).
    pub fn read<R>(&self, f: impl FnOnce(&Swarm) -> R) -> R {
        f(&lock(&self.slot.swarm))
    }

    pub fn is_closed(&self) -> bool {
        self.slot.closed.load(Ordering::Relaxed)
    }
}

/// An iroh endpoint hosting murmur swarms.
pub struct Node {
    shared: Arc<Shared>,
    router: Router,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Node({})", self.shared.endpoint.id().fmt_short())
    }
}

impl Node {
    /// Starts accepting murmur connections on `endpoint`. Must run inside a tokio runtime
    /// (natively) or a wasm-bindgen executor (browser).
    pub fn spawn(endpoint: Endpoint) -> Node {
        let shared = Arc::new(Shared {
            endpoint: endpoint.clone(),
            swarms: Mutex::default(),
            next_conn: AtomicU64::new(1),
            on_change: Mutex::default(),
            knocks: knock::Knocks::default(),
            spawner: Spawner::current(),
        });
        let router = Router::builder(endpoint)
            .accept(ALPN, Acceptor { shared: Arc::downgrade(&shared) })
            .accept(KNOCK_ALPN, knock::KnockAcceptor { knocks: shared.knocks.clone() })
            .spawn();
        Node { shared, router }
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.shared.endpoint
    }

    /// Spawns on the node's runtime (works from any thread).
    pub fn spawner(&self) -> Spawner {
        self.shared.spawner.clone()
    }

    pub fn peer_id(&self) -> PeerId {
        peer_id(self.shared.endpoint.id())
    }

    /// How to reach this node, for invites.
    pub fn addr(&self) -> EndpointAddr {
        self.shared.endpoint.addr()
    }

    /// Called (from a network task) after a swarm produced events, e.g. to repaint a UI.
    pub fn on_change(&self, f: impl Fn(SwarmId) + Send + Sync + 'static) {
        *lock(&self.shared.on_change) = Some(Arc::new(f));
    }

    /// Called (from a network task) when a knock arrives or is withdrawn.
    pub fn on_knock(&self, f: impl Fn() + Send + Sync + 'static) {
        self.shared.knocks.set_wake(Arc::new(f));
    }

    /// Knocks that arrived or were withdrawn since the last call.
    pub fn take_knock_events(&self) -> Vec<KnockEvent> {
        self.shared.knocks.take_events()
    }

    /// Answers a knock: `Some(bytes)` sends them, `None` refuses. Unknown ids are ignored.
    pub fn answer_knock(&self, id: u64, reply: Option<Vec<u8>>) {
        self.shared.knocks.answer(id, reply);
    }

    /// Knocks at `to` with `body` and waits up to `wait` for an answer: `Ok(Some(reply))`,
    /// `Ok(None)` when refused, `Err` when unreachable or nobody answered in time.
    pub async fn knock(&self, to: EndpointAddr, body: Vec<u8>, wait: Duration) -> Result<Option<Vec<u8>>, String> {
        knock::knock(&self.shared.endpoint, to, body, wait).await
    }

    /// Hosts `swarm`. Its identity must be this endpoint's key.
    pub fn add(&self, mut swarm: Swarm) -> SwarmHandle {
        let id = swarm.swarm_id();
        if let Some(old) = self.get(&id) {
            return old;
        }
        swarm.set_hint(encode_hint(&self.shared.endpoint.addr()));
        let slot = Arc::new(Slot {
            id,
            swarm: Mutex::new(swarm),
            links: Mutex::default(),
            closed: AtomicBool::new(false),
            shared: Arc::downgrade(&self.shared),
        });
        lock(&self.shared.swarms).insert(id, slot.clone());
        let ticker = slot.clone();
        self.shared.spawner.spawn(async move { ticker.run_ticks().await });
        SwarmHandle { slot }
    }

    pub fn get(&self, id: &SwarmId) -> Option<SwarmHandle> {
        lock(&self.shared.swarms).get(id).map(|slot| SwarmHandle { slot: slot.clone() })
    }

    pub fn swarms(&self) -> Vec<SwarmHandle> {
        lock(&self.shared.swarms).values().map(|slot| SwarmHandle { slot: slot.clone() }).collect()
    }

    /// Stops hosting a swarm and closes its connections. Returns the swarm.
    pub fn remove(&self, id: &SwarmId) -> Option<SwarmHandle> {
        let slot = lock(&self.shared.swarms).remove(id)?;
        slot.closed.store(true, Ordering::Relaxed);
        lock(&slot.swarm).close_all();
        slot.pump();
        Some(SwarmHandle { slot })
    }

    /// The network changed (wake from sleep, new Wi-Fi): retry all peers now.
    pub fn network_changed(&self) {
        let now = now_ms();
        for slot in lock(&self.shared.swarms).values() {
            lock(&slot.swarm).network_changed(now);
        }
    }

    /// Closes all swarms and the endpoint.
    pub async fn shutdown(self) {
        let ids: Vec<SwarmId> = lock(&self.shared.swarms).keys().copied().collect();
        for id in ids {
            self.remove(&id);
        }
        sleep(Duration::from_millis(100)).await;
        let _ = self.router.shutdown().await;
    }
}

impl Slot {
    async fn run_ticks(self: Arc<Self>) {
        let mut last_hint = 0u64;
        loop {
            sleep(TICK).await;
            if self.closed.load(Ordering::Relaxed) {
                return;
            }
            let now = now_ms();
            {
                let mut s = lock(&self.swarm);
                if now >= last_hint + HINT_EVERY
                    && let Some(shared) = self.shared.upgrade()
                {
                    s.set_hint(encode_hint(&shared.endpoint.addr()));
                    last_hint = now;
                }
                s.tick(now);
            }
            self.pump();
        }
    }

    /// Carries out the swarm's actions until there are none, then reports events.
    fn pump(self: &Arc<Self>) {
        loop {
            let (actions, events) = {
                let mut s = lock(&self.swarm);
                let a: Vec<Action> = std::iter::from_fn(|| s.poll_action()).collect();
                (a, s.has_events())
            };
            if actions.is_empty() {
                if events && let Some(shared) = self.shared.upgrade() {
                    let cb = lock(&shared.on_change).clone();
                    if let Some(cb) = cb {
                        cb(self.id);
                    }
                }
                return;
            }
            let mut dead = Vec::new();
            for a in actions {
                match a {
                    Action::Send { conn, msg } => {
                        let bytes = murmur::wire::encode(&msg);
                        let links = lock(&self.links);
                        if let Some(tx) = links.get(&conn)
                            && tx.try_send(Out::Frame(bytes)).is_err()
                        {
                            dead.push(conn);
                        }
                    }
                    Action::Dial { peer, hint } => {
                        if !self.closed.load(Ordering::Relaxed)
                            && let Some(shared) = self.shared.upgrade()
                        {
                            let slot = self.clone();
                            shared.spawner.spawn(async move { slot.dial(peer, hint).await });
                        }
                    }
                    Action::Close { conn, .. } => {
                        // Dropping the sender ends the writer, which finishes the stream
                        // gracefully once everything queued is written.
                        lock(&self.links).remove(&conn);
                    }
                }
            }
            if !dead.is_empty() {
                let now = now_ms();
                let mut s = lock(&self.swarm);
                for c in dead {
                    log::debug!("murmur: connection {c} too slow, closing");
                    lock(&self.links).remove(&c);
                    s.on_disconnected(c, now);
                }
            }
        }
    }

    async fn dial(self: Arc<Self>, peer: PeerId, hint: Vec<u8>) {
        let Some(shared) = self.shared.upgrade() else { return };
        let Some(id) = endpoint_id(peer) else {
            lock(&self.swarm).on_dial_failed(peer, now_ms());
            self.pump();
            return;
        };
        let addr = EndpointAddr::from_parts(id, decode_hint(&hint));
        let swarm_id = self.id;
        let opened = timeout(DIAL_TIMEOUT, async {
            let conn = shared.endpoint.connect(addr, ALPN).await.map_err(|e| e.to_string())?;
            let (mut send, recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
            let mut preface = Vec::with_capacity(36);
            preface.extend_from_slice(MAGIC);
            preface.extend_from_slice(&swarm_id.0);
            send.write_all(&preface).await.map_err(|e| e.to_string())?;
            Ok::<_, String>((conn, send, recv))
        })
        .await;
        drop(shared);
        match opened {
            Ok(Ok((conn, send, recv))) => self.run_link(conn, send, recv, peer, true).await,
            Ok(Err(e)) => {
                log::debug!("murmur: dial {} failed: {e}", peer.short());
                lock(&self.swarm).on_dial_failed(peer, now_ms());
                self.pump();
            }
            Err(_) => {
                log::debug!("murmur: dial {} timed out", peer.short());
                lock(&self.swarm).on_dial_failed(peer, now_ms());
                self.pump();
            }
        }
    }

    /// Runs one connection until it ends: registers it, writes queued frames in a separate
    /// task, and feeds read frames to the swarm.
    async fn run_link(self: Arc<Self>, conn: Connection, send: SendStream, mut recv: RecvStream, peer: PeerId, outbound: bool) {
        let Some(shared) = self.shared.upgrade() else { return };
        let id = shared.next_conn.fetch_add(1, Ordering::Relaxed);
        drop(shared);
        let (tx, rx) = mpsc::channel(LINK_QUEUE);
        lock(&self.links).insert(id, tx);
        lock(&self.swarm).on_connected(id, peer, outbound, now_ms());
        if let Some(shared) = self.shared.upgrade() {
            shared.spawner.spawn(write_frames(rx, send, conn.clone()));
        }
        self.pump();
        while let Ok(frame) = read_frame(&mut recv).await {
            lock(&self.swarm).on_bytes(id, &frame, now_ms());
            self.pump();
        }
        lock(&self.links).remove(&id);
        lock(&self.swarm).on_disconnected(id, now_ms());
        self.pump();
        conn.close(0u32.into(), b"done");
    }
}

async fn read_frame(recv: &mut RecvStream) -> Result<Vec<u8>, String> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > limits::MAX_MESSAGE {
        return Err(format!("bad frame length {len}"));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    Ok(buf)
}

async fn write_frames(mut rx: mpsc::Receiver<Out>, mut send: SendStream, conn: Connection) {
    while let Some(Out::Frame(bytes)) = rx.recv().await {
        let len = (bytes.len() as u32).to_be_bytes();
        if send.write_all(&len).await.is_err() || send.write_all(&bytes).await.is_err() {
            return;
        }
    }
    // The swarm closed this link (or it died): finish the stream so the peer reads what was
    // sent, wait briefly for it to take it, then close.
    let _ = send.finish();
    let _ = timeout(CLOSE_GRACE, send.stopped()).await;
    conn.close(0u32.into(), b"bye");
}

#[derive(Debug)]
struct Acceptor {
    shared: std::sync::Weak<Shared>,
}

impl ProtocolHandler for Acceptor {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let peer = peer_id(conn.remote_id());
        let Ok(Ok((send, mut recv))) = timeout(PREFACE_TIMEOUT, conn.accept_bi()).await else {
            conn.close(1u32.into(), b"no stream");
            return Ok(());
        };
        let mut preface = [0u8; 36];
        if !matches!(timeout(PREFACE_TIMEOUT, recv.read_exact(&mut preface)).await, Ok(Ok(()))) || &preface[..4] != MAGIC {
            conn.close(1u32.into(), b"bad preface");
            return Ok(());
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&preface[4..]);
        let slot = self.shared.upgrade().and_then(|s| lock(&s.swarms).get(&SwarmId(id)).cloned());
        let Some(slot) = slot else {
            conn.close(2u32.into(), b"unknown swarm");
            return Ok(());
        };
        slot.run_link(conn, send, recv, peer, false).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_round_trip_and_stay_small() {
        let id = iroh::SecretKey::from_bytes(&[1; 32]).public();
        let relay: iroh::RelayUrl = "https://euc1-1.relay.n0.iroh.link./".parse().unwrap();
        let mut addr = EndpointAddr::new(id).with_relay_url(relay.clone());
        for i in 0..40u16 {
            addr = addr.with_ip_addr(std::net::SocketAddr::from(([10, 0, (i >> 8) as u8, i as u8], 40_000 + i)));
        }
        let hint = encode_hint(&addr);
        assert!(hint.len() <= limits::MAX_HINT);
        let back = decode_hint(&hint);
        assert_eq!(back.first(), Some(&TransportAddr::Relay(undotted(&relay))), "the relay comes first and survives");
        assert!(back.len() > 5);
        assert!(decode_hint(b"\xff\xff\xff junk").is_empty());
    }

    #[test]
    fn relays_are_named_without_the_trailing_dot() {
        let urls = relay_map(&n0_relays()).urls::<Vec<iroh::RelayUrl>>();
        assert_eq!(urls.len(), 4);
        assert!(urls.iter().all(|u| u.host_str().is_some_and(|h| h.ends_with(".iroh.link"))), "{urls:?}");
        // A hint from an older peer (dotted) comes out undotted.
        let id = iroh::SecretKey::from_bytes(&[1; 32]).public();
        let dotted: iroh::RelayUrl = "https://euc1-1.relay.n0.iroh.link./".parse().unwrap();
        let back = decode_hint(&encode_hint(&EndpointAddr::new(id).with_relay_url(dotted)));
        let plain: iroh::RelayUrl = "https://euc1-1.relay.n0.iroh.link/".parse().unwrap();
        assert_eq!(back, vec![TransportAddr::Relay(plain)]);
        assert!(decode_hint(&[]).is_empty());
    }
}
