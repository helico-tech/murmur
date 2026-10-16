//! The swarm state machine: one peer's view of one swarm.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;

use crate::entry::{Entry, Flash, FlashKind};
use crate::id::{Identity, PeerId, SwarmId, SwarmKey};
use crate::logs::{Insert, Logs};
use crate::rng::Rng;
use crate::vector::Vector;
use crate::wire::{Message, PeerHint};
use crate::{PROTOCOL_VERSION, limits};

/// A connection, numbered by the transport. Unique for the life of the swarm.
pub type ConnId = u64;

/// Tuning. The defaults suit chat-sized swarms (up to a few hundred peers) on the internet.
/// All times are milliseconds.
#[derive(Clone, Debug)]
pub struct Config {
    /// Connections this peer opens and keeps (at least 3: with fewer, a random overlay falls
    /// apart into islands).
    pub target_degree: usize,
    /// Connections it accepts in total; more are sent peer suggestions and closed (at least
    /// `target_degree + 2`).
    pub max_degree: usize,
    /// How often neighbours compare vector digests.
    pub ae_interval: u64,
    /// How often one link is swapped for a random other peer (keeps the overlay mixing). The
    /// first swap comes after `rotate_start`; the gap doubles up to `rotate_interval`, so a new
    /// peer mixes into the overlay within seconds.
    pub rotate_start: u64,
    pub rotate_interval: u64,
    /// A link younger than this is not rotated away.
    pub rotate_min_age: u64,
    /// After rotating a peer away, wait this long before dialling it again.
    pub rotate_cooldown: u64,
    pub hello_timeout: u64,
    pub dial_timeout: u64,
    /// Back-off after failed dials: `backoff_base * 2^fails`, at most `backoff_max`.
    pub backoff_base: u64,
    pub backoff_max: u64,
    /// After `slow_after` failures in a row a peer is probably offline: try it only every
    /// `backoff_slow`. It dials us itself when it comes back, so nothing is lost but noise
    /// (each try may cost an address lookup).
    pub slow_after: u32,
    pub backoff_slow: u64,
    /// After a working link drops, wait this long before dialling that peer again.
    pub reconnect_delay: u64,
    /// How long a misbehaving peer is refused.
    pub ban: u64,
    /// Most bytes sent in answer to one `Have` (catch-up goes in windows of this size).
    pub catchup_window: usize,
    /// What we ask for from neighbours that aren't our catch-up source (and on connect): enough
    /// for ordinary gaps, small enough that pulling one backlog from several peers stays cheap.
    pub probe_window: usize,
    /// A catch-up source that sends nothing for this long is dropped for another.
    pub source_stall: u64,
    /// Largest `Entries` message we send, in bytes.
    pub batch_bytes: usize,
    /// When a neighbour is behind by more than this many entries of an author, new entries of
    /// that author are not pushed to it; it catches up by pulling instead.
    pub eager_gap: u64,
    /// How often to flood a presence flash; `None` turns presence off.
    pub presence_interval: Option<u64>,
    /// A peer counts as online this long after its last presence flash.
    pub presence_ttl: u64,
    /// Hops a flash may travel.
    pub flash_ttl: u8,
    /// Most peers remembered.
    pub known_limit: usize,
    /// Most peers tracked as online (presence).
    pub online_limit: usize,
    /// A new connection from a peer we have a link with that is older than this replaces it
    /// (the peer reconnected; the old link is likely dead).
    pub stale_link: u64,
    /// Minimum time between two identical `Have`s on one link.
    pub have_retry: u64,
    /// Peers in a `Peers` message.
    pub peers_sample: usize,
    /// Most queued events; older ones are dropped (see [`Swarm::events_dropped`]).
    pub event_limit: usize,
    /// How long a peer's unproven claim that we lost entries of our own log blocks publishing.
    pub claim_grace: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            target_degree: 6,
            max_degree: 12,
            ae_interval: 2_000,
            rotate_start: 3_000,
            rotate_interval: 60_000,
            rotate_min_age: 5_000,
            rotate_cooldown: 120_000,
            hello_timeout: 10_000,
            dial_timeout: 20_000,
            backoff_base: 1_000,
            backoff_max: 30_000,
            slow_after: 6,
            backoff_slow: 120_000,
            reconnect_delay: 2_000,
            ban: 600_000,
            catchup_window: 1 << 20,
            probe_window: 64 << 10,
            source_stall: 5_000,
            batch_bytes: 256 << 10,
            eager_gap: 64,
            presence_interval: Some(15_000),
            presence_ttl: 45_000,
            flash_ttl: 16,
            known_limit: 4096,
            online_limit: 4096,
            stale_link: 10_000,
            have_retry: 1_000,
            peers_sample: 16,
            event_limit: 10_000,
            claim_grace: 30_000,
        }
    }
}

/// Why a connection was closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// Another connection to the same peer is kept instead.
    Duplicate,
    /// We have enough connections; the peer was sent suggestions.
    Busy,
    /// Swapped for another peer to keep the overlay mixing.
    Rotate,
    /// The peer couldn't prove it knows the swarm secret.
    BadProof,
    /// The peer speaks an unsupported protocol version.
    Version,
    /// The peer broke the protocol (bad message, bad signature, over a limit).
    Misbehaved,
    /// No `Hello` in time.
    Timeout,
    SelfConnect,
    /// The peer is banned for misbehaving earlier.
    Banned,
    /// The peer isn't on the allow-list (see [`Swarm::set_allowed`]).
    NotAllowed,
    Shutdown,
}

/// What the transport should do.
#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    Send {
        conn: ConnId,
        msg: Message,
    },
    /// Open a connection to `peer` and report it with [`Swarm::on_connected`] (outbound) or
    /// [`Swarm::on_dial_failed`].
    Dial {
        peer: PeerId,
        hint: Vec<u8>,
    },
    /// Close the connection. The swarm has already forgotten it.
    Close {
        conn: ConnId,
        reason: CloseReason,
    },
}

/// What the application may want to know.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    /// New entries were added (see [`Swarm::revision`] and [`Swarm::since`]).
    Appended {
        count: usize,
    },
    /// A direct link to this peer is up / gone.
    PeerUp(PeerId),
    PeerDown(PeerId),
    /// Someone came online or went offline (see [`Swarm::online`]).
    Presence,
    /// An application flash.
    Flash {
        author: PeerId,
        payload: Vec<u8>,
    },
    /// A peer sent something invalid and was banned for a while.
    Misbehaved {
        peer: PeerId,
        reason: String,
    },
    /// An author signed two different entries with the same seq; the first one seen is kept.
    Conflict {
        author: PeerId,
        seq: u64,
    },
    /// The storage hook failed; the entries are still held in memory.
    StorageFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublishError {
    #[error("payload too large ({0} bytes)")]
    TooLarge(usize),
    /// Peers hold more of our own log than we do (we lost data); publishing now would sign a
    /// second entry with a seq that already exists. Wait until sync restores our log.
    #[error("waiting to recover our own log (have {have}, others have {seen})")]
    Behind { have: u64, seen: u64 },
    /// We hold none of our own entries and haven't synced with any peer yet, so we can't know
    /// our next seq. Call [`Swarm::assume_fresh`] for a new identity, or wait for a peer.
    #[error("not synced yet: connect to a peer first")]
    NotSynced,
}

/// Where accepted entries are persisted. Called once per accepted batch (including our own).
pub trait Storage: Send {
    fn append(&mut self, entries: &[Arc<Entry>]) -> Result<(), String>;
}

/// Counters, for tests and diagnostics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub messages_sent: u64,
    pub entries_sent: u64,
    pub entries_received: u64,
    pub duplicates_received: u64,
    pub flashes_forwarded: u64,
    pub dials: u64,
    pub haves_sent: u64,
    pub digests_sent: u64,
}

/// What [`Swarm::restore`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Restored {
    pub accepted: usize,
    pub rejected: usize,
    pub conflicts: usize,
    /// Entries kept waiting for a gap (storage lost something in between).
    pub waiting: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinkState {
    Handshake { deadline: u64 },
    Active,
}

#[derive(Debug)]
struct Link {
    peer: PeerId,
    outbound: bool,
    state: LinkState,
    opened_at: u64,
    active_at: u64,
    /// A lower bound of what the peer holds: what it told us, sent us, or we sent it.
    known: Vector,
    /// What the peer last said it holds.
    their: Vector,
    got_have: bool,
    last_have: Option<[u8; 32]>,
    last_have_at: u64,
}

#[derive(Clone, Debug, Default)]
struct PeerInfo {
    hint: Vec<u8>,
    fails: u32,
    next_try: u64,
    dialing_until: Option<u64>,
    banned_until: u64,
    last_seen: u64,
}

pub struct Swarm {
    key: SwarmKey,
    me: Identity,
    my_id: PeerId,
    cfg: Config,
    logs: Logs,
    links: BTreeMap<ConnId, Link>,
    peers: BTreeMap<PeerId, PeerInfo>,
    rng: Rng,
    actions: VecDeque<Action>,
    events: VecDeque<Event>,
    events_dropped: u64,
    storage: Option<Box<dyn Storage>>,
    hint: Vec<u8>,
    revision: u64,
    /// The highest seq of our own log seen in a signed entry (proof that we lost data).
    own_seen: u64,
    /// The highest seq of our own log a peer *claimed* in a `Have`, and when. Unproven: it only
    /// blocks publishing for `claim_grace`, so a lying peer can't silence us.
    own_claim: (u64, u64),
    /// We know where our own log ends: we restored some of it, synced with a peer, or were
    /// told the identity is new.
    own_known: bool,
    next_ae: u64,
    next_rotate: u64,
    rotations: u32,
    next_presence: u64,
    last_stamp: u64,
    /// The neighbour we pull a backlog from, and when it last sent us something new.
    source: Option<(ConnId, u64)>,
    /// If set, only these peers may connect (members admitted by the application).
    allowed: Option<BTreeSet<PeerId>>,
    /// Newest flash stamp per author and kind.
    flash_seen: HashMap<(PeerId, FlashKind), u64>,
    /// Online until (presence).
    online_until: BTreeMap<PeerId, u64>,
    stats: Stats,
}

impl std::fmt::Debug for Swarm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Swarm({} as {}, {} entries, {} links)", self.key.id().short(), self.my_id.short(), self.logs.len(), self.links.len())
    }
}

impl Swarm {
    /// A swarm for `me` with the swarm secret's key. `seed` drives its random choices.
    pub fn new(key: SwarmKey, me: Identity, mut cfg: Config, seed: u64) -> Swarm {
        cfg.target_degree = cfg.target_degree.max(3);
        cfg.max_degree = cfg.max_degree.max(cfg.target_degree + 2);
        let my_id = me.id();
        let salt = my_id.0.first_chunk::<8>().map(|b| u64::from_le_bytes(*b)).unwrap_or(0);
        let rng = Rng::new(seed ^ salt);
        let next_rotate = 0;
        Swarm {
            key,
            me,
            my_id,
            cfg,
            logs: Logs::default(),
            links: BTreeMap::new(),
            peers: BTreeMap::new(),
            rng,
            actions: VecDeque::new(),
            events: VecDeque::new(),
            events_dropped: 0,
            storage: None,
            hint: Vec::new(),
            revision: 0,
            own_seen: 0,
            own_claim: (0, 0),
            own_known: false,
            next_ae: 0,
            next_rotate,
            rotations: 0,
            next_presence: 0,
            last_stamp: 0,
            flash_seen: HashMap::new(),
            source: None,
            allowed: None,
            online_until: BTreeMap::new(),
            stats: Stats::default(),
        }
    }

    pub fn set_storage(&mut self, storage: Box<dyn Storage>) {
        self.storage = Some(storage);
    }

    /// How peers can reach us (opaque; sent in `Hello` and passed on in peer exchange).
    pub fn set_hint(&mut self, hint: Vec<u8>) {
        if hint.len() <= limits::MAX_HINT {
            self.hint = hint;
        }
    }

    // ------------------------------------------------------------------ reads

    pub fn id(&self) -> PeerId {
        self.my_id
    }

    pub fn swarm_id(&self) -> SwarmId {
        self.key.id()
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn vector(&self) -> &Vector {
        self.logs.vector()
    }

    /// Number of entries held.
    pub fn len(&self) -> u64 {
        self.logs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.logs.len() == 0
    }

    /// Payload bytes held.
    pub fn bytes(&self) -> usize {
        self.logs.bytes()
    }

    /// Goes up by one every time entries are added.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn get(&self, author: &PeerId, seq: u64) -> Option<&Arc<Entry>> {
        self.logs.get(author, seq)
    }

    /// Entries the holder of `known` lacks (oldest first per author), up to `max`.
    pub fn since(&self, known: &Vector, max: usize) -> Vec<Arc<Entry>> {
        self.logs.since(known, usize::MAX, max)
    }

    /// Entries waiting for a gap to fill.
    pub fn waiting(&self) -> usize {
        self.logs.pending()
    }

    /// Peers we have a working link to.
    pub fn neighbors(&self) -> Vec<PeerId> {
        let set: BTreeSet<PeerId> = self.links.values().filter(|l| l.state == LinkState::Active).map(|l| l.peer).collect();
        set.into_iter().collect()
    }

    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Peers worth remembering across restarts, with their hints (not banned ones). Give them
    /// back with [`Swarm::add_peer`] after a restart, so a peer doesn't forget who is out there.
    pub fn address_book(&self, now: u64) -> Vec<(PeerId, Vec<u8>)> {
        self.peers.iter().filter(|(_, i)| i.banned_until <= now).map(|(p, i)| (*p, i.hint.clone())).collect()
    }

    /// Peers we know of (not counting ourselves).
    pub fn known_peers(&self) -> Vec<PeerId> {
        self.peers.keys().copied().collect()
    }

    /// Whether some linked peer is known to hold `author` up to `seq` (it told us, sent it, or
    /// we sent it over a reliable link).
    pub fn peers_hold(&self, author: &PeerId, seq: u64) -> bool {
        seq == 0 || self.links.values().any(|l| l.state == LinkState::Active && l.known.get(author) >= seq)
    }

    /// One line per link and the catch-up source, for diagnostics.
    pub fn link_report(&self, now: u64) -> Vec<String> {
        let mut v: Vec<String> = self
            .links
            .iter()
            .map(|(c, l)| {
                format!(
                    "conn {c} {} {:?} out={} their={} known={} got_have={} last_have={}ms ago",
                    l.peer.short(),
                    l.state,
                    l.outbound,
                    l.their.total(),
                    l.known.total(),
                    l.got_have,
                    now.saturating_sub(l.last_have_at)
                )
            })
            .collect();
        v.push(format!("source {:?} (now {now}), mine {}", self.source.map(|(c, t)| (c, now.saturating_sub(t))), self.logs.len()));
        v
    }

    /// Our links' view of `peer`: (their total, known total, known per author) — diagnostics.
    pub fn link_view_of(&self, peer: &PeerId) -> Vec<(u64, u64, Vec<(PeerId, u64)>)> {
        self.links
            .values()
            .filter(|l| l.peer == *peer)
            .map(|l| (l.their.total(), l.known.total(), l.known.iter().map(|(a, s)| (*a, *s)).collect()))
            .collect()
    }

    /// What we know about a peer, for diagnostics: `(fails, next_try, banned_until, dialing)`.
    pub fn peer_state(&self, peer: &PeerId) -> Option<(u32, u64, u64, bool)> {
        self.peers.get(peer).map(|i| (i.fails, i.next_try, i.banned_until, i.dialing_until.is_some()))
    }

    /// Peers that are online now: direct neighbours, and peers whose presence flash is recent.
    pub fn online(&self, now: u64) -> Vec<PeerId> {
        let mut set: BTreeSet<PeerId> = self.online_until.iter().filter(|(_, until)| **until > now).map(|(p, _)| *p).collect();
        set.extend(self.links.values().filter(|l| l.state == LinkState::Active).map(|l| l.peer));
        set.into_iter().collect()
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Events dropped because nobody took them (see `Config::event_limit`).
    pub fn events_dropped(&self) -> u64 {
        self.events_dropped
    }

    /// Next thing for the transport to do.
    pub fn poll_action(&mut self) -> Option<Action> {
        self.actions.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn has_actions(&self) -> bool {
        !self.actions.is_empty()
    }

    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }

    // ------------------------------------------------------------------ setup

    /// Loads entries from storage. They are not written back. With `verify`, signatures are
    /// checked (slower; use it when the storage could have been tampered with).
    pub fn restore(&mut self, entries: impl IntoIterator<Item = Entry>, verify: bool) -> Restored {
        let mut r = Restored::default();
        let swarm = self.key.id();
        let mut added = 0;
        for e in entries {
            if e.payload.len() > limits::MAX_PAYLOAD || e.seq == 0 || (verify && !e.verify(&swarm)) {
                r.rejected += 1;
                continue;
            }
            match self.logs.insert(Arc::new(e)) {
                Insert::Appended(v) => {
                    added += v.len();
                    for e in &v {
                        if e.author != self.my_id {
                            self.peers.entry(e.author).or_default();
                        }
                    }
                }
                Insert::Conflict => r.conflicts += 1,
                Insert::Dropped => r.rejected += 1,
                Insert::Duplicate | Insert::Buffered => {}
            }
        }
        r.accepted = added;
        r.waiting = self.logs.pending();
        self.own_seen = self.own_seen.max(self.logs.pending_max(&self.my_id));
        if added > 0 {
            self.revision += 1;
        }
        self.trim_peers();
        r
    }

    /// Restricts connections to these peers (`None`: anyone who proves the swarm secret).
    /// Links to peers no longer allowed are closed; others are refused before any data is sent,
    /// never dialled and never suggested to others.
    pub fn set_allowed(&mut self, allowed: Option<BTreeSet<PeerId>>) {
        self.allowed = allowed;
        let out: Vec<ConnId> = self.links.iter().filter(|(_, l)| !self.is_allowed(&l.peer)).map(|(c, _)| *c).collect();
        for c in out {
            self.close(c, CloseReason::NotAllowed);
        }
    }

    pub fn is_allowed(&self, peer: &PeerId) -> bool {
        self.allowed.as_ref().is_none_or(|a| a.contains(peer))
    }

    /// Declares that this identity has never published in this swarm (a new member), so it may
    /// publish before it has synced with anyone.
    pub fn assume_fresh(&mut self) {
        self.own_known = true;
    }

    /// Whether [`Swarm::publish`] would work now (apart from the payload size).
    pub fn can_publish(&self, now: u64) -> bool {
        let have = self.logs.vector().get(&self.my_id);
        let claim = if now < self.own_claim.1 + self.cfg.claim_grace { self.own_claim.0 } else { 0 };
        (self.own_known || have > 0) && self.own_seen.max(claim) <= have
    }

    /// A peer to try (from an invite, a config file, a previous session).
    pub fn add_peer(&mut self, peer: PeerId, hint: Vec<u8>) {
        if peer == self.my_id {
            return;
        }
        let info = self.peers.entry(peer).or_default();
        if !hint.is_empty() && hint.len() <= limits::MAX_HINT {
            info.hint = hint;
        }
        self.trim_peers();
    }

    pub fn remove_peer(&mut self, peer: &PeerId) {
        self.peers.remove(peer);
    }

    // ------------------------------------------------------------------ app actions

    /// Appends a new entry to our own log and sends it to the neighbours.
    pub fn publish(&mut self, payload: Vec<u8>, now: u64) -> Result<Arc<Entry>, PublishError> {
        if payload.len() > limits::MAX_PAYLOAD {
            return Err(PublishError::TooLarge(payload.len()));
        }
        let have = self.logs.vector().get(&self.my_id);
        if !self.own_known && have == 0 {
            return Err(PublishError::NotSynced);
        }
        let seen = self.own_seen.max(if now < self.own_claim.1 + self.cfg.claim_grace { self.own_claim.0 } else { 0 });
        if seen > have {
            return Err(PublishError::Behind { have, seen });
        }
        let e = Arc::new(Entry::sign(&self.key.id(), &self.me, have + 1, payload));
        if let Insert::Appended(v) = self.logs.insert(e.clone()) {
            self.accepted(v, None, now);
        }
        Ok(e)
    }

    /// Floods an application flash to every online peer (not stored).
    pub fn flash(&mut self, payload: Vec<u8>, now: u64) -> Result<(), PublishError> {
        if payload.len() > limits::MAX_PAYLOAD {
            return Err(PublishError::TooLarge(payload.len()));
        }
        self.send_flash(FlashKind::App, payload, now);
        Ok(())
    }

    /// The machine's network changed or came back (wake from sleep, new Wi-Fi): forget dial
    /// back-offs so peers are tried again right away.
    pub fn network_changed(&mut self, now: u64) {
        for i in self.peers.values_mut() {
            if i.banned_until <= now {
                i.fails = 0;
                i.next_try = now;
            }
        }
    }

    /// Closes every connection (going offline).
    pub fn close_all(&mut self) {
        let conns: Vec<ConnId> = self.links.keys().copied().collect();
        for c in conns {
            self.close(c, CloseReason::Shutdown);
        }
    }

    // ------------------------------------------------------------------ transport input

    /// A connection to `peer` is open (it was authenticated by the transport). `outbound` is
    /// true when we dialled it.
    pub fn on_connected(&mut self, conn: ConnId, peer: PeerId, outbound: bool, now: u64) {
        if self.links.contains_key(&conn) {
            return;
        }
        if outbound && let Some(p) = self.peers.get_mut(&peer) {
            p.dialing_until = None;
        }
        if peer == self.my_id {
            self.actions.push_back(Action::Close { conn, reason: CloseReason::SelfConnect });
            return;
        }
        if self.peers.get(&peer).is_some_and(|p| p.banned_until > now) {
            self.actions.push_back(Action::Close { conn, reason: CloseReason::Banned });
            return;
        }
        if !self.is_allowed(&peer) {
            self.actions.push_back(Action::Close { conn, reason: CloseReason::NotAllowed });
            if outbound {
                self.failed(peer, now);
            }
            return;
        }
        // Two connections to one peer. If ours is old, the peer came back (restart, new
        // network) and our link is probably dead without us knowing yet: the new one wins.
        // Otherwise both dialled at once, and both sides keep the one dialled by the smaller id.
        let canonical = |out: bool| if out { self.my_id < peer } else { peer < self.my_id };
        let existing: Vec<(ConnId, u64)> = self.links.iter().filter(|(_, l)| l.peer == peer).map(|(c, l)| (*c, l.opened_at)).collect();
        if !existing.is_empty() {
            let stale = existing.iter().all(|(_, at)| now >= at + self.cfg.stale_link);
            if stale || canonical(outbound) {
                for (c, _) in existing {
                    self.close(c, CloseReason::Duplicate);
                }
            } else {
                self.actions.push_back(Action::Close { conn, reason: CloseReason::Duplicate });
                return;
            }
        }
        self.links.insert(
            conn,
            Link {
                peer,
                outbound,
                state: LinkState::Handshake { deadline: now + self.cfg.hello_timeout },
                opened_at: now,
                active_at: 0,
                known: Vector::new(),
                their: Vector::new(),
                got_have: false,
                last_have: None,
                last_have_at: 0,
            },
        );
        self.peers.entry(peer).or_default();
        let proof = self.key.proof(&self.my_id, &peer);
        self.send(conn, Message::Hello { version: PROTOCOL_VERSION, proof, hint: self.hint.clone() });
        self.trim_peers();
    }

    /// A dial we asked for failed.
    pub fn on_dial_failed(&mut self, peer: PeerId, now: u64) {
        self.failed(peer, now);
    }

    /// The connection is gone (closed by the peer or the network).
    pub fn on_disconnected(&mut self, conn: ConnId, now: u64) {
        let Some(link) = self.links.remove(&conn) else { return };
        self.link_gone(&link, now);
    }

    /// Bytes of one message arrived. Undecodable input closes the connection and bans the peer.
    pub fn on_bytes(&mut self, conn: ConnId, bytes: &[u8], now: u64) {
        match crate::wire::decode(bytes) {
            Ok(msg) => self.on_message(conn, msg, now),
            Err(e) => self.misbehaved(conn, format!("{e}"), now),
        }
    }

    /// A decoded message arrived.
    pub fn on_message(&mut self, conn: ConnId, msg: Message, now: u64) {
        if let Err(e) = crate::wire::check(&msg) {
            self.misbehaved(conn, e.to_string(), now);
            return;
        }
        let Some(link) = self.links.get(&conn) else { return };
        let peer = link.peer;
        match (link.state, msg) {
            (LinkState::Handshake { .. }, Message::Hello { version, proof, hint }) => {
                if version < PROTOCOL_VERSION {
                    self.close(conn, CloseReason::Version);
                    self.failed(peer, now);
                    return;
                }
                if !self.key.check(&peer, &self.my_id, &proof) {
                    self.ban(conn, peer, "bad proof of the swarm secret".into(), CloseReason::BadProof, now);
                    return;
                }
                self.hello_ok(conn, peer, hint, now);
            }
            (LinkState::Handshake { .. }, _) => self.misbehaved(conn, "message before Hello".into(), now),
            (LinkState::Active, Message::Hello { .. }) => self.misbehaved(conn, "second Hello".into(), now),
            (LinkState::Active, Message::Have { vector, want }) => self.on_have(conn, vector, want, now),
            (LinkState::Active, Message::Digest { hash }) => {
                // While a backlog streams in from our source, other neighbours' digests differ
                // anyway; they ask us if *they* lack something.
                let pulling = self.source.is_some_and(|(c, last)| c != conn && self.links.contains_key(&c) && now < last + self.cfg.source_stall);
                if hash != self.logs.vector().digest() && !pulling {
                    self.maybe_have(conn, now, self.cfg.probe_window);
                }
            }
            (LinkState::Active, Message::Entries { entries }) => self.on_entries(conn, entries, now),
            (LinkState::Active, Message::Peers { peers }) => {
                for p in peers {
                    self.add_peer(p.peer, p.hint);
                }
            }
            (LinkState::Active, Message::Flash(f)) => self.on_flash(conn, f, now),
        }
    }

    /// Time passed. Call it regularly (every 100–500 ms is fine); it times out handshakes and
    /// dials, opens new links, runs anti-entropy, rotates links and sends presence.
    pub fn tick(&mut self, now: u64) {
        // Handshake timeouts.
        let late: Vec<(ConnId, PeerId)> = self
            .links
            .iter()
            .filter_map(|(c, l)| matches!(l.state, LinkState::Handshake { deadline } if deadline <= now).then_some((*c, l.peer)))
            .collect();
        for (c, p) in late {
            self.close(c, CloseReason::Timeout);
            self.failed(p, now);
        }
        // Dial timeouts.
        let stale: Vec<PeerId> = self.peers.iter().filter(|(_, i)| i.dialing_until.is_some_and(|d| d <= now)).map(|(p, _)| *p).collect();
        for p in stale {
            self.failed(p, now);
        }
        self.fill(now);
        if now >= self.next_ae {
            self.next_ae = now + self.rng.jitter(self.cfg.ae_interval, self.cfg.ae_interval / 2);
            let hash = self.logs.vector().digest();
            let conns: Vec<ConnId> = self.links.iter().filter(|(_, l)| l.state == LinkState::Active).map(|(c, _)| *c).collect();
            for c in conns {
                self.stats.digests_sent += 1;
                self.send(c, Message::Digest { hash });
            }
        }
        if self.next_rotate == 0 {
            self.next_rotate = now + self.rng.jitter(self.cfg.rotate_start, self.cfg.rotate_start / 2);
        } else if now >= self.next_rotate {
            self.rotations = self.rotations.saturating_add(1);
            let gap = self.cfg.rotate_start.saturating_mul(1u64 << self.rotations.min(30)).min(self.cfg.rotate_interval);
            self.next_rotate = now + self.rng.jitter(gap, gap / 2);
            self.rotate(now);
        }
        if let Some(every) = self.cfg.presence_interval
            && now >= self.next_presence
        {
            self.next_presence = now + self.rng.jitter(every, every / 4);
            if self.links.values().any(|l| l.state == LinkState::Active) {
                self.send_flash(FlashKind::Presence, Vec::new(), now);
            }
        }
        let before = self.online_until.len();
        self.online_until.retain(|_, until| *until > now);
        if self.online_until.len() != before {
            self.event(Event::Presence);
        }
    }

    // ------------------------------------------------------------------ internals

    fn hello_ok(&mut self, conn: ConnId, peer: PeerId, hint: Vec<u8>, now: u64) {
        let active = self.links.values().filter(|l| l.state == LinkState::Active).count();
        if !self.links.contains_key(&conn) {
            return;
        }
        let info = self.peers.entry(peer).or_default();
        if !hint.is_empty() {
            info.hint = hint;
        }
        info.last_seen = now;
        info.dialing_until = None;
        // Full (counting links that finished their handshake while this one was pending, in
        // either direction): tell the peer about others and let it go.
        if active >= self.cfg.max_degree {
            let peers = self.sample_peers(Some(peer), now);
            self.send(conn, Message::Peers { peers });
            self.close(conn, CloseReason::Busy);
            return;
        }
        info.fails = 0;
        let was_up = self.links.values().any(|l| l.peer == peer && l.state == LinkState::Active);
        let vector = self.logs.vector().clone();
        if let Some(l) = self.links.get_mut(&conn) {
            l.state = LinkState::Active;
            l.active_at = now;
            l.last_have = Some(vector.digest());
            l.last_have_at = now;
        }
        if !was_up {
            self.event(Event::PeerUp(peer));
            self.event(Event::Presence);
        }
        self.stats.haves_sent += 1;
        self.send(conn, Message::Have { vector, want: self.cfg.probe_window as u32 });
        let peers = self.sample_peers(Some(peer), now);
        if !peers.is_empty() {
            self.send(conn, Message::Peers { peers });
        }
    }

    /// Whether `conn` may be (or is) the link we pull a backlog from.
    fn pull_from(&mut self, conn: ConnId, now: u64) -> bool {
        match self.source {
            Some((c, _)) if c == conn => true,
            Some((c, last)) if self.links.contains_key(&c) && now < last + self.cfg.source_stall => false,
            _ => {
                self.source = Some((conn, now));
                true
            }
        }
    }

    /// After hearing from `conn`: if it holds more than we do, ask it for the next window (full
    /// if it is our source, a probe otherwise).
    fn follow_up(&mut self, conn: ConnId, now: u64, gap: bool) {
        let behind = self.links.get(&conn).is_some_and(|l| self.logs.vector().lacks_from(&l.their));
        if behind {
            // Another neighbour is streaming the backlog to us; asking this one too would only
            // bring duplicates. If the source stalls, the next message from here takes over.
            if self.pull_from(conn, now) {
                self.maybe_have(conn, now, self.cfg.catchup_window);
            }
        } else {
            if self.source.is_some_and(|(c, _)| c == conn) {
                self.source = None;
            }
            if gap {
                self.maybe_have(conn, now, self.cfg.probe_window);
            }
        }
    }

    fn on_have(&mut self, conn: ConnId, vector: Vector, want: u32, now: u64) {
        let claim = vector.get(&self.my_id);
        if claim > self.logs.vector().get(&self.my_id) && claim > self.own_claim.0 {
            self.own_claim = (claim, now);
        }
        self.own_known = true;
        let authors: Vec<PeerId> =
            vector.authors().filter(|a| **a != self.my_id && !self.peers.contains_key(a)).take(self.cfg.known_limit).copied().collect();
        let Some(link) = self.links.get_mut(&conn) else { return };
        link.their = vector.clone();
        link.known.merge(&vector);
        link.got_have = true;
        for a in authors {
            self.peers.entry(a).or_default();
        }
        self.trim_peers();
        self.push_missing(conn, (want as usize).clamp(1, self.cfg.catchup_window));
        self.follow_up(conn, now, false);
    }

    fn on_entries(&mut self, conn: ConnId, entries: Vec<Arc<Entry>>, now: u64) {
        let swarm = self.key.id();
        let mut added: Vec<Arc<Entry>> = Vec::new();
        let mut gap = false;
        for e in entries {
            if !e.verify(&swarm) {
                let peer = self.links.get(&conn).map(|l| l.peer);
                if let Some(p) = peer {
                    self.ban(conn, p, format!("bad signature on {}:{}", e.author.short(), e.seq), CloseReason::Misbehaved, now);
                }
                break;
            }
            self.stats.entries_received += 1;
            if let Some(l) = self.links.get_mut(&conn) {
                l.known.raise(e.author, e.seq);
                l.their.raise(e.author, e.seq);
            }
            if e.author == self.my_id {
                self.own_seen = self.own_seen.max(e.seq);
            }
            let (author, seq) = (e.author, e.seq);
            match self.logs.insert(e) {
                Insert::Appended(v) => added.extend(v),
                Insert::Duplicate => self.stats.duplicates_received += 1,
                Insert::Conflict => self.event(Event::Conflict { author, seq }),
                Insert::Buffered | Insert::Dropped => gap = true,
            }
        }
        if !added.is_empty() {
            if let Some((c, last)) = self.source.as_mut()
                && *c == conn
            {
                *last = now;
            }
            self.accepted(added, Some(conn), now);
        }
        self.follow_up(conn, now, gap);
    }

    fn on_flash(&mut self, conn: ConnId, f: Flash, now: u64) {
        if f.author == self.my_id {
            return;
        }
        let key = (f.author, f.kind);
        if self.flash_seen.get(&key).is_some_and(|s| *s >= f.stamp) {
            return;
        }
        if !f.verify(&self.key.id()) {
            if let Some(p) = self.links.get(&conn).map(|l| l.peer) {
                self.ban(conn, p, "bad flash signature".into(), CloseReason::Misbehaved, now);
            }
            return;
        }
        if self.flash_seen.len() >= self.cfg.known_limit * 4 {
            // Forget the stalest half (a flood of throwaway keys can't grow this forever).
            let mut stamps: Vec<u64> = self.flash_seen.values().copied().collect();
            stamps.sort_unstable();
            let cut = stamps.get(stamps.len() / 2).copied().unwrap_or(0);
            self.flash_seen.retain(|_, s| *s > cut);
        }
        self.flash_seen.insert(key, f.stamp);
        match f.kind {
            FlashKind::Presence => {
                let fresh = !self.online_until.get(&f.author).is_some_and(|u| *u > now);
                self.online_until.insert(f.author, now + self.cfg.presence_ttl);
                if self.online_until.len() > self.cfg.online_limit {
                    let first = self.online_until.iter().min_by_key(|(_, u)| **u).map(|(p, _)| *p);
                    if let Some(p) = first {
                        self.online_until.remove(&p);
                    }
                }
                if fresh {
                    self.event(Event::Presence);
                }
                self.peers.entry(f.author).or_default();
                self.trim_peers();
            }
            FlashKind::App => self.event(Event::Flash { author: f.author, payload: f.payload.clone() }),
        }
        if f.ttl > 1 {
            let fwd = Flash { ttl: f.ttl - 1, ..f };
            let conns: Vec<ConnId> = self.links.iter().filter(|(c, l)| **c != conn && l.state == LinkState::Active).map(|(c, _)| *c).collect();
            for c in conns {
                self.stats.flashes_forwarded += 1;
                self.send(c, Message::Flash(fwd.clone()));
            }
        }
    }

    fn send_flash(&mut self, kind: FlashKind, payload: Vec<u8>, now: u64) {
        let stamp = now.max(self.last_stamp + 1);
        self.last_stamp = stamp;
        let f = Flash::sign(&self.key.id(), &self.me, kind, stamp, self.cfg.flash_ttl, payload);
        let conns: Vec<ConnId> = self.links.iter().filter(|(_, l)| l.state == LinkState::Active).map(|(c, _)| *c).collect();
        for c in conns {
            self.send(c, Message::Flash(f.clone()));
        }
    }

    /// New entries are in the log: store them, tell the app, and push them on.
    fn accepted(&mut self, added: Vec<Arc<Entry>>, source: Option<ConnId>, _now: u64) {
        if let Some(s) = self.storage.as_mut()
            && let Err(e) = s.append(&added)
        {
            self.event(Event::StorageFailed(e));
        }
        self.revision += 1;
        self.event(Event::Appended { count: added.len() });
        // First and last new seq per author.
        let mut spans: BTreeMap<PeerId, (u64, u64)> = BTreeMap::new();
        for e in &added {
            let s = spans.entry(e.author).or_insert((e.seq, e.seq));
            s.0 = s.0.min(e.seq);
            s.1 = s.1.max(e.seq);
            if e.author != self.my_id {
                self.peers.entry(e.author).or_default();
            }
        }
        self.trim_peers();
        let conns: Vec<ConnId> =
            self.links.iter().filter(|(c, l)| Some(**c) != source && l.state == LinkState::Active && l.got_have).map(|(c, _)| *c).collect();
        for c in conns {
            let mut out = Vec::new();
            if let Some(l) = self.links.get_mut(&c) {
                for (a, (first, last)) in &spans {
                    let from = l.known.get(a) + 1;
                    if from > *last {
                        continue;
                    }
                    // A neighbour far behind on this author pulls instead.
                    if first.saturating_sub(from) > self.cfg.eager_gap {
                        continue;
                    }
                    out.extend(self.logs.range(a, from, *last));
                    l.known.raise(*a, *last);
                }
            }
            self.send_entries(c, out);
        }
    }

    /// Sends what the peer on `conn` lacks, up to `budget` bytes.
    fn push_missing(&mut self, conn: ConnId, budget: usize) {
        let Some(l) = self.links.get_mut(&conn) else { return };
        let out = self.logs.since(&l.known, budget, usize::MAX);
        for e in &out {
            l.known.raise(e.author, e.seq);
        }
        self.send_entries(conn, out);
    }

    fn send_entries(&mut self, conn: ConnId, entries: Vec<Arc<Entry>>) {
        let mut batch = Vec::new();
        let mut size = 0;
        for e in entries {
            let s = e.wire_size();
            if !batch.is_empty() && (size + s > self.cfg.batch_bytes || batch.len() >= limits::MAX_ENTRIES_PER_MESSAGE) {
                self.stats.entries_sent += batch.len() as u64;
                self.send(conn, Message::Entries { entries: std::mem::take(&mut batch) });
                size = 0;
            }
            size += s;
            batch.push(e);
        }
        if !batch.is_empty() {
            self.stats.entries_sent += batch.len() as u64;
            self.send(conn, Message::Entries { entries: batch });
        }
    }

    /// Sends our vector asking for up to `want` bytes, unless the same one went out very recently.
    fn maybe_have(&mut self, conn: ConnId, now: u64, want: usize) {
        let vector = self.logs.vector();
        let digest = vector.digest();
        let Some(l) = self.links.get_mut(&conn) else { return };
        if l.last_have == Some(digest) && now < l.last_have_at + self.cfg.have_retry {
            return;
        }
        l.last_have = Some(digest);
        l.last_have_at = now;
        let vector = vector.clone();
        self.stats.haves_sent += 1;
        self.send(conn, Message::Have { vector, want: want.min(u32::MAX as usize) as u32 });
    }

    /// Opens links until we have `target_degree` (counting ones being set up).
    fn fill(&mut self, now: u64) {
        let linked: BTreeSet<PeerId> = self.links.values().map(|l| l.peer).collect();
        let dialing = self.peers.values().filter(|p| p.dialing_until.is_some()).count();
        let mut slots = linked.len() + dialing;
        if slots >= self.cfg.target_degree {
            return;
        }
        let mut candidates: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(p, i)| !linked.contains(p) && i.dialing_until.is_none() && i.next_try <= now && i.banned_until <= now && self.is_allowed(p))
            .map(|(p, _)| *p)
            .collect();
        self.rng.shuffle(&mut candidates);
        for peer in candidates {
            if slots >= self.cfg.target_degree {
                break;
            }
            let Some(info) = self.peers.get_mut(&peer) else { continue };
            info.dialing_until = Some(now + self.cfg.dial_timeout);
            let hint = info.hint.clone();
            self.stats.dials += 1;
            self.actions.push_back(Action::Dial { peer, hint });
            slots += 1;
        }
    }

    /// Swaps one long-lived link for another peer, if there is another peer to try.
    fn rotate(&mut self, now: u64) {
        let active: Vec<(ConnId, PeerId)> = self
            .links
            .iter()
            .filter(|(_, l)| l.state == LinkState::Active && l.active_at + self.cfg.rotate_min_age <= now)
            .map(|(c, l)| (*c, l.peer))
            .collect();
        if active.len() < self.cfg.target_degree {
            return;
        }
        let linked: BTreeSet<PeerId> = self.links.values().map(|l| l.peer).collect();
        let spare = self
            .peers
            .iter()
            .any(|(p, i)| !linked.contains(p) && i.dialing_until.is_none() && i.next_try <= now && i.banned_until <= now && self.is_allowed(p));
        if !spare {
            return;
        }
        let Some(&(conn, peer)) = self.rng.pick(&active) else { return };
        let peers = self.sample_peers(Some(peer), now);
        if !peers.is_empty() {
            self.send(conn, Message::Peers { peers });
        }
        self.close(conn, CloseReason::Rotate);
        if let Some(i) = self.peers.get_mut(&peer) {
            i.next_try = now + self.cfg.rotate_cooldown;
        }
        // The replacement is the peer we were linked to least recently (never first), so every
        // known peer gets its turn: a peer that alone bridges to a forgotten group is reached.
        let mut spares: Vec<(u64, u64, PeerId)> = self
            .peers
            .iter()
            .filter(|(p, i)| !linked.contains(p) && i.dialing_until.is_none() && i.next_try <= now && i.banned_until <= now && self.is_allowed(p))
            .map(|(p, i)| (i.last_seen, 0, *p))
            .collect();
        for s in spares.iter_mut() {
            s.1 = self.rng.next_u64();
        }
        spares.sort_unstable();
        if let Some(&(_, _, next)) = spares.first()
            && let Some(info) = self.peers.get_mut(&next)
        {
            info.dialing_until = Some(now + self.cfg.dial_timeout);
            let hint = info.hint.clone();
            self.stats.dials += 1;
            self.actions.push_back(Action::Dial { peer: next, hint });
        }
        self.fill(now);
    }

    fn sample_peers(&mut self, except: Option<PeerId>, now: u64) -> Vec<PeerHint> {
        let mut good: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(p, i)| Some(**p) != except && i.fails <= 3 && i.banned_until <= now && self.is_allowed(p))
            .map(|(p, _)| *p)
            .collect();
        self.rng.shuffle(&mut good);
        good.truncate(self.cfg.peers_sample.min(limits::MAX_PEERS_PER_MESSAGE));
        let mut out: Vec<PeerHint> =
            good.into_iter().map(|p| PeerHint { peer: p, hint: self.peers.get(&p).map(|i| i.hint.clone()).unwrap_or_default() }).collect();
        if out.len() < limits::MAX_PEERS_PER_MESSAGE && Some(self.my_id) != except {
            out.push(PeerHint { peer: self.my_id, hint: self.hint.clone() });
        }
        out
    }

    fn link_gone(&mut self, link: &Link, now: u64) {
        if link.state == LinkState::Active
            && let Some(i) = self.peers.get_mut(&link.peer)
        {
            i.last_seen = now;
        }
        let still_up = self.links.values().any(|l| l.peer == link.peer && l.state == LinkState::Active);
        if link.state == LinkState::Active && !still_up {
            self.event(Event::PeerDown(link.peer));
            self.event(Event::Presence);
        }
        let short_lived = link.state != LinkState::Active || now < link.active_at + 5_000;
        if short_lived {
            self.failed(link.peer, now);
        } else if let Some(i) = self.peers.get_mut(&link.peer) {
            let delay = self.rng.jitter(self.cfg.reconnect_delay, self.cfg.reconnect_delay / 2);
            i.fails = 0;
            i.next_try = i.next_try.max(now + delay);
        }
    }

    fn failed(&mut self, peer: PeerId, now: u64) {
        let Some(i) = self.peers.get_mut(&peer) else { return };
        i.dialing_until = None;
        i.fails = i.fails.saturating_add(1);
        let exp = if i.fails > self.cfg.slow_after {
            self.cfg.backoff_slow
        } else {
            self.cfg.backoff_base.saturating_mul(1u64 << i.fails.min(20)).min(self.cfg.backoff_max)
        };
        let delay = self.rng.jitter(exp, exp / 2);
        i.next_try = i.next_try.max(now + delay);
    }

    fn close(&mut self, conn: ConnId, reason: CloseReason) {
        if let Some(link) = self.links.remove(&conn) {
            let still_up = self.links.values().any(|l| l.peer == link.peer && l.state == LinkState::Active);
            if link.state == LinkState::Active && !still_up {
                self.event(Event::PeerDown(link.peer));
                self.event(Event::Presence);
            }
        }
        self.actions.push_back(Action::Close { conn, reason });
    }

    fn misbehaved(&mut self, conn: ConnId, reason: String, now: u64) {
        let Some(peer) = self.links.get(&conn).map(|l| l.peer) else { return };
        self.ban(conn, peer, reason, CloseReason::Misbehaved, now);
    }

    fn ban(&mut self, conn: ConnId, peer: PeerId, reason: String, close: CloseReason, now: u64) {
        let info = self.peers.entry(peer).or_default();
        info.banned_until = now + self.cfg.ban;
        info.dialing_until = None;
        self.close(conn, close);
        let others: Vec<ConnId> = self.links.iter().filter(|(_, l)| l.peer == peer).map(|(c, _)| *c).collect();
        for c in others {
            self.close(c, close);
        }
        self.event(Event::Misbehaved { peer, reason });
    }

    /// Keeps the peer table under `known_limit`: forgets unlinked peers, worst first.
    fn trim_peers(&mut self) {
        if self.peers.len() <= self.cfg.known_limit {
            return;
        }
        let linked: BTreeSet<PeerId> = self.links.values().map(|l| l.peer).collect();
        let mut drop: Vec<(u32, u64, PeerId)> = self
            .peers
            .iter()
            .filter(|(p, i)| !linked.contains(p) && i.dialing_until.is_none())
            .map(|(p, i)| (i.fails, u64::MAX - i.last_seen, *p))
            .collect();
        drop.sort_unstable_by(|a, b| b.cmp(a));
        let excess = self.peers.len() - self.cfg.known_limit;
        for (_, _, p) in drop.into_iter().take(excess) {
            self.peers.remove(&p);
        }
    }

    fn send(&mut self, conn: ConnId, msg: Message) {
        self.stats.messages_sent += 1;
        self.actions.push_back(Action::Send { conn, msg });
    }

    fn event(&mut self, e: Event) {
        if matches!(e, Event::Presence) && self.events.back() == Some(&Event::Presence) {
            return;
        }
        if let (Event::Appended { count }, Some(Event::Appended { count: last })) = (&e, self.events.back_mut()) {
            *last += count;
            return;
        }
        if self.events.len() >= self.cfg.event_limit {
            self.events.pop_front();
            self.events_dropped += 1;
        }
        self.events.push_back(e);
    }
}
