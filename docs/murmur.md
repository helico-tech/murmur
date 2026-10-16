# Murmur protocol

> Last updated: 2026-10-16. Code: `crates/murmur` (sans-IO core and simulator),
> `crates/murmur-iroh` (transport). Decisions: [ADR 0001](adr/0001-murmur-replication-library.md).

Murmur keeps a set of **signed, append-only, per-author logs** the same on every peer of a
**swarm**, with no server. It is eventually consistent: when changes stop and the online peers can
reach each other (directly or through others), they all end up holding exactly the same entries.

## Model

- **Peer**: an ed25519 key pair. The public key is the `PeerId` (and the iroh endpoint id).
- **Swarm**: everyone who knows a 32-byte **swarm secret**. From it come the `SwarmId`
  (`blake3::derive_key("murmur swarm id v1", secret)`) and an auth key
  (`derive_key("murmur swarm auth v1", secret)`).
- **Entry** `{author, seq, payload, sig}`: `seq` is 1, 2, 3… per author with no gaps; payload ≤ 64 KiB.
  The signature covers `"murmur entry v1\0" ‖ swarm id ‖ author ‖ seq ‖ len ‖ payload`.
- **Vector**: author → highest seq held. Because logs have no gaps, a vector sums up exactly what a
  peer holds. Its **digest** is a BLAKE3 hash of the sorted non-zero pairs.
- **Flash** `{author, kind, stamp, ttl, payload, sig}`: flooded, never stored. `stamp` grows per
  author and kind (the sender's clock, forced up by one when needed); older or equal stamps are
  dropped, which also stops replays. `ttl` is lowered on each hop and is not signed.

## Connection

One reliable, ordered byte stream per connection (murmur-iroh: one QUIC bi-stream; the dialler
first writes `"MUR1"` and the swarm id so the receiver can route it). Messages are postcard
encoded, one per frame (4-byte big-endian length), at most 4 MiB.

| Message | Meaning |
|---|---|
| `Hello {version, proof, hint}` | First message from each side. `proof = keyed_blake3(auth, sender ‖ receiver)`. |
| `Have {vector}` | Everything the sender holds. The receiver sends what the sender lacks. |
| `Digest {hash}` | The sender's vector digest. On mismatch the receiver sends `Have`. |
| `Entries {entries}` | Entries, oldest first per author. |
| `Peers {peers}` | Up to 64 `(peer, hint)` pairs. |
| `Flash {…}` | A flash. |

Handshake: both send `Hello` on connect. A receiver checks the version (lower → close, no ban)
and the proof, which is bound to both ids, so it can't be replayed. A wrong proof closes the link
and bans the peer. Nothing but `Hello` goes out before the other side's proof checks out.
The transport authenticates the remote's `PeerId` (iroh does this with TLS raw public keys).

After the handshake each side sends `Have` and a `Peers` sample.

## Sync

Per link we keep `known` — a lower bound of what the peer holds: what it said in `Have`, what it
sent us, and what we sent it (a reliable stream delivers what we send, and holding `seq n`
implies holding `1..n`).

- **Answering `Have`**: send everything above `known`, up to `catchup_window` (1 MiB) per `Have`,
  in `Entries` of at most 256 KiB, authors round-robin. If the peer has things we lack, send our
  own `Have` (not twice with the same digest within `have_retry`).
- **Catch-up** is pull-driven: after each batch the receiver's vector changed, so if the sender
  still has more, the receiver sends `Have` again and gets the next window. One window is in
  flight at a time; nothing is sent twice.
- **Eager push**: an entry we accept (our own or a peer's) goes at once to every neighbour whose
  `known` says it lacks it, except the one it came from. If a neighbour is more than `eager_gap`
  (64) entries behind on that author, it is skipped; it is catching up by pulling anyway.
- **Out-of-order arrival** (a later entry came by a faster path): it waits in a bounded buffer
  (8192 entries; the furthest ahead are dropped first) until the gap fills, and we send `Have` to
  ask for the gap.
- **Anti-entropy**: every `ae_interval` (2 s ± 50%) each peer sends its digest on every link. Any
  difference triggers `Have` and an exact repair. This is the backstop that makes the system
  eventually consistent whatever was lost.

Accepting an entry: the signature must be valid for this swarm (else ban the sender), the payload
within limits, and `seq` the author's next one. A different entry for a `seq` we already hold is
a **conflict**: the first one seen is kept and the app is told.

## Memory

Each author's log is packed: its entries sit back to back in byte chunks, each as
`payload ‖ signature`, with a 2-byte start offset per entry (author and seq are implicit). That is
the payload plus ~66 bytes per entry. Entries are decoded into an `Entry` when asked for (`get`,
`since`, answering a `Have`, eager push); duplicates and conflicts are checked against the stored
bytes. The out-of-order buffer holds whole entries. `Swarm::ram_bytes()` reports the packed size.

**Reading old entries back** (ADR 0002). A `Storage` may say it can read (`can_read`, `heads`,
`read`; the defaults can't). Then:

- The swarm tracks per author the highest seq the storage confirmed (an `Ok` append of a run that
  continues it). Only entries up to there may leave memory; a failed append keeps them in memory.
- It keeps about `ram_window` (256 KiB) of each author's newest entries in memory, in chunks of
  `ram_window / 8` (256 B to 32 KiB), and drops whole older chunks.
- Older entries are read through the storage when needed: answering `Have` (in batches of 64),
  eager push to a neighbour a little behind, duplicate and conflict checks, `get`, `since`.
- `load()` starts a swarm from such a storage: its `heads` become the vector; nothing is read.
  `replay(from, f)` walks the whole log in batches without holding it (use it to fold on start);
  `try_since` returns read errors. `since` and `get` can't: on a failed read they return nothing
  and queue `Event::StorageFailed`.
- `murmur::file::FileStorage` (native) is such a storage on the `codec` log format, with an index
  author/seq → offset and length (8 B per entry) built at open; a torn tail is cut at open.
- A storage that can't read changes nothing: every entry stays in memory, `restore` keeps all
  it is given. Browsers stay there: their storage can't be read synchronously.

## Overlay

- Known peers come from bootstrap hints (invites), every author in the logs, presence flashes and
  `Peers` messages. At most `known_limit` (4096); unlinked peers with most failures go first.
- Each peer keeps `target_degree` (6) links, opening new ones to random eligible peers, and accepts
  up to `max_degree` (12). Past that, a new inbound peer gets a `Peers` sample and is closed
  ("busy"), so newcomers spread out instead of piling onto the inviter.
- **Rotation**: after 3 s, then at doubling gaps up to 60 s, a peer with at least
  `target_degree` links drops a random one (older than 5 s) and dials a random other peer. This
  turns any bootstrap shape (a star of invitees, a ring) into a random graph within seconds, which
  keeps the diameter small and heals partitions.
- **Duplicates**: if two peers dial each other at once, both keep the connection dialled by the
  smaller id.
- **Back-off**: failed dials wait `1 s × 2^fails` (± 50%, at most 30 s). A link that dies after
  working reconnects after ~2 s. `network_changed()` resets all back-offs.
- **Bans**: a peer that breaks the protocol (bad proof, bad signature, bad message, over a limit)
  is closed and refused for 10 minutes.

## Presence

Every `presence_interval` (15 s) a peer with at least one link floods a presence flash
(`ttl` 16). A peer counts as online while it is a neighbour or for `presence_ttl` (45 s) after
its last presence flash. Application flashes (e.g. "typing…") use the same flooding.

## Safety of our own log

A peer must never sign two entries with the same `seq`. So `publish` refuses when:

- we hold none of our own entries and have neither synced with a peer nor been told the identity
  is new (`assume_fresh`) — e.g. a rejoin after local data was deleted (`NotSynced`);
- a peer sent us a signed entry of ours that we don't hold (`Behind`, until it is restored); or
- a peer *claimed* in `Have` to hold more of our log, for at most `claim_grace` (30 s) while we
  ask for it. A bare claim can't silence a peer for longer.

Known limit: if data is lost and the only copies of our newest entries are on peers that are
offline, a later publish can reuse a seq. Peers then report a conflict and keep the first copy
they saw; copies can differ for that one entry.

## Testing

- Unit tests per module (codec fuzzing, packed logs and windows, the log file, vectors, signatures).
- `tests/hostile.rs`: outsiders, forged and cross-swarm entries, protocol violations, lying
  `Have`s, replays, junk peer lists, and a random-abuse loop (nothing panics, limits hold).
- `tests/sim.rs` in the deterministic simulator (virtual time, latency, failing dials, breaking
  links, partitions, churn, restarts, wipes):
  - convergence from star and ring bootstraps; bounded degree; busy redirection;
  - speed: 120 peers, 10–60 ms links: delivery to all in ≤ 300 ms (about 150 ms on average),
    overlay diameter ≤ 6, under 14 messages per peer per publish;
  - idle cost under 400 bytes/s per peer; a 15 000-entry backlog with < 5% duplicates;
  - partitions heal; restarts resume; a wiped peer recovers its log before publishing;
  - **chaos**: random publishes, churn, restarts, partitions and flaky links, then everyone must
    converge with intact, identical data. `MURMUR_CHAOS_SEEDS=1000` (default 24),
    `MURMUR_CHAOS_SEED=n` for one run, `MURMUR_CHAOS_SALT` for a fresh set.
  - reading peers: small windows, a late joiner served from storage, restarts with `load`, a
    wiped reading peer; chaos runs a third of the seeds with some and a third with only reading
    peers (windows of 0–4 KB).
- `tests/file.rs`: swarms on `FileStorage` (window boundary, reopen and `replay`, a peer served
  from the file, a torn file healed by a peer).
- `crates/murmur-iroh/tests/local.rs`: real QUIC endpoints on localhost.
