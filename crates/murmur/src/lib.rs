#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]

//! # Murmur
//!
//! Eventually consistent replication of **signed, append-only, per-author logs** among any number
//! of peers, with no server. Every peer ends up with every entry, whatever order things happen in,
//! as long as the peers that are online stay (indirectly) connected now and then.
//!
//! Murmur is **sans-IO**: [`Swarm`] is a state machine. The caller feeds it what happened
//! (a connection opened, bytes arrived, time passed) and carries out what it asks for
//! ([`Action`]: send a message, dial a peer, close a connection). That makes the protocol fully
//! deterministic and testable; see the `sim` feature for the network simulator, and the
//! `murmur-iroh` crate for the driver that runs it over iroh (QUIC), natively and in browsers.
//!
//! ## How it works (see `docs/murmur.md` for the full protocol)
//!
//! - **Entries.** An author appends entries `seq = 1, 2, 3…` with no gaps, each signed with the
//!   author's ed25519 key over the swarm id. Holding `seq = n` of an author implies holding
//!   `1..n`, so a peer's whole state is summed up by a [`Vector`] (author → highest seq).
//! - **Overlay.** Each peer keeps a few connections (`target_degree`) to random known peers,
//!   accepts up to `max_degree`, and now and then drops one link for another random peer so the
//!   graph keeps mixing and partitions heal. Peers learn about each other from bootstrap
//!   addresses, from the authors in the logs, and from peer exchange.
//! - **Eager push.** A new entry is sent at once to every neighbour that doesn't have it yet:
//!   delivery takes about (overlay diameter × link latency).
//! - **Anti-entropy.** Neighbours compare a digest of their vectors every `ae_interval`; when they
//!   differ, they swap vectors and send each other exactly what is missing, in windows. This is
//!   what makes the system eventually consistent after loss, churn, partitions and restarts.
//! - **Flashes.** Small signed messages that are flooded but not stored: presence (who is
//!   online) and application signals such as "typing…".
//! - **Hostile input.** Connections must prove knowledge of the swarm secret before anything is
//!   sent; every entry and flash signature is checked; sizes are capped; a peer that sends
//!   something invalid is disconnected and banned for a while. Nothing panics on input.

mod entry;
mod id;
mod logs;
mod rng;
mod swarm;
mod vector;
pub mod wire;

#[cfg(feature = "sim")]
pub mod sim;
#[cfg(feature = "sim")]
pub use rng::Rng;

pub use entry::{Entry, Flash, FlashKind};
pub use id::{Identity, PeerId, SwarmId, SwarmKey, verify};
pub use swarm::{Action, CloseReason, Config, ConnId, Event, PublishError, Restored, Stats, Storage, Swarm};
pub use vector::Vector;
pub use wire::Message;

/// The protocol version spoken by this crate (sent in `Hello`).
pub const PROTOCOL_VERSION: u16 = 1;

/// Hard limits on what a peer accepts. Anything bigger is a protocol error.
pub mod limits {
    /// Largest encoded message (a frame).
    pub const MAX_MESSAGE: usize = 4 * 1024 * 1024;
    /// Largest entry or flash payload.
    pub const MAX_PAYLOAD: usize = 64 * 1024;
    /// Most entries in one `Entries` message.
    pub const MAX_ENTRIES_PER_MESSAGE: usize = 4096;
    /// Most peers in one `Peers` message.
    pub const MAX_PEERS_PER_MESSAGE: usize = 64;
    /// Most authors in a vector.
    pub const MAX_VECTOR: usize = 100_000;
    /// Largest address hint.
    pub const MAX_HINT: usize = 256;
}
