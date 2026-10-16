//! Knock: a one-question protocol between peers that don't share a swarm (ALPN
//! `murmur-knock/1`). The knocker opens a stream and sends one frame (at most 64 KiB); the
//! receiving application sees a [`KnockRequest`] and answers when it likes (a person may have to
//! decide), with bytes or a refusal (an empty frame). If the knocker gives up, the request is
//! withdrawn ([`KnockEvent::Withdrawn`]). The knocker's id is authenticated by iroh.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr};
use murmur::PeerId;
use n0_future::time::timeout;
use tokio::sync::oneshot;

use crate::{lock, peer_id};

pub const KNOCK_ALPN: &[u8] = b"murmur-knock/1";
/// Largest knock or answer.
pub const MAX_KNOCK: usize = 64 * 1024;
/// Most knocks waiting for an answer at once; more are refused straight away.
const MAX_WAITING: usize = 64;
/// How long a knock may wait for a person to answer.
const MAX_WAIT: Duration = Duration::from_secs(3600);
const READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnockRequest {
    /// Pass this to `Node::answer_knock`.
    pub id: u64,
    /// Who knocks (authenticated).
    pub peer: PeerId,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KnockEvent {
    Arrived(KnockRequest),
    /// The knocker went away before an answer.
    Withdrawn(u64),
}

type Wake = Arc<dyn Fn() + Send + Sync>;

#[derive(Default)]
struct Inner {
    waiting: HashMap<u64, oneshot::Sender<Option<Vec<u8>>>>,
    events: VecDeque<KnockEvent>,
    wake: Option<Wake>,
}

#[derive(Clone, Default)]
pub(crate) struct Knocks {
    inner: Arc<Mutex<Inner>>,
    next: Arc<AtomicU64>,
}

impl std::fmt::Debug for Knocks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Knocks")
    }
}

impl Knocks {
    pub(crate) fn set_wake(&self, wake: Wake) {
        lock(&self.inner).wake = Some(wake);
    }

    pub(crate) fn take_events(&self) -> Vec<KnockEvent> {
        lock(&self.inner).events.drain(..).collect()
    }

    pub(crate) fn answer(&self, id: u64, reply: Option<Vec<u8>>) {
        if let Some(tx) = lock(&self.inner).waiting.remove(&id) {
            let _ = tx.send(reply.filter(|r| !r.is_empty() && r.len() <= MAX_KNOCK));
        }
    }

    fn push(&self, e: KnockEvent) {
        let wake = {
            let mut i = lock(&self.inner);
            if i.events.len() >= 1024 {
                i.events.pop_front();
            }
            i.events.push_back(e);
            i.wake.clone()
        };
        if let Some(w) = wake {
            w();
        }
    }
}

async fn read_frame(recv: &mut RecvStream) -> Result<Vec<u8>, String> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_KNOCK {
        return Err(format!("knock frame too large ({len})"));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    Ok(buf)
}

async fn write_frame(send: &mut SendStream, bytes: &[u8]) -> Result<(), String> {
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await.map_err(|e| e.to_string())?;
    send.write_all(bytes).await.map_err(|e| e.to_string())
}

/// The knocker's side.
pub(crate) async fn knock(endpoint: &Endpoint, to: EndpointAddr, body: Vec<u8>, wait: Duration) -> Result<Option<Vec<u8>>, String> {
    if body.is_empty() || body.len() > MAX_KNOCK {
        return Err("knock must be 1 byte to 64 KiB".into());
    }
    let conn = timeout(Duration::from_secs(20), endpoint.connect(to, KNOCK_ALPN))
        .await
        .map_err(|_| "timed out connecting".to_string())?
        .map_err(|e| e.to_string())?;
    let r = async {
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
        write_frame(&mut send, &body).await?;
        let reply = timeout(wait, read_frame(&mut recv)).await.map_err(|_| "nobody answered in time".to_string())??;
        let _ = send.finish();
        Ok(if reply.is_empty() { None } else { Some(reply) })
    }
    .await;
    conn.close(0u32.into(), b"done");
    r
}

#[derive(Debug, Clone)]
pub(crate) struct KnockAcceptor {
    pub(crate) knocks: Knocks,
}

impl ProtocolHandler for KnockAcceptor {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let peer = peer_id(conn.remote_id());
        let Ok(Ok((mut send, mut recv))) = timeout(READ_TIMEOUT, conn.accept_bi()).await else {
            conn.close(1u32.into(), b"no stream");
            return Ok(());
        };
        let Ok(Ok(body)) = timeout(READ_TIMEOUT, read_frame(&mut recv)).await else {
            conn.close(1u32.into(), b"bad knock");
            return Ok(());
        };
        let id = self.knocks.next.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = oneshot::channel();
        let accepted = {
            let mut i = lock(&self.knocks.inner);
            let ok = !body.is_empty() && i.waiting.len() < MAX_WAITING;
            if ok {
                i.waiting.insert(id, tx);
            }
            ok
        };
        if !accepted {
            let _ = write_frame(&mut send, &[]).await;
            let _ = send.finish();
            conn.close(0u32.into(), b"busy");
            return Ok(());
        }
        self.knocks.push(KnockEvent::Arrived(KnockRequest { id, peer, body }));
        enum Outcome {
            Answer(Option<Vec<u8>>),
            Gone,
        }
        let answer = async { Outcome::Answer(rx.await.ok().flatten()) };
        let gone = async {
            conn.closed().await;
            Outcome::Gone
        };
        let outcome = timeout(MAX_WAIT, n0_future::future::race(answer, gone)).await.unwrap_or(Outcome::Gone);
        match outcome {
            Outcome::Answer(reply) => {
                let _ = write_frame(&mut send, reply.as_deref().unwrap_or(&[])).await;
                let _ = send.finish();
                let _ = timeout(Duration::from_secs(5), send.stopped()).await;
            }
            Outcome::Gone => {
                lock(&self.knocks.inner).waiting.remove(&id);
                self.knocks.push(KnockEvent::Withdrawn(id));
            }
        }
        conn.close(0u32.into(), b"done");
        Ok(())
    }
}
