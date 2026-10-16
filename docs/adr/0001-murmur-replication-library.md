# 0001. Murmur: replication of signed logs among N peers

## Status
(Written in OpenTeams as ADR 0005; moved here with the library on 2026-10-16.)
accepted (2026-10-16)

## Context
OpenTeams needs a robust way for N peers to stay in sync with no server: eventually consistent
whatever happens (loss, churn, partitions, restarts, hostile members), and fast while things are
calm. This is the hardest part of the product and useful beyond it, so it should be its own
library with its own thorough tests, not code inside the app.

Options for the protocol:

| Option | Gains | Costs |
|---|---|---|
| Full mesh (everyone connects to everyone) | Simplest | O(N²) connections; breaks down past a few dozen online peers |
| iroh-gossip (HyParView + PlumTree) | Proven broadcast, small fan-out | Broadcast only: no catch-up for peers that were offline, no storage, no repair |
| **Own: partial-view overlay + eager push + version-vector anti-entropy** | Catch-up and live delivery in one protocol; exact repair in one round trip (vectors are tiny because logs have no gaps); testable in a simulator | We own the code and its tests |
| Automerge/Yjs sync over a mesh | Rich document CRDTs | No signatures per author; sync is pairwise, not N-peer |

## Decision
- `crates/murmur`: a **sans-IO** state machine (`Swarm`): inputs are "connected", "bytes",
  "disconnected", "dial failed", "tick", "publish"; outputs are actions (send, dial, close) and
  events. No sockets, threads or clocks inside, and a seeded random generator, so every run can
  be replayed.
- Protocol as in [docs/murmur.md](../murmur.md): signed per-author logs, version vectors and
  digests, eager push to neighbours, pull-based catch-up in windows, periodic anti-entropy, a
  bounded random overlay with rotation and busy redirection, flooded presence and app flashes,
  bans for misbehaviour, and a guard against signing the same seq twice.
- A deterministic network simulator ships with the crate (feature `sim`) and is the main test
  tool: convergence, speed, cost, hostile peers, and a chaos test over many seeds.
- `crates/murmur-iroh`: the transport over iroh (ADR 0002), the same code natively and in the
  browser. One QUIC connection and stream per swarm link; graceful closes.
- Murmur knows nothing about OpenTeams. OpenTeams puts its own events in entry payloads
  (ADR 0003).

## Consequences
- Supersedes the "full mesh" part of ADR 0002 and the sync part of ADR 0003.
- Speed: in the simulator, 120 peers with 10–60 ms links get a new entry in ~150 ms on average.
- The whole history lives in memory in each `Swarm` (fine for chat volumes; a storage-backed log
  is future work).
- A member can still flood valid entries (no rate limits yet) or equivocate on purpose; both are
  detected but not prevented.
