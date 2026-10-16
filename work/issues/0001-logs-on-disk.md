---
status: todo
type: debt
created: 2026-10-16
---
# Murmur: logs on disk instead of all in memory

## Problem
`Swarm` holds every entry in memory (ADR 0005). Fine for chat, but a large team over years would
use a lot of RAM, and startup replays every entry.

## Notes
- A `LogStore` trait for reads (`get`, `range`) with an in-memory default; the swarm keeps only the
  vector and recent entries.
- Snapshots of app state so startup doesn't fold everything.
