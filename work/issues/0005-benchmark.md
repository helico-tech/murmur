---
status: done
type: idea
created: 2026-10-16
---
# Benchmark: disk, memory and load time for big logs

## Problem
Data growth is estimated, not measured. Apps need numbers before choosing logs on disk (0001)
or snapshots.

## Notes
- A harness (example or bench): N entries with a realistic payload mix, written with the store
  format, then: bytes on disk, resident memory of a restored `Swarm`, time to restore and to
  iterate `since()`. Apps add their own fold timing on top.
- Cases: OpenTeams busy team (50 people × 100 messages a day, ~1.8M entries in a year; also
  100k); Thyme busy grocery board (~100k entries in 3 years, 40–90 a day, ~45-byte payloads).
- Measure natively and in the browser (wasm), since phones are the tight case.

## Results (2026-10-16, M-series Mac, release build)
`cargo run --release -p murmur --example bench -- --entries N --payload 200`

| | 100k entries | 1M entries |
|---|---|---|
| JSON lines on disk | 45 MB (448 B/entry) | 449 MB |
| binary log on disk | 31 MB (307 B/entry) | 308 MB |
| parse (JSON / binary) | 32 / 42 ms | 270 / 313 ms |
| restore a `Swarm` / `since()` | 7 / 2 ms | 68 / 28 ms |
| resident memory of the swarm | 50 MB (~505 B/entry) | 506 MB |

- Speed is not the problem; memory is: ~500 B of RAM per entry (payload ~200 B; the rest is
  `Entry` (author 32 + sig 64 + seq + Vec), the `Arc`, and the per-author log maps).
- The binary log is ~1.45× smaller on disk; payloads (the apps' JSON events) are two thirds of it.
- OpenTeams' fold adds ~590 B/event of RAM (0.5 µs/event): ~1.1 KB of RAM per chat message in all.
- So: logs on disk (0001) and smaller in-memory ids matter most; the compact codec (0004) is the
  cheap first step.
