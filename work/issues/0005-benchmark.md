---
status: todo
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
  100k); Thime busy grocery board (~100k entries in 3 years, 40–90 a day, ~45-byte payloads).
- Measure natively and in the browser (wasm), since phones are the tight case.
