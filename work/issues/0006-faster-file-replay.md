---
status: todo
type: debt
created: 2026-10-16
---
# Faster replay and catch-up from FileStorage

## Problem
On `FileStorage`, `Swarm::replay` and `since` of old entries cost ~0.7 µs per entry (one
positioned read each): 1M entries replay in ~0.7 s, against ~0.35 s to parse and restore the same
log fully in memory. Startup folds of big teams on desktop pay this.

## Notes
- Authors' entries are interleaved in the file, so a per-author walk can't read sequentially.
- Options: a `Storage::scan` (whole file in file order, for folds that don't need per-author
  order); reading a run of nearby records in one read; app snapshots (0001's note) so startup
  doesn't fold everything.
