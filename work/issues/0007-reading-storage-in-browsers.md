---
status: todo
type: idea
created: 2026-10-16
---
# A reading storage for browsers

## Problem
`Storage::read` is synchronous (ADR 0002). On a web page, OPFS is async; synchronous access
handles exist only in dedicated workers. So web apps keep every entry in memory (packed, ~payload
+ 66 B each) and phones gain nothing from the window.

## Notes
- Run the swarm in a worker with an OPFS sync access handle, and a `FileStorage`-like storage on
  it; or make reads async (much more protocol code, see ADR 0002's options).
