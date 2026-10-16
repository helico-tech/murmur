---
status: todo
type: idea
created: 2026-10-16
---
# Murmur: rate limits per member

## Problem
Any member can publish (or flash) as fast as they like; every peer stores and forwards it.

## Notes
- Per-link and per-author budgets (entries/s, bytes/s); over budget → stop forwarding that author
  for a while (not a ban: the author may be honest but busy).
