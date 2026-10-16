---
status: todo
type: idea
created: 2026-10-16
---
# Murmur: lazy push to cut duplicate traffic

## Problem
The fuzzer shows ~50% of received entries are duplicates: eager flooding over a degree-6
overlay. PlumTree-style lazy push (send ids, not entries, on non-tree links) would cut this.

## Notes
Measure with the fuzzer's duplicate ratio; keep anti-entropy as the backstop.
