---
status: done
type: debt
created: 2026-10-16
---
# A compact binary format for stored entries, and a log file helper

## Problem
Apps store murmur entries as JSON lines (hex author, base64 payload and signature): OpenTeams
measured 459 bytes for a 60-character chat message. Both apps (OpenTeams, Thime) need the same
smaller format, so it belongs here, not in each app's store.

## Notes
- `Entry` ↔ bytes: 32-byte author, varint seq, length-prefixed payload, 64-byte signature.
- A log file helper: length-prefixed records with a CRC each; a torn or damaged tail is cut at the
  last good record (as the JSON stores do now).
- Keep `Entry`, `Storage`, `Swarm::restore`, `since` and `set_storage` as they are (both apps use them).
- Apps then encode their own event payloads compactly (postcard, raw ids) and add a store
  migration step.
- 2026-10-16: `murmur::codec` (`encode_entry`, `decode_entry`, `new_log`, `log_records`, `parse_log`; magic `MRL1`, u32 length, 4-byte BLAKE3 check per record). Apps adopt it with a store migration.
