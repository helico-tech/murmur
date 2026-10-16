---
status: done
type: debt
created: 2026-10-16
---
# Murmur: logs on disk instead of all in memory

## Problem
`Swarm` holds every entry in memory (ADR 0001). Fine for chat, but a large team over years would
use a lot of RAM, and startup replays every entry. Measured (0005): ~505 B of RAM per entry for
~200 B payloads; a busy OpenTeams team reaches ~1.8M entries a year. Phones (wasm in a browser)
are the tight case.

## Notes
- Snapshots of app state so startup doesn't fold everything (not part of this work).
- Browsers can't read storage synchronously (OPFS is async on a page; sync access handles exist
  only in workers). Web apps keep everything in memory, so **phase 2 saves RAM on desktop and
  CLI only**; phase 1 (packed logs) is the win on phones.

## Plan
Two phases, one commit each, on branch `memory`.

1. **Packed logs in memory** (all platforms, no API change except `get`, see below). Each author's
   log is a list of byte chunks (~32 KiB) holding `payload ‖ signature` back to back, plus a
   `u16` start offset per entry. The author and seq are implicit. Entries are decoded to
   `Arc<Entry>` when asked for (`get`, `since`, answering peers, eager push). Duplicates and
   conflicts compare against the stored bytes. The out-of-order buffer stays as it is.
   Target: payload + ~70 B per entry. `Swarm::get` must return `Option<Arc<Entry>>` (there is no
   stored `Arc` to borrow); neither app calls it.
2. **Reading logs back from storage** (native). `Storage` gets read methods with defaults
   (`can_read` false, `heads`, `read`), so apps that only `append` behave as today. When the
   storage can read, the swarm drops whole old chunks of an author once the storage holds them
   (it tracks per author the highest seq the storage confirmed) and keeps about
   `Config::ram_window` bytes per author. Older ranges are read through the storage: `since`,
   `get`, answering `Have`, eager push, duplicate checks. New: `Swarm::load` (start from a
   reading storage without passing every entry through memory), `Swarm::replay` (walk the whole
   log without holding it), `Swarm::try_since` (errors instead of short answers),
   `murmur::file::FileStorage` (native-only, the `codec` log format, an in-memory index
   author/seq → file offset, torn tails cut at open). ADR 0002 records the contract.

## Progress log
- 2026-10-16: baseline bench (before): 100k entries 50 MB (504 B/entry), restore 6 ms, since 2 ms;
  1M entries 506 MB (506 B/entry), restore 61 ms, since 25 ms.
- 2026-10-16: phase 1 done. Packed chunks per author (`logs.rs`), `codec::log_entries` to restore
  without a list of every entry, `Swarm::ram_bytes()`. Bench (restore now streams from the log
  bytes, so it includes parsing): 100k entries 26 MB (260 B/entry), restore 34 ms, since 9 ms;
  1M entries 255 MB (255 B/entry, payload ~199 B), restore 342 ms, since 89 ms. `since` is slower
  (it decodes and allocates every entry) but a 1 MiB catch-up window still takes ~0.3 ms.
- 2026-10-16: phase 2 done. `Storage::{can_read, heads, read}` with defaults; `Config::ram_window`;
  `Swarm::{load, replay, try_since}`; `murmur::file::FileStorage`; ADR 0002. Requirements from
  Thime built in: `since` still returns old entries (read through the storage) and never a part
  (on a failed read: nothing plus `StorageFailed`; `try_since` and `replay` return the error);
  `replay` walks everything without holding it; `restore` keeps everything it gets.
  Simulator: `Net::reading`, `Profile::reading`, `MemStorage::reader()`; two new scenarios; chaos
  draws reading peers and windows of 0–4 KB; the fuzzer gives half its scenarios reading peers
  (windows 0–256 KiB) and checks their memory bound. Chaos 1000 seeds: ok (297 s). Fuzz 12 min,
  85 scenarios, 0 failures.
- Follow-ups: [0006](0006-faster-file-replay.md) (replay from the file is ~0.7 µs/entry),
  [0007](0007-reading-storage-in-browsers.md) (browsers). The apps still need to switch their
  desktop stores to a reading storage and fold with `replay` to gain from phase 2.

## Results (2026-10-16, M-series Mac, release build, payload ~200 B, 20 authors)
`cargo run --release -p murmur --example bench -- --entries N --payload 200 [--file]`

| | before | phase 1 (packed) | phase 2 (`FileStorage`) |
|---|---|---|---|
| RAM, 100k entries | 50 MB (504 B/entry) | 26 MB (259 B/entry) | 1.5 MB (15 B/entry) |
| RAM, 1M entries | 506 MB (506 B/entry) | 255 MB (255 B/entry) | 10.5 MB (10 B/entry) |
| start, 1M (parse + restore / open + load) | 268 + 61 ms | 348 ms (streamed) | 286 ms + 0 ms |
| `since()` everything, 1M | 25 ms | 97 ms | 618 ms |
| full fold, 1M (`replay`) | – | 26 ms | 672 ms |
| `since()` of 4096 old entries (a catch-up window) | – | 0.5 ms | 3.2 ms |

- Phase 1 is payload + ~60 B per entry (64 B signature + 2 B offset, author and seq implicit).
- Phase 2 keeps the file index (8 B/entry) plus `ram_window` (256 KiB) per author. Reading old
  entries costs one positioned read each (~0.65 µs).
- Phase 2 is desktop/CLI only; web apps keep the default storage (see Notes).

