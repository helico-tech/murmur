# 0002. Reading old entries back from storage

## Status
accepted (2026-10-16)

## Context
A `Swarm` held every entry in memory (ADR 0001): ~505 B per entry for ~200 B payloads, so a busy
OpenTeams team (~1.8M entries a year) needed ~900 MB. Two steps fix this:

1. Packed logs (all platforms): each author's log is a list of byte chunks with
   `payload ‖ signature` back to back. About payload + 66 B per entry. No contract change.
2. Old entries out of memory: only possible when the swarm can get them back. The swarm is
   sans-IO, so it may only reach them through the `Storage` the app hands it.

Options for step 2:

| Option | Gains | Costs |
|---|---|---|
| **Read methods on `Storage`, with defaults that can't read** | One object for writing and reading; existing apps compile and behave as before | Reads are synchronous |
| A second trait (`LogReader`) beside `Storage` | Clear split | Two objects to keep in step; apps can pass mismatched ones |
| Async reads (the swarm asks, the app answers later) | Fits browsers (OPFS is async) | Every path that answers a peer becomes a state machine; much more code and tests |

## Decision
`Storage` gets three methods with defaults:

- `can_read() -> bool` (default `false`). Fixed for the life of the storage.
- `heads() -> Result<Vector, String>`: per author, the highest seq of the unbroken run `1..=n` held.
- `read(author, from, max) -> Result<Vec<Entry>, String>`: entries `from, from+1, …` of `author`, in
  order and without gaps, at most `max`. Fewer only at the end of what it holds; empty when it
  doesn't hold `from`. Entries are not re-verified (local data is trusted, as in
  `restore(.., false)`).

Rules on the swarm side:

- A storage that can't read (every app today) changes nothing: the swarm keeps every entry it was
  given, by `restore` or by peers.
- With a storage that can read, the swarm tracks per author the highest seq the storage
  confirmed: it moves only when `append` returns `Ok` for a run that continues it (from 0, or from
  `load`). Entries above it never leave memory. A failed append freezes it for that author (the
  entries stay in memory; `Event::StorageFailed` as before). `set_storage` resets it.
- It then keeps about `Config::ram_window` bytes (default 256 KiB) of each author's newest entries
  in memory and drops whole older chunks. Chunks are `ram_window / 8` bytes (256 B to 32 KiB).
- Older ranges are read through the storage when needed: answering `Have`, eager push to a
  neighbour that is a little behind, checking a duplicate or conflict, `get`, `since`.
- `Swarm::load()` starts a swarm from a reading storage: it takes `heads()` as the vector and reads
  nothing else. `restore` still works but keeps what it gets in memory.
- `Swarm::replay(from, f)` walks the whole log (storage, then memory) without holding it, and
  `Swarm::try_since` returns an error instead of a short answer. `since` and `get` can't return an
  error: on a failed read they return nothing and queue `Event::StorageFailed`. Apps with a reading
  storage should fold with `replay`.
- The swarm still does no I/O itself: every read goes through the app's `Storage`.

`murmur::file::FileStorage` (native only) is a ready reading storage on the `codec` log format: an
in-memory index author/seq → offset and length built at open (8 B per entry), one positioned read
per entry, a torn tail cut at open, gaps written but not indexed.

## Consequences
- Desktop and CLI apps that switch to a reading storage keep ~8 B per entry (the file index) plus
  `ram_window` per author in memory, and start without reading every entry (`load` + `replay`).
- **Browsers don't gain from step 2.** A page can't read storage synchronously (OPFS is async;
  sync access handles exist only in workers), so web apps keep the default storage and everything
  in memory. Phase 1 (packed logs) is the saving on phones.
- Updates ADR 0001's note that the whole history lives in memory.
- `Swarm::get` returns `Option<Arc<Entry>>` instead of `Option<&Arc<Entry>>`: there is no stored
  `Arc` to borrow any more.
- Catch-up from old entries costs disk reads; duplicates of old entries cost one read each.
- `bytes()` after `load` counts only entries added since (the storage doesn't report sizes).
- Swapping a reading storage for another after old entries left memory breaks reads; the new one
  must hold the same log.
