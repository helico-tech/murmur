# murmur: instructions for agents

A replication library for signed append-only logs among N peers (see README.md). Apps
(OpenTeams, Thime) use it as a git dependency pinned to a rev. Keep it app-neutral: nothing about
teams, chat or boards here.

## Build, test
- `cargo test --workspace --features murmur/sim`
- `cargo clippy --workspace --all-targets --features murmur/sim -- -D warnings`, `cargo fmt --all --check`
- `MURMUR_CHAOS_SEEDS=1000 cargo test --release -p murmur --features sim --test sim chaos`
- Fuzzer: `cargo run --release -p murmur --features sim --example fuzz -- --minutes 60` (`--seed N`
  replays, `--soak` one endless swarm); failures go to `target/murmur-fuzz-failures.txt`.
- wasm check: `cargo check -p murmur-iroh --target wasm32-unknown-unknown` (ring needs a clang that
  targets wasm: `CC_wasm32_unknown_unknown=clang`, `AR_wasm32_unknown_unknown=<rustup llvm-ar>`;
  on macOS Homebrew's LLVM).

## Rules
- Never crash: no unwrap/expect/panic outside tests; `unsafe` is forbidden; network input is hostile.
- Protocol or behaviour changes need simulator coverage; run the chaos test and a fuzz session.
- Wire format changes raise the protocol version in `Hello` (peers refuse older, accept newer).
- Public API used by apps: `Swarm` (`new`, `restore`, `since`, `publish`, `set_storage`, …),
  `Entry`, `Storage`, `Identity`, `verify`, `murmur_iroh::{Node, relay_map, n0_relays, …}`. Change
  it only on purpose, note it in the commit, and tell the apps (they bump their rev).

## Work
`work/queue.md`, `work/issues/`, decisions in `docs/adr/`.
