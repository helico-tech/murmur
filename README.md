# murmur

Eventually consistent, fast replication of **signed append-only logs** among N peers, with no
server. Each peer writes only its own log (ed25519-signed entries); every peer ends up with every
log. Used by [OpenTeams](https://github.com/helico-tech/openteams) and Thime.

- **`murmur`**: the sans-IO core. A `Swarm` per group of peers: a small random overlay, instant
  push of new entries, version vectors with digests, windowed catch-up, anti-entropy, presence
  and app flashes, allow-lists and bans. No I/O, threads or clock inside.
- **`murmur-iroh`**: runs swarms over [iroh](https://iroh.computer) (QUIC, hole punching, relays),
  natively and in the browser (wasm); plus a direct request/answer protocol ("knock").
- A deterministic network simulator (feature `sim`): bandwidth, slow and flapping peers, NAT,
  partitions, restarts, data loss, dishonest peers; chaos tests over many seeds; a fuzzer.

Protocol: [docs/murmur.md](docs/murmur.md). Decision record: [docs/adr/](docs/adr/).

## Use it
```toml
[dependencies]
murmur = { git = "https://github.com/helico-tech/murmur", rev = "…" }
murmur-iroh = { git = "https://github.com/helico-tech/murmur", rev = "…" }
```
Pin a rev; bump it on purpose.

## Develop
```sh
cargo test --workspace --features murmur/sim                      # all tests
cargo clippy --workspace --all-targets --features murmur/sim -- -D warnings
cargo fmt --all --check
MURMUR_CHAOS_SEEDS=1000 cargo test --release -p murmur --features sim --test sim chaos
cargo run --release -p murmur --features sim --example fuzz -- --minutes 60
```
