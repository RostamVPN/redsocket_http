# redsocket-http

The RostamVPN exit server: an exit-node tunnel that hides inside plain HTTP on
port 80. A client performs an ordinary HTTP Upgrade, then runs a Noise NK
session over the upgraded socket and asks the server to CONNECT to TCP
destinations (or to relay UDP datagrams) on its behalf. Optional modules add
egress-IP pinning, destination deny lists, exit-side domain/IP blocking from a
signed bundle, mailbox messaging to clients, load shedding, Prometheus metrics
and telemetry stats into a Valkey list.

## Wire protocol

1. Client sends `GET / HTTP/1.1` with `Upgrade: websocket` and
   `Connection: Upgrade`; the server answers `HTTP/1.1 101 Switching Protocols`.
   If `allowed_upgrade_hosts` is set, any other `Host:` gets a 404 instead.
2. The socket now carries `Noise_NK_25519_ChaChaPoly_BLAKE2s`. Every Noise
   message is framed as `[u16 BE len][ciphertext]`; the client already knows
   the server's static X25519 public key.
3. The first encrypted frame is either `META|tz|app|os|cid|sni|caps` (single
   stream, "v1") or `MUX2|tz|app|os|cid|sni|caps` (a yamux carrier). `caps` is a
   comma list such as `blk1,msg1`.
4. v1: the next frame is a SOCKS5-style CONNECT, `[0x05][atyp][addr][port]`,
   with no reply; the tunnel then relays bytes until either side closes.
5. MUX2: every yamux stream opens with the same CONNECT request and receives a
   10-byte reply `05 00 00 01 00 00 00 00 00 00` before relaying.
6. A MUX2 stream whose request is the 2-byte marker `0x05 0xFD` becomes a UDP
   association: after the 10-byte reply it carries `[u16 BE len][SOCKS5 UDP
   datagram]` in both directions, and `len == 0` closes it (`docs/udp-over-mux2.md`).
7. CONNECTs to the pseudo-host `_rs.<cmd>` are in-tunnel control calls.

## Build

    cargo build --release
    cargo test

All dependencies are vendored in `vendor/` and `.cargo/config.toml` points
cargo at them, so `cargo build --offline --release` works with no network.
Binaries: `redsocket-http` (the server), plus `client`, `mux_client`,
`legacy_client` and `flooder` test clients. Linux builds can select an
io_uring relay; other platforms always use the tokio relay.

## Keys

    redsocket-http --keygen

prints a fresh `private_key` / `public_key` pair (hex). Put both in the config;
clients need only the public key. `--config`, `--bind`, `--private-key` and
`--public-key` override the file at start-up. The server refuses the
`REPLACE_WITH_*` placeholders of `config.example.toml` and the key that file
once shipped with, whether in the config or on the command line.

## Configuration (`config.toml`)

Top level:

- `private_key` — server static X25519 private key, 64 hex chars (required).
- `public_key` — matching public key, 64 hex chars (required).
- `extra_private_keys` — older private keys still accepted during a rotation.
- `egress_ips` — pool of local source IPs; each cid is pinned to one by hash.
- `prefer_ipv6` — try a destination's AAAA before its A record.
- `deny_cidrs` — destination ranges refused before connecting (default: private,
  loopback, link-local and similar; set `[]` to disable). A list replaces the
  default rather than extending it. An IPv6 address that embeds an IPv4 one
  (IPv4-mapped, IPv4-compatible or in `64:ff9b::/96`) is refused when the
  embedded address is.
- `allow_cidrs` — carve-outs checked before `deny_cidrs`.
- `[valkey]` — fallback stats connection if `[stats.valkey]` is absent (same keys).

`[http]`:

- `bind` — listen address, default `0.0.0.0:80`.
- `extra_binds` — additional listen addresses; a bind that fails stops start-up.
- `proxy_protocol` — `disabled` (default), `auto` or `required` PROXY protocol
  v1/v2 on accept. Only `required` records the header's source address (and
  refuses a connection without a header); `auto` strips a header without
  trusting it. A header must arrive in full within 5 s.
- `socket_sndbuf` / `socket_rcvbuf` — accepted-socket buffer sizes; 0 keeps the kernel default.
- `allowed_upgrade_hosts` — `Host:` values that may receive a 101; empty allows any.

`[metrics]`:

- `bind` — Prometheus endpoint, default `127.0.0.1:9090`.
- `allow_public` — required before `bind` may be a non-loopback address.

`[stats]`:

- `cids` — emit cid and tunnel-closed rows (default `true`).
- `[stats.valkey]` — `addr`, `password`, `ca_file`, `server_name` of the stats
  instance; TLS is always on for this connection.

`[relay]`:

- `initial_buffer` — initial relay buffer size in bytes; 0 allocates the full
  64 KiB / 32 KiB up front, otherwise buffers grow on demand.
- `io_backend` — `epoll` (default) or `iouring` for the v1 relay loop (Linux only).

`[shed]`:

- `enabled` — answer new tunnels with the 404 decoy as memory runs out (default
  `true`).
- `high_pct` — percent of the memory limit at which refusing starts.
- `low_pct` — percent at which accepting resumes; must be below `high_pct`.
- `interval_secs` — seconds between memory samples (default 2).

`[protection]` (exit-side blocking, off by default):

- `enabled` — turn the module on.
- `pubkey` — Ed25519 public key (hex) that signs the bundle's `meta.json`.
- `brands` — META `app` values whose `blk1` tunnels are checked (default
  `["rostam"]`, the value the RostamVPN clients send).
- `allow_hosts` — names never judged: exact, or `*.suffix` (default
  `["rostam.app", "*.rostam.app", "*.cloudfront.net", "*.amazonaws.com"]`,
  the app's own control plane; set `[]` to judge everything).
- `block_bits` — bundle reason bits forced to block.
- `notify_bits` — bundle reason bits forced to notify only.
- `debug_log_destinations` — log destination host/port/client per block.
- `reload_secs` — bundle refresh interval (default 300; SIGHUP reloads at once).
- `bundle_dir` — load the bundle from a directory instead of Valkey.
- `[protection.valkey]` — where `protection:bundle` lives; absent uses `[messaging.valkey]`.

`[messaging]` (mailbox messages to `msg1` tunnels, off by default):

- `enabled` — turn the module on.
- `[messaging.valkey]` — the instance holding `msg:*`, `rules:*` and `cid:*`.

`[protection.valkey]` and `[messaging.valkey]` share one shape: `addr`, `tls`
(default `true`), `server_name`, `password`, `ca_file`, `cert_file`, `key_file`
(the last two together enable client-certificate auth).

## Telemetry stats

With a stats connection configured and `stats.cids = true`, the server batches
rows and sends them with `RPUSH` over TLS to two Valkey lists:

- `stats:cid` — one TSV row per tunnel open:
  `timestamp  real_ip  cid  tz  app  os  sni  tunnel  hostname`
  (`timestamp` is UTC RFC 3339; tabs and newlines inside fields become spaces,
  and the client's fields are cut to 64 characters, `sni` to 253).
- `stats:tunnel-closed` — one TSV usage row per tunnel close:
  `now_ts  cid  start_ts  duration_secs  bytes_up  bytes_down  hostname`
  (Unix seconds and byte counts in both directions).

Rows are dropped, and counted in `redsocket_stats_dropped_total`, if the queue
backs up or the stats instance is unreachable; the tunnel itself is never
delayed by the stats.

## Tests

`cargo test` runs the unit tests and eight end-to-end tests. Each e2e test is
its own binary because the protection module and the metrics are process-wide;
the shared harness (in-process server, MUX2 client, echo target and a RESP2
fake of Valkey) lives in `tests/harness/`.

## License

Apache-2.0. See the SPDX headers in each source file.

## Related repositories

| Repository | Contents |
|---|---|
| `redsocket_http` | The exit server (Rust). |
| `rostamvpn-android` | The Android app, the shared Rust client core (`redsocket-http-core/`) and the WireGuard-over-TCP core. |
| `rostamvpn-ios` | The iOS app and its Network Extension; its core frameworks are built from the cores in `rostamvpn-android`. |
| `redsocket_pfe` | AF_XDP triangle-routing front-end. |
| `redsocket_wgtcp` | The userspace WireGuard-over-TCP client library and tools; vendored into `rostamvpn-android` for the Android core. |
| `redsocket_proteus` | The server wrapped in Proteus programmable protocols; intended to replace `redsocket_http` once proven. |

## Removed for publication

Deployment and infrastructure documents, exporter scripts, release artifacts,
signing material and API keys (replaced by `REPLACE_WITH_*` placeholders),
server telemetry other than the cid stats, other brands, narrative comments,
and dead code. All third-party dependencies are vendored in the tree and keep
their own license files.
