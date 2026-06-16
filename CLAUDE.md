# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TunK is a Windows 11 VPN client built on Tauri v2 (Rust backend + Vanilla TS/HTML/CSS frontend), in the style of sing-box/happ. It implements a FakeIP DNS engine, a Wintun TUN adapter, traffic obfuscation (Shadowsocks AEAD / VLESS / Trojan headers), a TLS SNI sniffer, and a REALITY TLS camouflage handshake. The project is **under active development** — the README's implementation status table is the source of truth for what's real vs. stubbed.

## Repo layout caveat

The actual Cargo crate root is `src/` — `src/Cargo.toml` defines the `vpn-client` package (lib name `vpn_client_lib`, crate-type `cdylib`+`rlib`). **Run all `cargo`/`tauri` commands from inside `src/`**, not the repo root.

There is also a `@workspace/src/` directory containing a second, divergent `main.rs`/`lib.rs` with a different `AppState` design (e.g. `vpn_state`/`dns_engine` fields, `DnsEngine`/`FakeIpPool`/`DoHClient` types). It has no `Cargo.toml` of its own and is not part of the build — treat it as legacy/scratch code, not the active architecture. The active `AppState` lives in `src/state.rs`.

## Commands

All commands below assume the working directory is `src/`.

```bash
# Build backend
cargo build
cargo build --release

# Run all Rust unit tests
cargo test

# Run tests for a specific module
cargo test --lib network::dns
cargo test --lib proxy::connector
cargo test --lib proxy::reality
cargo test --lib state

# Run a single test by name
cargo test test_fake_ip_allocation

# Run ignored tests (require wintun.dll + admin, or network access)
cargo test -- --ignored --nocapture

# Coverage
cargo tarpaulin --out Html

# Frontend / Tauri dev (from repo root, uses package.json)
npm install
npm run dev      # vite dev server
npm run build    # tsc + vite build
tauri dev        # Tauri app with hot reload
tauri build      # production bundle
```

Wintun (`wintun.dll`) is required for the TUN adapter and is copied to the app directory at runtime; admin privileges are needed to create the TUN interface. Tests that depend on these are marked `#[ignore = "требует установленный wintun.dll и права администратора"]`.

For testing proxy connectivity against a real subscription, place proxy URLs (one per line) in `.local/local_subscription.txt` (this path is in `.gitignore`) and run `cargo test --lib proxy::connector -- --ignored --nocapture`.

## Architecture

### State management (`src/state.rs`)
`AppState` is the single Tauri-managed state object (`tauri::State<'_, AppState>`), shared via `Arc`. It holds:
- `status: RwLock<VpnStatus>` — `Disconnected | Connecting | Connected | Disconnecting`
- `stats: RwLock<ConnectionStats>` — ping, download/upload bps
- `fake_ip_cache: DashMap<String, FakeIpCacheEntry>` plus mirrored `domain_to_fake_ip` / `fake_ip_to_domain` DashMaps for O(1) lookups in both directions
- `logs: Arc<Mutex<Vec<LogEntry>>>` — capped ring buffer (max 100 entries) for the sniffer/event log UI
- `profile_id: RwLock<Option<String>>` — currently selected proxy profile
- `profiles: RwLock<Vec<ProxyProfile>>` — profiles parsed from the active subscription
- `tunnel: Mutex<Option<WintunAdapter>>` — active Wintun adapter/session, set by `toggle_vpn`

All cross-cutting mutation (status changes, stats updates, FakeIP cache writes, profile list, logging) goes through methods on `AppState` so locking stays centralized. `VpnStatus` and `LogEntry` derive `Serialize`/`Deserialize` for Tauri IPC.

### Tauri commands (`src/commands.rs`, `src/lib.rs`)
`src/lib.rs` owns the `run()` entrypoint and calls `tauri::generate_handler![]` there (not in `main.rs`). `src/main.rs` is a thin shim that just calls `vpn_client_lib::run()`. This layout is necessary because `#[tauri::command]` generates crate-local helper macros that `tauri::generate_handler!` must resolve in the same crate as the command functions.

Each `#[tauri::command] async fn` in `commands.rs` is a thin wrapper (`State<'_, AppState>` → `&AppState`) around a `*_impl(state: &AppState, ...)` function, so tests call the `_impl` functions directly without needing a real `tauri::State` (which has no public constructor).

Registered commands: `toggle_vpn`, `add_subscription`, `get_vpn_status`, `get_speed_bps`, `set_profile`, `get_profiles`, `get_logs`, `test_profile_connection`.

`toggle_vpn` validates the selected profile, activates/deactivates a `WintunAdapter` stored in `state.tunnel`, and returns the resulting `VpnStatus`. `test_profile_connection` calls `ProxyConnector::measure_latency` and updates `ConnectionStats.ping`.

### Config (`src/config.rs`)
`VpnConfig` aggregates `profiles: Vec<ProxyProfile>`, `SubscriptionConfig`, `DnsSettings` (FakeIP pool bounds `198.18.0.0`–`198.18.255.255`, DoH server `https://1.1.1.1/dns-query`), and `TunSettings` (interface name, MTU 9000, route metric).

`ProxyProfile`/`ProtocolType` (Vless/Shadowsocks/Trojan) describe parsed subscription entries. VLESS REALITY parameters are stored directly on `ProxyProfile`: `reality_public_key` (`pbk`, base64url X25519), `reality_short_id` (`sid`, hex), `sni`, `flow`, and `fingerprint`.

`parse_subscription_url` parses `vless://`, `ss://` (base64 `method:password` userinfo, tried against multiple base64 engines), and `trojan://` URLs into a `ProxyProfile`, decoding the `#name` fragment via `percent-encoding`. For VLESS, it also parses query params (`pbk`, `sid`, `sni`, `flow`, `fp`).

### Network layer (`src/network/`)
- `dns.rs` — `FakeIpManager` (DashMap-based, allocates from `198.18.0.0/16`, bidirectional domain↔IP maps) and `DoHClient` (real `reqwest`-based resolution against `https://1.1.1.1/dns-query` with caching), wrapped together by `DnsEngine`.
- `route.rs` — pure parsing of `route print -4` output into `RouteEntry`/`find_default_gateway`, plus `RouteManager` which shells out to `route`/`netsh` to read the routing table, set interface metrics, and add/remove routes.
- `tun.rs` — `WintunAdapter` wraps the `wintun` crate: `activate`/`deactivate` load `wintun.dll` and manage the adapter/session lifecycle, `packet_loop` reads packets via `tokio::task::spawn_blocking` + `receive_blocking` and feeds `VpnState.speed_bps`, and `configure_routing`/`restore_routing` use `route.rs` to make the TUN interface the default route while excluding the proxy server address.

### Proxy layer (`src/proxy/`)
- `connector.rs` — `ProxyConnector::connect` opens a TCP connection to the proxy server and performs the protocol handshake. `build_vless_request` / `build_trojan_request` serialize the respective wire formats. `ShadowsocksCipher` implements full AEAD-2017 stream encryption/decryption: key derivation via `EVP_BytesToKey` (OpenSSL-compatible MD5 chaining) + HKDF-SHA1 (`ss-subkey`) per-session subkey, with a little-endian incrementing 12-byte nonce. Supports `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`. `TargetAddr` represents either a domain or IP address and drives the two address-encoding schemes (VLESS vs. SOCKS5/Trojan). `ProxyConnector::measure_latency` connects to `www.gstatic.com:443` and reports round-trip milliseconds.
- `reality.rs` — `build_and_seal_client_hello` constructs a TLS 1.3 ClientHello with REALITY authentication. It generates an ephemeral X25519 keypair, computes `AuthKey = HKDF-SHA256(salt=random[..20], ikm=ECDH(ephemeral, server_pbk), info="REALITY")`, encrypts the 16-byte `session_id` plaintext (Xray version + timestamp + `short_id`) with `AES-256-GCM(key=AuthKey, nonce=random[20..32], aad=full ClientHello)`, and overwrites the `session_id` field. Returns a `RealityClientHello` with `raw`, `client_random`, `ephemeral_private_key`, and `auth_key` for subsequent TLS 1.3 key schedule.
- `obfuscation.rs` — `Obfuscator` with `ObfuscationMode::{ShadowsocksAead, Vless, Trojan}`; each mode prefixes payloads with a length header before encapsulation.
- `sniffer.rs` — `TlsSniffer::analyze_tls_handshake` parses a full TLS Client Hello to extract the SNI (`server_name`) extension without decrypting payload; used for FAKEIP → real-domain logging/routing decisions.

### Frontend (`public/`)
React + TypeScript, built with Vite (`vite.config.ts` at repo root, `root: 'public'`, output to `../dist`). Entry point is `public/src/main.tsx` rendering `public/src/App.tsx` into `public/index.html`'s `#app` div. `App.tsx` polls `get_vpn_status`, `get_speed_bps`, and `get_logs` every second via `invoke()` (no Tauri event emitters are wired up yet) and calls `toggle_vpn`, `add_subscription`, `set_profile`, `get_profiles`, `test_profile_connection` for user actions. `tauri.conf.json`'s `build.frontendDist` points at `../dist`, with `devUrl` pointing at the Vite dev server.

## Coding conventions

- Every backend module must have an inline `#[cfg(test)] mod tests`; async tests use `#[tokio::test]`.
- No `.unwrap()`/`.expect()` in production code paths — propagate errors via `?` returning `anyhow::Result<T>` or custom `thiserror` error types (existing code in `state.rs` does not fully follow this yet).
- Tests that require system resources (wintun, admin, network) are marked `#[ignore = "..."]` with a descriptive reason string.
- A module is done once it compiles and `cargo test` passes for it — no placeholder TODO logic.
