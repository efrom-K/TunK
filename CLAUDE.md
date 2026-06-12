# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TunK is a Windows 11 VPN client built on Tauri v2 (Rust backend + Vanilla TS/HTML/CSS frontend), in the style of sing-box/happ. It implements a FakeIP DNS engine, a Wintun TUN adapter, traffic obfuscation (Shadowsocks AEAD / VLESS / Trojan headers), and a TLS SNI sniffer. The project is **under active development** — many modules contain `TODO` placeholders and the README's implementation status table is the source of truth for what's real vs. stubbed.

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
cargo test --lib proxy::obfuscation
cargo test --lib state

# Run a single test by name
cargo test test_fake_ip_allocation

# Coverage
cargo tarpaulin --out Html

# Frontend / Tauri dev (from repo root, uses package.json)
npm install
npm run dev      # vite dev server
npm run build    # tsc + vite build
tauri dev        # Tauri app with hot reload
tauri build      # production bundle
```

Wintun (`wintun.dll`) is required for the TUN adapter and is copied to the app directory at runtime; admin privileges are needed to create the TUN interface.

## Architecture

### State management (`src/state.rs`)
`AppState` is the single Tauri-managed state object (`tauri::State<'_, AppState>`), shared via `Arc`. It holds:
- `status: RwLock<VpnStatus>` — `Disconnected | Connecting | Connected | Disconnecting`
- `stats: RwLock<ConnectionStats>` — ping, download/upload bps
- `fake_ip_cache: DashMap<String, FakeIpCacheEntry>` plus mirrored `domain_to_fake_ip` / `fake_ip_to_domain` DashMaps for O(1) lookups in both directions
- `logs: Arc<Mutex<Vec<LogEntry>>>` — capped ring buffer (max 100 entries) for the sniffer/event log UI
- `profile_id: RwLock<Option<String>>` — currently selected proxy profile

All cross-cutting mutation (status changes, stats updates, FakeIP cache writes, logging) goes through methods on `AppState` so locking stays centralized.

### Tauri commands (`src/commands.rs`, `src/main.rs`)
Frontend <-> backend communication is exclusively through `#[tauri::command] async fn` handlers registered in `invoke_handler(tauri::generate_handler![...])`: `toggle_vpn`, `add_subscription`, `get_vpn_status`, `get_speed_bps`. Note `src/main.rs` and `src/commands.rs` currently define overlapping/duplicate command sets — when wiring new commands, register them in `main.rs`'s `generate_handler!` and keep the implementations in `commands.rs`.

### Config (`src/config.rs`)
`VpnConfig` aggregates `profiles: Vec<ProxyProfile>`, `SubscriptionConfig`, `DnsSettings` (FakeIP pool bounds `198.18.0.0`–`198.18.255.255`, DoH server `https://1.1.1.1/dns-query`), and `TunSettings` (interface name, MTU 9000, route metric). `ProxyProfile`/`ProtocolType` (Vless/Shadowsocks/Trojan) describe parsed subscription entries.

### Network layer (`src/network/`)
- `dns.rs` — `FakeIpManager` (DashMap-based, allocates from `198.18.0.0/16`, bidirectional domain<->IP maps) and `DoHClient` (real `reqwest`-based resolution against `https://1.1.1.1/dns-query` with caching), wrapped together by `DnsEngine`.
- `route.rs` — pure parsing of `route print -4` output into `RouteEntry`/`find_default_gateway`, plus `RouteManager` which shells out to `route`/`netsh` to read the routing table, set interface metrics, and add/remove routes.
- `tun.rs` — `WintunAdapter` wraps the `wintun` crate: `activate`/`deactivate` load `wintun.dll` and manage the adapter/session lifecycle, `packet_loop` reads packets via `tokio::task::spawn_blocking` + `receive_blocking` and feeds `VpnState.speed_bps`, and `configure_routing`/`restore_routing` use `route.rs` to make the TUN interface the default route while excluding the proxy server address. Activation requires `wintun.dll` and admin privileges, so the corresponding tests are `#[ignore]`.

### Proxy layer (`src/proxy/`)
- `obfuscation.rs` — `Obfuscator` with `ObfuscationMode::{ShadowsocksAead, Vless, Trojan}`; each mode prefixes payloads with a length header before encapsulation.
- `sniffer.rs` — `TlsSniffer::analyze_tls_handshake` parses TLS Client Hello records (record type `0x16`) to extract the SNI extension without decrypting payload, used for FAKEIP -> real-domain logging/routing decisions.

### Frontend (`public/`)
Despite the README calling for Vanilla TS, `package.json` and `public/src/App.tsx` pull in React — the frontend stack is in flux. Tauri events (`tauri::emitter`) are expected to stream sniffer log lines (`[HH:MM:SS] [FAKEIP] <fakeip> -> <domain> [PROXY]`) to a scrolling log table in the UI.

## Coding conventions (from project brief)

- Every backend module (`network`, `proxy`, `utils`, `state`) should have an inline `#[cfg(test)] mod tests`; async tests use `#[tokio::test]`.
- No `.unwrap()`/`.expect()` in production code paths — propagate errors via `?` returning `anyhow::Result<T>` or custom `thiserror` error types (note: existing code does not fully follow this yet, especially in `state.rs` and the `@workspace` tree).
- No placeholder TODO logic when "completing" a module — a module is done once it compiles and `cargo test` passes for it.
