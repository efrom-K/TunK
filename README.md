# TunK VPN Client for Windows 11

MIT License | Rust Backend | Tauri v2 Frontend

> **STATUS: UNDER ACTIVE DEVELOPMENT**
> Core data path is fully implemented. See the status table below for what works vs. what is planned.

---

## Project Overview

A lightweight VPN client for Windows 11 built on **Tauri v2** (Rust backend + Vanilla TypeScript frontend), inspired by sing-box and happ. It intercepts DNS queries via a FakeIP engine, routes all traffic through a Wintun TUN adapter, and proxies TCP flows to VLESS / Trojan / Shadowsocks AEAD servers — including servers behind the **REALITY TLS camouflage** protocol.

---

## Implementation Status

| Component | Status | Notes |
| :--- | :---: | :--- |
| **FakeIP Manager** | ✅ Done | IP allocation from `198.18.0.0/16`; DashMap bidirectional maps. |
| **DNS Proxy** | ✅ Done | `DnsProxy` listens on UDP 127.0.0.1:53, returns FakeIPs for A queries, NXDOMAIN for AAAA; writes mappings to `AppState`. |
| **DoH Client** | ✅ Done | Resolves via `https://1.1.1.1/dns-query` with an in-memory cache. |
| **Wintun TUN Adapter** | ✅ Done | Adapter/session lifecycle; `get_session()` exposes the raw session for the dispatch loop. |
| **Routing Management** | ✅ Done | `route`/`netsh` default-route and proxy-exclusion management. |
| **Packet Dispatch Loop** | ✅ Done | `network/dispatch.rs`: parses IPv4+TCP headers, maintains a per-flow table (DashMap keyed by 4-tuple), opens a proxy connection for every SYN to the FakeIP range, splices TUN ↔ proxy bidirectionally, and updates download/upload stats. |
| **Proxy Connector** | ✅ Done | Real VLESS / Trojan (SHA-224) / Shadowsocks AEAD (AES-128/256-GCM, ChaCha20-Poly1305) handshakes over TCP. |
| **REALITY Handshake** | ✅ Done | `proxy/reality.rs` builds a TLS 1.3 ClientHello with REALITY-authenticated `session_id` (X25519 ECDH + HKDF-SHA256 + AES-256-GCM). `proxy/tls13.rs` completes the full TLS 1.3 key schedule, decrypts the server handshake, verifies server Finished (HMAC-SHA256), and derives application traffic keys. Wired into `ProxyConnector::connect` when `reality_public_key` is set. |
| **TLS Sniffer** | ✅ Done | SNI extraction from raw TLS ClientHello bytes without decryption. |
| **Subscription Parsing** | ✅ Done | `vless://`, `ss://`, `trojan://` URL parsing; REALITY `pbk`/`sid`/`sni`/`fp` query params decoded. |
| **Tauri Commands & UI** | ✅ Done | `toggle_vpn`, `add_subscription`, `get_vpn_status`, `get_speed_bps`, `set_profile`, `get_profiles`, `get_logs`, `test_profile_connection` wired to the React frontend. |
| **Obfuscation Module** | ⚠️ Partial | `proxy/obfuscation.rs` is length-prefix framing only (unit-test scaffolding); real crypto lives in `proxy/connector.rs`. |
| **toggle_vpn wiring** | ✅ Done | `toggle_vpn` activates Wintun, resolves the proxy IP, configures routing, spawns the DNS proxy and dispatch loop as `AbortHandle`-tracked tasks; on disconnect aborts tasks, restores routing, and clears FakeIP cache. |
| **System Tray** | ✅ Done | `lib.rs` `.setup()` builds a `TrayIconBuilder` tray (32×32 RGBA icon, dark-blue "T" glyph). Context menu: Open / Connect / Disconnect / — / Exit. Left-click toggles window visibility. Window close is intercepted and redirected to hide. Exit performs graceful shutdown (abort tasks → restore routing → deactivate adapter). |

---

## Architecture

```
src/
├── main.rs              # Thin shim — calls vpn_client_lib::run()
├── lib.rs               # Tauri entry point + generate_handler!
├── commands.rs          # #[tauri::command] thin wrappers over *_impl fns
├── state.rs             # AppState (RwLock/DashMap/Mutex), VpnStatus, ConnectionStats
├── config.rs            # ProxyProfile, VpnConfig, parse_subscription_url
│
├── network/
│   ├── dispatch.rs      # IPv4/TCP dispatch loop: FakeIP→proxy relay, flow table, stats
│   ├── dns.rs           # FakeIpManager, DoHClient, DnsProxy (UDP listener)
│   ├── route.rs         # Windows route print / netsh parsing and management
│   └── tun.rs           # WintunAdapter: activate/deactivate/packet_loop/get_session
│
└── proxy/
    ├── connector.rs     # ProxyConnector::connect, ShadowsocksCipher, REALITY path
    ├── reality.rs       # build_and_seal_client_hello → RealityClientHello
    ├── tls13.rs         # complete_tls13_handshake, Tls13Stream, key schedule
    ├── obfuscation.rs   # Obfuscator (length-prefix framing, scaffolding)
    └── sniffer.rs       # TlsSniffer::analyze_tls_handshake (SNI extraction)
```

### Data path (fully implemented)

```
OS TCP packet
  └─▶ Wintun TUN (tun.rs)
        └─▶ packet_loop → dispatch::run_dispatch (dispatch.rs)
              ├─ parse IPv4+TCP header
              ├─ SYN to 198.18.x.x → look up domain in AppState.fake_ip_to_domain
              │     └─▶ ProxyConnector::connect (connector.rs)
              │           ├─ plain VLESS / Trojan / Shadowsocks
              │           └─ VLESS+REALITY → build_and_seal_client_hello (reality.rs)
              │                               └─▶ complete_tls13_handshake (tls13.rs)
              └─ data packets → relay task: TUN ↔ proxy TcpStream, update stats
```

### DNS path (fully implemented)

```
OS DNS query (UDP 127.0.0.1:53)
  └─▶ DnsProxy::run (dns.rs)
        ├─ A query  → allocate FakeIP from 198.18.0.0/16
        │              write to AppState.fake_ip_to_domain + domain_to_fake_ip
        │              return synthetic A response
        └─ AAAA / other → NXDOMAIN
```

---

## Build

> All `cargo` commands must be run from inside `src/`.

```bash
# Backend
cd src
cargo build
cargo test

# Run a specific test module
cargo test --lib network::dispatch
cargo test --lib proxy::reality
cargo test --lib proxy::connector

# Run a single test by name
cargo test test_fake_ip_allocation

# Full Tauri app (from repo root)
npm install
tauri dev      # hot-reload dev server
tauri build    # production bundle
```

**Requirements:** Windows 10/11 64-bit, Rust 1.75+, Node.js 18+, administrator privileges.

### wintun.dll

`wintun.dll` is required for the TUN adapter but is not committed to the repo (it is gitignored). You must obtain it separately:

1. Download the latest Wintun release from **<https://www.wintun.net>**
2. Extract `wintun.dll` (x64 build) and place it next to the compiled executable:
   - **Development** (`tauri dev` / `cargo build`): copy to `src/target/debug/vpn-client.exe`'s directory, i.e. `src/target/debug/wintun.dll`
   - **Production** (`tauri build`): copy to `src/wintun.dll` before running the bundler — Tauri copies resources listed in `bundle.resources` into the installer next to the executable

`WintunAdapter::activate()` uses `locate_wintun_dll()` which searches the running executable's directory first, then falls back to the OS PATH/CWD search. In a production bundle the DLL is placed next to the exe automatically.

---

## Testing

```bash
# All unit tests — no admin or network access required
cd src && cargo test

# Tests that need wintun.dll + admin
cargo test -- --ignored --nocapture

# Tests against a real proxy subscription
# Put proxy URLs (one per line) in .local/local_subscription.txt (gitignored)
cargo test --lib proxy::connector -- --ignored --nocapture
```

Current test count: **170 tests**, 0 failures, 8 ignored (wintun/admin/network).

---

## Changelog

### v0.6.0 — Critical routing, DNS and port fixes (Stages 6–9)

**`network/tun.rs`** (updated):
- `activate()` now assigns static IP `198.18.0.1/16` to the Wintun interface via `netsh interface ip set address` — without this the OS had no subnet route pointing at the adapter.
- `configure_routing()` extended with three additional steps: split-default routes `0.0.0.0/1` + `128.0.0.0/1` (override real `0.0.0.0/0` by LPM); DNS `127.0.0.1` on the TUN interface (Windows DNS Client picks lowest-metric interface first); `ipconfig /flushdns` (best-effort).
- `restore_routing()` now also removes split-default routes, clears TUN DNS, and flushes the cache.
- `deactivate()` calls `clear_interface_address` (best-effort) to remove the stale static IP.
- `locate_wintun_dll()` searches the running executable's directory first, then falls back to OS PATH/CWD — covers both development and Tauri production bundles.

**`network/route.rs`** (updated):
- New helpers: `set_interface_address` / `clear_interface_address`, `set_interface_dns` / `clear_interface_dns`, `flush_dns_cache`, `add_split_default_route` / `delete_split_default_route`.

**`commands.rs`** (updated):
- `ensure_dns_port_free()`: binds `127.0.0.1:53`; if occupied, stops `Dnscache` service and polls up to 2 s for release. Called in `toggle_vpn_impl` before spawning the DNS proxy.
- `restore_dnscache()`: best-effort `sc start Dnscache` on disconnect.

**`tauri.conf.json`** (updated):
- `bundle.resources` array added — add `"wintun.dll"` here when building a production installer with the DLL present.

---

### v0.5.0 — System tray

**`lib.rs`** (updated):
- `.setup()` now calls `build_system_tray()`, which builds a `TrayIconBuilder` icon (32×32, programmatically generated RGBA, dark-blue background with a white "T" glyph).
- Context menu items: **Открыть TunK** (show/focus window), **Подключить** (connect via `toggle_vpn_impl`), **Отключить** (disconnect), separator, **Выход** (graceful shutdown).
- Left click on the tray icon toggles window visibility (show if hidden, hide if visible).
- `.on_window_event()` intercepts `CloseRequested` — calls `api.prevent_close()` and hides the window, so the app stays in the tray.
- **Выход** performs a clean shutdown: `abort_background_tasks()` → `restore_routing()` → `adapter.deactivate()` → `std::process::exit(0)`.
- Connect/Disconnect tray actions spawn tokio tasks that call `commands::toggle_vpn_impl` (now `pub(crate)`).

**`tauri.conf.json`** (updated):
- Removed the `trayIcon` config section (which would create a second, handler-less tray icon alongside the one built in setup).
- Added explicit `"label": "main"` to the window entry (required for `app.get_webview_window("main")`).
- Removed `icons/icon.icns` from `bundle.icon` (macOS-only, not needed for the Windows target).

**`src/icons/`** (new files):
- `32x32.png` and `128x128.png` generated for the bundle configuration.
- `icon.ico` regenerated as a minimal PNG-in-ICO container.

---

### v0.4.0 — Full connect/disconnect lifecycle (toggle_vpn wiring)

**`commands.rs`** (updated):
- `toggle_vpn_impl` is now `async fn` and accepts `Arc<AppState>`.
- All Tauri command signatures changed from `State<'_, AppState>` to `State<'_, Arc<AppState>>` so the Arc can be cloned into spawned tasks.
- **On connect**: activates Wintun adapter → extracts `Arc<Session>` → resolves proxy server hostname to IPv4 via `resolve_host_ipv4` (direct parse, then `tokio::net::lookup_host`) → calls `configure_routing` → stores adapter in `state.tunnel` → spawns `DnsProxy::run` and `dispatch::run_dispatch` as Tokio tasks → stores their `AbortHandle`s in `state.task_handles`.
- **On disconnect**: calls `state.abort_background_tasks()` to cancel DNS + dispatch tasks → calls `adapter.restore_routing` to remove the proxy-exclusion route → calls `adapter.deactivate()` → clears FakeIP cache → resets `proxy_ip`.
- 2 new tests: `test_resolve_host_ipv4_direct`, `test_resolve_host_ipv4_ipv6_address_is_skipped`.

**`state.rs`** (updated):
- New fields: `task_handles: Mutex<Vec<AbortHandle>>`, `proxy_ip: Mutex<Option<Ipv4Addr>>`.
- New methods: `register_task_handle`, `abort_background_tasks`, `set_proxy_ip`, `get_proxy_ip`.

**`lib.rs`** (updated):
- Managed type changed from `AppState` to `Arc<AppState>`: `.manage(Arc::new(AppState::new()))`.

---

### v0.3.0 — Packet dispatch loop + REALITY TLS 1.3

**`network/dispatch.rs`** (new):
- Full IPv4/TCP packet dispatch loop reading from a Wintun session.
- `DashMap` flow table keyed by `(src_ip, src_port, dst_ip, dst_port)`.
- On TCP SYN to the FakeIP range (`198.18.0.0/16`): looks up the real domain from `AppState.fake_ip_to_domain`, selects the active proxy profile, sends a synthetic SYN-ACK, and spawns a relay task.
- Relay task calls `ProxyConnector::connect`, then splices the proxy `TcpStream` ↔ Wintun session bidirectionally — ACKs are sent back to the OS, downstream data is chunked (≤1400 bytes) into PSH+ACK packets.
- `AppState` stats (download/upload bps) updated on every relay tick.
- RFC 1071 IP + TCP checksums; IPv4/TCP header builder and parser; 9 unit tests.

**`proxy/tls13.rs`** (new):
- `complete_tls13_handshake(TcpStream, RealityClientHello) → Tls13Stream`.
- Sends the REALITY ClientHello as a TLS record (outer version 0x0301 for middlebox compatibility).
- Reads and parses ServerHello; extracts the cipher suite and X25519 `key_share`.
- Full RFC 8446 HKDF key schedule: `HKDF-Extract` chain (early → handshake → master), `HKDF-Expand-Label` for traffic secrets, per-direction keys, IVs, and finished keys.
- Decrypts server handshake records (AES-128-GCM or ChaCha20-Poly1305), verifies server Finished via HMAC-SHA256.
- Sends client Finished encrypted with the client handshake write key.
- Derives application traffic keys; returns a `Tls13Stream` implementing `AsyncRead + AsyncWrite` with per-direction AEAD + sequence counters.
- 13 unit tests (AEAD roundtrip for both cipher suites, key schedule vectors, record format, parsing helpers).

**`proxy/connector.rs`** (updated):
- When a VLESS profile has `reality_public_key` set: calls `build_and_seal_client_hello`, then `complete_tls13_handshake`, sends the VLESS request header as TLS application data, returns the inner `TcpStream`.
- `parse_reality_pubkey` — base64url-decodes the `pbk` field to `[u8; 32]`.
- `parse_reality_short_id` — hex-decodes the `sid` field to `Vec<u8>` (0–8 bytes).
- 7 new tests for both helpers.

**`network/tun.rs`** (updated):
- `packet_loop` signature changed from `Arc<Mutex<VpnState>>` to `Arc<AppState>`.
- `get_session() → Result<Arc<wintun::Session>>` added for use by the dispatch loop.
- Dead `VpnState` local struct removed.

### v0.2.0 — DNS proxy

- `network/dns.rs`: `DnsProxy` UDP listener, DNS wire-format parser/builder, `handle_dns_query`, 13 tests including a full UDP round-trip test.

### v0.1.0 — Core foundation

- FakeIP Manager, DoH client, Wintun adapter lifecycle, Windows routing management.
- Full Tauri command set wired to a React frontend.
- Real VLESS / Trojan / Shadowsocks AEAD handshakes (`proxy/connector.rs`).
- REALITY ClientHello builder (`proxy/reality.rs`).
- TLS sniffer (SNI extraction), subscription URL parser with REALITY query params.

---

## Security Notes

- **REALITY camouflage**: The TLS 1.3 ClientHello is indistinguishable from a legitimate browser handshake to a DPI system. The REALITY server verifies the encrypted `session_id` to authenticate the client.
- **FakeIP isolation**: The `198.18.0.0/16` pool does not overlap with public IP space; DashMap ensures lock-free concurrent writes under load.
- **No unwrap in production paths**: errors are propagated via `anyhow::Result<T>` or `thiserror`-derived types throughout.
- **Wintun**: requires a Microsoft-signed driver and administrator privileges; TUN creation is gated behind `activate()`.

---

## Support

- GitHub Issues: open an issue for bugs or feature requests.
- Email: efimromancenko@gmail.com

---

## License

MIT — see `LICENSE`.
