# 🛡️ TunK VPN Client for Windows 11

🌆 MIT License  |  ⚙️ Rust Backend  |  💎 Tauri v2 Frontend

> **⚠️ STATUS: UNDER ACTIVE DEVELOPMENT**  
> This project is currently in active development. Some core features are fully implemented, while others are placeholders for future implementation. Please read the [Architecture Overview](#-architecture-overview) before building.

---

## 📋 Project Overview

A high-performance, lightweight VPN client specifically optimized for **Windows 11**. Built on the robust **Tauri v2** stack, this application leverages a Rust backend for maximum safety and performance, paired with a Vanilla TypeScript frontend.

### Core Capabilities
- 🔒 **FakeIP Manager**: Intelligent IP allocation from reserved pools (`198.18.0.0/16`) with `DashMap` concurrency support.
- 🌐 **DNS Engine**: DoH client structure ready with advanced DNS interception logic.
- 🕵️ **TLS Sniffer**: Parses SNI (Server Name Indication) from TLS Client Hello packets without decrypting payload traffic.
- 🛡️ **Obfuscation Module**: Implements Shadowsocks AEAD, VLESS, and Trojan header obfuscation to bypass deep packet inspection.

---

## 🎯 Implementation Status

| Component | Status | Notes |
| :--- | :---: | :--- |
| **FakeIP Manager** | ✅ Implemented | IP allocation from `198.18.0.0/16` pool; DashMap concurrency. |
| **DNS Engine** | ✅ Implemented | `DoHClient` resolves via Cloudflare DoH JSON API with caching. |
| **Obfuscation Module** | ✅ Implemented | Shadowsocks AEAD, VLESS, Trojan header obfuscation complete. |
| **TLS Sniffer** | ✅ Implemented | SNI parsing from real TLS Client Hello byte streams, covered by raw-byte tests. |
| **Wintun TUN Interface** | ✅ Implemented | Adapter creation, session start and async packet loop via `wintun` crate. |
| **System Tray (Win 11)** | ⚠️ Partial | Basic structure in place; menu actions to be completed. |
| **Routing Logic** | ✅ Implemented | `route`/`netsh` based default-route and proxy-exclusion management. |
| **Subscription Parsing** | ✅ Implemented | `vless://`, `ss://`, `trojan://` URL parsing into `ProxyProfile`. |
| **Tauri Commands & UI** | ✅ Implemented | `toggle_vpn`, `add_subscription`, `get_vpn_status`, `get_speed_bps`, `set_profile`, `get_profiles`, `get_logs` wired to a React frontend. |

---

## 🛠️ Architecture Overview

The project follows a clean separation of concerns between the Rust backend (logic) and the Frontend (UI).

```text
src/
├── main.rs              # Tauri v2 application entry point
├── commands.rs          # Tauri command handlers (toggle_vpn, add_subscription)
├── state.rs             # Thread-safe application state management
├── config.rs            # Configuration structures and serialization
│
├── lib.rs               # Library module exports
├── network/             # Network layer components
│   ├── dns.rs           # FakeIpManager + DoH resolver
│   ├── route.rs         # Windows routing table parsing & netsh/route management
│   └── tun.rs           # Wintun adapter, session and packet loop
│
└── proxy/               # Traffic handling and security
    ├── obfuscation.rs   # Traffic obfuscation headers
    └── sniffer.rs       # TLS SNI sniffing and domain logging
```
---

## 📦 System Requirements

To build and run the application, ensure your environment meets the following criteria:

* **OS:** Windows 10/11 (64-bit)
* **Rust:** Version 1.75 or higher
* **Driver:** Wintun.dll (Included in release builds; requires Admin privileges for installation)
* **Privileges:** Administrator rights are required for creating the TUN interface.

## 🚀 Installation & Build Instructions
* **1. Prerequisites:** Install Rust Toolchain
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
* **2. Clone the Repository**
```bash
git clone https://github.com/yourusername/vpn-client.git
cd vpn-client
```
* **3. Build the Application**
You need both Rust and Node.js toolchains installed to build a Tauri app.

Build Backend (Rust):

```bash
cargo build --release
Build Frontend (via Tauri):
```
```bash
# Install npm dependencies
npm install
# Run in Development mode (Hot reload)
tauri dev
# Build Production Release
tauri build
```
Note on Wintun: The wintun.dll driver is automatically copied to the application directory on first run. For manual installation, download the official driver from the WireGuard repository.
## 🧪 Testing & Quality Assurance
### Unit Tests
Run all unit tests for the Rust backend:

```bash
cargo test
```
Or target specific modules:

```bash
cargo test --package vpn-client --lib network::dns
cargo test --package vpn-client --lib proxy::obfuscation
```
### Test Coverage
Analyze coverage with tarpaulin:

```bash
cargo tarpaulin --out Html
```
### Current Coverage Metrics
| Module | Status | Notes |
| :--- | :---: | :--- |
| network/dns.rs | ✅ 100% | IP allocation, collision prevention, reverse resolution. |
| proxy/obfuscation.rs | ✅ 95% | AEAD header logic, packet length validation. |
| state.rs | ✅ 100% | Logging, status management, profiles, concurrent access. |
| proxy/sniffer.rs | ✅ 95% | TLS record detection, SNI extraction from real Client Hello bytes. |
| config.rs | ✅ 100% | Subscription URL parsing for vless/ss/trojan. |
| commands.rs | ✅ 100% | Tauri command handlers (status, speed, profiles, logs, toggle). |

## 📁 Project Structure (Root)
```text
vpn-client/
├── .gitignore
├── Cargo.toml              # Rust dependencies
├── tauri.conf.json         # Tauri configuration
├── LICENSE                 # MIT License
├── README.md               # This file
├── src/                    # Rust Backend Source
│   ├── main.rs
│   ├── commands.rs
│   ├── state.rs
│   ├── config.rs
│   ├── lib.rs
│   ├── network/            # DNS & TUN logic
│   └── proxy/              # Obfuscation & Sniffing
├── public/                 # Frontend source (Vite root)
│   ├── index.html
│   └── src/                # React + TypeScript
│       ├── App.tsx
│       ├── main.tsx
│       └── style.css
├── dist/                   # Vite production build output (frontendDist)
├── icons/                  # Application icons
├── vite.config.ts          # Vite build configuration
├── tsconfig.json           # TypeScript configuration
└── package.json            # NPM dependencies & scripts
```
---

## ⚠️ Important Security Notes
### 🔒 Traffic Obfuscation
* **AEAD Encryption:** All packets pass through Shadowsocks AEAD with a 2-byte length header.
* **Privacy First:** SNI is masked during DoH requests to protect user privacy.
### 🛡️ FakeIP Isolation
* **Reserved Pool:** The pool 198.18.0.0/16 strictly does not overlap with public IP ranges, ensuring no collision with real internet infrastructure.
* **Concurrency Safety:** Uses DashMap to ensure thread-safe storage without blocking locks under high load.
### 🔍 TLS Sniffer Capabilities
* **Non-Intrusive:** The sniffer operates only at the SNI extension level of the TLS handshake.
* **Encrypted Payload:** Real traffic remains encrypted; only the target domain name is logged for routing purposes.

## 📞 Support & Issues
* **GitHub Issues:** Open an issue for bugs or feature requests.
* **Email:** efimromancenko@gmail.com

## ⚖️ Development Ethics
We are committed to ethical, transparent, and safe development:

* **Transparency:** All code is open-source; tests run in CI before release.
* **Safety:*** No .unwrap() or .expect() calls in production code paths; all errors handled via Result.
* **Privacy:** Logs strictly exclude sensitive user data (no personal IP addresses logged).
* **Openness:** MIT license permits commercial use with proper attribution.

## 📜 Changelog
v0.1.0 (Current Development Version)
* ✅ [x] Implemented FakeIpManager with DashMap concurrency support.
* ✅ [x] Completed DNS engine structure and DoH client integration.
* ✅ [x] Added traffic obfuscation headers (Shadowsocks AEAD, VLESS, Trojan).
* ✅ [x] Deployed TLS sniffer for SNI parsing.
* ✅ [x] Wintun TUN integration: adapter/session lifecycle, async packet loop, route management (Stage 3).
* ✅ [x] SNI extraction validated against real TLS Client Hello byte streams, subscription URL parsing (vless/ss/trojan), full Tauri v2 command set wired to a React UI (Stage 4).
* ⬜ [ ] System tray full implementation.
v0.0.1
* ✅ [x] Project skeleton with Tauri v2 established.
* ✅ [x] Configuration structures and profile serialization defined.

## Future Roadmap
 * VLESS Protocol: Full client transport implementation for VLESS.
 * Advanced TLS 1.3 Sniffer: Optional deep decryption module (Opt-in only).
 * GUI Routing: Visual configuration via netsh GUI.
 * Subscription Manager: Import/Export functionality for JSON/YAML configs.
 * Performance Dashboard: Real-time stats and monitoring UI.

## 📜 Acknowledgments
🤝 Tauri Team for the incredible framework enabling seamless native desktop apps.
⚡ WireGuard/Wintun developers for robust TUN driver support.
💪 Rust Community for language reliability and memory safety guarantees.
---
Built with a commitment to security, performance, and ethical development practices.