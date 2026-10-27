<p align="center">
  <img src="Assets/AppIcon.png" width="160" alt="LANA Scanner icon">
</p>

<h1 align="center">LANA Scanner</h1>
<p align="center"><b>LAN Advanced Scanner for macOS</b> — a native, Advanced&nbsp;IP&nbsp;Scanner‑style network scanner with nmap‑like features.</p>

<p align="center">
  <img alt="macOS 13+" src="https://img.shields.io/badge/macOS-13%2B-black?logo=apple">
  <img alt="Swift 5.9+" src="https://img.shields.io/badge/Swift-5.9%2B-F05138?logo=swift&logoColor=white">
  <img alt="No root required" src="https://img.shields.io/badge/root-not%20required-2FE6B0">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue">
</p>

<p align="center"><a href="README.ru.md">Русская версия</a></p>

---

LANA Scanner finds every device on your LAN, shows its IP, hostname, MAC address and vendor, scans open TCP ports, identifies services from their banners and gives you one‑click actions (web UI, SSH, SMB, RDP, VNC, ping, traceroute, Wake‑on‑LAN). It is a single native SwiftUI app: no root, no Homebrew, no third‑party dependencies.

> The interface is available in **English** and **Russian** and follows the macOS system language. To pick a language for LANA Scanner only: *System Settings → General → Language & Region → Applications → + → LANA Scanner*.

## Features

| Feature | Implementation | nmap equivalent |
|---|---|---|
| Host discovery | ARP cache + ICMP echo + TCP ping on 9 ports (an RST also means "alive") | `-sn -PE -PS22,80,…` |
| MAC & vendor | `arp -an` + IEEE OUI registry (downloaded on first launch) | — |
| Hostnames | reverse DNS, mDNS (unicast to :5353), NetBIOS NBSTAT (:137) | `-R`, `nbstat.nse` |
| Port scan | non‑blocking `connect()` multiplexed with `poll()`, up to 4096 sockets in flight | `-sT --top-ports N` |
| Service detection | greeting banners (SSH/FTP/SMTP/POP3/IMAP/VNC/MySQL) + HTTP `HEAD` → `Server` header | `-sV` (simplified) |
| Host actions | HTTP/HTTPS, SSH, SMB (Finder), RDP, VNC, FTP, Ping, Traceroute, Wake‑on‑LAN, copy IP/MAC | — |

- **Port presets:** Top 100 / Top 1000 (same sets as `nmap --top-ports`), 1–1024, all 65535, or a custom list such as `22,80,443,8000-8100`.
- **Targets:** `192.168.1.0/24`, `10.0.0.1-10.0.0.50`, `10.0.0.1-50`, single IPs; comma‑separated.
- **UI:** sortable and filterable host table, detail pane, context menu, double‑click opens a device's web UI.

## Install

### Option 1: download a release

1. Download `LANA-Scanner-<version>-macOS.zip` from the [Releases](../../releases) page and unzip it.
2. Move **LANA Scanner.app** to **Applications**.
3. The app is ad‑hoc signed, not notarized, so the first launch is blocked by Gatekeeper. Either right‑click → **Open**, or use *System Settings → Privacy & Security → Open Anyway*, or run:
   ```bash
   xattr -dr com.apple.quarantine "/Applications/LANA Scanner.app"
   ```
4. Allow **Local Network** access when macOS asks.

### Option 2: build from source

Requires macOS 13+ and Xcode or the Command Line Tools (`xcode-select --install`), Swift 5.9+.

```bash
git clone <this-repo-url> LANA-scanner && cd LANA-scanner
./scripts/build-app.sh --install        # builds and installs "/Applications/LANA Scanner.app"
```

| Command | Result |
|---|---|
| `./scripts/build-app.sh` | `build/LANA Scanner.app` for the host architecture |
| `./scripts/build-app.sh --universal` | arm64 + x86_64 binary (needs full Xcode) |
| `INSTALL_DIR=~/Applications ./scripts/build-app.sh --install` | install for the current user only |
| `swift run` | run without an app bundle (Local Network permission comes from Terminal) |
| `swift test` | unit tests (XCTest needs full Xcode) |

## How it works

```
┌──────────────── SwiftUI (MainActor) ────────────────┐
│ ContentView · HostTable · HostDetail · Settings      │
│            ▲ polls snapshot() every 300 ms           │
└────────────┼─────────────────────────────────────────┘
             │ ResultStore (lock-protected, versioned)
┌────────────┴────────────── ScanJob (GCD) ───────────┐
│ 1 Discovery   ARP poke ║ ICMP sweep ║ TCP ping       │──► arp -an → MAC
│ 2 Enrichment  OUI vendor · DNS · mDNS · NetBIOS      │   (runs alongside 3)
│ 3 Ports       ConnectScanner: 1 thread, poll()       │──► ServiceProbe (banners)
└──────────────────────────────────────────────────────┘
```

- **No root.** ICMP uses `SOCK_DGRAM` + `IPPROTO_ICMP`, which macOS allows for unprivileged processes; ports use plain `connect()`. That is why SYN scans, UDP scans and OS fingerprinting are intentionally out of scope.
- **One thread, thousands of sockets.** `ConnectScanner` keeps a window of non‑blocking sockets and multiplexes them with `poll()`. Sockets close with `SO_LINGER=0` (RST), so no `TIME_WAIT` pile‑up.
- **File descriptors.** The macOS default soft limit is 256; the app raises it to 10240 via `setrlimit` and caps parallelism at `limit − 128`.
- **Responsive UI.** Workers write into `ResultStore` under a lock; the UI takes a snapshot only when the version changes.

## Things to know

- **Local Network privacy (macOS 15+).** If no devices are found, check *System Settings → Privacy & Security → Local Network → LANA Scanner*. Rebuilding with a new ad‑hoc signature can reset the permission.
- **Yellow dot, "ARP only".** The device answered neither ICMP nor TCP but is in the ARP cache: either a firewalled host (typical for Windows) or a stale entry. macOS keeps ARP entries for about 20 minutes; flush them with `sudo arp -a -d`.
- **MAC addresses** are visible only within your own L2 segment. Behind a router or VPN you get IP, names and ports only (sometimes a MAC via NetBIOS).
- **"Random MAC"** means an iOS, Android or macOS private Wi‑Fi address, which has no vendor by design.
- **Network load.** "All 1–65535" × /24 means millions of connections. IDS/IPS may alert and consumer routers may choke (NAT/conntrack table). Prefer Top 100/1000 for wide ranges and keep parallelism around 256–512 on Wi‑Fi.
- **Timeout.** The 800 ms default suits wired LANs. Use 1500–2000 ms on Wi‑Fi with sleepy phones and IoT devices.

> **Only scan networks you own or are explicitly authorized to test.**

## Project layout

```
Sources/NetScanner/
  App/     NetScannerApp.swift   @main, menus, AppDelegate (rlimit, SIGPIPE)
  Model/   IPv4, TargetParser (targets/ports/services), Models, ScanSettings, PortData (generated)
  Net/     Sockets, Interfaces, ConnectScanner, ICMPPinger (+ARP), NameResolver (DNS/mDNS/NetBIOS),
           ServiceProbe (+Wake-on-LAN), OUIDatabase
  Engine/  ScanJob (pipeline), ResultStore, ScanViewModel, ToolRunner (ping/traceroute)
  UI/      ContentView, HostTableView, HostDetailView, HostActions, SettingsView
Tests/NetScannerTests/       parser and protocol tests
Assets/                      app icon (SVG source + .icns)
Localization/                en.lproj / ru.lproj UI strings (copied into the app bundle)
scripts/                     build-app.sh, gen-portdata.py
.github/workflows/           CI (tests + build) and release (published release → zipped .app attached)
```

## Maintenance

- **Vendor database:** menu *Scan → Update Vendor Database*. The source is IEEE, with `nmap-mac-prefixes` as a fallback. It is stored in `~/Library/Application Support/NetScanner/oui.txt`, and `build-app.sh` bundles it when present, so builds work offline.
- **Top‑ports refresh:**
  ```bash
  curl -fsSLo /tmp/nmap-services https://raw.githubusercontent.com/nmap/nmap/master/nmap-services
  python3 scripts/gen-portdata.py /tmp/nmap-services
  ```
- **Uninstall:** delete `/Applications/LANA Scanner.app` and `~/Library/Application Support/NetScanner/`, then run `defaults delete com.github.lanascanner`.

## Localization

UI strings live in `Localization/<lang>.lproj/Localizable.strings`. The keys are the English strings used in the Swift code. To add a language:

1. Copy `Localization/en.lproj` to `Localization/<lang>.lproj` and translate the right-hand side of every line, keeping `%lld` / `%@` placeholders.
2. Add the language code to `CFBundleLocalizations` in `scripts/build-app.sh`.
3. Run `python3 scripts/check-l10n.py`: it verifies keys and placeholders (CI runs it too).

To test another language without changing the system language: `open -n "build/LANA Scanner.app" --args -AppleLanguages "(ru)"`.

## Releasing

Open **Releases → Draft a new release**, create a tag such as `v1.0.0`, click **Generate release notes** and **Publish**. GitHub Actions then builds a universal app and attaches `LANA-Scanner-<version>-macOS.zip` (plus a SHA-256 checksum) to the release within a few minutes.

## Acknowledgements

- Port popularity rankings and service names are derived from [`nmap-services`](https://github.com/nmap/nmap/blob/master/nmap-services) by the Nmap Project. Nmap itself is neither included nor required.
- MAC vendor data comes from the [IEEE OUI registry](https://standards-oui.ieee.org/) and is downloaded at runtime, not redistributed.

## License

[MIT](LICENSE) © 2026 Vianor Gvazbaya
