# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-10-27

### Added
- English user interface; Russian is kept as a localization and selected automatically from the macOS system language.
- `scripts/check-l10n.py` (run in CI) to verify translation keys and format placeholders.

## [1.0.0] - 2026-10-27

### Added
- Host discovery without root: ARP cache, ICMP echo (unprivileged DGRAM socket), TCP ping.
- MAC address and vendor lookup (IEEE OUI, auto-downloaded and cached).
- Hostname resolution via reverse DNS, mDNS and NetBIOS (name, workgroup).
- TCP connect port scanner multiplexed with `poll()`; presets Top 100 / Top 1000 (nmap rankings), 1–1024, all ports, custom lists.
- Service detection from banners (SSH, FTP, SMTP, POP3, IMAP, VNC, MySQL/MariaDB, HTTP `Server` header).
- Host actions: open HTTP/HTTPS, SSH, SMB, RDP, VNC, FTP; ping and traceroute with live output; Wake-on-LAN; copy IP/MAC/name.
- Sortable, filterable host table with detail pane and context menu.
- `scripts/build-app.sh`: app bundle, ad-hoc signing, install to `/Applications`.
- CI workflow and a release workflow that attaches the built app to published GitHub Releases.
