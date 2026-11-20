<div align="center">

<img src="src/resources/9ns-mark.svg" alt="9NS Logo" width="128" height="128">

# 9NS

**Advanced System DNS Client for Windows**  


[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20(x64)-blue.svg)](#requirements)
[![C++](https://img.shields.io/badge/C%2B%2B-17-00599C.svg?logo=c%2B%2B)](#build)
[![Qt](https://img.shields.io/badge/Qt-6.5%2B-41CD52.svg?logo=qt)](#build)
[![Protocols](https://img.shields.io/badge/Protocols-DoH%20%7C%20DoT%20%7C%20DoQ%20%7C%20ODoH%20%7C%20DNSCrypt-purple.svg)](#1-supported-protocols)
[![License](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

</div>



<div align="center">
9NS is a <span style="color: red;">ULTRA</span>&nbsp;&nbsp;/&nbsp;&nbsp;<span style="color: brown;">SUPER</span>&nbsp;&nbsp;/&nbsp;&nbsp;<span style="color: blue;">GROUNDBREAKING</span>&nbsp;&nbsp;/&nbsp;&nbsp;<span style="color: darkblue;">UNBELIEVABLE</span> DNS Client for Windows :)

<img src="doc/assets/batman.gif" alt="9NS + Batman" width="256" height="256">

</div>

---

## Overview
**9NS** is a good DNS client, proxy, and routing engine for Windows 10/11 (x64). It intercepts system DNS requests on local port 53 and securely routes them through encrypted transports, multi-server pools, and customizable filtering rules.


### Interface

The window uses a sidebar with six pages, reachable from the sidebar, the View menu
or `Ctrl+1`–`Ctrl+6`:

1. **Overview** - protection summary, live metrics and last-tested upstream latency.
2. **Query Log** - bounded live query history with domain search (`Ctrl+F`), status
   filter, numeric latency sorting and right-click block/bypass/inspect.
3. **Servers & Pools** - upstreams, pools, the default target, and inline tests.
4. **Rules** - first-match routing and blocking rules with keyboard reordering.
5. **Settings** - listener/cache, security, background operation and logging.
6. **System Log** - diagnostics output.
7. **kernel driver** - The optional kernel driver additionally requires test signing (or a trusted code-signing
  certificate) to load.

---

## Key Features

### 1. Supported Protocols
- **Plain DNS**: Traditional UDP and TCP on port 53 with fallback and timeout controls.
- **DNS over HTTPS (DoH)**: Encrypted DNS over HTTPS using HTTP/2 with custom bootstrap IPs to eliminate bootstrap chicken-and-egg resolution loops.
- **DNS over TLS (DoT - RFC 7858)**: Dedicated TLS encryption on TCP port 853 via OpenSSL, featuring Server Name Indication (SNI) and Windows Root Certificate Store verification.
- **DNSCrypt v2**: Curve25519 authenticated and encrypted tunnels protecting queries from ISP tampering.
- **Anonymized DNSCrypt Relays**: Two-hop onion-style relays (`0x81` stamps) hiding client IP addresses from resolver operators.
- **Oblivious DoH (ODoH - RFC 9230)**: HPKE-encrypted queries sent through ODoH relays (`0x85` stamps) so no single server sees both the client IP and the query; optionally direct to the target.
- **DNS over QUIC (DoQ - RFC 9250)**: DNS over QUIC streams on UDP port 853 via the OpenSSL QUIC client, with TLS 1.3 and ALPN `doq`.
- **DNS Stamps (`sdns://`)**: Import and decode DNS stamps across all encrypted protocols.

### 2. DNS Server Pools & Load Balancing
Group multiple upstream servers with intelligent routing strategies:
- **`failover`**: Priority-based fallback (routes to secondary servers if primary fails).
- **`fastest`**: Routes queries to the server with the lowest measured round-trip latency.
- **`round_robin`**: Evenly balances queries across healthy upstream servers.
- **`random`**: Distributes queries randomly among active pool members.

### 3. Rules Engine & Hosts Integration
- **Flexible Pattern Matching**: Wildcard expressions (`*.example.com`, `*`, `ad*.domain.org`).
- **Multi-Hostname Rules**: Comma, semicolon, or newline-delimited domain lists in a single rule.
- **Hosts File / Blocklist Import**: Load external blocklists or standard `/etc/hosts` formatted files directly.
- **Rich Action Modes**:
  - `process`: Route to a designated server or server pool.
  - `block`: Block queries returning **NXDOMAIN**, **Null IP** (`0.0.0.0` / `::`), **REFUSED**, or silent **DROP**.
  - `bypass`: Bypass the proxy and resolve directly through the system network adapter.
  - `local`: Return static mapped IPv4 or IPv6 addresses.
- **Query Type & Interface Conditions**: Bind rules to specific query types (A, AAAA, PTR, ANY) or network adapters.

### 4. Client-Side DNSSEC Validation
- Validates the Authenticated Data (**AD**) bit over secure encrypted upstream transports.
- Performs cryptographic **RRSIG** signature validity checks against inception and expiration timestamps.
- Automatically marks status as `Secure`, `Insecure`, `Bogus`, or `Indeterminate`, and returns `SERVFAIL` on `Bogus` replies to prevent cache poisoning.

### 5. Multi-Homed Leak Prevention & Dual-Stack Loopback
- Configures dual-stack `127.0.0.1` and `::1` loopback on active network adapters.
- Mitigates Windows Multi-Homed DNS leaks by managing the `DisableSmartNameResolution` registry policy.
- Automatic **Crash Recovery Watchdog**: An isolated watchdog process monitors the main proxy and restores original adapter DNS configurations in the event of an abnormal termination.

### 6. Windows Background Service
- Run 9NS completely in the background without requiring a user to be logged in:
  ```cmd
  9ns.exe --install-service
  9ns.exe --uninstall-service
  9ns.exe --service
  ```

### 7. Public Resolvers & Relays Browser
- Directly synchronizes with official repositories:
  - [`public-resolvers.md`](https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/public-resolvers.md) (780+ resolvers)
  - [`relays.md`](https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/relays.md) (315+ relays)
  - [`odoh-servers.md`](https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-servers.md) and [`odoh-relays.md`](https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-relays.md) (ODoH targets and relays)
- Search by name, country, or protocol (DoH, DoQ, ODoH, DNSCrypt, Relay).
- Filter by capabilities: **DNSSEC**, **No Logs**, **No Filter**.
- Live **RTT Ping Benchmarking** directly in the UI.
- One-click server import and one-click **Server Pool Generation**.

### 8. Kernel DNS Guard Driver (NineNsFlt)
- A Windows Filtering Platform callout driver that blocks DNS (UDP/TCP 53) to any
  non-loopback address, enforcing resolution through 9NS at the kernel level.
- Ships inside the portable package and the setup installer (optional wizard checkbox);
  installs via its INF as a kernel service depending on the Base Filtering Engine (BFE).
- Test-signed: load it only on test machines with `bcdedit /set testsigning on` and
  trust the certificate actually used to sign the package (Root + Trusted Publishers).
  The build defaults to `9NS Test Signing`; `NINENS_SIGNING_THUMBPRINT` selects an
  existing signing certificate without creating one.
- Note: the policy also blocks 9NS's own plain-DNS upstreams - use DoH, DoT, DoQ,
  ODoH, or DNSCrypt upstreams while the driver is active.



### 9. Configuration Reference

Configuration files are located in `%ProgramData%\9NS\config.json`. 
A complete example is provided in [`src/config/config.example.json`](src/config/config.example.json)


---

## Requirements

- Windows 10 or 11 (64-bit x64).
- Administrator rights to run (local port 53 and adapter DNS changes).
- Optional kernel driver: Visual Studio Build Tools (C++), the Windows Driver
  Kit, and test signing.

## Build

Build from an MSYS2 MinGW64 shell (CMake + Ninja; Qt 6.5+, OpenSSL, libsodium,
nlohmann-json):

```bash
cmake -S . -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=<msys64>/mingw64
cmake --build build-win
```

See [CONTRIBUTING.md](CONTRIBUTING.md#building-and-testing) for the full
development, test and packaging workflow.

---

## Windows installer

The native `9NS-Setup-1.0.0.exe` installs for all users and requests administrator
rights. Its wizard includes the license, Typical or Custom setup, installation
folder, components, a review of choices, progress details and a completion report.
Typical setup uses the current defaults; Custom exposes each choice. Fresh
installs select desktop and Start Menu shortcuts, but **not** the background
service or kernel DNS guard. Launch happens only when you click Finish.

Setup checks Windows/x64 compatibility, Windows' inbox `tar.exe`, the destination
and its permissions, available disk space, and running 9NS processes/services.
Before upgrading, exit 9NS from its tray menu and stop its background service
normally so adapter DNS can be restored. If reinstalling the kernel driver, stop
`NineNsFlt` first as well. Setup does not terminate these processes, redirect
adapter DNS, start the background service, reboot Windows, enable test-signing or
disable Secure Boot. The optional driver must meet Windows' signing requirements.

Existing registered installations are upgraded in place. Configuration and DNS
backups in `%ProgramData%\9NS` are not modified; an existing root `config.json`
in the install folder is preserved too. Unchecked integrations are left installed,
not removed. Existing service account, startup and recovery settings are preserved
when updating its executable path. A newly registered service starts on the next
Windows boot.

Setup records planned file ownership before replacing payload files. A failed
installation can be retried using that recovery manifest, even if `9ns.exe` was
not copied yet. Unknown files are preserved, and a new payload cannot overwrite
an unowned file. There is **no automatic rollback**: some files may already have
been updated when an installation fails. Resolve the reported error and rerun
setup; do not remove the recovery manifest.

### Unattended installation

Run from an elevated PowerShell session. `/silent` requires `/acceptlicense` and
never launches the app, even if `/launch=yes` is supplied. UAC elevation is not
bypassed. For example:

```powershell
$setup = Start-Process -FilePath .\9NS-Setup-1.0.0.exe -ArgumentList @(
    '/silent', '/acceptlicense', '/service=yes', '/driver=no',
    '/desktop=no', '/startmenu=yes'
) -Wait -PassThru
$setup.ExitCode
```

Supported switches (case-insensitive, no duplicates):

| Switch | Meaning / default |
| --- | --- |
| `/silent` | No setup UI; requires `/acceptlicense` |
| `/acceptlicense` | Accept the bundled AGPL v3 license |
| `/dir=<absolute folder>` | Existing registered folder, otherwise Program Files\9NS |
| `/log=<absolute file>` | New UTF-8 log file; parent folder must already exist |
| `/desktop=yes|no` | Desktop shortcut; default `yes` |
| `/startmenu=yes|no` | Start Menu shortcut; default `yes` |
| `/service=yes|no` | Register background service; default `no` |
| `/driver=yes|no` | Install kernel DNS guard; default `no` |
| `/launch=yes|no` | Launch on Finish; default `yes`, always `no` in silent mode |
| `/help` or `/?` | Show options; `/silent /help` prints without a dialog |

Quote an entire argument containing spaces, such as
`"/dir=C:\Program Files\9NS"`. By default, a uniquely named
`%TEMP%\9NS-Setup-<random>.log` records installation stages, pre-install failures
and integration warnings. `/log` never overwrites an existing file. The completion
screen and console output identify the log path.

Exit codes: `0` success; `1` installation/log failure; `2` invalid command line;
`3` pre-install check failed; `4` core files installed with integration/log warnings;
`1602` cancelled. Code `4` requires checking the log; it does not mean the service
or driver was installed successfully.

Build with `python scripts/package_windows.py` followed by
`python scripts/create_setup.py` from the MSYS2 MinGW64 shell. Rebuild the portable
ZIP first after application changes: the setup generator reuses an existing ZIP.
These wizard and command-line options apply to the native installer, not the
separate optional Inno Setup script.

---

## License

This project is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE) for details.
