<div align="center">

<img src="src/resources/9ns-mark.svg" alt="9NS Logo" width="128" height="128">

# 9NS

**Advanced System DNS Client for Windows**  


[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20(x64)-blue.svg)](#requirements)
[![C++](https://img.shields.io/badge/C%2B%2B-17-00599C.svg?logo=c%2B%2B)](#build)
[![Qt](https://img.shields.io/badge/Qt-6.5%2B-41CD52.svg?logo=qt)](#build)
[![Protocols](https://img.shields.io/badge/Protocols-DoH%20%7C%20DoT%20%7C%20DoQ%20%7C%20ODoH%20%7C%20DNSCrypt-purple.svg)](#1-supported-protocols)
[![License](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Donate BTC](https://img.shields.io/badge/Donate-BTC-F7931A.svg?logo=bitcoin&logoColor=white)](#donate)

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
5. **Settings** - listener/cache, security, background operation, logging and the optional local forwarding proxy.
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



### 9. Local Forwarding Proxy (SOCKS5 / SOCKS4a / HTTP CONNECT)

Enable **Local forwarding proxy** in Settings, save, and restart the engine. Point
applications at `127.0.0.1:1080` (or the configured port). SOCKS5, SOCKS4/4a and HTTP
CONNECT share one auto-detecting TCP port. The listener is always loopback-only;
IPv6 `::1` is also used when available. It is disabled by default and works in
both GUI and service mode. An occupied proxy port is logged without stopping DNS.

Use SOCKS5 remote hostname resolution (often called `socks5h`) or SOCKS4a so names
reach 9NS instead of the application's own DNS resolver. Hostname lookups use the
existing DNS rules, cache, pools and DNSSEC pipeline and appear in the Query Log.
Block rules refuse connections; `local` rules substitute the configured static
address. Connection outcomes appear in the System Log. `bypass` does not bypass
DNS resolution for forwarding targets. Numeric targets cannot recover a hostname
that the client resolved itself, so hostname rules require remote resolution.

Optional username/password authentication supports SOCKS5 and HTTP Basic; both
fields must be set together. SOCKS4/4a is refused when authentication is enabled,
since it cannot carry a password. Credentials are stored in the protected config
file, not encrypted separately. Only TCP CONNECT is supported: no SOCKS BIND,
UDP ASSOCIATE or ordinary HTTP forwarding. Connections are capped at 128, with a
120-second relay idle timeout. Settings apply at the next engine start.

#### Outbound DNS upstream proxy

The separate `upstream_proxy` config block routes supported **DNS transports**
through an HTTP CONNECT or SOCKS5 proxy; it does not chain local forwarding-proxy
application traffic through that proxy. Port `0` selects `1080` for SOCKS5 or
`8080` for HTTP. DoH/ODoH use WinHTTP and require an HTTP proxy, not SOCKS5;
bootstrap-IP pinning is skipped in that mode because the proxy reaches the target.
Plain DNS uses TCP when proxying, and DoT uses a tunnel. Unsupported combinations
are rejected rather than silently falling back to direct DNS. DoQ and UDP-only
DNSCrypt cannot traverse an upstream proxy.

### 10. Configuration Reference

Configuration files are located in `%ProgramData%\9NS\config.json`.
The optional `forward_proxy` and `upstream_proxy` blocks are disabled by default;
omitting them preserves the existing DNS-only behavior. A complete example is
provided in [`src/config/config.example.json`](src/config/config.example.json).


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

The native `9NS-Setup-1.1.0.exe` installs for all users and requests administrator
rights. Its wizard includes the license, Typical or Custom setup, installation
folder, components, a review of choices, progress details and a completion report.
Typical setup uses the current defaults; Custom exposes each choice. Fresh
installs select desktop and Start Menu shortcuts, but **not** the background
service or kernel DNS guard. Launch happens only when you click Finish.

Setup checks Windows/x64 compatibility, Windows' inbox `tar.exe`, the destination
and its permissions, available disk space, and running 9NS processes/services.
Before upgrading, exit 9NS from its tray menu and stop its background service
normally so adapter DNS can be restored. If reinstalling the kernel driver, stop
`NineNsFlt` first as well. Normal installation does not terminate these processes;
the explicit uninstall and repair modes stop the installed app and service and
restore adapter DNS first. Setup does not start the background service, reboot
Windows, enable test-signing or disable Secure Boot. The optional driver must meet
Windows' signing requirements.

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
$setup = Start-Process -FilePath .\9NS-Setup-1.1.0.exe -ArgumentList @(
    '/silent', '/acceptlicense', '/service=yes', '/driver=no',
    '/desktop=no', '/startmenu=yes'
) -Wait -PassThru
$setup.ExitCode
```

Supported switches (case-insensitive, no duplicates):

| Switch | Meaning / default |
| --- | --- |
| `/silent` | No setup UI; `/acceptlicense` is required only for installation |
| `/uninstall` | Remove the registered native installation |
| `/repair` | Re-extract and repair the registered native installation |
| `/keepdata=yes\|no` | Uninstall: keep settings/logs/DNS backup by default (`yes`) |
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

### Uninstallation

Use Windows **Installed apps / Add or remove programs → 9NS → Uninstall**, or run
`uninstall.exe /uninstall` from the installed folder. The native uninstaller
requests administrator rights and offers to remove settings, logs and the DNS
backup in `%ProgramData%\9NS`; **keeping data is the default**. It requires the
registered installation and a valid ownership manifest. A missing or unreadable
manifest is a preflight failure, never permission to recursively delete a folder.

```powershell
$remove = Start-Process -FilePath '.\uninstall.exe' -ArgumentList @(
    '/uninstall', '/silent', '/keepdata=no', '/log=C:\temp\9ns-uninstall.log'
) -Wait -PassThru
$remove.ExitCode
```

The log's parent directory must already exist and the file must not exist.
Silent removal needs no `/acceptlicense`; Windows' quiet uninstall command keeps
data. `/uninstall` and `/repair` cannot be combined. Installation component
switches are not accepted with `/uninstall`, and `/dir` cannot select a different
folder from the registered installation.

Teardown stops the installed GUI, stops and deletes its service, waits for its
watchdog, and invokes `9ns.exe --restore-dns` before removing application files.
It then stops/deletes the driver service, removes the identified driver-store
package and driver binary, removes shared shortcuts and the current user's
`HKCU\Software\9NS`, removes manifest-owned files and empty directories, and
optionally purges known runtime data. The ARP entry is removed only after file
removal succeeds. The running `uninstall.exe` may need deletion at reboot; the
completion report and log say when this is required. No portable copy outside
the registered folder is intentionally stopped.

Unknown files in either folder and a root-level install-folder `config.json`
are always preserved. `/keepdata=no` removes only `config.json`,
`system-dns-backup.json`, `service.log`, `9ns.log` and recognized log rotations
inside the protected runtime directory; a nonempty directory is kept. DNS-restore
and driver-removal failures are warnings, not hidden successes: inspect the log
and resolve them before assuming networking and driver state are clean.

Default removal logs use `%TEMP%\9NS-Uninstall-<random>.log`. Exit codes are `0`
for success, `1` for a fatal operation/log failure, `2` for invalid arguments,
`3` for preflight failure, `4` for warnings, and `1602` for cancellation. A failed
file removal retains the ARP entry for retry. Unknown files intentionally kept
are not permission to remove them manually without checking their ownership.

`uninstall.bat` remains an emergency fallback if `uninstall.exe` is missing. It
is **not equivalent** to the native uninstaller: it does not restore adapter DNS,
does not provide the native cleanup/logging guarantees, and must be run elevated.
Restore DNS first with `9ns.exe --restore-dns` while the executable still exists.
Service command-line operations also accept `--quiet` to suppress modal dialogs.

### Repair

Run `uninstall.exe /repair`, or `uninstall.exe /repair /silent`, to stop the
installed processes, restore adapter DNS and re-extract the bundled application
payload. The recovery manifest and uninstaller are committed before payload
replacement. `%ProgramData%\9NS` settings and unknown files remain untouched;
this is not a reset to factory settings or an upgrade to a newer version.
Component switches such as `/service=yes` and `/driver=yes` re-register the
selected integrations; unchecked integrations are not removed. `/log` and the
same exit-code contract apply. Repair is exposed as a command-line mode, not an
advertised non-MSI Windows Repair button.

---

## Donate

9NS is free, open-source software. If it has earned a place on your machine, a Bitcoin
donation keeps it maintained.

**BTC (Native SegWit / bech32):**

```
bc1qe0fg8qsc6n7ffke22qz38727e0nxnersq0en2u
```

The same address is reachable in the app under **About 9NS** and from the **Donate**
button in the Public Resolvers browser.

---

## License

This project is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE) for details.
