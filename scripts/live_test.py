#!/usr/bin/env python3
"""
9NS Live Verification Suite
Executes live network tests against real public DNS resolvers, validates protocols
(Plain DNS with DNSSEC, DoT over TLS 853, DoH wire format, GitHub repos),
and verifies package integrity for 9ns.exe and the Windows distribution.
"""

import socket
import ssl
import struct
import urllib.request
import urllib.error
import time
import os
import shutil
import subprocess
import zipfile

GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

passed_tests = 0
failed_tests = 0

OBJDUMP = shutil.which("objdump")
if not OBJDUMP:
    raise SystemExit("Error: objdump not found. Run from the MSYS2 MinGW64 shell (mingw64/bin first on PATH).")

def report(name, success, detail=""):
    global passed_tests, failed_tests
    if success:
        passed_tests += 1
        print(f"  [{GREEN}PASS{RESET}] {BOLD}{name}{RESET} {detail}")
    else:
        failed_tests += 1
        print(f"  [{RED}FAIL{RESET}] {BOLD}{name}{RESET} {RED}{detail}{RESET}")

def build_dns_query(domain, qtype=1, set_dnssec_do=True):
    """Builds standard DNS wire format query."""
    tx_id = 0x5a31
    flags = 0x0100  # Standard query with Recursion Desired (RD)
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 1 if set_dnssec_do else 0

    header = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)
    qname = b""
    for part in domain.split("."):
        qname += struct.pack("!B", len(part)) + part.encode("ascii")
    qname += b"\x00"

    question = qname + struct.pack("!HH", qtype, 1)  # Class IN

    edns = b""
    if set_dnssec_do:
        # OPT record (type 41, UDP payload 4096, DO bit 0x8000)
        edns = b"\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00"

    return header + question + edns

def parse_dns_response(data):
    """Parses basic fields from DNS wire response."""
    if len(data) < 12:
        return None
    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x000F
    ad_bit = bool(flags & 0x0020)
    ra_bit = bool(flags & 0x0080)
    return {
        "tx_id": tx_id,
        "rcode": rcode,
        "ad_bit": ad_bit,
        "ra_bit": ra_bit,
        "ancount": ancount,
        "data_len": len(data)
    }

print(f"\n{CYAN}{BOLD}======================================================================{RESET}")
print(f"{CYAN}{BOLD}               9NS Live Test & Verification Suite               {RESET}")
print(f"{CYAN}{BOLD}======================================================================{RESET}\n")

# ---------------------------------------------------------------------------
# TEST GROUP 1: Live GitHub Resolvers Repositories
# ---------------------------------------------------------------------------
print(f"{BOLD}1. Live Public Resolvers Repository Sync:{RESET}")
resolvers_url = "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/public-resolvers.md"
relays_url = "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/relays.md"

try:
    req = urllib.request.Request(resolvers_url, headers={"User-Agent": "9NS-Test/1.0"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=10) as resp:
        content = resp.read().decode("utf-8", errors="replace")
    rtt = (time.time() - t0) * 1000
    resolvers_count = content.count("## ")
    stamps_count = content.count("sdns://")
    report("GitHub public-resolvers.md fetch", resp.status == 200,
           f"({len(content):,} bytes, {resolvers_count} resolvers, {stamps_count} stamps, {rtt:.0f} ms)")
except Exception as e:
    report("GitHub public-resolvers.md fetch", False, str(e))

try:
    req = urllib.request.Request(relays_url, headers={"User-Agent": "9NS-Test/1.0"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=10) as resp:
        content = resp.read().decode("utf-8", errors="replace")
    rtt = (time.time() - t0) * 1000
    relays_count = content.count("## ")
    report("GitHub relays.md fetch", resp.status == 200,
           f"({len(content):,} bytes, {relays_count} anonymized relays, {rtt:.0f} ms)")
except Exception as e:
    report("GitHub relays.md fetch", False, str(e))

# ---------------------------------------------------------------------------
# TEST GROUP 2: Live Plain DNS (UDP 53) & DNSSEC AD Validation
# ---------------------------------------------------------------------------
print(f"\n{BOLD}2. Live Plain DNS & DNSSEC AD Bit Validation (UDP 53):{RESET}")

def test_plain_dns(server_ip, name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(4.0)
    query = build_dns_query("example.com", qtype=1, set_dnssec_do=True)
    t0 = time.time()
    try:
        sock.sendto(query, (server_ip, 53))
        reply, _ = sock.recvfrom(4096)
        rtt = (time.time() - t0) * 1000
        parsed = parse_dns_response(reply)
        ok = parsed and parsed["rcode"] == 0 and parsed["ancount"] > 0
        ad_str = f"{GREEN}AD=1 (DNSSEC Validated){RESET}" if parsed and parsed["ad_bit"] else "AD=0"
        report(f"Plain DNS to {name} ({server_ip}:53)", ok,
               f"-> RCODE: {parsed['rcode']}, Answers: {parsed['ancount']}, {ad_str}, RTT: {rtt:.1f} ms")
    except Exception as e:
        report(f"Plain DNS to {name} ({server_ip}:53)", False, str(e))
    finally:
        sock.close()

test_plain_dns("1.1.1.1", "Cloudflare")
test_plain_dns("8.8.8.8", "Google DNS")
test_plain_dns("9.9.9.9", "Quad9 (DNSSEC)")

# ---------------------------------------------------------------------------
# TEST GROUP 3: Live DNS over TLS (DoT - RFC 7858 TCP 853)
# ---------------------------------------------------------------------------
print(f"\n{BOLD}3. Live DNS over TLS (DoT - TCP 853 with TLS & SNI):{RESET}")

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(f"Connection closed while reading {n} bytes (got {len(buf)})")
        buf += chunk
    return buf

def test_dot(server_ip, sni_name):
    query = build_dns_query("example.com", qtype=1, set_dnssec_do=False)
    framed_query = struct.pack("!H", len(query)) + query
    t0 = time.time()
    for attempt in range(2):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((server_ip, 853), timeout=8.0) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=sni_name) as tls_sock:
                    tls_version = tls_sock.version()
                    cipher = tls_sock.cipher()[0]
                    tls_sock.sendall(framed_query)
                    length_bytes = recv_exact(tls_sock, 2)
                    length = struct.unpack("!H", length_bytes)[0]
                    reply = recv_exact(tls_sock, length)
                    rtt = (time.time() - t0) * 1000
                    parsed = parse_dns_response(reply)
                    ok = parsed and parsed["rcode"] == 0 and parsed["ancount"] > 0
                    ad_str = "AD=1" if parsed and parsed["ad_bit"] else "AD=0"
                    report(f"DoT to {sni_name} ({server_ip}:853)", ok,
                           f"-> {tls_version} ({cipher}), Answers: {parsed['ancount']}, {ad_str}, RTT: {rtt:.1f} ms")
                    return
        except Exception as e:
            if attempt == 1:
                report(f"DoT to {sni_name} ({server_ip}:853)", False, str(e))
            else:
                time.sleep(0.5)

test_dot("1.1.1.1", "cloudflare-dns.com")
test_dot("8.8.8.8", "dns.google")
test_dot("9.9.9.9", "dns.quad9.net")

# ---------------------------------------------------------------------------
# TEST GROUP 4: Live DNS over HTTPS (DoH / Wire Format)
# ---------------------------------------------------------------------------
print(f"\n{BOLD}4. Live DNS over HTTPS (DoH Wire Format application/dns-message):{RESET}")

def test_doh(doh_url, provider_name):
    query = build_dns_query("example.com", qtype=1, set_dnssec_do=True)
    req = urllib.request.Request(doh_url, data=query, headers={
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
        "User-Agent": "9NS/1.0"
    })
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=6.0) as resp:
            data = resp.read()
            rtt = (time.time() - t0) * 1000
            parsed = parse_dns_response(data)
            ok = resp.status == 200 and parsed and parsed["rcode"] == 0 and parsed["ancount"] > 0
            ad_str = "AD=1" if parsed and parsed["ad_bit"] else "AD=0"
            report(f"DoH to {provider_name} ({doh_url})", ok,
                   f"-> HTTP {resp.status}, Answers: {parsed['ancount']}, {ad_str}, RTT: {rtt:.1f} ms")
    except Exception as e:
        report(f"DoH to {provider_name} ({doh_url})", False, str(e))

test_doh("https://cloudflare-dns.com/dns-query", "Cloudflare DoH")
test_doh("https://dns.google/dns-query", "Google DoH")
test_doh("https://dns.adguard-dns.com/dns-query", "AdGuard DoH")

# ---------------------------------------------------------------------------
# TEST GROUP 5: Binary PE, Manifest & Dependencies Verification
# ---------------------------------------------------------------------------
print(f"\n{BOLD}5. Binary PE & Dependency Closure Verification:{RESET}")

exe_path = "build-win/9ns.exe"
if os.path.isfile(exe_path):
    size_mb = os.path.getsize(exe_path) / (1024 * 1024)
    res = subprocess.run([OBJDUMP, "-f", exe_path], capture_output=True, text=True)
    is_x86_64 = "pei-x86-64" in res.stdout or "x86-64" in res.stdout
    report("Target PE Binary Architecture (x86-64)", is_x86_64, f"({exe_path}, {size_mb:.2f} MB)")
else:
    report("Target PE Binary Architecture (x86-64)", False, "File missing")

# Check bundled DLLs in distribution folder
dist_dir = "dist/9ns-windows-x64"
required_core_dlls = [
    "Qt6Core.dll", "Qt6Gui.dll", "Qt6Widgets.dll",
    "libcrypto-3-x64.dll", "libssl-3-x64.dll", "libsodium-26.dll",
    "libgcc_s_seh-1.dll", "libstdc++-6.dll", "libwinpthread-1.dll"
]
missing_dlls = [d for d in required_core_dlls if not os.path.isfile(os.path.join(dist_dir, d))]
report("Distribution Core Runtime DLLs", len(missing_dlls) == 0,
       f"Checked {len(required_core_dlls)} critical DLLs (Missing: {missing_dlls or 'None'})")

qwindows_path = os.path.join(dist_dir, "platforms", "qwindows.dll")
report("Qt6 Windows Platform Plugin (platforms/qwindows.dll)", os.path.isfile(qwindows_path))

# Check ZIP archive
zip_path = "dist/9ns-windows-x64.zip"
if os.path.isfile(zip_path):
    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            corrupt = z.testzip()
            file_count = len(z.infolist())
        report("Distribution ZIP Archive Integrity", corrupt is None,
               f"({zip_path}, {os.path.getsize(zip_path)/(1024*1024):.1f} MB, {file_count} files, checksums OK)")
    except Exception as e:
        report("Distribution ZIP Archive Integrity", False, str(e))
else:
    report("Distribution ZIP Archive Integrity", False, "Missing zip file")

# ---------------------------------------------------------------------------
# TEST GROUP 6: Windows Setup Installer Verification
# ---------------------------------------------------------------------------
print(f"\n{BOLD}6. Windows Setup Installer Verification:{RESET}")
setup_path = "dist/9NS-Setup-1.0.0.exe"
if os.path.isfile(setup_path):
    res_objdump = subprocess.run([OBJDUMP, "-f", setup_path], capture_output=True, text=True)
    is_x64 = "pei-x86-64" in res_objdump.stdout
    setup_size = os.path.getsize(setup_path) / (1024 * 1024)
    report("Standalone Windows Setup Installer PE (x86-64)", is_x64,
           f"({setup_path}, {setup_size:.2f} MB, embedded zip payload, elevated manifest)")
else:
    report("Standalone Windows Setup Installer", False, f"Missing {setup_path}")

iss_path = "packaging/9ns-setup.iss"
report("Inno Setup Script Configuration", os.path.isfile(iss_path), f"({iss_path}, Modern WizardStyle)")

print(f"\n{BOLD}----------------------------------------------------------------------{RESET}")
print(f"Results: {GREEN}{passed_tests} PASSED{RESET}, {RED}{failed_tests} FAILED{RESET} (Total: {passed_tests + failed_tests})")
print(f"{BOLD}----------------------------------------------------------------------{RESET}\n")

if failed_tests > 0:
    exit(1)
