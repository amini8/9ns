#!/usr/bin/env python3
"""
Packages 9NS into a standalone, portable Windows x64 distribution.
Collects 9ns.exe, all transitive runtime MinGW and Qt6 DLLs,
Qt plugins (platforms, styles, imageformats), configuration templates,
the NineNsFlt kernel driver package, and convenient service control
batch files into a zip archive.
"""

import os
import sys
import shutil
import subprocess
import re
import zipfile

DIST_DIR = "dist"
PACKAGE_NAME = "9ns-windows-x64"
STAGE_DIR = os.path.join(DIST_DIR, PACKAGE_NAME)
ZIP_OUTPUT = os.path.join(DIST_DIR, "9ns-windows-x64.zip")

SYSTEM_DLLS = {
    "advapi32.dll", "kernel32.dll", "user32.dll", "gdi32.dll", "msvcrt.dll",
    "shell32.dll", "ole32.dll", "oleaut32.dll", "comctl32.dll", "comdlg32.dll",
    "winspool.drv", "imm32.dll", "ws2_32.dll", "winmm.dll", "shlwapi.dll",
    "version.dll", "iphlpapi.dll", "netapi32.dll", "winhttp.dll", "crypt32.dll",
    "secur32.dll", "d3d11.dll", "d3d9.dll", "d3d12.dll", "dxgi.dll", "dwrite.dll",
    "d2d1.dll", "uxtheme.dll", "dwmapi.dll", "wtsapi32.dll", "mpr.dll",
    "userenv.dll", "ntdll.dll", "rpcrt4.dll", "setupapi.dll", "bcrypt.dll",
    "ncrypt.dll", "shcore.dll", "authz.dll", "mscms.dll", "usp10.dll"
}

def detect_toolchain():
    """Returns (mingw_bin, qt_plugins_dir, objdump) for the MSYS2 MinGW64 environment."""
    objdump = shutil.which("objdump")
    if objdump:
        mingw_bin = os.path.dirname(os.path.abspath(objdump))
        plugins = os.path.normpath(os.path.join(mingw_bin, os.pardir, "share", "qt6", "plugins"))
        if os.path.isfile(os.path.join(mingw_bin, "Qt6Core.dll")) and os.path.isdir(plugins):
            return mingw_bin, plugins, objdump
    sys.exit("Error: MSYS2 MinGW64 toolchain not found. Run from the MSYS2 MinGW64 shell "
             "(mingw64/bin first on PATH).")

MINGW_BIN, QT_PLUGINS_DIR, OBJDUMP = detect_toolchain()
BUILD_EXE = "build-win/9ns.exe"

def get_imported_dlls(filepath):
    res = subprocess.run([OBJDUMP, "-p", filepath],
                         capture_output=True, text=True, check=True)
    dlls = []
    for line in res.stdout.splitlines():
        m = re.search(r"DLL Name:\s*(\S+)", line, re.I)
        if m:
            dlls.append(m.group(1).lower())
    return dlls

def main():
    if not os.path.isfile(BUILD_EXE):
        print(f"Error: {BUILD_EXE} not found. Please build the project first.")
        sys.exit(1)

    print("=== Creating 9NS Windows x64 Distribution Package ===")
    print(f"Toolchain bin: {MINGW_BIN}")
    print(f"Qt plugins:    {QT_PLUGINS_DIR}")
    
    # 1. Clean staging directory
    if os.path.exists(STAGE_DIR):
        shutil.rmtree(STAGE_DIR)
    os.makedirs(STAGE_DIR, exist_ok=True)
    os.makedirs(os.path.join(STAGE_DIR, "platforms"), exist_ok=True)
    os.makedirs(os.path.join(STAGE_DIR, "styles"), exist_ok=True)
    os.makedirs(os.path.join(STAGE_DIR, "imageformats"), exist_ok=True)

    # 2. Copy main executable
    shutil.copy2(BUILD_EXE, STAGE_DIR)
    print(f"Copied {BUILD_EXE} -> {STAGE_DIR}")

    # 3. Copy Qt plugins
    qwindows = os.path.join(QT_PLUGINS_DIR, "platforms", "qwindows.dll")
    shutil.copy2(qwindows, os.path.join(STAGE_DIR, "platforms"))
    print("Copied platforms/qwindows.dll")

    qstyle = os.path.join(QT_PLUGINS_DIR, "styles", "qmodernwindowsstyle.dll")
    if os.path.exists(qstyle):
        shutil.copy2(qstyle, os.path.join(STAGE_DIR, "styles"))
        print("Copied styles/qmodernwindowsstyle.dll")

    for img in ["qico.dll", "qjpeg.dll", "qgif.dll", "qsvg.dll"]:
        img_path = os.path.join(QT_PLUGINS_DIR, "imageformats", img)
        if os.path.exists(img_path):
            dst = os.path.join(STAGE_DIR, "imageformats", img)
            shutil.copy2(img_path, dst)
            print(f"Copied imageformats/{img}")

    # 4. Resolve transitive dependencies
    available_dlls = {f.lower(): f for f in os.listdir(MINGW_BIN) if f.lower().endswith(".dll")}

    to_analyze = [
        os.path.join(STAGE_DIR, "9ns.exe"),
        os.path.join(STAGE_DIR, "platforms", "qwindows.dll")
    ]
    if os.path.exists(os.path.join(STAGE_DIR, "styles", "qmodernwindowsstyle.dll")):
        to_analyze.append(os.path.join(STAGE_DIR, "styles", "qmodernwindowsstyle.dll"))
    for img in ["qico.dll", "qjpeg.dll", "qgif.dll", "qsvg.dll"]:
        p = os.path.join(STAGE_DIR, "imageformats", img)
        if os.path.exists(p):
            to_analyze.append(p)

    copied_dlls = set()
    while to_analyze:
        curr = to_analyze.pop(0)
        for dep in get_imported_dlls(curr):
            if dep in SYSTEM_DLLS or dep.startswith("api-ms-win-") or dep.startswith("ext-ms-win-"):
                continue
            if dep in copied_dlls:
                continue
            if dep in available_dlls:
                real_name = available_dlls[dep]
                src = os.path.join(MINGW_BIN, real_name)
                dst = os.path.join(STAGE_DIR, real_name)
                shutil.copy2(src, dst)
                copied_dlls.add(dep)
                to_analyze.append(dst)
                print(f"  + Bundled dependency: {real_name}")
            else:
                print(f"  ! Warning: dependency not found in MinGW bin dir: {dep}")

    # 5. Copy example configuration
    shutil.copy2("src/config/config.example.json", os.path.join(STAGE_DIR, "config.example.json"))

    # 6. Stage the NineNsFlt kernel driver package
    driver_out = os.path.join("src", "driver", "out")
    driver_files = ["NineNsFlt.sys", "NineNsFlt.cat", "NineNsFlt.inf"]
    missing = [f for f in driver_files if not os.path.isfile(os.path.join(driver_out, f))]
    if missing:
        print(f"Error: driver package not built (missing: {', '.join(missing)} in src/driver/out).")
        print("Run src\\driver\\build.cmd first.")
        sys.exit(1)
    os.makedirs(os.path.join(STAGE_DIR, "driver"), exist_ok=True)
    for f in driver_files:
        shutil.copy2(os.path.join(driver_out, f), os.path.join(STAGE_DIR, "driver", f))
    print("Copied driver/NineNsFlt.{sys,cat,inf}")

    # 7. Create helper batch scripts
    start_app_bat = """@echo off
cd /d "%~dp0"
echo Starting 9NS (Run as Administrator recommended for port 53 and adapter DNS)...
start "" "%~dp09ns.exe"
"""
    with open(os.path.join(STAGE_DIR, "start-app.bat"), "w", newline="\r\n") as f:
        f.write(start_app_bat)

    install_svc_bat = """@echo off
cd /d "%~dp0"
echo ===================================================================
echo Installing 9NS as a Windows Background Service
echo ===================================================================
echo.
"%~dp09ns.exe" --install-service
echo.
pause
"""
    with open(os.path.join(STAGE_DIR, "install-service.bat"), "w", newline="\r\n") as f:
        f.write(install_svc_bat)

    uninstall_svc_bat = """@echo off
cd /d "%~dp0"
echo ===================================================================
echo Uninstalling 9NS Background Windows Service
echo ===================================================================
echo.
"%~dp09ns.exe" --uninstall-service
echo.
pause
"""
    with open(os.path.join(STAGE_DIR, "uninstall-service.bat"), "w", newline="\r\n") as f:
        f.write(uninstall_svc_bat)

    # 8. Create README.txt
    readme_txt = """========================================================================
9NS - Advanced System DNS Client & Proxy for Windows
========================================================================

9NS is an advanced DNS client, proxy, and routing engine for Windows.
It intercepts and secures DNS traffic across your system with DoH, DoT,
DoQ, ODoH, DNSCrypt v2, Anonymized Relays, server pools, DNSSEC validation,
hosts blocklists, and multi-homed DNS leak protection.

REQUIREMENTS:
- Windows 10 or Windows 11 (64-bit).
- Administrator rights (requested automatically via application manifest)
  to bind to local port 53 and configure network adapter DNS.

QUICK START:
1. Extract this entire folder to your preferred location (e.g. C:\\Program Files\\9NS).
2. Double-click "9ns.exe" (or run "start-app.bat").
3. On first launch, the Setup Wizard will guide you through choosing:
   - Popular encrypted presets (Cloudflare, Google, Quad9, AdGuard)
   - Or open the "Public Resolvers" browser to pick from 1,000+ public resolvers.
4. Click "Start Engine" to activate protection.

FEATURES INCLUDED:
- Live Query Log: Real-time traffic inspection with instant right-click domain blocking/bypassing.
- Public Resolvers Browser: Directly loaded from dnscrypt-resolvers (780+ resolvers, 315+ relays)
  with ping latency benchmarking and 1-click pool generation.
- Encrypted Protocols: DNS over HTTPS (DoH / HTTP/2), DNS over TLS (DoT - RFC 7858),
  DNSCrypt v2, Anonymized Relays.
- Server Pools: Failover, Fastest (RTT ping), Round Robin, Random.
- Flexible Rules: Wildcard hostname patterns (*.example.com), hosts files, blocking modes
  (NXDOMAIN, Null IP 0.0.0.0, Refused, Drop), local IP mapping.
- Client DNSSEC: AD flag validation, RRSIG signature lifetime checks, SERVFAIL on Bogus.
- Leak Prevention: Dual-stack loopback (127.0.0.1, ::1) with DisableSmartNameResolution policy.
- Windows Service: Run in the background without any user logged in:
    9ns.exe --install-service
    9ns.exe --uninstall-service

RUNTIME CONFIGURATION & DATA:
Configuration and runtime logs are stored in:
    %ProgramData%\\9NS\\config.json
    %ProgramData%\\9NS\\9ns.log

KERNEL DNS GUARD DRIVER (driver\\ folder):
The driver\\ folder contains NineNsFlt, a WFP callout driver that blocks
DNS (UDP/TCP 53) to any non-loopback address so all system DNS is forced
through 9NS. The setup installer installs it optionally; to install
manually, right-click driver\\NineNsFlt.inf and choose Install.
NOTE: the driver also blocks 9NS's own plain-DNS upstreams - use
DoH, DoT, DoQ, ODoH, or DNSCrypt upstreams while it is active.
The driver is test-signed: to load it, enable test signing
(bcdedit /set testsigning on) and trust the certificate used to sign the
package (install it into Trusted Root and Trusted Publishers).
The default build uses "9NS Test Signing"; an explicit signing-thumbprint
override may select a different existing certificate.

========================================================================
"""
    with open(os.path.join(STAGE_DIR, "README.txt"), "w", newline="\r\n") as f:
        f.write(readme_txt)

    # 9. Create ZIP archive
    print(f"\nCompressing into {ZIP_OUTPUT}...")
    with zipfile.ZipFile(ZIP_OUTPUT, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(STAGE_DIR):
            for file in files:
                abs_file = os.path.join(root, file)
                rel_file = os.path.relpath(abs_file, DIST_DIR)
                zf.write(abs_file, rel_file)

    zip_size = os.path.getsize(ZIP_OUTPUT) / (1024 * 1024)
    print(f"\nSuccessfully created package:")
    print(f"  Archive: {ZIP_OUTPUT} ({zip_size:.2f} MB)")
    print(f"  Folder:  {STAGE_DIR}")
    print(f"  Total bundled files: {sum(len(files) for _, _, files in os.walk(STAGE_DIR))}")

if __name__ == "__main__":
    main()
