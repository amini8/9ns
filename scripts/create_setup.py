#!/usr/bin/env python3
"""
9NS Windows Setup Installer Generator
Compiles a native, self-extracting Windows Win32 Setup installer
(dist/9NS-Setup-1.0.0.exe) with embedded package payload, GUI wizard,
elevation manifest, desktop/start menu shortcuts, and uninstaller registration.
Also stages the Inno Setup script (packaging/9ns-setup.iss).
"""

import os
import sys
import subprocess
import shutil

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST_DIR = os.path.join(ROOT_DIR, "dist")
ZIP_PKG = os.path.join(DIST_DIR, "9ns-windows-x64.zip")
INSTALLER_DIR = os.path.join(ROOT_DIR, "src", "installer")
SETUP_EXE = os.path.join(DIST_DIR, "9NS-Setup-1.0.0.exe")

WINDRES = shutil.which("windres")
CXX = shutil.which("g++")
if not WINDRES or not CXX:
    sys.exit("Error: windres/g++ not found. Run from the MSYS2 MinGW64 shell (mingw64/bin first on PATH).")

def main():
    print("=== 9NS Windows Setup Installer Generator ===")

    # 1. Ensure distribution package exists
    if not os.path.isfile(ZIP_PKG):
        print("Distribution ZIP not found. Running scripts/package_windows.py first...")
        subprocess.run([sys.executable, os.path.join(ROOT_DIR, "scripts", "package_windows.py")], check=True)

    if not os.path.isfile(ZIP_PKG):
        print(f"Error: Could not locate {ZIP_PKG}")
        sys.exit(1)

    # 2. Stage payload.zip inside installer/
    payload_dest = os.path.join(INSTALLER_DIR, "payload.zip")
    print(f"Staging payload: {ZIP_PKG} -> {payload_dest}")
    shutil.copy2(ZIP_PKG, payload_dest)

    res_obj = os.path.join(INSTALLER_DIR, "setup.res.o")

    try:
        # 3. Compile Windows resource (icon, manifest, embedded zip)
        print("Compiling installer resources (manifest, icon, zip payload)...")
        subprocess.run([
            WINDRES,
            "-i", os.path.join(INSTALLER_DIR, "setup.rc"),
            "-o", res_obj,
            "-O", "coff"
        ], check=True, cwd=INSTALLER_DIR)

        # 4. Compile native Win32 Setup executable
        print("Compiling native Windows Win32 Setup installer with MinGW-w64...")
        cmd = [
            CXX,
            "-std=c++17",
            "-O2",
            "-mwindows",
            "-municode",
            "-s",
            "-static",
            os.path.join(INSTALLER_DIR, "setup.cpp"),
            res_obj,
            "-lcomctl32",
            "-lshlwapi",
            "-lole32",
            "-luuid",
            "-lshell32",
            "-ladvapi32",
            "-lsetupapi",
            "-o", SETUP_EXE
        ]
        subprocess.run(cmd, check=True)

        size_mb = os.path.getsize(SETUP_EXE) / (1024 * 1024)
        print(f"\n[SUCCESS] Windows Setup Installer generated successfully:")
        print(f"  Installer: {SETUP_EXE} ({size_mb:.2f} MB)")
        print(f"  Architecture: x86-64 PE32+ (Windows 10 / Windows 11)")
        print(f"  Elevation: Administrator Manifest Embedded")
        print(f"  Inno Setup: packaging/9ns-setup.iss (available for optional ISCC builds)")

    finally:
        # Clean up temporary staged files
        if os.path.exists(payload_dest):
            os.remove(payload_dest)
        if os.path.exists(res_obj):
            os.remove(res_obj)

if __name__ == "__main__":
    main()
