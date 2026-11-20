#!/usr/bin/env python3
"""
9NS Windows MSI Installer Generator
Builds dist/9NS-Setup-1.0.0.msi with the WiX Toolset (3.14): harvests the
portable package (dist/9ns-windows-x64) with heat, compiles packaging/9ns.wxs
with candle, and links an embedded-cab MSI with light (WixUI_InstallDir).
Service and driver installation are opt-in via INSTALLSERVICE=1 / INSTALLDRIVER=1.
"""

import os
import sys
import glob
import shutil
import subprocess

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST_DIR = os.path.join(ROOT_DIR, "dist")
PACKAGE_DIR = os.path.join(DIST_DIR, "9ns-windows-x64")
WXS = os.path.join(ROOT_DIR, "packaging", "9ns.wxs")
HARVEST_WXS = os.path.join(DIST_DIR, "PackageFiles.wxs")
MSI_OUTPUT = os.path.join(DIST_DIR, "9NS-Setup-1.0.0.msi")


def find_wix_tool(name):
    """Locates a WiX tool via PATH, WixToolPath, or the standard install dirs."""
    found = shutil.which(name)
    if found:
        return found
    candidates = []
    wix_path = os.environ.get("WixToolPath")
    if wix_path:
        candidates.append(os.path.join(wix_path, name + ".exe"))
    for program_files in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
        if program_files:
            candidates.extend(glob.glob(os.path.join(program_files, "WiX Toolset*", "bin", name + ".exe")))
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    sys.exit(f"Error: {name} not found. Install the WiX Toolset (e.g. scoop install wixtoolset3).")


def main():
    print("=== 9NS Windows MSI Installer Generator ===")

    if not os.path.isfile(os.path.join(PACKAGE_DIR, "9ns.exe")):
        print("Portable package not found. Running scripts/package_windows.py first...")
        subprocess.run([sys.executable, os.path.join(ROOT_DIR, "scripts", "package_windows.py")], check=True)
    if not os.path.isfile(os.path.join(PACKAGE_DIR, "9ns.exe")):
        sys.exit(f"Error: Could not locate {PACKAGE_DIR}")

    heat = find_wix_tool("heat")
    candle = find_wix_tool("candle")
    light = find_wix_tool("light")

    print("Harvesting portable package files (heat)...")
    subprocess.run([
        heat, "dir", PACKAGE_DIR,
        "-nologo", "-ag", "-srd", "-sreg", "-platform", "x64",
        "-cg", "PackageFiles",
        "-dr", "INSTALLDIR",
        "-var", "var.PackageDir",
        "-out", HARVEST_WXS
    ], check=True)

    print("Compiling installer sources (candle)...")
    subprocess.run([
        candle, "-nologo", "-arch", "x64",
        f"-dPackageDir={PACKAGE_DIR}",
        "-out", DIST_DIR + os.sep,
        WXS, HARVEST_WXS
    ], check=True)

    print("Linking MSI with embedded cabinet (light)...")
    subprocess.run([
        light, "-nologo",
        "-ext", "WixUIExtension",
        "-out", MSI_OUTPUT,
        os.path.join(DIST_DIR, "9ns.wixobj"),
        os.path.join(DIST_DIR, "PackageFiles.wixobj")
    ], check=True)

    size_mb = os.path.getsize(MSI_OUTPUT) / (1024 * 1024)
    print(f"\n[SUCCESS] Windows MSI Installer generated successfully:")
    print(f"  Installer: {MSI_OUTPUT} ({size_mb:.2f} MB)")
    print(f"  Architecture: x64, per-machine (Windows 10 / Windows 11)")
    print(f"  Optional integration: msiexec /i \"{MSI_OUTPUT}\" INSTALLSERVICE=1 INSTALLDRIVER=1")


if __name__ == "__main__":
    main()
