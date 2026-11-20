# Contributing to 9NS

Thanks for your interest in contributing. By participating, you agree to
abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting the code

```bash
git clone https://github.com/amini8/9ns.git 9ns
cd 9ns
```

## Development setup

The app is a Qt6 Windows desktop application built with the MSYS2 MinGW64
toolchain. Install the toolchain packages in an MSYS2 MinGW64 shell:

```bash
pacman -S mingw-w64-x86_64-{gcc,cmake,ninja,qt6-base,qt6-svg,openssl,libsodium,nlohmann-json}
```

The optional kernel driver (`src/driver/`) additionally needs Visual Studio
Build Tools (C++) and the Windows Driver Kit.

## Building and testing

From the MSYS2 MinGW64 shell at the repository root:

```bash
cmake -S . -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=<msys64>/mingw64
cmake --build build-win
```

`build-win/` is a gitignored scratch directory; never commit build outputs.

### Offline regression tests

An opt-in test suite covers configuration parsing/validation, draft and
persistence semantics, query-log model behavior, background resolver jobs and
native Qt page interactions. Additional offline regressions cover DoQ stream
framing with fake I/O, hosts/domain blocklists, public-resolver imports and
cache failure handling, and restriction-preserving rule editing. They do not
establish live protocol interoperability or validate the deferred DNSSEC,
adapter, installer, or driver behavior. The widget suites (`test_querypage` and
`test_settingspages`) use Qt's offscreen platform, without constructing
MainWindow or the DNS engine. They exercise filters, inspection snapshots,
sorting, settings round-trips and signal-only page actions; offscreen rendering
is a smoke check, not full Windows DPI/high-contrast visual QA.
It never touches ProgramData, real adapters, the registry, Windows services or
the network. Configure with `-DBUILD_TESTING=ON` and run it with CTest:

```bash
cmake -S . -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=<msys64>/mingw64 -DBUILD_TESTING=ON
cmake --build build-win
ctest --test-dir build-win --output-on-failure
```

Add a regression test alongside any behavior fix.
Installer regressions include command-line/license handling, recovery-manifest
merging, allow-ACE screening, and interrupted file placement under `QTemporaryDir`.
They never run setup or access real services, adapters or the registry. Native
wizard visual/accessibility checks, actual elevated installation/upgrade/uninstall
and driver loading still require a disposable Windows VM.
The release workflow runs the offline suites before building distribution packages.

Run the live protocol verification suite against public resolvers before
submitting protocol or networking changes:

```bash
python scripts/live_test.py
```

Kernel driver (requires the WDK):

```cmd
src\driver\build.cmd
```

Full packaging (portable zip and setup installer, includes the driver):

```bash
python scripts/package_windows.py
python scripts/create_setup.py
```

Continuous integration runs the same steps on every push to `master`; tag
releases with `v*` to publish a GitHub Release.

## Code style

Please match the surrounding code:

- PascalCase types and files, camelCase functions and locals, trailing
  underscore for members (`s_`, `logger_`), `k`-prefixed constants.
- UTF-8 `std::string` internally; Win32 APIs get `std::wstring` via
  `widen()`/`narrow()` from `Text.h` at the boundary.
- Errors: throw `std::runtime_error` naming the offending value; state
  threading contracts and preconditions in header comments.
- RAII for handles; owners delete copy ctor/assignment.
- Includes: system/Win32 first, then Qt, then project headers; `#pragma once`
  in every header.
- Every new `.cpp` must be listed in `CMakeLists.txt` or it will not build.

## Commits and pull requests

- Commits are terse lowercase one-liners.
- Keep pull requests focused: one feature or fix per PR.
- Describe what changed and why, and how you tested it (including the live
  suite results for protocol work).
- Update `README.md` or `AGENTS.md` when behavior, config schema, or the
  build process changes.

## Reporting bugs

Open a GitHub issue with:

- 9NS version and Windows version
- The `config.json` (redact anything private) and relevant log lines from
  `%ProgramData%\9NS\9ns.log`
- Steps to reproduce and expected versus actual behavior

## License

By contributing, you agree that your contributions are licensed under the
[GNU Affero General Public License v3.0](LICENSE).
