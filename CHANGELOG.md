# Changelog

All notable changes to the SCS Scanner. Versions follow [Semantic Versioning](https://semver.org/).

## Unreleased

- `tools/verify_release.py`: checks downloaded release files against the source code (files inside the archives,
  `scs.ps1`, SBOM, `SHA256SUMS`) – independent of the zlib version that compressed the archives.
- Windows installer test (`packaging/windows/test-installer.ps1`), run by CI on every push and by the release workflow
  before anything is published: silent install, installed files and version information, self-test of the installed
  program, its window opens, the installed PowerShell edition runs, silent uninstall.
- `"SCS Scanner.exe" --check REPORT.txt` runs the self-test of the installed Windows program without a window
  (for support). The build script finds Inno Setup 6 and 7.
- Supply chain: CI, the release workflow and the Windows build install their tools (pytest, ruff, PyInstaller) only
  from hash-pinned lock files (`requirements/`, `packaging/windows/requirements.txt`), kept current by Dependabot.
- The minimum Python version is now 3.9 – the oldest version the tests run on (Python 3.8 is end-of-life).
- Releases also contain the signed build provenance as files (`*-provenance.sigstore.json`) for checks without the
  GitHub API.

## 0.2.0 – 2026-10-29

### New
- **PowerShell edition** (`powershell/scs.ps1`): runs on Windows without Python or any installation, as a file or as a
  one-line command. Same indicator lists, quarantine, change detection and report formats as the Python version.
- **One-line commands** for PowerShell and for Linux/macOS terminals, including a verified variant that checks the
  SHA-256 checksum before anything runs (`docs/ONE-LINERS.md`).
- **Single-file version** `scs.pyz` – `python3 scs.pyz scan`, no unpacking.
- **Change detection**: every scan remembers autostart entries, services, tasks, VPNs, DNS servers, proxies, certificates
  and apps, and reports what is new since the last scan of the same device.
- **Network watch** (`scs netwatch`): watches name lookups and connections live for a few minutes.
- **Privacy cleanup** (`scs clean`): lists and – after confirmation – deletes thumbnail caches that keep copies of deleted photos.
- **Combined report** (`scs merge`): one overview of the JSON reports of several devices, without remote access.
- **YARA scanning** in the full scan (optional, `pip install yara-python`, rules via `scs update --yara`).
- **VPN, proxy, DNS server and root certificate checks** on all systems, including Android (always-on VPN, private DNS,
  user CA certificates) and iPhone backups (VPN and network extension configurations).
- Command line with subcommands (`scs -h`), `pyproject.toml` with the `scs` command.
- Test suite (pytest, synthetic data only), Windows checks tested with mocks, reproducible release build.

### Official release tooling
- **Windows installer** (`SCS-Scanner-Setup-<version>.exe`): program built with PyInstaller, Start menu entries,
  uninstaller, version information and icon; optional code signing in the release workflow.
- macOS launcher `Start-Mac.command`, Linux user install script with menu entry (`packaging/linux/install.sh`).
- Opt-in check for new program versions (`scs update`, `scs version --check`, *About › Check for updates*), `scs --version`.
- Diagnostic log `~/.scs-scanner/logs/scs.log` (no scan results) and friendly error messages instead of crashes.
- Window icon, sharp text on high-resolution Windows screens, first-start notice is asked once per user.
- Software bill of materials (`sbom.cdx.json`, CycloneDX) in every release; OpenSSF Scorecard workflow.
- Project documents: privacy, support, code of conduct, release guide, "what to do if something was found",
  issue forms (bug, false positive, idea) and pull request checklist.

### Security
- Downloads only over HTTPS with size limits; indicator files are only stored when they are valid JSON.
- Data folder `~/.scs-scanner` is private (0700); temporary files are created with `mkstemp`.
- Quarantine IDs are validated; quarantined files get the suffix `.quarantined` and are read-only on macOS/Linux.
- Strict validation of ADB serials, package names, APK paths and SSH parameters; no shell command lines are built from input.
- Special files (FIFOs, sockets, devices) are never opened during scans.

## 0.1.0 – 2026-10-28

- First test version: Windows, Linux and macOS scan, Android over ADB (with root mode), iPhone backups and jailbroken
  iPhones over SSH, indicator matching (MVT indicators, stalkerware indicators, Zero Breach), hidden and disguised images,
  thumbnail caches, quarantine, HTML/JSON reports, retro user interface.
