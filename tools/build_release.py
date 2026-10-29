#!/usr/bin/env python3
"""Builds the release files into dist/.

  scs.pyz                    single-file version: python3 scs.pyz scan
  scs.ps1                    PowerShell edition (no Python needed)
  SCS-Scanner-<version>.zip  complete program with the Windows/Mac/Linux launchers
  SHA256SUMS                 checksums of the files above
  ONE-LINERS.md              copy-and-paste commands with the checksums filled in

The build is reproducible: the same sources always give byte-identical files (fixed timestamps,
sorted entries, fixed permissions), so anyone can rebuild a release and compare the checksums.

  python3 tools/build_release.py [--repo OWNER/NAME] [--out dist]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
import uuid
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EPOCH = max(int(os.environ.get("SOURCE_DATE_EPOCH", "315532800")), 315532800)  # not before 1980-01-01 (ZIP limit)
DATE = time.gmtime(EPOCH)[:6]

PROGRAM_FILES = [
    "LICENSE", "NOTICE", "README.md", "CHANGELOG.md", "SECURITY.md", "PRIVACY.md",
    "scs.py", "start.sh", "Start-Mac.command", "optional-packages.txt",
    "Start-Windows.bat", "Run-as-Administrator.bat", "Terminal-Scan-Windows.bat", "Scan-with-PowerShell.bat",
    "powershell/scs.ps1", "docs/ONE-LINERS.md", "docs/WHAT-TO-DO.md",
    "packaging/linux/install.sh", "packaging/linux/scs.png",
]
EXECUTABLE = {"scs.py", "start.sh", "Start-Mac.command", "packaging/linux/install.sh"}
CRLF = (".bat",)  # cmd.exe expects Windows line endings


def version():
    with open(os.path.join(ROOT, "scs", "core.py"), encoding="utf-8") as fh:
        m = re.search(r'^VERSION\s*=\s*"([^"]+)"', fh.read(), re.M)
    if not m:
        sys.exit("VERSION not found in scs/core.py")
    return m.group(1)


def package_files():
    out = []
    for name in sorted(os.listdir(os.path.join(ROOT, "scs"))):
        if name.endswith(".py"):
            out.append("scs/" + name)
    return out


def read(rel):
    with open(os.path.join(ROOT, rel), "rb") as fh:
        data = fh.read()
    if rel.endswith(CRLF):
        data = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    return data


def add(z, arcname, data, executable=False):
    info = zipfile.ZipInfo(arcname, date_time=DATE)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = ((0o100755 if executable else 0o100644) & 0xFFFF) << 16
    z.writestr(info, data, compresslevel=9)


def build_pyz(path):
    main = b'"""SCS Scanner - single-file version."""\nimport sys\n\nfrom scs.cli import main\n\nsys.exit(main())\n'
    tmp = path + ".tmp"
    with zipfile.ZipFile(tmp, "w") as z:
        add(z, "__main__.py", main)
        for rel in package_files():
            if rel != "scs/__main__.py":
                add(z, rel, read(rel))
            else:
                add(z, rel, read(rel))
    with open(tmp, "rb") as fh:
        body = fh.read()
    os.remove(tmp)
    with open(path, "wb") as fh:
        fh.write(b"#!/usr/bin/env python3\n" + body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)  # like chmod +x


def build_zip(path, ver):
    top = f"SCS-Scanner-{ver}/"
    files = sorted(set(PROGRAM_FILES + package_files()))
    with zipfile.ZipFile(path, "w") as z:
        for rel in files:
            if not os.path.exists(os.path.join(ROOT, rel)):
                sys.exit(f"missing file: {rel}")
            add(z, top + rel, read(rel), executable=rel in EXECUTABLE)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sbom(ver, repo, files):
    """Software bill of materials (CycloneDX 1.5): what the release consists of and where third-party parts come from."""
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(EPOCH))
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"https://github.com/{repo}/releases/v{ver}")),
        "metadata": {
            "timestamp": stamp,
            "component": {"type": "application", "bom-ref": "scs-scanner", "name": "scs-scanner", "version": ver,
                          "supplier": {"name": "Sedic Code Studio", "contact": [{"email": "info@sediccodestudio.de"}]},
                          "licenses": [{"license": {"id": "Apache-2.0"}}], "purl": f"pkg:github/{repo}@v{ver}",
                          "externalReferences": [{"type": "vcs", "url": f"https://github.com/{repo}"}]},
        },
        "components": [
            {"type": "file", "name": os.path.basename(p), "hashes": [{"alg": "SHA-256", "content": h}]} for p, h in files
        ] + [
            {"type": "library", "name": "yara-python", "purl": "pkg:pypi/yara-python", "scope": "optional",
             "description": "optional YARA scanning", "licenses": [{"license": {"id": "Apache-2.0"}}]},
            {"type": "library", "name": "iphone_backup_decrypt", "purl": "pkg:pypi/iphone-backup-decrypt", "scope": "optional",
             "description": "optional decryption of encrypted iPhone backups", "licenses": [{"license": {"id": "MIT"}}]},
            {"type": "data", "name": "indicator lists", "scope": "excluded",
             "description": "downloaded at run time from mvt-project/mvt-indicators and the sources it lists; not part of the release"},
        ],
    }
    return json.dumps(doc, indent=1, ensure_ascii=False) + "\n"


def one_liners(repo, ver, sums):
    tag = f"v{ver}"
    raw = f"https://raw.githubusercontent.com/{repo}/{tag}"
    rel = f"https://github.com/{repo}/releases/download/{tag}"
    ps_hash = sums["scs.ps1"].upper()
    pyz_hash = sums["scs.pyz"]
    return f"""# One-line commands - SCS Scanner {ver}

Copy one line into PowerShell or a terminal and press Enter. Only check your own devices,
or devices whose owner has agreed.

## Windows - PowerShell, nothing to install

Quick scan (opens the report in the browser when done):

```powershell
& ([scriptblock]::Create((irm {raw}/powershell/scs.ps1))) -Open
```

Full scan - start PowerShell with "Run as administrator" first:

```powershell
& ([scriptblock]::Create((irm {raw}/powershell/scs.ps1))) -Mode Full -Open
```

Verified - downloads the release file, checks its SHA-256 checksum and only then starts it:

```powershell
$f="$env:TEMP\\scs.ps1"; iwr {rel}/scs.ps1 -OutFile $f -UseBasicParsing; if ((Get-FileHash $f -Algorithm SHA256).Hash -eq '{ps_hash}') {{ powershell -NoProfile -ExecutionPolicy Bypass -File $f -Open }} else {{ Write-Warning 'Checksum mismatch - the file was not started.' }}
```

## Linux and macOS - terminal (Python 3 is preinstalled on most systems)

Quick scan with a verified download:

```sh
curl -fsSLO {rel}/scs.pyz && echo "{pyz_hash}  scs.pyz" | shasum -a 256 -c - && python3 scs.pyz scan --html scs-report.html
```

Full scan with root rights:

```sh
sudo python3 scs.pyz scan --full --html scs-report.html
```

Android phone over USB (needs adb) and iPhone backup:

```sh
python3 scs.pyz android
python3 scs.pyz iphone-backup ~/path/to/backup
```

PowerShell 7 on Linux/macOS also runs the PowerShell edition (fewer checks than the Python version):

```sh
pwsh -c '& ([scriptblock]::Create((irm {raw}/powershell/scs.ps1))) -Open'
```

## Checksums (SHA-256)

```
""" + "".join(f"{v}  {k}\n" for k, v in sorted(sums.items())) + "```\n"


def main():
    ap = argparse.ArgumentParser(description="Build the SCS Scanner release files.")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "SedicCodeStudio/scs-scanner"))
    ap.add_argument("--out", default=os.path.join(ROOT, "dist"))
    a = ap.parse_args()
    if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", a.repo):
        sys.exit("--repo must look like OWNER/NAME")
    ver = version()
    os.makedirs(a.out, exist_ok=True)
    pyz = os.path.join(a.out, "scs.pyz")
    ps1 = os.path.join(a.out, "scs.ps1")
    zp = os.path.join(a.out, f"SCS-Scanner-{ver}.zip")
    build_pyz(pyz)
    with open(ps1, "wb") as fh:
        fh.write(read("powershell/scs.ps1"))
    build_zip(zp, ver)
    sums = {os.path.basename(p): sha256(p) for p in (pyz, ps1, zp)}
    bom = os.path.join(a.out, "sbom.cdx.json")
    with open(bom, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(sbom(ver, a.repo, [(p, sums[os.path.basename(p)]) for p in (pyz, ps1, zp)]))
    sums["sbom.cdx.json"] = sha256(bom)
    with open(os.path.join(a.out, "SHA256SUMS"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("".join(f"{v}  {k}\n" for k, v in sorted(sums.items())))
    with open(os.path.join(a.out, "ONE-LINERS.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(one_liners(a.repo, ver, sums))
    for k, v in sorted(sums.items()):
        print(f"{v}  {k}")
    print(f"Release {ver} written to {a.out}")


if __name__ == "__main__":
    main()
