#!/usr/bin/env python3
"""Checks downloaded release files against the source code they were built from.

  python3 tools/verify_release.py DOWNLOADS [--source SOURCE] [--repo OWNER/NAME]

DOWNLOADS  folder with files of a GitHub release: scs.pyz, scs.ps1, SCS-Scanner-<version>.zip, sbom.cdx.json and
           SHA256SUMS (all or some of them)
SOURCE     source code of the same version (default: this checkout). For an older release, for example:
             git worktree add ../scs-v0.2.0 v0.2.0
             python3 tools/verify_release.py ~/Downloads/scs --source ../scs-v0.2.0

The release is rebuilt from SOURCE with that version's own tools/build_release.py and compared with the downloads:

  - the checksums in SHA256SUMS against the downloaded files,
  - scs.ps1 byte for byte,
  - every file inside scs.pyz and the ZIP: name, permissions and content. The archives themselves can differ byte for
    byte when another zlib version compressed them, so the files inside are compared, not the compressed bytes,
  - the software bill of materials, apart from the checksums of the archives (those are checked against the downloads).

The Windows installer cannot be rebuilt byte for byte; its checksum in SHA256SUMS and the signed build provenance
(gh attestation verify FILE --repo SedicCodeStudio/scs-scanner) cover it.

Exit code: 0 = the downloads contain exactly the source code, 1 = differences (listed), 2 = usage error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_MEMBERS = 5000
MAX_UNPACKED = 200 * 1024 * 1024  # downloads are untrusted: refuse archives that unpack to more than this


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def count(n, word):
    return f"{n} {word}" + ("" if n == 1 else "s")


def commit_time(source):
    """Commit time of the source checkout - the release workflow uses it as SOURCE_DATE_EPOCH."""
    try:
        r = subprocess.run(["git", "-C", source, "log", "-1", "--format=%ct"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    value = r.stdout.strip()
    return value if r.returncode == 0 and value.isdigit() else None


def rebuild(source, repo, out):
    script = os.path.join(source, "tools", "build_release.py")
    if not os.path.isfile(script):
        raise SystemExit(f"not an SCS Scanner source folder (tools/build_release.py is missing): {source}")
    env = dict(os.environ)
    epoch = commit_time(source)
    if epoch:
        env["SOURCE_DATE_EPOCH"] = epoch
    r = subprocess.run([sys.executable, script, "--repo", repo, "--out", out], capture_output=True, text=True,
                       env=env, timeout=600)
    if r.returncode:
        raise SystemExit("rebuilding from the source failed:\n" + (r.stderr or r.stdout))
    m = re.search(r"Release (\S+) written", r.stdout)
    return m.group(1) if m else "?"


def members(path):
    """name -> (permission bits, content) of every file in a ZIP archive; reading checks each CRC."""
    out = {}
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        if len(infos) > MAX_MEMBERS or sum(i.file_size for i in infos) > MAX_UNPACKED:
            raise ValueError("archive is unexpectedly large")
        for i in infos:
            out[i.filename] = ((i.external_attr >> 16) & 0o7777, z.read(i))
    return out


def prefix(path):
    """Bytes in front of the ZIP data (the #! line of scs.pyz)."""
    with open(path, "rb") as fh:
        head = fh.read(4096)
    pos = head.find(b"PK\x03\x04")
    return head[:pos] if pos >= 0 else head


def compare_archive(name, got, want, problems):
    try:
        a = members(got)
    except (zipfile.BadZipFile, ValueError, OSError, EOFError) as exc:  # damaged or manipulated download
        problems.append(f"{name}: cannot be read ({exc})")
        return 0
    b = members(want)
    for n in sorted(set(b) - set(a)):
        problems.append(f"{name}: {n} is missing")
    for n in sorted(set(a) - set(b)):
        problems.append(f"{name}: {n} is not in the source")
    for n in sorted(set(a) & set(b)):
        if a[n][1] != b[n][1]:
            problems.append(f"{name}: {n} differs from the source")
        elif a[n][0] != b[n][0]:
            problems.append(f"{name}: {n} has the permissions {a[n][0]:o} instead of {b[n][0]:o}")
    if prefix(got) != prefix(want):
        problems.append(f"{name}: the start of the file (before the archive) differs from the source")
    return len(set(a) & set(b))


def without_volatile(bom):
    """The SBOM without the archive checksums and the timestamp (those depend on zlib and on the build time)."""
    bom = json.loads(json.dumps(bom))
    bom.get("metadata", {}).pop("timestamp", None)
    for c in bom.get("components", []):
        if c.get("type") == "file":
            c.pop("hashes", None)
    return bom


def compare_sbom(got, want, downloads, problems):
    try:
        with open(got, encoding="utf-8") as fh:
            a = json.load(fh)
    except (OSError, ValueError) as exc:
        problems.append(f"sbom.cdx.json: cannot be read ({exc})")
        return
    with open(want, encoding="utf-8") as fh:
        b = json.load(fh)
    for c in a.get("components", []):
        if c.get("type") != "file":
            continue
        listed = next((h.get("content") for h in c.get("hashes", []) if h.get("alg") == "SHA-256"), None)
        path = os.path.join(downloads, os.path.basename(str(c.get("name", ""))))
        if os.path.isfile(path) and listed != sha256(path):
            problems.append(f"sbom.cdx.json: the checksum listed for {c.get('name')} is not that of the downloaded file")
    if without_volatile(a) != without_volatile(b):
        problems.append("sbom.cdx.json: differs from the source (apart from the archive checksums)")


def check_sums(downloads, ok, problems, notes):
    path = os.path.join(downloads, "SHA256SUMS")
    if not os.path.isfile(path):
        notes.append("SHA256SUMS was not downloaded - checksums not checked")
        return
    present = matching = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = re.match(r"^([0-9a-fA-F]{64})\s+\*?(\S.*?)\s*$", line)
            if not m:
                continue
            name = os.path.basename(m.group(2))
            f = os.path.join(downloads, name)
            if not os.path.isfile(f):
                notes.append(f"{name} was not downloaded")
                continue
            present += 1
            if sha256(f) == m.group(1).lower():
                matching += 1
            else:
                problems.append(f"{name}: SHA-256 checksum does not match SHA256SUMS")
    if not present:
        notes.append("SHA256SUMS lists none of the downloaded files")
    elif matching == present:
        ok.append(f"SHA256SUMS: {count(matching, 'downloaded file')} with a matching checksum")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check downloaded SCS Scanner release files against the source code.")
    ap.add_argument("downloads", help="folder with the downloaded release files")
    ap.add_argument("--source", default=HERE, help="source code of the same version (default: this checkout)")
    ap.add_argument("--repo", default="SedicCodeStudio/scs-scanner", help="repository the release was built for")
    a = ap.parse_args(argv)
    if not os.path.isdir(a.downloads):
        print(f"not a folder: {a.downloads}", file=sys.stderr)
        return 2
    if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", a.repo):
        print("--repo must look like OWNER/NAME", file=sys.stderr)
        return 2
    problems, notes, ok = [], [], []
    check_sums(a.downloads, ok, problems, notes)
    with tempfile.TemporaryDirectory(prefix="scs-verify-") as tmp:
        version = rebuild(os.path.abspath(a.source), a.repo, tmp)
        zips = sorted(n for n in os.listdir(a.downloads) if re.match(r"^SCS-Scanner-[0-9][^/]*\.zip$", n))
        for z in zips:
            if z != f"SCS-Scanner-{version}.zip":
                problems.append(f"{z}: the source is version {version} - use --source with the matching version")
        found = False
        ps1 = os.path.join(a.downloads, "scs.ps1")
        if os.path.isfile(ps1):
            found = True
            if sha256(ps1) == sha256(os.path.join(tmp, "scs.ps1")):
                ok.append("scs.ps1: identical to the source, byte for byte")
            else:
                problems.append("scs.ps1: differs from the source")
        for name in ["scs.pyz"] + [z for z in zips if z == f"SCS-Scanner-{version}.zip"]:
            got = os.path.join(a.downloads, name)
            if os.path.isfile(got):
                found = True
                before = len(problems)
                n = compare_archive(name, got, os.path.join(tmp, name), problems)
                if len(problems) == before:
                    ok.append(f"{name}: all {count(n, 'file')} inside are identical to the source")
        bom = os.path.join(a.downloads, "sbom.cdx.json")
        if os.path.isfile(bom):
            found = True
            before = len(problems)
            compare_sbom(bom, os.path.join(tmp, "sbom.cdx.json"), a.downloads, problems)
            if len(problems) == before:
                ok.append("sbom.cdx.json: matches the source and the downloaded files")
        if any(n.startswith("SCS-Scanner-Setup-") for n in os.listdir(a.downloads)):
            notes.append("the Windows installer is covered by SHA256SUMS and the build provenance "
                         f"(gh attestation verify FILE --repo {a.repo}); it cannot be rebuilt byte for byte")
    if not found:
        print("no release files (scs.pyz, scs.ps1, SCS-Scanner-<version>.zip, sbom.cdx.json) in " + a.downloads,
              file=sys.stderr)
        return 2
    print(f"SCS Scanner {version} - checking the downloads in {a.downloads}")
    for line in ok:
        print("  OK    " + line)
    for line in notes:
        print("  NOTE  " + line)
    for line in problems:
        print("  FAIL  " + line)
    if problems:
        print(f"RESULT: {count(len(problems), 'problem')} - do not use these files, download them again from the "
              "release page and report it if this persists (SECURITY.md).")
        return 1
    print(f"RESULT: the downloaded files contain exactly the source code of version {version}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
