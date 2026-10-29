"""tools/verify_release.py: downloaded release files are compared with the source by content, not by compressed bytes."""
import importlib.util
import json
import os
import subprocess
import sys
import zipfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = "SedicCodeStudio/scs-scanner"

_spec = importlib.util.spec_from_file_location("verify_release", os.path.join(ROOT, "tools", "verify_release.py"))
verify = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify)


@pytest.fixture
def downloads(tmp_path):
    out = tmp_path / "downloads"
    subprocess.run([sys.executable, os.path.join(ROOT, "tools", "build_release.py"), "--out", str(out), "--repo", REPO],
                   check=True, capture_output=True, timeout=300, env=dict(os.environ, SOURCE_DATE_EPOCH="1700000000"))
    (out / "ONE-LINERS.md").unlink()
    return out


def rewrite(path, level=9, change=None, add=None):
    """Writes the archive again (other compression level = other bytes), optionally changing or adding a file."""
    raw = path.read_bytes()
    head = raw[:raw.find(b"PK\x03\x04")]
    with zipfile.ZipFile(path) as z:
        items = [(i, z.read(i)) for i in z.infolist()]
    tmp = path.with_name(path.name + ".tmp")
    with zipfile.ZipFile(tmp, "w") as z:
        for info, data in items:
            if change and info.filename.endswith(change[0]):
                data = change[1](data)
            z.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=level)
        if add:
            z.writestr(add[0], add[1])
    path.write_bytes(head + tmp.read_bytes())
    tmp.unlink()


def run(folder, capsys):
    rc = verify.main([str(folder), "--repo", REPO])
    return rc, capsys.readouterr().out


def test_accepts_an_untouched_release(downloads, capsys):
    rc, out = run(downloads, capsys)
    assert rc == 0, out
    assert "SHA256SUMS: 4 downloaded files with a matching checksum" in out
    assert "scs.ps1: identical" in out and "contain exactly the source code" in out


def test_other_compression_is_not_a_difference(downloads, capsys):
    """Another zlib gives other archive bytes - the files inside still have to match."""
    for name in ("scs.pyz", next(p.name for p in downloads.glob("SCS-Scanner-*.zip"))):
        before = (downloads / name).read_bytes()
        rewrite(downloads / name, level=1)
        assert (downloads / name).read_bytes() != before
    (downloads / "SHA256SUMS").unlink()
    (downloads / "sbom.cdx.json").unlink()
    rc, out = run(downloads, capsys)
    assert rc == 0, out
    assert (downloads / "scs.pyz").read_bytes().startswith(b"#!/usr/bin/env python3\n")


def test_detects_a_changed_file(downloads, capsys):
    zipname = next(p.name for p in downloads.glob("SCS-Scanner-*.zip"))
    rewrite(downloads / zipname, change=("scs/core.py", lambda b: b + b"\nimport os  # injected\n"))
    rc, out = run(downloads, capsys)
    assert rc == 1
    assert f"{zipname}: SHA-256 checksum does not match" in out
    assert "scs/core.py differs from the source" in out


def test_detects_an_added_file_and_a_changed_script(downloads, capsys):
    rewrite(downloads / "scs.pyz", add=("scs/extra.py", b"print('not from the source')\n"))
    with open(downloads / "scs.ps1", "ab") as fh:
        fh.write(b"\r\n# appended\r\n")
    rc, out = run(downloads, capsys)
    assert rc == 1
    assert "scs.pyz: scs/extra.py is not in the source" in out
    assert "scs.ps1: differs from the source" in out


def test_detects_a_changed_sbom(downloads, capsys):
    bom = json.loads((downloads / "sbom.cdx.json").read_text(encoding="utf-8"))
    bom["metadata"]["component"]["licenses"] = [{"license": {"id": "MIT"}}]
    (downloads / "sbom.cdx.json").write_text(json.dumps(bom), encoding="utf-8")
    (downloads / "SHA256SUMS").unlink()
    rc, out = run(downloads, capsys)
    assert rc == 1 and "sbom.cdx.json: differs from the source" in out


def test_rejects_a_damaged_archive_and_an_empty_folder(downloads, tmp_path, capsys):
    (downloads / "scs.pyz").write_bytes(b"#!/usr/bin/env python3\nnot a zip archive")
    rc, out = run(downloads, capsys)
    assert rc == 1 and "scs.pyz: cannot be read" in out
    empty = tmp_path / "empty"
    empty.mkdir()
    assert verify.main([str(empty)]) == 2
