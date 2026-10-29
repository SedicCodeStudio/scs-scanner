import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build(out):
    subprocess.run([sys.executable, os.path.join(ROOT, "tools", "build_release.py"), "--out", str(out), "--repo", "owner/repo"],
                   check=True, capture_output=True, timeout=300)
    return (out / "SHA256SUMS").read_text()


def test_release_is_reproducible(tmp_path):
    assert build(tmp_path / "a") == build(tmp_path / "b")


def test_sbom_and_launchers(tmp_path):
    import json
    import zipfile
    build(tmp_path)
    bom = json.loads((tmp_path / "sbom.cdx.json").read_text(encoding="utf-8"))
    assert bom["bomFormat"] == "CycloneDX" and bom["metadata"]["component"]["name"] == "scs-scanner"
    assert {c["name"] for c in bom["components"] if c["type"] == "file"} >= {"scs.pyz", "scs.ps1"}
    assert "sbom.cdx.json" in (tmp_path / "SHA256SUMS").read_text()
    z = zipfile.ZipFile(next(tmp_path.glob("SCS-Scanner-*.zip")))
    modes = {i.filename.split("/", 1)[1]: (i.external_attr >> 16) & 0o777 for i in z.infolist()}
    assert modes["Start-Mac.command"] == 0o755 and modes["packaging/linux/install.sh"] == 0o755
    assert b"\r\n" in z.read(next(n for n in z.namelist() if n.endswith("Start-Windows.bat")))


def test_single_file_version_runs(tmp_path):
    build(tmp_path)
    r = subprocess.run([sys.executable, str(tmp_path / "scs.pyz"), "version"], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0 and "SCS Scanner" in r.stdout
    one = (tmp_path / "ONE-LINERS.md").read_text(encoding="utf-8")
    assert "https://raw.githubusercontent.com/owner/repo/" in one
    ps_hash = [ln.split()[0] for ln in (tmp_path / "SHA256SUMS").read_text().splitlines() if ln.endswith("scs.ps1")][0]
    assert ps_hash.upper() in one


def test_no_hidden_unicode_controls():
    """Bidirectional and invisible control characters can hide code from reviewers ("Trojan Source")."""
    bad = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200B, 0x200C, 0x200D, 0xFEFF}
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", ".pytest_cache", "dist")]
        for f in files:
            if f.endswith((".py", ".js", ".mjs", ".ps1", ".html", ".css", ".md", ".toml", ".yml", ".json", ".bat", ".sh")):
                with open(os.path.join(base, f), encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
                assert not any(ord(c) in bad for c in text), f"hidden control character in {os.path.join(base, f)}"
