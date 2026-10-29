import os
import subprocess
import sys

from scs.core import VERSION

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(*args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "scs.py"), *args], capture_output=True, text=True,
                          timeout=300, env=dict(os.environ, PYTHONIOENCODING="utf-8"))


def test_version():
    r = run("version")
    assert r.returncode == 0 and VERSION in r.stdout


def test_selftest_detects_and_quarantines(tmp_path):
    report = tmp_path / "selftest.json"
    r = run("selftest", "--no-baseline", "--json", str(report))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Self-test passed" in r.stdout
    assert report.exists()
    listing = run("quarantine", "list")
    assert "Self-test" in listing.stdout


def test_invalid_quarantine_id_is_refused():
    r = run("quarantine", "delete", "../../etc")
    assert r.returncode == 2 and "Invalid quarantine ID" in r.stdout


def test_clean_lists_without_deleting():
    r = run("clean")
    assert r.returncode == 0
    assert "Nothing deleted" in r.stdout or "Nothing to clean up" in r.stdout


def test_overlapping_folders_are_checked_once(tmp_path, monkeypatch):
    from scs import common, ioc
    from scs.core import HIT, Context
    inner = tmp_path / "outer" / "inner"
    inner.mkdir(parents=True)
    (inner / "SCS-SELFTEST.txt").write_bytes(ioc.SELFTEST_CONTENT)
    monkeypatch.setattr(common, "risky_dirs", lambda: [str(tmp_path / "outer"), str(inner)])
    ctx = Context(log=lambda m: None)
    ctx.ioc = ioc.IOCIndex().load_dir(directory=str(tmp_path / "none"))
    common.check_hashes(ctx)
    assert len([f for f in ctx.findings if f.sev == HIT]) == 1
