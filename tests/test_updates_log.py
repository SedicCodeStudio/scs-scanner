import os
import subprocess
import sys

from scs import log, updates
from scs.core import SKIP, VERSION, Context

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_version_compare():
    assert updates.parse_version("v1.12.3") == (1, 12, 3)
    assert updates.newer("0.10.0", "0.9.9")
    assert not updates.newer("0.2.0", "0.2.0")
    assert not updates.newer("garbage", "0.2.0")


def test_update_message(monkeypatch):
    monkeypatch.setattr(updates, "latest_version", lambda timeout=15: ("99.0.0", "https://github.com/x/y/releases/tag/v99.0.0"))
    assert "newer version is available: 99.0.0" in updates.check()
    monkeypatch.setattr(updates, "latest_version", lambda timeout=15: (VERSION, "https://github.com/x/y/releases/tag/v" + VERSION))
    assert "up to date" in updates.check()

    def offline(timeout=15):
        raise OSError("no network")
    monkeypatch.setattr(updates, "latest_version", offline)
    assert "not possible right now" in updates.check()


def test_failed_check_is_logged_without_findings():
    ctx = Context(log=lambda m: None)

    def broken(c):
        raise ValueError("secret-path-should-not-matter")
    ctx.section("Broken area", broken)
    assert ctx.findings[-1].sev == SKIP
    for h in log.get().handlers:
        h.flush()
    with open(log.LOG_FILE, encoding="utf-8") as fh:
        text = fh.read()
    assert "check failed: Broken area" in text and "ValueError" in text


def test_cli_version_flag():
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scs.py"), "--version"], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and VERSION in r.stdout


