"""Runs the PowerShell edition when PowerShell 7 (pwsh) is installed; skipped otherwise."""
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PWSH = os.environ.get("PWSH") or shutil.which("pwsh")
pytestmark = pytest.mark.skipif(not PWSH, reason="PowerShell 7 (pwsh) not installed")


def pwsh(*args, env=None):
    return subprocess.run([PWSH, "-NoProfile", "-NonInteractive", *args], capture_output=True, text=True, timeout=900,
                          env=dict(os.environ, **(env or {})))


def test_script_parses():
    script = os.path.join(ROOT, "powershell", "scs.ps1")
    r = pwsh("-Command", "$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("
             f"'{script}',[ref]$t,[ref]$e);if($e){{$e|%{{$_.Message}};exit 1}}")
    assert r.returncode == 0, r.stdout + r.stderr


def test_script_is_ascii():
    with open(os.path.join(ROOT, "powershell", "scs.ps1"), "rb") as fh:
        data = fh.read()
    assert all(b < 128 for b in data), "keep scs.ps1 ASCII-only: Windows PowerShell 5.1 reads files without BOM as ANSI"


def test_selftest(tmp_path):
    r = pwsh("-File", os.path.join(ROOT, "powershell", "scs.ps1"), "-SelfTest", "-NoColor", env={"SCS_HOME": str(tmp_path)})
    assert r.returncode == 0 and "Self-test passed" in r.stdout, r.stdout + r.stderr


def test_windows_checks_with_mocks():
    r = pwsh("-File", os.path.join(ROOT, "tests", "windows-mock.ps1"))
    assert r.returncode == 0, r.stdout[-4000:] + r.stderr[-2000:]
    assert "expectations met" in r.stdout
