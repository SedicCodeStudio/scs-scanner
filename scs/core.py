"""Shared foundations: findings, scan context, running commands, helpers."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time

VERSION = "0.2.0"
APPNAME = "SCS Scanner"
HOME = os.path.expanduser("~")
DATA_DIR = os.path.join(HOME, ".scs-scanner")

# Result states
HIT = "DETECTED"         # matches a known indicator of compromise
WARN = "WARNING"         # suspicious, please review
SKIP = "NOT CHECKED"     # could not be checked (permissions, missing tool ...)
INFO = "INFO"            # inventory, not a problem in itself
OK = "OK"                # check ran, nothing found
SEV_ORDER = {HIT: 0, WARN: 1, SKIP: 2, INFO: 3, OK: 4}


class Finding:
    __slots__ = ("sev", "area", "title", "detail", "path", "action", "source", "ts")

    def __init__(self, sev, area, title, detail="", path=None, action=None, source=""):
        self.sev = sev
        self.area = area
        self.title = title
        self.detail = detail
        self.path = path
        self.action = action      # e.g. {"type": "quarantine", "path": ...}
        self.source = source      # indicator source
        self.ts = time.strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


class Context:
    """Holds the settings of one run and collects its findings."""

    def __init__(self, full=False, root_mode=False, log=None, emit=None, progress=None):
        self.full = full
        self.root_mode = root_mode
        self.findings: list[Finding] = []
        self.ioc = None
        self._log = log or (lambda m: print(m, flush=True))
        self._emit = emit
        self._progress = progress
        self.cancel = False
        self.meta = {
            "program": f"{APPNAME} {VERSION}",
            "system": f"{platform.system()} {platform.release()} ({platform.machine()})",
            "host": platform.node(),
            "started": time.strftime("%Y-%m-%d %H:%M:%S"),
            "mode": "Full scan" if full else "Quick scan",
            "admin_root": is_admin(),
        }
        self.processes = []   # filled by the OS modules: dicts with name/path/pid/cmd
        self.vpn = []         # names of active VPN tunnels (set by the routing check)
        self.snap = {}        # current state for change detection (see baseline.py)
        self.scope = None     # which device the change detection belongs to
        self.no_baseline = False

    def add(self, sev, area, title, detail="", **kw) -> Finding:
        f = Finding(sev, area, title, detail, **kw)
        self.findings.append(f)
        if self._emit:
            self._emit(f)
        return f

    def log(self, msg):
        self._log(msg)

    def step(self, text, pct=None):
        self.log(f"» {text}")
        if self._progress:
            self._progress(text, pct)

    def section(self, area, func, *a, **kw):
        """Runs one check; errors are recorded as 'not checked' instead of aborting the scan."""
        if self.cancel:
            return
        try:
            func(self, *a, **kw)
        except PermissionError as e:
            self.add(SKIP, area, "No permission", f"{e}\nTip: run with admin/root rights or grant access.")
        except Exception as e:  # noqa: BLE001 – a single check must never abort the scan
            self.add(SKIP, area, "Check failed", f"{type(e).__name__}: {e}")
            try:
                from . import log
                log.check_failed(area, e)
            except Exception:  # noqa: BLE001 – logging must never break a scan
                pass

    def counts(self):
        c = {HIT: 0, WARN: 0, SKIP: 0, INFO: 0, OK: 0}
        for f in self.findings:
            c[f.sev] = c.get(f.sev, 0) + 1
        return c


def os_name() -> str:
    s = platform.system().lower()
    if s.startswith("win"):
        return "windows"
    if s == "darwin":
        return "macos"
    return "linux"


def is_admin() -> bool:
    try:
        if os_name() == "windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def _decode(b: bytes) -> str:
    if not b:
        return ""
    for enc in ("utf-8", "cp850", "cp1252", "latin-1"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            continue
    return b.decode("utf-8", "replace")


def run(cmd, timeout=60, input_bytes=None):
    """Starts a program and returns (return code, stdout, stderr)."""
    kw = {}
    if os_name() == "windows":
        kw["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, input=input_bytes, **kw)
        return p.returncode, _decode(p.stdout), _decode(p.stderr)
    except FileNotFoundError:
        return 127, "", f"Program not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Timed out after {timeout}s"


def ps(script: str, timeout=180):
    """Runs a PowerShell command (Windows only) with UTF-8 output."""
    pre = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; "
    return run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", pre + script], timeout=timeout)


def ps_json(script: str, timeout=180) -> list:
    rc, out, err = ps(script + " | ConvertTo-Json -Depth 3 -Compress", timeout=timeout)
    out = out.strip()
    if not out:
        if rc != 0 and err.strip():
            raise RuntimeError(err.strip()[:400])
        return []
    data = json.loads(out)
    return data if isinstance(data, list) else [data]


def sha256_file(path, max_bytes=200 * 1024 * 1024):
    try:
        if os.path.getsize(path) > max_bytes:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def fmt(n) -> str:
    """Number with thousands separators."""
    return f"{int(n):,}"


def count(n, singular, plural=None) -> str:
    """'1 file', '2 files' – number with the right noun form."""
    n = int(n)
    return f"{fmt(n)} {singular if n == 1 else (plural or singular + 's')}"


def human(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def walk(root, max_depth=6, max_files=50000, skip_names=()):
    """Walks a folder robustly (without following symlinks) and yields (path, os.DirEntry)."""
    count = 0
    stack = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            if depth < max_depth and e.name not in skip_names:
                                stack.append((e.path, depth + 1))
                        elif e.is_file(follow_symlinks=False):
                            if e.name.endswith(".quarantined"):
                                continue  # already neutralised by this program's quarantine
                            count += 1
                            yield e.path, e
                            if count >= max_files:
                                return
                    except OSError:
                        continue
        except (OSError, PermissionError):
            continue


def is_hidden(entry) -> bool:
    """Hidden = dot name or (Windows) hidden attribute."""
    if entry.name.startswith("."):
        return True
    if os_name() == "windows":
        try:
            attrs = entry.stat(follow_symlinks=False).st_file_attributes
            return bool(attrs & 0x2)
        except (OSError, AttributeError):
            return False
    return False


def ensure_dir(p):
    """Creates a folder of this program; on macOS/Linux only the owner may open it."""
    os.makedirs(p, exist_ok=True)
    if os_name() != "windows":
        for d in {p, DATA_DIR} if os.path.abspath(p).startswith(os.path.abspath(DATA_DIR)) else {p}:
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass
    return p


def tmp_dir():
    return ensure_dir(os.path.join(DATA_DIR, "tmp"))


def private_tmp(suffix=""):
    """Path of a new, unpredictable temporary file inside the program's private folder."""
    fd, path = tempfile.mkstemp(dir=tmp_dir(), suffix=suffix)
    os.close(fd)
    return path


def resource_path(*parts):
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, *parts)


def py_exe():
    return sys.executable
