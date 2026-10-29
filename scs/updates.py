"""Checks – only when asked – whether a newer version of the program has been released.

One request to github.com: the address /releases/latest forwards to the page of the newest release, whose address
contains the version number. Nothing about this computer is sent apart from what every web request contains.
"""
from __future__ import annotations

import re
import urllib.request

from .core import VERSION

REPO = "SedicCodeStudio/scs-scanner"
LATEST = f"https://github.com/{REPO}/releases/latest"


def parse_version(text: str):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def newer(latest: str, current: str = VERSION) -> bool:
    a, b = parse_version(latest), parse_version(current)
    return bool(a and b and a > b)


def latest_version(timeout: int = 15):
    """Returns (version, url) of the newest release, or raises OSError when github.com cannot be reached."""
    req = urllib.request.Request(LATEST, method="HEAD", headers={"User-Agent": f"SCS-Scanner/{VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # follows the redirect to /releases/tag/vX.Y.Z
        final = r.geturl()
    m = re.search(r"/releases/tag/v?(\d+\.\d+\.\d+)", final)
    if not m:
        raise OSError("No release has been published yet.")
    return m.group(1), final


def check() -> str:
    """Human-readable result for the command line and the window."""
    try:
        ver, url = latest_version()
    except OSError as e:
        return f"The update check is not possible right now ({e})."
    if newer(ver):
        return f"A newer version is available: {ver} (you have {VERSION}).\nDownload: {url}"
    return f"SCS Scanner {VERSION} is up to date."
