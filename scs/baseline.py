"""Change detection.

Every scan remembers the persistence and network settings it saw (autostart entries, services, scheduled
tasks, VPNs, DNS servers, proxies, trusted certificates, apps …). The next scan reports what is new since
then – new autostart entries or a new VPN are exactly what spyware and stalkerware leave behind.
"""
from __future__ import annotations

import json
import os
import re
import time

from .core import DATA_DIR, INFO, OK, WARN, count, ensure_dir

BASE_DIR = os.path.join(DATA_DIR, "baseline")

# category: (singular, plural, severe)
LABELS = {
    "autostart": ("autostart entry", "autostart entries", True),
    "tasks": ("scheduled task", "scheduled tasks", True),
    "services": ("service", "services", True),
    "launch": ("launch agent/daemon", "launch agents/daemons", True),
    "cron": ("cron job", "cron jobs", True),
    "systemd": ("systemd service", "systemd services", True),
    "vpn": ("VPN connection or VPN app", "VPN connections or VPN apps", True),
    "proxy": ("proxy setting", "proxy settings", True),
    "certs": ("trusted root certificate", "trusted root certificates", True),
    "profiles": ("configuration profile", "configuration profiles", True),
    "extensions": ("network extension", "network extensions", True),
    "admins": ("device administrator", "device administrators", True),
    "accessibility": ("accessibility service", "accessibility services", True),
    "remote": ("remote access program", "remote access programs", True),
    "dns": ("DNS server", "DNS servers", False),
    "apps": ("app", "apps", False),
}
_STATE = re.compile(r"\s*[–-]\s*(Up|Down|Disconnected|Connected|Disabled|Not Present|Dormant)\b.*$|"
                    r"\s*\((active: \w+|Connected|Disconnected|Connecting|Disconnecting|Invalid|active|up|down|unknown|dormant)\)",
                    re.I)


def seen(ctx, category):
    """Marks a category as checked, so that its first new item is reported even if it was empty before."""
    if category in LABELS:
        ctx.snap.setdefault(category, set())


def note(ctx, category, item):
    """Records one item of the current state (status words are removed so that only real changes count)."""
    if category not in LABELS or item is None:
        return
    text = _STATE.sub("", str(item)).strip()[:300]
    if text:
        ctx.snap.setdefault(category, set()).add(text)


def _path(scope):
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", scope)[:80].replace("..", "_").strip(".") or "default"
    return os.path.join(BASE_DIR, safe + ".json")


def load(scope):
    try:
        with open(_path(scope), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def compare_and_save(ctx, scope):
    if not ctx.snap or getattr(ctx, "no_baseline", False):
        return
    ensure_dir(BASE_DIR)
    current = {k: sorted(v) for k, v in ctx.snap.items()}
    old = load(scope)
    if old is None:
        ctx.add(INFO, "Changes", "Baseline created",
                "From now on every scan of this device reports new autostart entries, services, scheduled tasks, VPNs, "
                "DNS servers, proxies, trusted certificates and apps since this scan.")
    else:
        when = old.get("time", "the last scan")
        changes = 0
        for cat, items in current.items():
            if cat not in old.get("items", {}):
                continue  # not recorded last time – nothing to compare with
            before = set(old["items"][cat])
            new = [i for i in items if i not in before]
            if not new:
                continue
            changes += 1
            sing, plur, severe = LABELS[cat]
            ctx.add(WARN if severe else INFO, "Changes", f"{count(len(new), 'new ' + sing, 'new ' + plur)} since {when}",
                    "\n".join(new[:60]) + ("\n\nNew autostart entries, services, VPNs, proxies or certificates are what spyware "
                                           "and stalkerware typically leave behind. Check that you made each change yourself."
                                           if severe else ""))
        if not changes:
            ctx.add(OK, "Changes", f"No changes since {when}",
                    "No new autostart entries, services, tasks, VPNs, DNS servers, proxies, certificates or apps.")
    with open(_path(scope), "w", encoding="utf-8") as fh:
        json.dump({"time": time.strftime("%Y-%m-%d %H:%M"), "scope": scope, "items": current}, fh, ensure_ascii=False, indent=1)
