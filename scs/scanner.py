"""Order of the checks in a scan."""
from __future__ import annotations

import platform

from . import baseline, common, ioc, yarascan
from .core import count, HIT, INFO, OK, SKIP, WARN, Context, is_admin, os_name


def load_ioc(ctx):
    ctx.step("Loading indicators", 5)
    ctx.ioc = ioc.load()
    common.check_ioc_status(ctx)


def system_scan(ctx: Context):
    """Quick or full scan of this computer."""
    ctx.scope = f"system-{platform.node()}"
    load_ioc(ctx)
    o = os_name()
    if not is_admin():
        ctx.add(INFO, "Permissions", "Started without admin/root rights",
                "Some areas (system services, other users' processes, Defender exclusions, system profiles) remain limited. "
                + ("Choose “Restart as administrator”." if o == "windows" else "For the full check: sudo python3 scs.py"))
    if o == "windows":
        from . import win as mod
    elif o == "macos":
        from . import mac as mod
    else:
        from . import lin as mod
    mod.run_checks(ctx)
    ctx.step("Processes & remote access", 55)
    ctx.section("Processes", common.check_processes)
    ctx.section("Network", common.check_hosts)
    ctx.step("Known spyware file paths", 60)
    ctx.section("Traces", common.check_ioc_paths)
    ctx.step("Browser histories", 65)
    ctx.section("Browser", common.check_browsers)
    ctx.step("File fingerprints", 72)
    ctx.section("Files", common.check_hashes)
    if ctx.full:
        ctx.section("YARA", yarascan.scan, common.risky_dirs())
    ctx.step("Hidden images & caches", 85)
    ctx.section("Thumbnail caches", common.check_thumbcaches)
    ctx.section("Hidden images", common.check_media)
    finish(ctx)


def android_scan(ctx, serial=None, adb_path=None):
    load_ioc(ctx)
    ctx.step("Checking Android over USB", 30)
    from . import android
    ctx.section("Android", android.check, serial=serial, adb_path=adb_path)
    finish(ctx)


def ios_backup_scan(ctx, path=None, password=None):
    load_ioc(ctx)
    ctx.step("Analysing iPhone backup", 30)
    from . import ios
    ctx.section("iPhone backup", ios.check_backup, path, password)
    finish(ctx)


def ios_ssh_scan(ctx, host, user="root", port=22):
    load_ioc(ctx)
    ctx.step("Checking iPhone over SSH", 30)
    from . import ios
    ctx.section("iPhone (root/SSH)", ios.check_ssh, host, user, port)
    finish(ctx)


def selftest(ctx):
    p = common.create_selftest()
    ctx.add(INFO, "Self-test", "Harmless test file created", p)
    load_ioc(ctx)
    ctx.section("Files", common.check_hashes)
    finish(ctx)
    return p


def finish(ctx):
    if ctx.scope and not ctx.cancel:
        ctx.section("Changes", lambda c: baseline.compare_and_save(c, c.scope))
    c = ctx.counts()
    ctx.step("Done", 100)
    ctx.add(OK if not (c[HIT] or c[WARN]) else INFO, "Result",
            f"{c[HIT]} detected, {count(c[WARN], 'warning')}, {c[SKIP]} not checked",
            "A result without detections is no guarantee: high-end spyware is built to survive checks like this, and many traces "
            "disappear within a few weeks. If you have a well-founded suspicion, contact the Access Now Digital Security Helpline "
            "or the Amnesty International Security Lab.")
