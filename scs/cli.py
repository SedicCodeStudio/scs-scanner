"""Command line of the SCS Scanner.

Without arguments the user interface opens. Commands:
  scan [--full]                  Check this computer
  update [--yara]                Download the indicator lists (and optionally the YARA rules), check for a newer version
  android [--root] [--full]      Check an Android phone over USB
  iphone-backup [FOLDER]         Check an iPhone backup (--password for encrypted backups)
  iphone-ssh IP                  Check a jailbroken iPhone over SSH
  netwatch [--minutes N]         Watch name lookups and connections live
  clean [--yes]                  Privacy cleanup: thumbnail caches with copies of deleted photos
  merge REPORT.json … -o OUT     Combine the JSON reports of several devices
  quarantine [list|restore ID|delete ID]
  selftest                       Harmless test that detection and quarantine work
  version [--check]              Show the version (and look for a newer one)
Options for all checks: --html FILE / --json FILE saves a report, --no-baseline skips change detection.
"""
from __future__ import annotations

import argparse
import sys

from . import ioc, log, quarantine, report, scanner
from .core import APPNAME, HIT, INFO, OK, SKIP, VERSION, WARN, Context, count

MARK = {HIT: "[DETECTED]", WARN: "[WARNING] ", SKIP: "[--]      ", INFO: "[INFO]    ", OK: "[OK]      "}


def _print(f, verbose):
    print(f"{MARK.get(f.sev, f.sev)} {f.area}: {f.title}", flush=True)
    if f.detail and (verbose or f.sev in (HIT, WARN)):
        for ln in f.detail.splitlines()[:25]:
            print(f"             {ln}")


def _parser():
    ap = argparse.ArgumentParser(prog="scs", description=f"{APPNAME} {VERSION} – checks your own devices for spyware, malware, "
                                                         "hidden files and redirected traffic.")
    ap.add_argument("--version", action="version", version=f"{APPNAME} {VERSION}")
    sub = ap.add_subparsers(dest="cmd")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--html", help="save an HTML report")
    common.add_argument("--json", help="save a JSON report")
    common.add_argument("-v", "--verbose", action="store_true", help="show details for all findings")
    common.add_argument("--root", action="store_true", help="use root features (Android su)")
    common.add_argument("--no-baseline", action="store_true", help="do not compare with or update the last scan")
    s = sub.add_parser("scan", parents=[common], help="check this computer")
    s.add_argument("--full", action="store_true", help="full scan (more thorough, takes longer)")
    u = sub.add_parser("update", help="update the indicators")
    u.add_argument("--yara", action="store_true", help="also download the open signature-base YARA rules")
    a = sub.add_parser("android", parents=[common], help="check an Android phone over USB")
    a.add_argument("--serial", help="serial number of the device (if several are connected)")
    a.add_argument("--adb", help="path to adb")
    a.add_argument("--full", action="store_true", help="check every app individually")
    i = sub.add_parser("iphone-backup", parents=[common], help="check an iPhone backup")
    i.add_argument("folder", nargs="?")
    i.add_argument("--password")
    h = sub.add_parser("iphone-ssh", parents=[common], help="check a jailbroken iPhone over SSH")
    h.add_argument("ip")
    h.add_argument("--user", default="root")
    h.add_argument("--port", type=int, default=22)
    n = sub.add_parser("netwatch", parents=[common], help="watch name lookups and connections live")
    n.add_argument("--minutes", type=int, default=10)
    n.add_argument("--interval", type=int, default=5, help="seconds between checks")
    c = sub.add_parser("clean", help="privacy cleanup of thumbnail caches")
    c.add_argument("--yes", action="store_true", help="really delete (without it only a list is shown)")
    c.add_argument("--recycle-bin", action="store_true", help="also empty the Windows Recycle Bin")
    c.add_argument("--restart-explorer", action="store_true", help="restart Windows Explorer if the cache is in use")
    m = sub.add_parser("merge", help="combine the JSON reports of several devices")
    m.add_argument("reports", nargs="+")
    m.add_argument("-o", "--output", default="SCS-Combined-Report.html")
    q = sub.add_parser("quarantine", help="manage the quarantine")
    q.add_argument("action", nargs="?", default="list", choices=["list", "restore", "delete"])
    q.add_argument("id", nargs="?")
    sub.add_parser("selftest", parents=[common], help="harmless function test")
    sub.add_parser("gui", help="open the user interface")
    vp = sub.add_parser("version", help="show the version")
    vp.add_argument("--check", action="store_true", help="also check on github.com whether a newer version exists")
    return ap


def main(argv=None):
    """Runs a command; unexpected errors are written to the diagnostic log instead of ending with a traceback."""
    try:
        return _main(argv)
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130
    except Exception:  # noqa: BLE001
        path = log.crash(*sys.exc_info())
        print(f"\nUnexpected error: {sys.exc_info()[1]}\nDetails were saved to {path}\n"
              "Please report it at https://github.com/SedicCodeStudio/scs-scanner/issues and attach that file "
              "(it contains no scan results).", file=sys.stderr)
        return 3


def _main(argv=None):
    args = _parser().parse_args(argv)
    if args.cmd not in (None, "gui"):
        log.start(args.cmd)
    if args.cmd in (None, "gui"):
        try:
            from . import gui
        except ImportError as e:
            print(f"User interface not available ({e}). On Linux: sudo apt install python3-tk\nHelp: scs -h")
            return 2
        gui.main()
        return 0
    if args.cmd == "version":
        print(f"{APPNAME} {VERSION}")
        if args.check:
            from . import updates
            print(updates.check())
        return 0
    if args.cmd == "update":
        ok, fails = ioc.update()
        print(f"\n{count(ok, 'source')} loaded, {count(len(fails), 'error')}.")
        from . import updates
        print(updates.check())
        if args.yara:
            from . import yarascan
            try:
                yarascan.update_rules()
            except Exception as e:  # noqa: BLE001
                print(f"YARA rules could not be downloaded: {e}")
                return 1
        return 0 if ok else 1
    if args.cmd == "quarantine":
        if args.action == "list":
            entries = quarantine.entries()
            for e in entries:
                print(f"{e['id']}\n    {e['original']}\n    {e['reason']}")
            if not entries:
                print("The quarantine is empty.")
        elif not args.id:
            print("Please give the ID (see: scs quarantine list).")
            return 2
        else:
            try:
                if args.action == "restore":
                    print("Restored:", quarantine.restore(args.id))
                else:
                    quarantine.delete(args.id)
                    print("Deleted.")
            except (ValueError, OSError) as e:
                print(f"Not possible: {e}")
                return 2
        return 0
    if args.cmd == "merge":
        from . import fleet
        n = fleet.merge(args.reports, args.output)
        print(f"Combined report of {count(n, 'device')}: {args.output}")
        return 0
    if args.cmd == "clean":
        from . import cleanup
        items = [it for it in cleanup.plan() if args.recycle_bin or it["id"] != "win-recycle"]
        if not items:
            print("Nothing to clean up.")
            return 0
        for it in items:
            print(f"  • {it['text']}\n      {it['detail']}")
        if not args.yes:
            print("\nNothing deleted. Run again with --yes to delete these items permanently.")
            return 0
        for label, msg in cleanup.execute({it["id"] for it in items}, items, restart_explorer=args.restart_explorer):
            print(f"{label}: {msg}")
        return 0

    print(f"{APPNAME} {VERSION}\n" + "=" * 60)
    ctx = Context(full=getattr(args, "full", False), root_mode=args.root, log=lambda msg: print(msg, flush=True),
                  emit=lambda f: _print(f, args.verbose))
    ctx.no_baseline = args.no_baseline
    selftest_rc = None
    try:
        if args.cmd == "scan":
            scanner.system_scan(ctx)
        elif args.cmd == "android":
            scanner.android_scan(ctx, args.serial, args.adb)
        elif args.cmd == "iphone-backup":
            scanner.ios_backup_scan(ctx, args.folder, args.password)
        elif args.cmd == "iphone-ssh":
            scanner.ios_ssh_scan(ctx, args.ip, args.user, args.port)
        elif args.cmd == "netwatch":
            from . import netwatch
            netwatch.watch(ctx, args.minutes, args.interval)
        elif args.cmd == "selftest":
            p = scanner.selftest(ctx)
            if [f for f in ctx.findings if f.sev == HIT]:
                qid = quarantine.quarantine(p, "Self-test")
                print(f"\nSelf-test passed: the test file was detected and moved to quarantine ({qid}).")
                selftest_rc = 0
            else:
                print("\nSelf-test FAILED: the test file was not detected.")
                selftest_rc = 2
    except KeyboardInterrupt:
        ctx.cancel = True
        print("\nCancelled.")
    if args.html:
        report.save_html(ctx, args.html)
        print(f"Report: {args.html}")
    if args.json:
        report.save_json(ctx, args.json)
        print(f"Data: {args.json}")
    if selftest_rc is not None:
        return selftest_rc
    return 1 if ctx.counts()[HIT] else 0


if __name__ == "__main__":
    sys.exit(main())
