"""Entry point of the Windows program (SCS Scanner.exe) built with PyInstaller: opens the window.

    "SCS Scanner.exe" --check REPORT.txt

runs the harmless self-test without a window instead, writes its output to REPORT.txt and ends with the self-test's
exit code (0 = passed). It proves that the installed program and all its parts work - used by CI after installing,
and useful for support.
"""
import sys


def check(report):
    import contextlib
    import io

    out = io.StringIO()
    rc = 3
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            # every part of the program has to be inside the executable, not only the ones the self-test uses
            from scs import (android, baseline, cleanup, cli, common, fleet, gui, icon, ioc, ios, lin, log, mac, net,  # noqa: F401
                             netwatch, quarantine, report as report_mod, scanner, updates, win, yarascan)
            rc = cli.main(["selftest", "--no-baseline"])
    except BaseException as exc:  # noqa: BLE001 - the report has to say what went wrong
        out.write(f"\n{type(exc).__name__}: {exc}\n")
    with open(report, "w", encoding="utf-8") as fh:
        fh.write(out.getvalue() + f"\nexit code: {rc}\n")
    return rc


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        sys.exit(check(sys.argv[2]))
    from scs.gui import main

    main()
