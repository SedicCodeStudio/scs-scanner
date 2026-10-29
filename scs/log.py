"""Diagnostic log: ~/.scs-scanner/logs/scs.log

Records which checks ran and any program errors – never findings, file contents or indicator matches – so that a
problem can be reported without sharing private data. The file is rotated at 512 KB (three old copies are kept).
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import platform
import sys
import traceback

from .core import DATA_DIR, VERSION, ensure_dir

LOG_DIR = os.path.join(DATA_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "scs.log")
_logger = None


def get() -> logging.Logger:
    global _logger
    if _logger is not None:
        return _logger
    lg = logging.getLogger("scs")
    lg.setLevel(logging.INFO)
    lg.propagate = False
    try:
        ensure_dir(LOG_DIR)
        h = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=512 * 1024, backupCount=3, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
        lg.addHandler(h)
        if os.name != "nt":
            try:
                os.chmod(LOG_FILE, 0o600)
            except OSError:
                pass
    except OSError:
        lg.addHandler(logging.NullHandler())
    _logger = lg
    return lg


def start(what: str):
    get().info("SCS Scanner %s – %s – Python %s on %s %s", VERSION, what, platform.python_version(), platform.system(), platform.release())


def check_failed(area: str, exc: BaseException):
    get().error("check failed: %s – %s\n%s", area, type(exc).__name__, "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)).rstrip())


def crash(exc_type, exc, tb) -> str:
    """Writes an unexpected error with its traceback to the log and returns the log path for the user."""
    get().critical("unexpected error\n%s", "".join(traceback.format_exception(exc_type, exc, tb)).rstrip())
    return LOG_FILE


def install_excepthook():
    def hook(exc_type, exc, tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc, tb)
            return
        path = crash(exc_type, exc, tb)
        sys.stderr.write(f"\nUnexpected error: {exc_type.__name__}: {exc}\nDetails were saved to {path}\n"
                         "Please report it: https://github.com/SedicCodeStudio/scs-scanner/issues (attach the log file).\n")
    sys.excepthook = hook
