"""Quarantine: move suspicious files safely out of the way (never delete them) and restore them."""
from __future__ import annotations

import json
import os
import re
import shutil
import time

from .core import DATA_DIR, ensure_dir, os_name, sha256_file

QDIR = os.path.join(DATA_DIR, "quarantine")
SUFFIX = ".quarantined"
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}$")


def _entry_dir(qid: str) -> str:
    """Path of a quarantine entry; refuses IDs that would point outside the quarantine folder."""
    if not qid or not _ID_RE.match(qid) or ".." in qid:
        raise ValueError(f"Invalid quarantine ID: {qid!r}")
    return os.path.join(QDIR, qid)


def quarantine(path: str, reason: str = "") -> str:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path}")
    ensure_dir(QDIR)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.basename(path))[:60].replace("..", "_")
    stem = time.strftime("%Y%m%d-%H%M%S") + "_" + safe
    qid, n = stem, 1
    while os.path.exists(os.path.join(QDIR, qid)):
        n += 1
        qid = f"{stem}_{n}"
    target = os.path.join(QDIR, qid)
    os.makedirs(target, mode=0o700)
    meta = {"id": qid, "original": os.path.abspath(path), "sha256": sha256_file(path),
            "reason": reason, "time": time.strftime("%Y-%m-%d %H:%M:%S"), "mode": os.stat(path).st_mode & 0o777}
    # Append a suffix so the file cannot be started by accident; on macOS/Linux also make it read-only
    dst = os.path.join(target, os.path.basename(path) + SUFFIX)
    shutil.move(path, dst)
    if os_name() != "windows":
        os.chmod(dst, 0o400)
    with open(os.path.join(target, "info.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, ensure_ascii=False, indent=1)
    return qid


def entries():
    out = []
    if not os.path.isdir(QDIR):
        return out
    for d in sorted(os.listdir(QDIR)):
        try:
            with open(os.path.join(QDIR, d, "info.json"), encoding="utf-8") as fh:
                out.append(json.load(fh))
        except Exception:
            continue
    return out


def restore(qid: str) -> str:
    d = _entry_dir(qid)
    with open(os.path.join(d, "info.json"), encoding="utf-8") as fh:
        meta = json.load(fh)
    src = [f for f in os.listdir(d) if f.endswith(SUFFIX)][0]
    dst = meta["original"]
    if os.path.exists(dst):
        raise FileExistsError(f"A file already exists at the original location: {dst}")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.move(os.path.join(d, src), dst)
    if os_name() != "windows":
        os.chmod(dst, meta.get("mode", 0o600) & 0o777)
    shutil.rmtree(d, ignore_errors=True)
    return dst


def delete(qid: str):
    d = _entry_dir(qid)
    if not os.path.isfile(os.path.join(d, "info.json")):
        raise FileNotFoundError(f"No quarantine entry with the ID {qid}")
    for root, _dirs, files in os.walk(d):
        for f in files:
            try:
                os.chmod(os.path.join(root, f), 0o600)  # read-only files cannot be removed on Windows
            except OSError:
                pass
    shutil.rmtree(d)
