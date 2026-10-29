"""Optional YARA scanning (full scan only).

Needs the optional package yara-python (pip install yara-python). Rules come from
  ~/.scs-scanner/yara/custom/*.yar        – your own rules
  ~/.scs-scanner/yara/signature-base/     – after “scs update --yara”: the open signature-base collection
                                            by Florian Roth / Nextron Systems (Detection Rule License 1.1)
The rules are downloaded straight from their source to the user's computer; they are not shipped with this program.
"""
from __future__ import annotations

import glob
import io
import os
import shutil
import zipfile

from .core import DATA_DIR, SKIP, WARN, count, ensure_dir, walk

YARA_DIR = os.path.join(DATA_DIR, "yara")
SIGBASE_URL = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"
# signature-base rules use these external variables (as defined by its own scanners)
EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}
SCAN_EXT = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".hta", ".jar", ".msi", ".lnk",
            ".php", ".jsp", ".aspx", ".asp", ".sh", ".py", ".elf", ".so", ".dylib", ".bin", ".apk", ""}


def update_rules(log=print):
    from .ioc import _get
    ensure_dir(YARA_DIR)
    ensure_dir(os.path.join(YARA_DIR, "custom"))
    log("Downloading the signature-base YARA rules (Florian Roth / Nextron Systems, DRL 1.1) …")
    data = _get(SIGBASE_URL, timeout=180, limit=200 * 1024 * 1024)
    target = os.path.join(YARA_DIR, "signature-base")
    shutil.rmtree(target, ignore_errors=True)
    os.makedirs(target)
    n = 0
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for name in z.namelist():
            parts = name.split("/")
            # only <repo>/yara/<file>.yar – never write outside the target folder
            if len(parts) == 3 and parts[1] == "yara" and parts[2].endswith((".yar", ".yara")) and ".." not in parts[2]:
                with open(os.path.join(target, os.path.basename(parts[2])), "wb") as fh:
                    fh.write(z.read(name))
                n += 1
            elif len(parts) == 2 and parts[1] == "LICENSE":
                with open(os.path.join(target, "LICENSE"), "wb") as fh:
                    fh.write(z.read(name))
    log(f"  {count(n, 'rule file')} saved to {target}")
    return n


def rule_files():
    files = glob.glob(os.path.join(YARA_DIR, "custom", "*.yar")) + glob.glob(os.path.join(YARA_DIR, "custom", "*.yara"))
    files += glob.glob(os.path.join(YARA_DIR, "signature-base", "*.yar"))
    return sorted(files)


def compile_rules(yara):
    good, bad = {}, 0
    for i, path in enumerate(rule_files()):
        try:
            yara.compile(filepath=path, externals=EXTERNALS)
            good[f"r{i}"] = path
        except Exception:
            bad += 1  # rules that need special modules or variables are skipped
    if not good:
        return None, bad, 0
    return yara.compile(filepaths=good, externals=EXTERNALS), bad, len(good)


def scan(ctx, dirs):
    area = "YARA"
    try:
        import yara  # optional
    except ImportError:
        ctx.add(SKIP, area, "YARA not installed (optional)", "For YARA rule scanning: pip install yara-python, then “scs update --yara”.")
        return
    if not rule_files():
        ctx.add(SKIP, area, "No YARA rules available", "Run “scs update --yara” or put your own .yar files into " + os.path.join(YARA_DIR, "custom"))
        return
    ctx.step("YARA: compiling rules", 80)
    rules, bad, good = compile_rules(yara)
    if not rules:
        ctx.add(SKIP, area, "No YARA rule file could be compiled", f"{bad} files skipped.")
        return
    n, hits = 0, 0
    seen = set()
    for base in dirs:
        for path, e in walk(base, max_depth=8, max_files=200000):
            if ctx.cancel or n >= 20000:
                break
            ext = os.path.splitext(e.name)[1].lower()
            if ext not in SCAN_EXT:
                continue
            key = os.path.normcase(os.path.realpath(path))
            if key in seen:
                continue
            seen.add(key)
            try:
                if e.stat(follow_symlinks=False).st_size > 20 * 1024 * 1024:
                    continue
            except OSError:
                continue
            n += 1
            ext_vars = {"filename": e.name, "filepath": os.path.dirname(path), "extension": ext, "filetype": ext.lstrip(".").upper(), "owner": ""}
            try:
                matches = rules.match(path, externals=ext_vars, timeout=30)
            except Exception:
                continue
            if matches:
                hits += 1
                lines = []
                for m in matches[:15]:
                    meta = getattr(m, "meta", {}) or {}
                    lines.append(f"• {m.rule}: {meta.get('description', '–')}")
                ctx.add(WARN, area, f"{count(len(matches), 'YARA rule matches', 'YARA rules match')} {e.name}",
                        f"{path}\n" + "\n".join(lines) + "\n\nYARA rules can also match harmless files (e.g. admin tools). "
                        "Check the file with a second opinion (e.g. VirusTotal) before deleting it.",
                        path=path, source="YARA", action={"type": "quarantine", "path": path})
    from .core import OK
    ctx.add(OK, area, f"{count(n, 'file')} checked with {count(good, 'rule file')}" + (f", {count(hits, 'file')} with matches" if hits else ""),
            f"{bad} rule files skipped (they need special modules or variables)." if bad else "")
