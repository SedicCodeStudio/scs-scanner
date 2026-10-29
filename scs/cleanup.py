"""Privacy cleanup.

Thumbnail caches keep small copies of photos – also of photos that were deleted long ago. This module lists
those leftovers and deletes them on request. Deleting is permanent, so nothing happens without confirmation.
"""
from __future__ import annotations

import glob
import os
import subprocess
import time

from .core import DATA_DIR, HOME, count, human, os_name, ps, run


def _size(files):
    total = 0
    for f in files:
        try:
            total += os.path.getsize(f)
        except OSError:
            pass
    return total


def plan(android=None):
    """Returns the cleanable items: dicts with id, label, detail, files, size, permanent."""
    items = []
    o = os_name()
    if o == "windows":
        base = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Windows", "Explorer")
        files = glob.glob(os.path.join(base, "thumbcache_*.db"))
        if files:
            items.append(dict(id="win-thumbcache", label="Windows thumbnail cache", detail=base, files=files, size=_size(files)))
        rc, out, _ = ps("(New-Object -ComObject Shell.Application).NameSpace(10).Items().Count")
        n = int(out.strip()) if out.strip().isdigit() else 0
        if n:
            items.append(dict(id="win-recycle", label=f"Recycle Bin ({n} items)",
                              detail="Empties the Recycle Bin – the files cannot be restored afterwards.", files=[], size=0))
    elif o == "linux":
        base = os.path.join(HOME, ".cache", "thumbnails")
        files = [f for f in glob.glob(os.path.join(base, "**", "*"), recursive=True) if os.path.isfile(f)]
        if files:
            items.append(dict(id="linux-thumbs", label="Thumbnail cache (freedesktop)", detail=base, files=files, size=_size(files)))
    elif o == "macos":
        base = os.path.join(HOME, "Library", "Caches", "com.apple.QuickLook.thumbnailcache")
        files = [f for f in glob.glob(os.path.join(base, "**", "*"), recursive=True) if os.path.isfile(f)]
        items.append(dict(id="mac-quicklook", label="Quick Look thumbnail cache",
                          detail="Resets the cache with “qlmanage -r cache”.", files=files, size=_size(files)))
    tmp = [f for f in glob.glob(os.path.join(DATA_DIR, "tmp", "*")) if os.path.isfile(f)]
    if tmp:
        items.append(dict(id="scs-tmp", label="Temporary files of this scanner", detail=os.path.join(DATA_DIR, "tmp"),
                          files=tmp, size=_size(tmp)))
    if android:
        items.append(dict(id="android-thumbs", label="Android thumbnail cache (/sdcard/DCIM/.thumbnails)",
                          detail=f"Phone {android['serial']} – previews of photos, also of deleted ones.", files=[], size=0))
    for it in items:
        it["text"] = f"{it['label']}" + (f" – {human(it['size'])}" if it["size"] else "")
    return items


def _delete(files):
    done, locked = 0, []
    for f in files:
        try:
            os.remove(f)
            done += 1
        except OSError:
            locked.append(f)
    return done, locked


def execute(selected_ids, items, restart_explorer=False, android=None):
    """Deletes the selected items. Returns a list of (label, result text)."""
    out = []
    for it in items:
        if it["id"] not in selected_ids:
            continue
        if it["id"] == "win-thumbcache":
            done, locked = _delete(it["files"])
            if locked and restart_explorer:
                run(["taskkill", "/f", "/im", "explorer.exe"], timeout=30)
                time.sleep(1.5)
                d2, locked = _delete(locked)
                done += d2
                subprocess.Popen(["explorer.exe"])
            msg = f"{count(done, 'file')} deleted"
            if locked:
                msg += (f", {len(locked)} in use by Windows Explorer – choose the option to restart Explorer, "
                        "or use Disk Cleanup › Thumbnails")
            out.append((it["label"], msg))
        elif it["id"] == "win-recycle":
            rc, _, err = ps("Clear-RecycleBin -Force -ErrorAction Stop", timeout=300)
            out.append((it["label"], "emptied" if rc == 0 else f"failed: {err.strip()[:200]}"))
        elif it["id"] in ("linux-thumbs", "scs-tmp"):
            done, locked = _delete(it["files"])
            out.append((it["label"], f"{count(done, 'file')} deleted" + (f", {len(locked)} could not be deleted" if locked else "")))
        elif it["id"] == "mac-quicklook":
            rc, _, err = run(["qlmanage", "-r", "cache"], timeout=60)
            out.append((it["label"], "reset" if rc == 0 else f"failed: {err.strip()[:200]}"))
        elif it["id"] == "android-thumbs" and android:
            from .android import ADB
            a = ADB(android["adb"], android["serial"])
            a.sh("rm -rf /sdcard/DCIM/.thumbnails/*")
            out.append((it["label"], "deleted"))
    return out
