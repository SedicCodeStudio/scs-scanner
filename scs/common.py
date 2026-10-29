"""Cross-platform checks: browser histories, hidden images, file fingerprints, indicator paths,
remote access software, hosts file."""
from __future__ import annotations

import glob
import os
import shutil
import sqlite3
from urllib.parse import urlparse

from . import baseline
from .core import (count, private_tmp, DATA_DIR, HIT, HOME, INFO, OK, SKIP, WARN, ensure_dir, human,
                   is_hidden, os_name, sha256_file, walk)
from .ioc import SELFTEST_CONTENT

IMG_EXT = {".jpg", ".jpeg", ".png", ".gif", ".heic", ".heif", ".webp", ".bmp", ".tif", ".tiff", ".raw",
           ".dng", ".cr2", ".nef", ".arw", ".mp4", ".mov", ".avi", ".mkv", ".3gp", ".m4v", ".wmv"}
EXEC_EXT = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
            ".jar", ".msi", ".lnk", ".com", ".pif", ".apk", ".ipa", ".sh", ".py", ".dylib", ".so", ".elf",
            ".bin", ".pkg", ".dmg", ".app", ".command", ".iso", ".img", ".zip", ".rar", ".7z"}
MAGIC = [(b"\xff\xd8\xff", "JPEG image"), (b"\x89PNG\r\n\x1a\n", "PNG image"), (b"GIF8", "GIF image"),
         (b"RIFF", "RIFF (WebP/AVI)"), (b"BM", None)]
SKIP_DIRS = {"node_modules", ".git", "__pycache__", "site-packages", ".npm", ".cargo", ".rustup",
             "AppData" if os_name() != "windows" else "__none__", "Library" if os_name() != "macos" else "__none__"}

# Well-known remote access programs – legitimate, but frequently abused by scammers and attackers
REMOTE_TOOLS = {
    "anydesk": "AnyDesk", "teamviewer": "TeamViewer", "tv_w32": "TeamViewer", "tv_x64": "TeamViewer",
    "rustdesk": "RustDesk", "client32": "NetSupport Manager", "screenconnect": "ScreenConnect",
    "ateraagent": "Atera", "srservice": "Splashtop", "strwinclt": "Splashtop", "aa_v3": "Ammyy Admin",
    "ultraviewer": "UltraViewer", "supremo": "Supremo", "logmein": "LogMeIn", "lmiguardiansvc": "LogMeIn",
    "remoting_host": "Chrome Remote Desktop", "dwagent": "DWService", "tvnserver": "TightVNC",
    "winvnc": "UltraVNC", "vncserver": "VNC Server", "x11vnc": "x11vnc", "remotepc": "RemotePC",
    "zohoassist": "Zoho Assist", "level": "Level RMM", "meshagent": "MeshCentral", "simplehelp": "SimpleHelp",
}


# ------------------------------------------------------------------ indicators
def check_ioc_status(ctx):
    n = ctx.ioc.total() if ctx.ioc else 0
    if n < 10:
        ctx.add(SKIP, "Indicators", "No indicator lists loaded",
                "Without the lists, Pegasus, Predator, stalkerware and similar spyware cannot be detected.\n"
                "Run “Update indicators” first (internet connection required).")
    else:
        feeds = "\n".join(f"  {c:6}  {name}" for name, c in ctx.ioc.feeds)
        ctx.add(INFO, "Indicators", f"{count(n, 'indicator')} loaded from {count(len(ctx.ioc.feeds), 'source')}", feeds)


# ------------------------------------------------------------------ browsers
def _browser_dbs():
    o = os_name()
    L, R = os.environ.get("LOCALAPPDATA", ""), os.environ.get("APPDATA", "")
    chromium, firefox, safari = [], [], []
    if o == "windows":
        for name, base in [("Chrome", rf"{L}\Google\Chrome\User Data"), ("Edge", rf"{L}\Microsoft\Edge\User Data"),
                           ("Brave", rf"{L}\BraveSoftware\Brave-Browser\User Data"), ("Vivaldi", rf"{L}\Vivaldi\User Data"),
                           ("Chromium", rf"{L}\Chromium\User Data")]:
            chromium += [(name, p) for p in glob.glob(os.path.join(base, "*", "History"))]
        chromium += [("Opera", p) for p in glob.glob(rf"{R}\Opera Software\*\History")]
        firefox += glob.glob(rf"{R}\Mozilla\Firefox\Profiles\*\places.sqlite")
    elif o == "macos":
        AS = os.path.join(HOME, "Library", "Application Support")
        for name, sub in [("Chrome", "Google/Chrome"), ("Edge", "Microsoft Edge"), ("Brave", "BraveSoftware/Brave-Browser"),
                          ("Vivaldi", "Vivaldi"), ("Chromium", "Chromium"), ("Arc", "Arc/User Data")]:
            chromium += [(name, p) for p in glob.glob(os.path.join(AS, sub, "*", "History"))]
        firefox += glob.glob(os.path.join(AS, "Firefox", "Profiles", "*", "places.sqlite"))
        safari.append(os.path.join(HOME, "Library", "Safari", "History.db"))
    else:
        C = os.path.join(HOME, ".config")
        for name, sub in [("Chrome", "google-chrome"), ("Chromium", "chromium"), ("Brave", "BraveSoftware/Brave-Browser"),
                          ("Edge", "microsoft-edge"), ("Vivaldi", "vivaldi"), ("Opera", "opera")]:
            chromium += [(name, p) for p in glob.glob(os.path.join(C, sub, "*", "History"))]
        firefox += glob.glob(os.path.join(HOME, ".mozilla", "firefox", "*", "places.sqlite"))
        firefox += glob.glob(os.path.join(HOME, "snap", "firefox", "common", ".mozilla", "firefox", "*", "places.sqlite"))
    out = [(n, p, "SELECT url, last_visit_time FROM urls") for n, p in chromium]
    out += [("Firefox", p, "SELECT url, last_visit_date FROM moz_places") for p in firefox]
    out += [("Safari", p, "SELECT url, 0 FROM history_items") for p in safari]
    return out


def query_copy(db_path, sql, limit=500000):
    """Copies a (possibly locked) SQLite file and reads it."""
    tmp = private_tmp(".sqlite")
    shutil.copy2(db_path, tmp)
    for ext in ("-wal", "-shm"):
        if os.path.exists(db_path + ext):
            try:
                shutil.copy2(db_path + ext, tmp + ext)
            except OSError:
                pass
    try:
        con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        rows = con.execute(f"{sql} LIMIT {limit}").fetchall()
        con.close()
        return rows
    finally:
        for ext in ("", "-wal", "-shm"):
            try:
                os.remove(tmp + ext)
            except OSError:
                pass


def match_urls(ctx, area, urls, label):
    """urls: iterable of (url, time). Reports indicator hits and returns the number of URLs checked."""
    n, hits = 0, {}
    for url, _ts in urls:
        n += 1
        host = urlparse(url if "://" in str(url) else "http://" + str(url)).hostname
        m = ctx.ioc.match_domain(host) if ctx.ioc and host else None
        if m:
            hits.setdefault(m[0], (m[1], url))
    for dom, ((feed, mal), url) in hits.items():
        ctx.add(HIT, area, f"Known spyware address: {dom}",
                f"Found in: {label}\nAddress: {url}\nAttributed to: {mal}\n\nThis alone does not prove an infection, but it is a "
                f"serious warning sign. Save the report and consult experts.", source=feed)
    return n


def check_browsers(ctx):
    dbs = _browser_dbs()
    found = 0
    for name, path, sql in dbs:
        if not os.path.exists(path):
            continue
        try:
            rows = query_copy(path, sql)
        except PermissionError:
            ctx.add(SKIP, "Browser", f"{name}: no access",
                    f"{path}\n" + ("On a Mac: System Settings › Privacy & Security › Full Disk Access – enable it for Terminal "
                                   "or Python." if os_name() == "macos" else "Close the browser and try again."))
            continue
        except Exception as e:  # noqa: BLE001
            ctx.add(SKIP, "Browser", f"{name}: history not readable", f"{path}\n{e}")
            continue
        found += 1
        n = match_urls(ctx, "Browser", rows, f"{name} history: {path}")
        ctx.add(OK, "Browser", f"{name}: {count(n, 'address', 'addresses')} checked", path)
    if not found:
        ctx.add(INFO, "Browser", "No readable browser history found")


# ------------------------------------------------------------------ images, hiding places
def _magic(path):
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except OSError:
        return None
    if head[4:8] == b"ftyp":
        brand = head[8:12]
        return "HEIC image" if brand in (b"heic", b"heix", b"mif1", b"heim") else "Video (MP4/MOV)"
    for sig, label in MAGIC:
        if label and head.startswith(sig):
            if sig == b"RIFF" and head[8:12] not in (b"WEBP", b"AVI "):
                return None
            return label
    return None


def _trailing(path):
    """Detects data appended after the end of a JPEG/PNG."""
    try:
        if os.path.getsize(path) > 40 * 1024 * 1024:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    end = None
    if data.startswith(b"\xff\xd8"):
        i = data.rfind(b"\xff\xd9")
        end = i + 2 if i > 0 else None
    elif data.startswith(b"\x89PNG"):
        i = data.rfind(b"IEND")
        end = i + 8 if i > 0 else None
    if not end:
        return None
    extra = len(data) - end
    if extra < 2048:
        return None
    tail = data[end:end + 64]
    if b"ftyp" in tail[:16]:
        kind = "an appended video (Motion Photo – usually harmless)"
    elif tail.startswith(b"PK\x03\x04"):
        kind = "an appended ZIP archive"
    elif tail.startswith(b"Rar!"):
        kind = "an appended RAR archive"
    elif tail.startswith(b"MZ"):
        kind = "an appended Windows program"
    else:
        kind = "unknown appended data"
    return extra, kind


def media_roots():
    roots = [HOME]
    if os_name() == "linux" and os.path.isdir("/media"):
        roots.append("/media")
    return roots


def check_media(ctx):
    full = ctx.full
    depth, maxf = (14, 600000) if full else (6, 80000)
    hidden_imgs, disguised, trailing = [], [], []
    cache_dirs = {}
    scanned = 0
    for root in media_roots():
        for path, e in walk(root, max_depth=depth, max_files=maxf, skip_names=SKIP_DIRS):
            if ctx.cancel:
                return
            scanned += 1
            name = e.name
            ext = os.path.splitext(name)[1].lower()
            rel_parts = os.path.relpath(path, root).split(os.sep)
            in_hidden_dir = any(p.startswith(".") for p in rel_parts[:-1])
            low = path.lower()
            is_cache = any(k in low for k in ("cache", "thumbnail", ".thumbnails", "temp", "tmp"))
            if ext in IMG_EXT:
                if is_hidden(e) or in_hidden_dir:
                    if is_cache:
                        cache_dirs[os.path.dirname(path)] = cache_dirs.get(os.path.dirname(path), 0) + 1
                    else:
                        hidden_imgs.append(path)
                if full and ext in (".jpg", ".jpeg", ".png"):
                    t = _trailing(path)
                    if t:
                        trailing.append((path, t))
                continue
            try:
                size = e.stat(follow_symlinks=False).st_size
            except OSError:
                continue
            if 1500 < size < 80 * 1024 * 1024 and (full or ext in ("", ".dat", ".tmp", ".bin", ".db", ".0", ".cache", ".txt", ".sys", ".dll")):
                kind = _magic(path)
                if kind:
                    if is_cache:
                        cache_dirs[os.path.dirname(path)] = cache_dirs.get(os.path.dirname(path), 0) + 1
                    else:
                        disguised.append((path, kind, size))
    area = "Hidden images"
    if hidden_imgs:
        ctx.add(INFO, area, f"{count(len(hidden_imgs), 'hidden image/video file')}",
                "Files with the hidden attribute or inside hidden folders (excerpt):\n" + "\n".join(hidden_imgs[:60]),
                action={"type": "open", "path": os.path.dirname(hidden_imgs[0])})
    if disguised:
        lines = "\n".join(f"{k:16} {human(s):>9}  {p}" for p, k, s in disguised[:60])
        ctx.add(WARN, area, f"{count(len(disguised), 'disguised image file')} (wrong file extension)",
                "By their content these files are images or videos, but they carry a different extension – typical of vault apps "
                "or deliberately hidden photos:\n" + lines, action={"type": "open", "path": os.path.dirname(disguised[0][0])})
    if cache_dirs:
        top = sorted(cache_dirs.items(), key=lambda x: -x[1])[:25]
        ctx.add(INFO, area, f"Images in {count(len(cache_dirs), 'cache folder')}",
                "Viewed or deleted images often remain in caches (count · folder):\n" +
                "\n".join(f"{n:7}  {d}" for d, n in top), action={"type": "open", "path": top[0][0]})
    for path, (extra, kind) in trailing[:40]:
        sev = INFO if "harmless" in kind else WARN
        ctx.add(sev, area, f"Image with {kind}", f"{path}\n{human(extra)} of extra data after the end of the image.\n"
                "Use binwalk or 7-Zip to inspect what is attached.", path=path,
                action={"type": "quarantine", "path": path} if sev == WARN else None)
    if not (hidden_imgs or disguised or cache_dirs or trailing):
        ctx.add(OK, area, f"{count(scanned, 'file')} checked, nothing hidden found")
    else:
        ctx.add(OK, area, f"{count(scanned, 'file')} searched")


def check_thumbcaches(ctx):
    o = os_name()
    places = []
    if o == "windows":
        places.append(("Windows thumbnail cache", os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Windows", "Explorer"), "thumbcache_*.db"))
        places.append(("Windows icon cache", os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Windows", "Explorer"), "iconcache_*.db"))
    elif o == "linux":
        places.append(("Thumbnail cache (freedesktop)", os.path.join(HOME, ".cache", "thumbnails"), "**/*.png"))
    elif o == "macos":
        places.append(("Quick Look cache", os.path.join(HOME, "Library", "Caches", "com.apple.QuickLook.thumbnailcache"), "*"))
    for label, base, pat in places:
        files = glob.glob(os.path.join(base, pat), recursive=True)
        if not files:
            continue
        size = sum(os.path.getsize(f) for f in files if os.path.isfile(f))
        ctx.add(INFO, "Thumbnail caches", f"{label}: {human(size)} in {count(len(files), 'file')}",
                f"{base}\nThumbnails are stored here – often also of photos that were deleted long ago. "
                "View them e.g. with Thumbcache Viewer; clear them with Disk Cleanup (Windows).",
                action={"type": "open", "path": base})


# ------------------------------------------------------------------ fingerprints & paths
def risky_dirs():
    o = os_name()
    d = []
    if o == "windows":
        L, R, P = os.environ.get("LOCALAPPDATA", ""), os.environ.get("APPDATA", ""), os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        d = [os.path.join(HOME, "Downloads"), os.path.join(HOME, "Desktop"), os.environ.get("TEMP", ""), R, L,
             P, r"C:\Users\Public", os.path.join(R, r"Microsoft\Windows\Start Menu\Programs\Startup"),
             r"C:\Windows\Temp"]
    elif o == "macos":
        d = [os.path.join(HOME, "Downloads"), os.path.join(HOME, "Library", "LaunchAgents"), "/Library/LaunchAgents",
             "/Library/LaunchDaemons", "/tmp", "/private/var/tmp", os.path.join(HOME, "Library", "Application Support"), "/Users/Shared"]
    else:
        d = [os.path.join(HOME, "Downloads"), "/tmp", "/var/tmp", "/dev/shm", os.path.join(HOME, ".local", "bin"),
             os.path.join(HOME, ".config"), os.path.join(HOME, ".local", "share"), "/opt", "/usr/local/bin"]
    d.append(os.path.join(DATA_DIR, "selftest"))
    return [x for x in d if x and os.path.isdir(x)]


def check_hashes(ctx):
    maxf = 60000 if ctx.full else 5000
    maxb = 150 * 1024 * 1024 if ctx.full else 25 * 1024 * 1024
    n = 0
    seen = set()  # the folders overlap (e.g. AppData and the Startup folder inside it): check every file once
    for base in risky_dirs():
        for path, e in walk(base, max_depth=8 if ctx.full else 4, max_files=maxf * 10, skip_names=SKIP_DIRS):
            if ctx.cancel or n >= maxf:
                break
            ext = os.path.splitext(e.name)[1].lower()
            if not (ctx.full or ext in EXEC_EXT or e.name.startswith("SCS-SELFTEST")):
                continue
            key = os.path.normcase(os.path.realpath(path))
            if key in seen:
                continue
            seen.add(key)
            h = sha256_file(path, maxb)
            n += 1
            if not h:
                continue
            hit = ctx.ioc.get("sha256", h) if ctx.ioc else None
            if hit:
                feed, mal = hit
                ctx.add(HIT, "Files", f"Known malware: {os.path.basename(path)}",
                        f"{path}\nSHA-256: {h}\nAttributed to: {mal}", path=path, source=feed,
                        action={"type": "quarantine", "path": path})
    ctx.add(OK, "Files", f"{count(n, 'file')} checked by fingerprint (SHA-256)",
            "Folders checked:\n" + "\n".join(risky_dirs()))


def _expand(p):
    return os.path.expandvars(os.path.expanduser(p))


def check_ioc_paths(ctx):
    if not ctx.ioc:
        return
    o = os_name()
    hits = 0
    for raw, (feed, mal) in ctx.ioc.data["file_path"].items():
        p = _expand(raw)
        if o == "windows" and not (len(p) > 2 and p[1] == ":"):
            continue
        if o != "windows" and not p.startswith("/"):
            continue
        if p.startswith("/private/var/mobile") or p.startswith("/data/"):
            continue  # phone paths are checked by the phone modules
        if os.path.exists(p):
            hits += 1
            ctx.add(HIT, "Traces", f"Known spyware file present: {os.path.basename(p) or p}",
                    f"{p}\nAttributed to: {mal}", path=p, source=feed,
                    action={"type": "quarantine", "path": p} if os.path.isfile(p) else None)
    if not hits:
        ctx.add(OK, "Traces", "No known spyware file paths found")


# ------------------------------------------------------------------ processes
def check_processes(ctx):
    if not ctx.processes:
        ctx.add(SKIP, "Processes", "Process list not available")
        return
    names = {}
    for p in ctx.processes:
        names.setdefault(p.get("name") or "", p)
    hits = 0
    if ctx.ioc:
        for name, p in names.items():
            base = os.path.splitext(name)[0] if os_name() == "windows" else name
            hit = ctx.ioc.get("process", name) or ctx.ioc.get("process", base)
            if hit:
                hits += 1
                ctx.add(HIT, "Processes", f"Running process matches spyware: {name}",
                        f"PID {p.get('pid')}  Path: {p.get('path') or '?'}\nAttributed to: {hit[1]}",
                        source=hit[0], path=p.get("path"),
                        action={"type": "quarantine", "path": p["path"]} if p.get("path") else None)
    seen = set()
    baseline.seen(ctx, "remote")
    for name, p in names.items():
        key = os.path.splitext(name.lower())[0]
        for pat, label in REMOTE_TOOLS.items():
            if key == pat or (len(pat) > 5 and key.startswith(pat)):
                if label in seen:
                    break
                seen.add(label)
                baseline.note(ctx, "remote", label)
                ctx.add(WARN, "Remote access", f"Remote access program running: {label}",
                        f"Process: {name}  Path: {p.get('path') or '?'}\nLegitimate software, but often abused by scammers "
                        "(fake “Microsoft support”) and stalkers. If you did not install it yourself: quit it, uninstall it and "
                        "change your passwords.")
                break
    ctx.add(OK, "Processes", f"{count(len(ctx.processes), 'process', 'processes')} checked" + (f", {count(hits, 'hit')}" if hits else ""))


def check_remote_ips(ctx, ips, label="connections"):
    hits = 0
    for ip in set(ips):
        if ctx.ioc and ip in ctx.ioc.data["ipv4"]:
            feed, mal = ctx.ioc.data["ipv4"][ip]
            hits += 1
            ctx.add(HIT, "Network", f"Connection to known spyware IP {ip}", f"Attributed to: {mal}", source=feed)
    note = ""
    if ctx.vpn:
        note = (f"A VPN is active ({', '.join(ctx.vpn)}): connections inside the tunnel are not visible here, "
                "only the VPN server and traffic outside the tunnel.")
    ctx.add(OK, "Network", f"{count(len(set(ips)), 'remote host')} ({label}) checked" + (f", {count(hits, 'hit')}" if hits else "")
            + (" – limited by VPN" if ctx.vpn else ""), note)


def check_hosts(ctx):
    p = r"C:\Windows\System32\drivers\etc\hosts" if os_name() == "windows" else "/etc/hosts"
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            lines = [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]
    except OSError as e:
        ctx.add(SKIP, "Network", "hosts file not readable", str(e))
        return
    normal = {"localhost", "ip6-localhost", "ip6-loopback", "broadcasthost", "ip6-allnodes", "ip6-allrouters", "ip6-localnet", "ip6-mcastprefix"}
    odd = [ln for ln in lines if not set(ln.split()[1:]) <= normal and ln.split()[0] not in ("127.0.1.1",)]
    if odd:
        ctx.add(WARN, "Network", f"hosts file contains {count(len(odd), 'redirect')}",
                f"{p}\n" + "\n".join(odd[:40]) + "\n\nMalware uses this file to redirect banking or update sites. "
                "Entries added by ad blockers you installed yourself are harmless.",
                action={"type": "open", "path": os.path.dirname(p)})
    else:
        ctx.add(OK, "Network", "hosts file looks normal")


# ------------------------------------------------------------------ self-test
def create_selftest():
    d = ensure_dir(os.path.join(DATA_DIR, "selftest"))
    p = os.path.join(d, "SCS-SELFTEST.txt")
    with open(p, "wb") as fh:
        fh.write(SELFTEST_CONTENT)
    return p
