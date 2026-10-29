"""iPhone check.

1) From an iTunes/Finder backup (no jailbreak) – modelled on MVT: Safari history, SMS links, WhatsApp links,
   process traces (DataUsage/netusage), file paths, apps, configuration profiles, VPN/network extension
   configurations, hidden photos.
2) With a jailbreak (root) over SSH: running processes and indicator files directly on the device.
"""
from __future__ import annotations

import glob
import os
import plistlib
import re
import shutil
import sqlite3

from . import baseline, net
from .core import count, HIT, HOME, INFO, OK, SKIP, WARN, os_name, run, tmp_dir

URL_RE = re.compile(r"(?:https?://)?(?:[\w-]+\.)+[a-z]{2,}(?:/[^\s\"'<>]*)?", re.I)
BUNDLE_RE = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+){2,}$")


def default_backup_dirs():
    if os_name() == "windows":
        c = [os.path.join(os.environ.get("APPDATA", ""), "Apple Computer", "MobileSync", "Backup"),
             os.path.join(HOME, "Apple", "MobileSync", "Backup")]
    elif os_name() == "macos":
        c = [os.path.join(HOME, "Library", "Application Support", "MobileSync", "Backup")]
    else:
        c = [os.path.join(HOME, ".local", "share", "MobileSync", "Backup")]
    out = []
    for base in c:
        out += [d for d in glob.glob(os.path.join(base, "*")) if os.path.isfile(os.path.join(d, "Manifest.plist"))]
    return out


class Backup:
    def __init__(self, path, password=None):
        self.path = path
        self.password = password
        self.enc = None
        with open(os.path.join(path, "Manifest.plist"), "rb") as fh:
            self.manifest = plistlib.load(fh)
        try:
            with open(os.path.join(path, "Info.plist"), "rb") as fh:
                self.info = plistlib.load(fh)
        except Exception:
            self.info = {}
        self.encrypted = bool(self.manifest.get("IsEncrypted"))
        self.db = os.path.join(path, "Manifest.db")
        if self.encrypted:
            self._open_encrypted()

    def _open_encrypted(self):
        if not self.password:
            raise PermissionError("The backup is encrypted – a password is required.")
        try:
            from iphone_backup_decrypt import EncryptedBackup  # optional: pip install iphone_backup_decrypt
        except ImportError:
            raise PermissionError("The add-on package for decryption is missing: pip install iphone_backup_decrypt\n"
                                  "Alternative: mvt-ios decrypt-backup -p PASSWORD -d TARGET_FOLDER BACKUP_FOLDER, then check the target folder.")
        self.enc = EncryptedBackup(backup_directory=self.path, passphrase=self.password)
        out = os.path.join(tmp_dir(), "Manifest_decrypted.db")
        self.enc.save_manifest_file(out)
        self.db = out

    def files(self):
        con = sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)
        rows = con.execute("SELECT fileID, domain, relativePath FROM Files").fetchall()
        con.close()
        return rows

    def extract(self, file_id, domain, rel):
        """Returns a local path to the (decrypted, if needed) file."""
        if self.enc:
            out = os.path.join(tmp_dir(), "ios_" + file_id)
            self.enc.extract_file(relative_path=rel, domain_like=domain, output_filename=out)
            return out if os.path.exists(out) else None
        for p in (os.path.join(self.path, file_id[:2], file_id), os.path.join(self.path, file_id)):
            if os.path.isfile(p):
                out = os.path.join(tmp_dir(), "ios_" + file_id)
                shutil.copy2(p, out)
                return out
        return None


def _sql(path, query):
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return con.execute(query).fetchall()
    finally:
        con.close()


def _plist_strings(path):
    """All strings inside a (possibly NSKeyedArchiver) property list."""
    try:
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
    except Exception:
        return []
    out = []

    def walk(o):
        if isinstance(o, str):
            out.append(o)
        elif isinstance(o, dict):
            for k, v in o.items():
                walk(k)
                walk(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                walk(v)
    walk(data)
    return out


def check_backup(ctx, path, password=None):
    area = "iPhone backup"
    if not path:
        found = default_backup_dirs()
        if not found:
            ctx.add(SKIP, area, "No iPhone backup found",
                    "Connect the iPhone by cable and choose “Back Up Now” in iTunes (Windows) or Finder (Mac). "
                    "An encrypted backup contains more traces; in that case enter the backup password here.")
            return
        path = found[0]
    if not os.path.isfile(os.path.join(path, "Manifest.plist")):
        ctx.add(SKIP, area, "Folder is not an iPhone backup", f"{path}\nManifest.plist is missing.")
        return
    try:
        b = Backup(path, password)
    except PermissionError as e:
        ctx.add(SKIP, area, "Encrypted backup", str(e))
        return
    ctx.scope = "iphone-" + os.path.basename(os.path.normpath(path))
    info = b.info
    ver = info.get("Product Version", "?")
    ctx.add(INFO, area, f"{info.get('Device Name','iPhone')} – {info.get('Product Type','?')}, iOS {ver}",
            f"Backup: {path}\nCreated: {info.get('Last Backup Date','?')}\nEncrypted: {'yes' if b.encrypted else 'no'}")
    ctx.meta["iphone"] = f"{info.get('Product Type','?')} iOS {ver}"
    try:
        if int(str(ver).split(".")[0]) < 17:
            ctx.add(WARN, area, f"iOS {ver} is out of date", "Older versions have known flaws that spyware exploits. Please update.")
    except ValueError:
        pass
    if not b.encrypted:
        ctx.add(INFO, area, "Unencrypted backup – some traces are missing",
                "Encrypted backups contain more data (e.g. health and system data). For a more thorough check, enable "
                "“Encrypt local backup” in iTunes/Finder and enter the password here.")
    apps = list((b.manifest.get("Applications") or {}).keys())
    baseline.seen(ctx, "apps")
    for app in apps:
        baseline.note(ctx, "apps", app)
    if ctx.ioc:
        for app in apps:
            hit = ctx.ioc.get("app_id", app)
            if hit:
                ctx.add(HIT, area, f"Known spyware app: {app}", f"Attributed to: {hit[1]}", source=hit[0])
    rows = b.files()
    ctx.add(OK, area, f"{count(len(rows), 'file')} in the backup, {count(len(apps), 'app')}")
    by_rel = {}
    for fid, dom, rel in rows:
        by_rel.setdefault(rel, []).append((fid, dom))
        if ctx.ioc and rel:
            full = "/private/var/mobile/" + rel if dom == "HomeDomain" else "/private/var/" + rel
            for cand in (full, "/" + rel):
                hit = ctx.ioc.get("file_path", cand)
                if hit:
                    ctx.add(HIT, area, f"Spyware file in the backup: {cand}", f"Attributed to: {hit[1]}", source=hit[0])
            hit = ctx.ioc.get("file_name", os.path.basename(rel))
            if hit:
                ctx.add(HIT, area, f"File with a spyware name: {rel}", f"Domain: {dom}\nAttributed to: {hit[1]}", source=hit[0])
            if "ConfigurationProfiles" in rel:
                for pid in ctx.ioc.data["profile_id"]:
                    if pid in rel:
                        ctx.add(HIT, area, f"Spyware profile: {pid}", rel, source=ctx.ioc.data["profile_id"][pid][0])

    from .common import match_urls

    def each(suffix):
        for rel, lst in by_rel.items():
            if rel.endswith(suffix):
                for fid, dom in lst:
                    p = b.extract(fid, dom, rel)
                    if p:
                        yield p

    for p in each("Library/Safari/History.db"):
        n = match_urls(ctx, area, _sql(p, "SELECT url, 0 FROM history_items"), "Safari history")
        ctx.add(OK, area, f"Safari: {count(n, 'address', 'addresses')} checked")
    for p in each("Library/SMS/sms.db"):
        texts = [r[0] or "" for r in _sql(p, "SELECT text FROM message")]
        urls = [(u, "") for t in texts for u in URL_RE.findall(t)]
        n = match_urls(ctx, area, urls, "Links in SMS/iMessage (typical Pegasus infection route)")
        if ctx.ioc:
            for (h,) in _sql(p, "SELECT id FROM handle"):
                hit = ctx.ioc.get("email", h or "")
                if hit:
                    ctx.add(HIT, area, f"Message from a known spyware address: {h}", f"Attributed to: {hit[1]}", source=hit[0])
        ctx.add(OK, area, f"SMS/iMessage: {count(len(texts), 'message')}, {count(n, 'link')} checked")
    for p in each("ChatStorage.sqlite"):
        try:
            texts = [r[0] or "" for r in _sql(p, "SELECT ZTEXT FROM ZWAMESSAGE")]
            urls = [(u, "") for t in texts for u in URL_RE.findall(t)]
            n = match_urls(ctx, area, urls, "Links in WhatsApp")
            ctx.add(OK, area, f"WhatsApp: {count(n, 'link')} checked")
        except sqlite3.Error:
            pass
    procs = set()
    for suffix in ("DataUsage.sqlite", "netusage.sqlite"):
        for p in each(suffix):
            try:
                for name, bundle in _sql(p, "SELECT ZPROCNAME, ZBUNDLENAME FROM ZPROCESS"):
                    procs.add(name or "")
                    procs.add(bundle or "")
            except sqlite3.Error:
                continue
    if procs:
        hits = 0
        for n in procs:
            hit = ctx.ioc.get("process", n) if ctx.ioc and n else None
            if hit:
                hits += 1
                ctx.add(HIT, area, f"Process trace of a spyware: {n}",
                        f"According to the data usage log, this process transferred data.\nAttributed to: {hit[1]}", source=hit[0])
        ctx.add(OK, area, f"{count(len(procs), 'process name')} from data usage logs checked")
    for p in each("Media/PhotoData/Photos.sqlite"):
        for table in ("ZASSET", "ZGENERICASSET"):
            try:
                hidden = _sql(p, f"SELECT COUNT(*) FROM {table} WHERE ZHIDDEN=1")[0][0]
                trashed = _sql(p, f"SELECT COUNT(*) FROM {table} WHERE ZTRASHEDSTATE=1")[0][0]
                total = _sql(p, f"SELECT COUNT(*) FROM {table}")[0][0]
                ctx.add(INFO, "Hidden images", f"iPhone: {count(hidden, 'hidden photo')} and {trashed} in “Recently Deleted”",
                        f"Out of {total} photos and videos in total. Hidden ones are in the “Hidden” album; deleted ones stay "
                        "available for about 30 days.")
                break
            except sqlite3.Error:
                continue
    # VPN and network extension configurations (VPN apps, content filters, DNS proxies)
    ne = []
    for p in each("com.apple.networkextension.plist"):
        ne += [s for s in _plist_strings(p) if BUNDLE_RE.match(s) and not s.startswith("com.apple.")]
    ne = sorted(set(ne))
    baseline.seen(ctx, "extensions")
    for bundle in ne:
        baseline.note(ctx, "extensions", bundle)
    if ne:
        for bundle in ne:
            hit = ctx.ioc.get("app_id", bundle) if ctx.ioc else None
            if hit:
                ctx.add(HIT, net.AREA_VPN, f"VPN/network extension of a known spyware: {bundle}", f"Attributed to: {hit[1]}", source=hit[0])
        ctx.add(INFO, net.AREA_VPN, f"{count(len(ne), 'app')} with VPN or network extension configuration on the iPhone",
                "These apps may route, filter or inspect the iPhone's internet traffic (VPN, content filter, DNS proxy). "
                "Check that you set each one up yourself:\n" + "\n".join(ne) +
                "\n\nOn the iPhone: Settings › General › VPN & Device Management")
    elif any(rel.endswith("com.apple.networkextension.plist") for rel in by_rel):
        ctx.add(OK, net.AREA_VPN, "No third-party VPN or network extension configured on the iPhone")
    profs = [rel for rel in by_rel if "ConfigurationProfiles" in rel and rel.endswith(".stub")]
    baseline.seen(ctx, "profiles")
    for p in profs:
        baseline.note(ctx, "profiles", p)
    if profs:
        ctx.add(WARN, area, f"{count(len(profs), 'configuration profile')} in the backup",
                "Profiles can redirect traffic (VPN, proxy), install certificates or manage the device:\n" + "\n".join(profs[:30]) +
                "\n\nCheck on the iPhone: Settings › General › VPN & Device Management")
    for f in glob.glob(os.path.join(tmp_dir(), "ios_*")):
        try:
            os.remove(f)
        except OSError:
            pass


def check_ssh(ctx, host, user="root", port=22):
    """Jailbreak: direct check over SSH (key-based login required, e.g. ssh-copy-id root@IP)."""
    area = "iPhone (root/SSH)"
    if not re.match(r"^[A-Za-z0-9.:-]{1,253}$", host or "") or not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", user or "") \
            or not 0 < int(port) < 65536:
        ctx.add(SKIP, area, "Invalid address, user name or port", f"{host!r} {user!r} {port!r}")
        return
    base = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new", "-p", str(port), f"{user}@{host}"]
    rc, out, err = run(base + ["echo SCS_OK; uname -a"], timeout=20)
    if "SCS_OK" not in out:
        ctx.add(SKIP, area, "SSH connection failed",
                f"{err.strip()[:300]}\n\nRequirements: jailbreak with OpenSSH, the same Wi-Fi network, key-based login "
                f"(once: ssh-copy-id {user}@{host}). If the PC or the iPhone uses a VPN, the two devices may not see each other – "
                "pause the VPN for the check or use the VPN's local network option.")
        return
    ctx.add(INFO, area, "Connected", out.replace("SCS_OK", "").strip())
    rc, out, _ = run(base + ["ps -A -o comm 2>/dev/null || ps -A"], timeout=60)
    names = {os.path.basename(ln.strip()) for ln in out.splitlines() if ln.strip()}
    hits = 0
    for n in names:
        hit = ctx.ioc.get("process", n) if ctx.ioc else None
        if hit:
            hits += 1
            ctx.add(HIT, area, f"Running spyware process: {n}", f"Attributed to: {hit[1]}", source=hit[0])
    if ctx.ioc:
        paths = [p for p in ctx.ioc.data["file_path"] if p.startswith(("/private/", "/var/", "/Library/", "/usr/", "/System/")) and '"' not in p]
        script = "; ".join(f'[ -e "{p}" ] && echo "{p}"' for p in paths[:500])
        rc, out, _ = run(base + [script], timeout=120)
        for p in [ln.strip() for ln in out.splitlines() if ln.strip()]:
            if p in ctx.ioc.data["file_path"]:
                hits += 1
                ctx.add(HIT, area, f"Spyware file on the iPhone: {p}", f"Attributed to: {ctx.ioc.data['file_path'][p][1]}",
                        source=ctx.ioc.data["file_path"][p][0])
    ctx.add(OK, area, f"{count(len(names), 'process', 'processes')} and the indicator paths checked" + (f", {count(hits, 'hit')}" if hits else ""))
