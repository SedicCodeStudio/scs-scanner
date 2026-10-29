"""Android check over USB (ADB) – modelled on MVT/androidqf, but with its own code.

Without root: apps, install source, permissions, accessibility services, device admins, hidden icons,
VPN apps / always-on VPN / proxy / private DNS, processes, indicator matching (package name, APK hash,
signing certificate), hidden media folders.
With root (su on the device): additionally trusted ADB keys, user-installed CA certificates, system paths,
Chrome history, SMS links.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import struct
import time
import zipfile

from . import baseline, net
from .core import count, HIT, HOME, INFO, OK, SKIP, WARN, os_name, run, tmp_dir

STORES = {"com.android.vending", "com.google.android.feedback", "com.amazon.venezia", "com.sec.android.app.samsungapps",
          "com.huawei.appmarket", "com.xiaomi.market", "com.xiaomi.mipicks", "com.heytap.market", "com.oppo.market",
          "com.bbk.appstore", "org.fdroid.fdroid", "com.aurora.store", "com.google.android.apps.work.clouddpc",
          "com.android.shell", "com.miui.packageinstaller"}
VAULT_HINT = re.compile(r"vault|hide(app|photo|pic)|privatephoto|calculator.*(lock|vault|hide)|gallery.?lock|keepsafe|com\.kii\.safe|"
                        r"photo.?lock|secret.?(photo|gallery)|applock", re.I)
DANGER = ["READ_SMS", "RECEIVE_SMS", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "READ_CALL_LOG",
          "CAMERA", "READ_CONTACTS", "READ_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE", "SYSTEM_ALERT_WINDOW",
          "BIND_ACCESSIBILITY_SERVICE", "BIND_NOTIFICATION_LISTENER_SERVICE", "BIND_DEVICE_ADMIN", "PACKAGE_USAGE_STATS",
          "READ_PHONE_STATE", "PROCESS_OUTGOING_CALLS", "REQUEST_INSTALL_PACKAGES", "BIND_VPN_SERVICE"]
SYSTEM_PREFIX = ("com.google.", "com.android.", "com.samsung.", "com.sec.")
SERIAL_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
PKG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
APK_PATH_RE = re.compile(r"^/[A-Za-z0-9_./=~+-]+\.apk$")


def find_adb(custom=None):
    cands = [custom] if custom else []
    w = shutil.which("adb")
    if w:
        cands.append(w)
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    exe = "adb.exe" if os_name() == "windows" else "adb"
    cands += [os.path.join(here, "platform-tools", exe),
              os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk", "platform-tools", exe),
              os.path.join(HOME, "Library", "Android", "sdk", "platform-tools", exe),
              os.path.join(HOME, "Android", "Sdk", "platform-tools", exe),
              os.path.join(HOME, "platform-tools", exe), os.path.join(HOME, "Downloads", "platform-tools", exe)]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


class ADB:
    def __init__(self, adb, serial=None):
        self.adb, self.serial = adb, serial

    def _base(self):
        return [self.adb] + (["-s", self.serial] if self.serial else [])

    def devices(self):
        rc, out, _ = run([self.adb, "devices", "-l"], timeout=20)
        devs = []
        for ln in out.splitlines()[1:]:
            parts = ln.split()
            if len(parts) >= 2:
                devs.append((parts[0], parts[1], " ".join(parts[2:])))
        return devs

    def sh(self, cmd, timeout=90):
        rc, out, err = run(self._base() + ["shell", cmd], timeout=timeout)
        return out if rc == 0 or out else ""

    def su(self, cmd, timeout=90):
        out = self.sh(f"su -c '{cmd}'", timeout)
        if not out.strip():
            out = self.sh(f"su 0 sh -c '{cmd}'", timeout)
        return out

    def pull(self, remote, local, timeout=300):
        rc, out, err = run(self._base() + ["pull", remote, local], timeout=timeout)
        return rc == 0 and os.path.exists(local)


# --------------------------------------------------------------- APK signing certificate (v2/v3 and v1)
def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _lp(b, o):
    n = _u32(b, o)
    return b[o + 4:o + 4 + n], o + 4 + n


def _cert_v2(path):
    with open(path, "rb") as fh:
        data = fh.read()
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        return None
    cd_off = _u32(data, eocd + 16)
    if data[cd_off - 16:cd_off] != b"APK Sig Block 42":
        return None
    size = struct.unpack_from("<Q", data, cd_off - 24)[0]
    start = cd_off - size - 8
    o = start + 8
    while o < cd_off - 24:
        ln = struct.unpack_from("<Q", data, o)[0]
        bid = _u32(data, o + 8)
        val = data[o + 12:o + 8 + ln]
        o += 8 + ln
        if bid in (0x7109871A, 0xF05368C0, 0x1B93AD61):
            signers, _ = _lp(val, 0)
            signer, _ = _lp(signers, 0)
            signed, _ = _lp(signer, 0)
            _, p = _lp(signed, 0)          # digests
            certs, _ = _lp(signed, p)      # certificates
            cert, _ = _lp(certs, 0)
            return cert
    return None


def _tlv(b, o):
    tag = b[o]
    ln = b[o + 1]
    o2 = o + 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[o2:o2 + n], "big")
        o2 += n
    return tag, o2, o2 + ln  # tag, content start, end


def _children(b, s, e):
    out = []
    while s < e:
        t, cs, ce = _tlv(b, s)
        out.append((t, cs, ce, s))
        s = ce
    return out


def _cert_v1(path):
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist() if re.match(r"META-INF/[^/]+\.(RSA|DSA|EC)$", n, re.I)]
        if not names:
            return None
        b = z.read(names[0])
    t, cs, ce = _tlv(b, 0)                       # ContentInfo
    kids = _children(b, cs, ce)
    t, cs, ce, _ = kids[1]                       # [0] EXPLICIT
    t, cs, ce = _tlv(b, cs)                      # SignedData SEQUENCE
    for t, s, _e, _start in _children(b, cs, ce):
        if t == 0xA0:                            # certificates [0] IMPLICIT
            t2, s2, e2 = _tlv(b, s)
            return b[s:e2]
    return None


def apk_cert_hashes(path):
    cert = None
    try:
        cert = _cert_v2(path)
    except Exception:
        cert = None
    if not cert:
        try:
            cert = _cert_v1(path)
        except Exception:
            cert = None
    if not cert:
        return None, None
    # The signing certificate is public. SHA-1 only serves to compare it with indicator lists that publish
    # certificate SHA-1 fingerprints (stalkerware indicators) - it protects nothing.
    return hashlib.sha1(cert, usedforsecurity=False).hexdigest(), hashlib.sha256(cert).hexdigest()


# --------------------------------------------------------------- check
def _comp_pkgs(val):
    return {c.split("/")[0] for c in re.split(r"[:\s]", val or "") if "/" in c}


def _setting(a, ns, key):
    v = a.sh(f"settings get {ns} {key}").strip()
    return "" if v in ("null", "") else v


def uninstall(adb_path, serial, pkg):
    if not PKG_RE.match(pkg or "") or not SERIAL_RE.match(serial or ""):
        raise ValueError("Invalid package name or serial number.")
    a = ADB(adb_path, serial)
    out = a.sh(f"pm uninstall --user 0 {pkg}")
    if "Success" not in out:
        raise RuntimeError(out.strip() or "Uninstall failed. Is the app a device administrator? If so, deactivate it first "
                           "under Settings › Security › Device admin apps.")
    return out.strip()


def check(ctx, serial=None, adb_path=None):
    area = "Android"
    adb = find_adb(adb_path)
    if not adb:
        ctx.add(SKIP, area, "ADB not found",
                "1. Download “SDK Platform-Tools” from developer.android.com and unpack the platform-tools folder next to scs.py.\n"
                "2. On the phone: Settings › About phone › tap “Build number” 7 times, then Developer options › USB debugging on.\n"
                "3. Connect the phone via USB and confirm the “Allow USB debugging?” prompt.")
        return
    a = ADB(adb)
    devs = [d for d in a.devices() if d[1] == "device"]
    unauth = [d for d in a.devices() if d[1] == "unauthorized"]
    if not devs:
        ctx.add(SKIP, area, "No authorised Android device connected",
                ("Confirm the “Allow USB debugging?” prompt on the phone." if unauth else
                 "Connect the phone via USB and enable USB debugging."))
        return
    a.serial = serial or devs[0][0]
    if not SERIAL_RE.match(a.serial):
        ctx.add(SKIP, area, "Unusual device serial number – check aborted", a.serial[:80])
        return
    ctx.android = {"adb": adb, "serial": a.serial}
    ctx.scope = f"android-{a.serial}"

    # Device info
    props = dict(re.findall(r"\[([^\]]+)\]: \[([^\]]*)\]", a.sh("getprop")))
    model = f"{props.get('ro.product.manufacturer','?')} {props.get('ro.product.model','?')}"
    patch = props.get("ro.build.version.security_patch", "")
    ctx.add(INFO, area, f"Device: {model}, Android {props.get('ro.build.version.release','?')}",
            f"Serial number: {a.serial}\nSecurity patch level: {patch or '?'}\nBuild: {props.get('ro.build.fingerprint','?')}")
    ctx.meta["android"] = model
    if patch and patch < time.strftime("%Y-%m-%d", time.localtime(time.time() - 200 * 86400)):
        ctx.add(WARN, area, f"Security patch level is out of date ({patch})",
                "Old devices can be attacked through known flaws. Install updates or replace the device.")
    if props.get("ro.boot.verifiedbootstate") in ("orange", "yellow") or props.get("ro.boot.flash.locked") == "0":
        ctx.add(WARN, area, "Bootloader unlocked", "An unlocked bootloader allows a modified system to be installed. "
                "If this was not intentional, reset the device to factory settings.")
    if ctx.ioc:
        for prop, (feed, mal) in ctx.ioc.data["android_prop"].items():
            if prop in props:
                ctx.add(HIT, area, f"System property of a spyware is set: {prop}", f"Attributed to: {mal}", source=feed)

    # Apps
    raw = a.sh("pm list packages -f -i -U --user 0") or a.sh("pm list packages -f -i")
    third = set(re.findall(r"package:(\S+)", a.sh("pm list packages -3")))
    apps = {}
    for ln in raw.splitlines():
        m = re.match(r"package:(.+)=([\w.]+)\s+installer=(\S*)", ln.strip())
        if m:
            apps[m.group(2)] = {"apk": m.group(1), "installer": m.group(3) if m.group(3) not in ("null", "") else None}
    if not apps:
        for p in re.findall(r"package:(\S+)", a.sh("pm list packages")):
            apps[p] = {"apk": "", "installer": None}
    launch = set(re.findall(r"^([\w.]+)/", a.sh("cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER"), re.M))
    acc = _comp_pkgs(a.sh("settings get secure enabled_accessibility_services"))
    notif = _comp_pkgs(a.sh("settings get secure enabled_notification_listeners"))
    dp = a.sh("dumpsys device_policy")
    admins = set(re.findall(r"ComponentInfo\{([\w.]+)/", dp))
    owner = re.findall(r"(Device Owner|Profile Owner)[^\n]*\n[^\n]*?package=([\w.]+)", dp)

    baseline.seen(ctx, "apps")
    for pkg in apps:
        if pkg in third or not third:
            baseline.note(ctx, "apps", pkg)
    baseline.seen(ctx, "accessibility")
    baseline.seen(ctx, "admins")
    for p in acc:
        baseline.note(ctx, "accessibility", p)
    for p in admins:
        baseline.note(ctx, "admins", p)

    def uninstall_action(pkg):
        return {"type": "adb_uninstall", "adb": adb, "serial": a.serial, "pkg": pkg}

    sideloaded = []
    for pkg, info in sorted(apps.items()):
        is_third = pkg in third or not third
        hit = ctx.ioc.get("app_id", pkg) if ctx.ioc else None
        if hit:
            ctx.add(HIT, area, f"Known spyware/stalkerware app: {pkg}", f"Attributed to: {hit[1]}\nAPK: {info['apk']}",
                    source=hit[0], action=uninstall_action(pkg))
            continue
        if is_third and info["installer"] not in STORES:
            sideloaded.append(pkg)
        if VAULT_HINT.search(pkg):
            ctx.add(INFO, area, f"Vault or hiding app installed: {pkg}",
                    "Such apps hide photos and files behind a harmless-looking interface.")
    if sideloaded:
        ctx.add(WARN, area, f"{count(len(sideloaded), 'app')} from unknown sources (not from an app store)",
                "Stalkerware is almost always installed this way. You should recognise every one of these apps:\n" + "\n".join(
                    f"{p}   (installer: {apps[p]['installer'] or 'unknown/manual'})" for p in sideloaded))
    hidden = [p for p in (third or apps) if launch and p not in launch and not p.startswith(("com.google.", "com.android.", "com.samsung."))]
    if hidden:
        ctx.add(WARN, area, f"{count(len(hidden), 'app')} without an icon in the app drawer",
                "Stalkerware hides its icon. Keyboards, widgets and background services are often harmless:\n" + "\n".join(hidden[:60]))
    for title, pkgs, why in (("Accessibility services", acc, "can read everything on the screen and trigger input"),
                             ("Notification access", notif, "can read all notifications"),
                             ("Device administrator", admins, "cannot easily be uninstalled")):
        odd = [p for p in pkgs if not p.startswith(SYSTEM_PREFIX)]
        bad = [p for p in odd if p in sideloaded or (ctx.ioc and ctx.ioc.get("app_id", p))]
        if bad:
            ctx.add(WARN, area, f"{title}: {count(len(bad), 'app')} from unknown sources with this permission",
                    f"These apps {why} – typical of stalkerware:\n" + "\n".join(bad))
        rest = [p for p in odd if p not in bad]
        if rest:
            ctx.add(INFO, area, f"{title}: {count(len(rest), 'store app')} with this permission",
                    f"These apps {why}. Check that this is what you want:\n" + "\n".join(rest))
    for kind, pkg in owner:
        ctx.add(WARN, area, f"{kind} set: {pkg}", "The device is controlled by a management app (work phone?).")

    # VPN, proxy, private DNS
    _check_vpn(ctx, a, apps, sideloaded, uninstall_action)

    # Permissions and fingerprints of third-party apps
    check_list = sideloaded if not ctx.full else sorted(third or apps)
    for pkg in check_list[:120]:
        if ctx.cancel:
            return
        apk = apps[pkg]["apk"]
        if not apk:
            lines = a.sh(f"pm path {pkg}").replace("package:", "").split()
            apk = lines[0] if lines else ""
        if not apk or not APK_PATH_RE.match(apk):
            continue
        h = a.sh(f"sha256sum '{apk}'").split(" ")[0].strip().lower()
        hit = ctx.ioc.get("sha256", h) if ctx.ioc and len(h) == 64 else None
        if hit:
            ctx.add(HIT, area, f"APK fingerprint matches malware: {pkg}", f"SHA-256: {h}\nAttributed to: {hit[1]}",
                    source=hit[0], action=uninstall_action(pkg))
        if pkg in sideloaded or ctx.full:
            local = os.path.join(tmp_dir(), f"{pkg}.apk")
            if a.pull(apk, local):
                try:
                    s1, s256 = apk_cert_hashes(local)
                    for typ, val in (("cert_sha1", s1), ("cert_sha256", s256)):
                        hit = ctx.ioc.get(typ, val) if ctx.ioc and val else None
                        if hit:
                            ctx.add(HIT, area, f"Signing certificate of a spyware: {pkg}", f"{typ}: {val}\nAttributed to: {hit[1]}",
                                    source=hit[0], action=uninstall_action(pkg))
                finally:
                    try:
                        os.remove(local)
                    except OSError:
                        pass
        if pkg in sideloaded:
            dump = a.sh(f"dumpsys package {pkg}", timeout=60)
            granted = [d for d in DANGER if re.search(rf"android\.permission\.{d}: granted=true", dump)]
            if granted:
                ctx.add(INFO, area, f"Permissions of {pkg}", "Sensitive permissions granted:\n" + "\n".join(granted))

    # Processes
    ps_out = a.sh("ps -A -o NAME") or a.sh("ps")
    names = {ln.split()[-1] for ln in ps_out.splitlines()[1:] if ln.split()}
    if ctx.ioc:
        for n in names:
            hit = ctx.ioc.get("process", n)
            if hit:
                ctx.add(HIT, area, f"Process matches spyware: {n}", f"Attributed to: {hit[1]}", source=hit[0])

    # Hidden media
    nomedia = [ln.strip() for ln in a.sh("find /sdcard/ -name .nomedia 2>/dev/null", timeout=120).splitlines() if ln.strip()]
    nomedia = [p for p in nomedia if "/Android/data/" not in p]
    if nomedia:
        ctx.add(INFO, area, f"{count(len(nomedia), 'folder')} hidden from the gallery (.nomedia)",
                "The contents of these folders do not appear in the gallery:\n" + "\n".join(os.path.dirname(p) for p in nomedia[:60]))
    thumbs = a.sh("du -sh /sdcard/DCIM/.thumbnails 2>/dev/null").split()
    if thumbs:
        ctx.add(INFO, area, f"Thumbnail cache: {thumbs[0]}", "/sdcard/DCIM/.thumbnails – often contains previews of deleted photos.")
    trash = a.sh("ls -d /sdcard/.Trash* /sdcard/DCIM/.trash* /sdcard/Android/.Trash 2>/dev/null").split()
    if trash:
        ctx.add(INFO, area, "Gallery trash folders found", "\n".join(trash))

    # Indicator paths (without root only the reachable ones)
    root = False
    if ctx.root_mode:
        root = "uid=0" in a.su("id")
        if not root:
            ctx.add(SKIP, area, "Root mode selected, but no root access",
                    "Allow “su” on the device (Magisk/KernelSU: grant shell access) and check again.")
    if ctx.ioc:
        paths = [p for p in ctx.ioc.data["file_path"] if p.startswith(("/data/", "/sdcard/", "/storage/", "/system/"))]
        if paths:
            script = "; ".join(f'[ -e "{p}" ] && echo "{p}"' for p in paths[:400] if '"' not in p and "'" not in p)
            out = a.su(script) if root else a.sh(script)
            for p in [ln.strip() for ln in out.splitlines() if ln.strip()]:
                if p in ctx.ioc.data["file_path"]:
                    feed, mal = ctx.ioc.data["file_path"][p]
                    ctx.add(HIT, area, f"Spyware file on the device: {p}", f"Attributed to: {mal}", source=feed)
    if root:
        _root_checks(ctx, a)
    ctx.add(OK, area, f"{count(len(apps), 'app')} and {count(len(names), 'process', 'processes')} checked" + (" (with root)" if root else ""))


def _check_vpn(ctx, a, apps, sideloaded, uninstall_action):
    """VPN apps, always-on VPN, active tunnels, global proxy and private DNS on the phone."""
    vpn_apps = set(re.findall(r"^([\w.]+)/", a.sh("cmd package query-services --brief -a android.net.VpnService"), re.M))
    always_on = _setting(a, "secure", "always_on_vpn_app")
    lockdown = _setting(a, "secure", "always_on_vpn_lockdown") == "1"
    ifaces = a.sh("ls /sys/class/net").split()
    if not ifaces:
        ifaces = re.findall(r"^\d+:\s*([\w.-]+)[:@]", a.sh("ip -o link"), re.M)
    tunnels = [i for i in ifaces if re.match(r"^(tun|ppp|wg|ipsec|tap)", i)]
    configured = []
    for pkg in sorted(vpn_apps | ({always_on} if always_on else set())):
        src = "unknown source" if pkg in sideloaded else "app store or system"
        configured.append(f"VPN app: {pkg} ({src})" + (" – set as always-on VPN" if pkg == always_on else ""))
        if pkg in sideloaded:
            ctx.add(WARN, net.AREA_VPN, f"VPN app from an unknown source: {pkg}",
                    "A VPN app can see, log and redirect all internet traffic of the phone. Stalkerware sometimes uses its own "
                    "VPN to intercept data. If you did not install it yourself, remove it.", action=uninstall_action(pkg))
    if always_on:
        ctx.add(INFO if always_on not in sideloaded else WARN, net.AREA_VPN, f"Always-on VPN is set: {always_on}",
                "All traffic of the phone always goes through this VPN" +
                (" and is blocked without it (lockdown mode)." if lockdown else ".") +
                " Settings › Network & internet › VPN.")
    active = [f"{t} on the phone" + (f" (probably {always_on})" if always_on else "") for t in tunnels]
    net.report_vpn(ctx, active, configured)

    proxies = []
    for key, label in (("http_proxy", "Global HTTP proxy"), ("global_http_proxy_host", "Managed global proxy")):
        v = _setting(a, "global", key)
        if v and v != ":0":
            if key == "global_http_proxy_host":
                v += ":" + (_setting(a, "global", "global_http_proxy_port") or "")
            proxies.append((label, v))
    net.judge_proxy(ctx, proxies)

    mode = _setting(a, "global", "private_dns_mode") or "off"
    spec = _setting(a, "global", "private_dns_specifier")
    if mode == "hostname" and spec:
        m = ctx.ioc.match_domain(spec) if ctx.ioc else None
        if m:
            ctx.add(HIT, net.AREA_DNS, f"Private DNS points to a known spyware address: {spec}", f"Attributed to: {m[1][1]}", source=m[1][0])
        else:
            ctx.add(INFO, net.AREA_DNS, f"Private DNS: {spec}",
                    "All name lookups of the phone go encrypted to this server. Check that you set this up yourself "
                    "(Settings › Network & internet › Private DNS).")
    else:
        ctx.add(OK, net.AREA_DNS, f"Private DNS: {mode} (no custom server)")


def _pull_root(a, remote, name):
    tmp = f"/sdcard/.scs_{name}"
    a.su(f'cp "{remote}" {tmp} && chmod 644 {tmp}')
    local = os.path.join(tmp_dir(), name)
    ok = a.pull(tmp, local)
    a.sh(f"rm -f {tmp}")
    return local if ok else None


def _root_checks(ctx, a):
    area = "Android (root)"
    keys = a.su("cat /data/misc/adb/adb_keys 2>/dev/null")
    if keys.strip():
        lines = [ln.split(" ", 1)[-1] for ln in keys.splitlines() if ln.strip()]
        ctx.add(WARN, area, f"{count(len(lines), 'computer')} {'is' if len(lines) == 1 else 'are'} allowed USB debugging access",
                "Unknown entries indicate access by someone else (MVT checks the same):\n" + "\n".join(lines) +
                "\n\nRemove them: Developer options › Revoke USB debugging authorisations")
    cas = [ln.strip() for ln in a.su("ls /data/misc/user/0/cacerts-added 2>/dev/null").splitlines() if ln.strip()]
    if cas:
        ctx.add(WARN, net.AREA_CERT, f"{count(len(cas), 'user-installed root certificate')} on the phone",
                "They allow the HTTPS traffic of apps that trust user certificates to be read – used by interception tools and "
                "some stalkerware:\n" + "\n".join(cas) +
                "\n\nCheck: Settings › Security › Encryption & credentials › Trusted credentials › User")
    mods = a.su("ls /data/adb/modules 2>/dev/null")
    if mods.strip():
        ctx.add(INFO, area, "Magisk/KernelSU modules installed", mods.strip())
    from .common import match_urls
    local = _pull_root(a, "/data/data/com.android.chrome/app_chrome/Default/History", "chrome_history.db")
    if local:
        try:
            import sqlite3
            con = sqlite3.connect(local)
            rows = con.execute("SELECT url, last_visit_time FROM urls LIMIT 300000").fetchall()
            con.close()
            n = match_urls(ctx, area, rows, "Chrome history on the phone")
            ctx.add(OK, area, f"Chrome history: {count(n, 'address', 'addresses')} checked")
        except Exception as e:  # noqa: BLE001
            ctx.add(SKIP, area, "Chrome history not readable", str(e))
        finally:
            os.remove(local)
    local = _pull_root(a, "/data/data/com.android.providers.telephony/databases/mmssms.db", "sms.db")
    if local:
        try:
            import sqlite3
            con = sqlite3.connect(local)
            bodies = [r[0] or "" for r in con.execute("SELECT body FROM sms").fetchall()]
            con.close()
            urls = [(u, "") for b in bodies for u in re.findall(r"(?:https?://)?[\w.-]+\.[a-z]{2,}(?:/\S*)?", b)]
            n = match_urls(ctx, area, urls, "Links in SMS (typical Pegasus/Predator infection route)")
            ctx.add(OK, area, f"SMS: {count(len(bodies), 'message')}, {count(n, 'link')} checked")
        except Exception as e:  # noqa: BLE001
            ctx.add(SKIP, area, "SMS database not readable", str(e))
        finally:
            os.remove(local)
    tmpf = a.su("ls -la /data/local/tmp 2>/dev/null")
    if len(tmpf.splitlines()) > 3:
        ctx.add(INFO, area, "Contents of /data/local/tmp", "Exploits and spyware often drop files here:\n" + tmpf.strip()[:3000])
