"""macOS checks: launch agents/daemons, configuration profiles (MDM), protection features, VPN/proxy/DNS,
processes, network.

Many areas need "Full Disk Access" (granted by the user) or root (sudo)."""
from __future__ import annotations

import glob
import os
import plistlib
import re

from . import baseline, net
from .core import count, HIT, HOME, INFO, OK, SKIP, WARN, is_admin, run

SUSP = re.compile(r"(curl|wget)\s+[^|;]*\|\s*(ba|z)?sh|base64\s+(-d|--decode)|/dev/tcp/|osascript\s+-e|python[23]?\s+-c|/tmp/|/private/tmp/|/Users/Shared/", re.I)


def check_fda(ctx):
    test = os.path.join(HOME, "Library", "Application Support", "com.apple.TCC", "TCC.db")
    try:
        with open(test, "rb"):
            pass
        ctx.add(OK, "Permissions", "Full Disk Access is granted")
    except PermissionError:
        ctx.add(SKIP, "Permissions", "No Full Disk Access – Safari, Mail and system data remain unchecked",
                "How to grant it: System Settings › Privacy & Security › Full Disk Access › “+” › add Terminal "
                "(or Python), then restart the program.")
    except OSError:
        pass


def load_processes(ctx):
    rc, out, _ = run(["ps", "-axo", "pid=,comm="])
    procs = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        pid, _, path = ln.partition(" ")
        procs.append({"pid": pid, "path": path.strip(), "name": os.path.basename(path.strip())})
    ctx.processes = procs
    for p in procs:
        if p["path"].startswith(("/tmp/", "/private/tmp/", "/Users/Shared/")) or "/." in p["path"]:
            ctx.add(WARN, "Processes", f"Program running from an unusual location: {p['name']}", p["path"])


def check_launch(ctx):
    dirs = [os.path.join(HOME, "Library/LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"]
    n, flagged = 0, 0
    lines = []
    baseline.seen(ctx, "launch")
    for d in dirs:
        for f in glob.glob(os.path.join(d, "*.plist")):
            n += 1
            try:
                with open(f, "rb") as fh:
                    pl = plistlib.load(fh)
            except Exception:
                continue
            args = pl.get("ProgramArguments") or ([pl["Program"]] if pl.get("Program") else [])
            cmd = " ".join(str(a) for a in args)
            baseline.note(ctx, "launch", f"{os.path.basename(f)} → {cmd}")
            lines.append(f"{os.path.basename(f):50.50} {cmd[:110]}")
            exe = args[0] if args else ""
            reasons = []
            if SUSP.search(cmd):
                reasons.append("suspicious command")
            if exe and ("/." in exe or exe.startswith(("/tmp", "/private/tmp", "/Users/Shared"))):
                reasons.append("program is hidden or in a temp folder")
            if exe and not os.path.exists(exe) and exe.startswith("/"):
                reasons.append("target is missing")
            if ctx.full and exe and os.path.exists(exe) and not reasons:
                rc, _, err = run(["codesign", "-v", exe], timeout=30)
                if rc != 0:
                    reasons.append("program is not validly signed")
            if reasons:
                flagged += 1
                ctx.add(WARN, "Autostart", f"Suspicious launch item: {os.path.basename(f)}",
                        f"{f}\nCommand: {cmd}\nReason: {'; '.join(reasons)}", path=f, action={"type": "quarantine", "path": f})
    ctx.add(INFO if not flagged else WARN, "Autostart", f"{count(n, 'launch agent/daemon', 'launch agents/daemons')}, {flagged} suspicious", "\n".join(lines[:80]))
    rc, out, _ = run(["sfltool", "dumpbtm"], timeout=60) if is_admin() else (1, "", "")
    if rc == 0 and out:
        items = re.findall(r"Name:\s*(.+)\n.*?URL:\s*(.+)", out)
        if items:
            ctx.add(INFO, "Autostart", f"{count(len(items), 'background or login item')} (BTM)", "\n".join(f"{a.strip()}  {b.strip()}" for a, b in items[:80]))
    elif not is_admin():
        ctx.add(SKIP, "Autostart", "Login and background items not fully checkable", "Run with sudo to read the BTM database (sfltool dumpbtm).")


def check_profiles(ctx):
    rc, out, err = run(["profiles", "list"] if not is_admin() else ["profiles", "show", "-all"], timeout=60)
    if rc != 0 and not out:
        ctx.add(SKIP, "Profiles", "Configuration profiles not readable", (err or "").strip()[:300] + "\nRun with sudo.")
        return
    ids = re.findall(r"profileIdentifier:\s*(\S+)", out) + re.findall(r"attribute: profileIdentifier: (\S+)", out)
    baseline.seen(ctx, "profiles")
    for pid in ids:
        baseline.note(ctx, "profiles", pid)
    for pid in ids:
        hit = ctx.ioc.get("profile_id", pid) if ctx.ioc else None
        if hit:
            ctx.add(HIT, "Profiles", f"Known spyware profile: {pid}", f"Attributed to: {hit[1]}", source=hit[0])
    if ids:
        ctx.add(WARN, "Profiles", f"{count(len(ids), 'configuration profile')} installed",
                "Profiles can redirect traffic (VPN, proxy), install certificates or remote-control the device (MDM). "
                "Unusual on private devices:\n" + "\n".join(ids) + "\n\nCheck: System Settings › General › Device Management")
    else:
        ctx.add(OK, "Profiles", "No configuration profiles installed")


def check_protection(ctx):
    rc, out, _ = run(["csrutil", "status"])
    if "disabled" in out.lower():
        ctx.add(WARN, "Protection", "System Integrity Protection (SIP) is off", out.strip())
    elif out:
        ctx.add(OK, "Protection", "System Integrity Protection is on")
    rc, out, _ = run(["spctl", "--status"])
    if "disabled" in out.lower():
        ctx.add(WARN, "Protection", "Gatekeeper is off", "Programs from any source start without being checked.")
    elif out:
        ctx.add(OK, "Protection", "Gatekeeper is on")
    rc, out, _ = run(["fdesetup", "status"])
    if "off" in out.lower():
        ctx.add(INFO, "Protection", "FileVault (disk encryption) is off", "If the Mac is stolen, all files are readable.")


def check_routing(ctx):
    """VPN configurations and network extensions, proxy settings, DNS servers, custom-trusted root certificates."""
    active, configured = [], []
    rc, out, _ = run(["scutil", "--nc", "list"], timeout=20)
    for ln in out.splitlines():
        m = re.search(r"\((\w+)\).*?\"(.+?)\"", ln)
        if m:
            configured.append(f"VPN configuration: {m.group(2)} ({m.group(1)})")
            if m.group(1) == "Connected":
                active.append(m.group(2))
    rc, out, _ = run(["systemextensionsctl", "list"], timeout=20)
    for ln in out.splitlines():
        if "network_extension" in ln or "networkextension" in ln.lower():
            m = re.search(r"\s([\w.-]+\.[\w.-]+)\s+\(", ln)
            bundle = m.group(1) if m else ln.strip()[:80]
            configured.append(f"Network extension: {bundle} {'(active)' if 'activated enabled' in ln else ''}".strip())
            hit = ctx.ioc.get("app_id", bundle) if ctx.ioc and m else None
            if hit:
                ctx.add(HIT, net.AREA_VPN, f"Network extension of a known spyware: {bundle}", f"Attributed to: {hit[1]}", source=hit[0])
    net.report_vpn(ctx, active, configured,
                   "Network extensions (VPNs, content filters) can read or block all traffic of the Mac.")

    proxies = []
    rc, out, _ = run(["scutil", "--proxy"], timeout=20)
    kv = dict(re.findall(r"^\s*(\w+)\s*:\s*(.+?)\s*$", out, re.M))
    for proto in ("HTTP", "HTTPS", "SOCKS"):
        if kv.get(f"{proto}Enable") == "1" and kv.get(f"{proto}Proxy"):
            proxies.append((f"{proto} proxy", f"{kv[f'{proto}Proxy']}:{kv.get(f'{proto}Port', '')}"))
    if kv.get("ProxyAutoConfigEnable") == "1" and kv.get("ProxyAutoConfigURLString"):
        proxies.append(("Proxy auto-config script (PAC)", kv["ProxyAutoConfigURLString"]))
    net.judge_proxy(ctx, proxies)

    rc, out, _ = run(["scutil", "--dns"], timeout=20)
    servers, iface = [], ""
    for ln in out.splitlines():
        m = re.search(r"if_index\s*:\s*\d+\s*\((\w+)\)", ln)
        if m:
            iface = m.group(1)
        m = re.search(r"nameserver\[\d+\]\s*:\s*(\S+)", ln)
        if m:
            servers.append((m.group(1), iface))
    net.judge_dns(ctx, servers)

    names = []
    for args, where in ((["security", "dump-trust-settings", "-d"], "admin trust settings"),
                        (["security", "dump-trust-settings"], "user trust settings")):
        rc, out, err = run(args, timeout=30)
        names += [(n.strip(), where) for n in re.findall(r"Cert \d+:\s*(.+)", out)]
    if names:
        ctx.add(INFO, net.AREA_CERT, f"{count(len(names), 'certificate')} with custom trust settings",
                "These certificates were marked as trusted by you, your company or a program:\n" +
                "\n".join(f"{n}  ({w})" for n, w in names[:40]))
    net.judge_certs(ctx, [n for n, _ in names], "macOS keychain trust settings")


def check_network(ctx):
    rc, out, _ = run(["netstat", "-an", "-p", "tcp"], timeout=30)
    ips = []
    for ln in out.splitlines():
        if "ESTABLISHED" in ln:
            parts = ln.split()
            if len(parts) >= 5:
                ips.append(parts[4].rsplit(".", 1)[0])
    from .common import check_remote_ips
    check_remote_ips(ctx, ips, "active TCP connections")


def run_checks(ctx):
    ctx.step("macOS: permissions", 20)
    ctx.section("Permissions", check_fda)
    ctx.step("macOS: processes", 25)
    ctx.section("Processes", load_processes)
    ctx.step("macOS: autostart", 32)
    ctx.section("Autostart", check_launch)
    ctx.step("macOS: profiles & protection", 38)
    ctx.section("Profiles", check_profiles)
    ctx.section("Protection", check_protection)
    ctx.step("macOS: VPN, proxy, DNS servers, certificates", 42)
    ctx.section("VPN", check_routing)
    ctx.section("Network", check_network)
