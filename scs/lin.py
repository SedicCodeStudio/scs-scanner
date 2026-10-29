"""Linux checks: processes, autostart (cron, systemd, XDG), rootkit tricks, VPN/proxy/DNS, network, SSH keys."""
from __future__ import annotations

import glob
import os
import re
import shutil
import socket
import struct
import time

from . import baseline, net
from .core import count, HOME, INFO, OK, WARN, is_admin, run

SUSP = re.compile(r"(curl|wget)\s+[^|;]*\|\s*(ba|z|da)?sh|base64\s+-d|/dev/tcp/|\bnc\s+-e|ncat\s+-e|mkfifo|python[23]?\s+-c\s+['\"]import\s+(socket|pty)|"
                  r"socat\s+exec|chmod\s+\+x\s+/tmp|/dev/shm/", re.I)
TMP = ("/tmp/", "/var/tmp/", "/dev/shm/")


def load_processes(ctx):
    procs = []
    for d in glob.glob("/proc/[0-9]*"):
        pid = d.rsplit("/", 1)[1]
        try:
            with open(f"{d}/comm") as fh:
                name = fh.read().strip()
            with open(f"{d}/cmdline", "rb") as fh:
                cmd = fh.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except OSError:
            continue
        try:
            exe = os.readlink(f"{d}/exe")
        except OSError:
            exe = ""
        procs.append({"pid": pid, "name": name, "path": exe.replace(" (deleted)", ""), "cmd": cmd, "deleted": exe.endswith(" (deleted)")})
    ctx.processes = procs
    for p in procs:
        if p["deleted"] and not p["path"].startswith(("/usr/", "/opt/", "/snap/")):
            ctx.add(WARN, "Processes", f"Process running from a deleted file: {p['name']} (PID {p['pid']})",
                    f"{p['path']}\nTypical of malware that deletes itself after starting. Save a copy: cp /proc/{p['pid']}/exe /tmp/sample")
        elif p["path"].startswith(TMP):
            ctx.add(WARN, "Processes", f"Program running from a temp folder: {p['name']}", p["path"], path=p["path"],
                    action={"type": "quarantine", "path": p["path"]})
        elif SUSP.search(p["cmd"]):
            ctx.add(WARN, "Processes", f"Suspicious command line: {p['name']} (PID {p['pid']})", p["cmd"][:1500])
    if not is_admin():
        ctx.add(INFO, "Processes", "Without root, the program paths of other users' processes are hidden",
                "For the full check: sudo python3 scs.py")


def _scan_text(ctx, area, path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            txt = fh.read(200000)
    except OSError:
        return 0
    bad = [ln.strip() for ln in txt.splitlines() if SUSP.search(ln) and not ln.strip().startswith("#")]
    if bad:
        ctx.add(WARN, area, f"Suspicious command in {path}", "\n".join(bad[:20]), action={"type": "open", "path": os.path.dirname(path)})
    return 1


def check_autostart(ctx):
    n = 0
    files = ["/etc/crontab", "/etc/rc.local", "/etc/profile", "/etc/bash.bashrc", "/etc/environment"]
    files += glob.glob("/etc/cron.*/*") + glob.glob("/etc/profile.d/*") + glob.glob("/var/spool/cron/*") + glob.glob("/var/spool/cron/crontabs/*")
    files += [os.path.join(HOME, f) for f in (".bashrc", ".bash_profile", ".profile", ".zshrc", ".bash_login", ".xprofile", ".xinitrc")]
    for f in files:
        if os.path.isfile(f):
            n += _scan_text(ctx, "Autostart", f)
    rc, out, _ = run(["crontab", "-l"])
    baseline.seen(ctx, "cron")
    if rc == 0:
        jobs = [ln for ln in out.splitlines() if ln.strip() and not ln.startswith("#")]
        for ln in jobs:
            baseline.note(ctx, "cron", ln)
        if jobs:
            ctx.add(INFO, "Autostart", f"{count(len(jobs), 'personal cron job')}", "\n".join(jobs[:40]))
        for ln in jobs:
            if SUSP.search(ln) or any(t in ln for t in TMP):
                ctx.add(WARN, "Autostart", "Suspicious cron job", ln)
    units = glob.glob(os.path.join(HOME, ".config/systemd/user/*.service")) + glob.glob("/etc/systemd/system/*.service") + \
        glob.glob("/etc/systemd/system/*/*.service")
    recent = []
    baseline.seen(ctx, "systemd")
    baseline.seen(ctx, "autostart")
    for u in units:
        n += 1
        try:
            txt = open(u, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        m = re.search(r"^ExecStart=(.+)$", txt, re.M)
        cmd = m.group(1) if m else ""
        baseline.note(ctx, "systemd", f"{u} → {cmd}")
        if SUSP.search(cmd) or any(t in cmd for t in TMP) or "/." in cmd:
            ctx.add(WARN, "Autostart", f"Suspicious systemd service: {os.path.basename(u)}", f"{u}\nExecStart={cmd}")
        try:
            if time.time() - os.path.getmtime(u) < 30 * 86400:
                recent.append(f"{time.strftime('%Y-%m-%d', time.localtime(os.path.getmtime(u)))}  {u}  →  {cmd[:120]}")
        except OSError:
            pass
    if recent:
        ctx.add(INFO, "Autostart", f"{count(len(recent), 'systemd service')} changed in the last 30 days", "\n".join(recent[:40]))
    for d in (os.path.join(HOME, ".config/autostart"), "/etc/xdg/autostart"):
        for f in glob.glob(os.path.join(d, "*.desktop")):
            n += 1
            txt = open(f, encoding="utf-8", errors="replace").read()
            m = re.search(r"^Exec=(.+)$", txt, re.M)
            baseline.note(ctx, "autostart", f"{os.path.basename(f)} = {m.group(1) if m else ''}")
            if m and (SUSP.search(m.group(1)) or any(t in m.group(1) for t in TMP) or "/." in m.group(1)):
                ctx.add(WARN, "Autostart", f"Suspicious desktop autostart: {os.path.basename(f)}", f"{f}\nExec={m.group(1)}")
    ctx.add(OK, "Autostart", f"{count(n, 'autostart source')} checked")


def check_rootkit(ctx):
    area = "Rootkit traces"
    p = "/etc/ld.so.preload"
    if os.path.exists(p):
        try:
            content = open(p).read().strip()
        except OSError:
            content = "(not readable)"
        if content:
            ctx.add(WARN, area, "/etc/ld.so.preload is set",
                    f"Content:\n{content}\n\nThis loads libraries into every program – a classic rootkit trick (e.g. Azazel, Jynx).")
    else:
        ctx.add(OK, area, "No ld.so.preload")
    try:
        t = int(open("/proc/sys/kernel/tainted").read().strip())
        if t & (1 << 12) or t & (1 << 13):
            ctx.add(INFO, area, "Kernel contains unsigned or out-of-tree modules", f"tainted={t}. Often harmless (e.g. NVIDIA, VirtualBox).")
    except (OSError, ValueError):
        pass
    if ctx.full and is_admin():
        odd = []
        for base in ("/tmp", "/var/tmp", "/dev/shm", "/home", "/opt", "/srv"):
            rc, out, _ = run(["find", base, "-xdev", "-perm", "-4000", "-type", "f"], timeout=300)
            odd += [ln for ln in out.splitlines() if ln.strip()]
        if odd:
            ctx.add(WARN, area, f"{count(len(odd), 'SUID program')} in unusual locations", "\n".join(odd[:50]))
    hidden = []
    for base in ("/tmp", "/var/tmp", "/dev/shm"):
        try:
            for e in os.scandir(base):
                if e.name.startswith(".") and e.name not in (".X11-unix", ".ICE-unix", ".XIM-unix", ".font-unix", ".Test-unix", ".X0-lock", ".X1-lock"):
                    hidden.append(e.path)
        except OSError:
            continue
    if hidden:
        ctx.add(WARN, area, f"{count(len(hidden), 'hidden entry', 'hidden entries')} in temp folders", "\n".join(hidden[:40]))


def check_routing(ctx):
    """VPN interfaces and NetworkManager VPNs, proxy settings, DNS servers, locally added root certificates."""
    active, configured = [], []
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if net.VPN_IFACE.search(name):
                try:
                    state = open(f"/sys/class/net/{name}/operstate").read().strip()
                except OSError:
                    state = "unknown"
                configured.append(f"Interface: {name} ({state})")
                if state in ("up", "unknown"):
                    active.append(name)
    except OSError:
        pass
    if shutil.which("nmcli"):
        rc, out, _ = run(["nmcli", "-t", "-f", "NAME,TYPE,ACTIVE", "connection", "show"], timeout=20)
        for ln in out.splitlines():
            parts = ln.rsplit(":", 2)
            if len(parts) == 3 and parts[1] in ("vpn", "wireguard"):
                configured.append(f"NetworkManager: {parts[0]} ({parts[1]}, active: {parts[2]})")
                if parts[2] == "yes":
                    active.append(parts[0])
    net.report_vpn(ctx, active, configured)

    proxies = []
    for var in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        if os.environ.get(var):
            proxies.append((f"Environment variable {var}", os.environ[var]))
    try:
        for ln in open("/etc/environment", encoding="utf-8", errors="replace"):
            m = re.match(r"\s*(https?_proxy|all_proxy)\s*=\s*[\"']?([^\"'\s]+)", ln, re.I)
            if m:
                proxies.append((f"/etc/environment {m.group(1)}", m.group(2)))
    except OSError:
        pass
    if shutil.which("gsettings"):
        rc, mode, _ = run(["gsettings", "get", "org.gnome.system.proxy", "mode"], timeout=10)
        mode = mode.strip().strip("'")
        if mode == "manual":
            rc, host, _ = run(["gsettings", "get", "org.gnome.system.proxy.http", "host"], timeout=10)
            rc, port, _ = run(["gsettings", "get", "org.gnome.system.proxy.http", "port"], timeout=10)
            proxies.append(("Desktop proxy (GNOME)", f"{host.strip().strip(chr(39))}:{port.strip()}"))
        elif mode == "auto":
            rc, url, _ = run(["gsettings", "get", "org.gnome.system.proxy", "autoconfig-url"], timeout=10)
            proxies.append(("Proxy auto-config script (GNOME)", url.strip().strip("'")))
    net.judge_proxy(ctx, [p for p in proxies if p[1]])

    servers = []
    try:
        for ln in open("/etc/resolv.conf", encoding="utf-8", errors="replace"):
            m = re.match(r"\s*nameserver\s+(\S+)", ln)
            if m:
                servers.append((m.group(1), "resolv.conf"))
    except OSError:
        pass
    if shutil.which("resolvectl"):
        rc, out, _ = run(["resolvectl", "dns"], timeout=15)
        for ln in out.splitlines():
            m = re.match(r"(Global|Link \d+ \(([^)]+)\)):\s*(.*)", ln.strip())
            if m:
                for ip in m.group(3).split():
                    servers.append((ip, m.group(2) or "global"))
    net.judge_dns(ctx, servers)

    certs = glob.glob("/usr/local/share/ca-certificates/**/*.crt", recursive=True) + glob.glob("/etc/pki/ca-trust/source/anchors/*")
    names = []
    for c in certs:
        subj = os.path.basename(c)
        if shutil.which("openssl"):
            rc, out, _ = run(["openssl", "x509", "-noout", "-subject", "-in", c], timeout=10)
            if rc == 0 and out.strip():
                subj = out.strip()
        names.append(subj)
    if names:
        ctx.add(INFO, net.AREA_CERT, f"{count(len(names), 'root certificate')} added locally",
                "These certificates were added to the system on purpose (by you, your company or a program):\n" + "\n".join(names[:40]))
    net.judge_certs(ctx, names, "locally added certificates (/usr/local/share/ca-certificates, /etc/pki/ca-trust)")


def _proc_net():
    out = []
    for fname, fam in (("/proc/net/tcp", socket.AF_INET), ("/proc/net/tcp6", socket.AF_INET6)):
        try:
            lines = open(fname).read().splitlines()[1:]
        except OSError:
            continue
        for ln in lines:
            parts = ln.split()
            if len(parts) < 4:
                continue
            rem, state = parts[2], parts[3]
            ip_hex, port = rem.split(":")
            try:
                if fam == socket.AF_INET:
                    ip = socket.inet_ntop(fam, struct.pack("<I", int(ip_hex, 16)))
                else:
                    raw = bytes.fromhex(ip_hex)
                    ip = socket.inet_ntop(fam, b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
                    if ip.startswith("::ffff:"):
                        ip = ip[7:]
            except (ValueError, OSError):
                continue
            out.append((ip, int(port, 16), state))
    return out


def check_network(ctx):
    conns = _proc_net()
    est = [ip for ip, port, st in conns if st == "01"]
    from .common import check_remote_ips
    check_remote_ips(ctx, est, "active TCP connections")


def check_ssh(ctx):
    keys = []
    for f in [os.path.join(HOME, ".ssh", "authorized_keys")] + (glob.glob("/root/.ssh/authorized_keys") + glob.glob("/home/*/.ssh/authorized_keys") if is_admin() else []):
        try:
            for ln in open(f):
                if ln.strip() and not ln.startswith("#"):
                    keys.append(f"{f}: …{ln.strip()[-60:]}")
        except OSError:
            continue
    if keys:
        ctx.add(INFO, "Remote access", f"{count(len(keys), 'authorised SSH key')}",
                "Anyone holding one of these keys can log in without a password. Remove unknown entries:\n" + "\n".join(keys))


def run_checks(ctx):
    ctx.step("Linux: processes", 25)
    ctx.section("Processes", load_processes)
    ctx.step("Linux: autostart", 32)
    ctx.section("Autostart", check_autostart)
    ctx.step("Linux: rootkit traces", 38)
    ctx.section("Rootkit traces", check_rootkit)
    ctx.step("Linux: VPN, proxy, DNS servers, certificates", 42)
    ctx.section("VPN", check_routing)
    ctx.section("Network", check_network)
    ctx.section("Remote access", check_ssh)
