"""Windows checks: autostart, scheduled tasks, services, processes, VPN/proxy/DNS, DNS history,
Defender, hidden data streams."""
from __future__ import annotations

import os
import re

from . import baseline, net
from .core import count, HOME, INFO, OK, SKIP, WARN, is_admin, ps, ps_json

SUSP_DIRS = re.compile(r"\\(appdata|temp|tmp|users\\public|programdata|downloads|\$recycle\.bin)\\", re.I)
SUSP_CMD = re.compile(
    r"(-enc(odedcommand)?\s|frombase64string|downloadstring|invoke-expression|\biex\b|mshta(\.exe)?\s+(http|javascript|vbscript)|"
    r"rundll32(\.exe)?\s+javascript|regsvr32.*/i:http|bitsadmin.*/transfer|certutil.*-urlcache|wscript.*\\appdata|"
    r"cscript.*\\appdata|powershell.*-w(indowstyle)?\s+hidden)", re.I)
MS_OK = re.compile(r"\\(microsoft|windows defender|windowsapps|onedrive|google\\update|mozilla maintenance)\\", re.I)


def _exe_from_cmd(cmd: str) -> str:
    if not cmd:
        return ""
    cmd = os.path.expandvars(cmd.strip())
    if cmd.startswith('"'):
        return cmd[1:].split('"', 1)[0]
    m = re.match(r"(.+?\.(exe|dll|bat|cmd|ps1|vbs|js|com|scr|lnk))\b", cmd, re.I)
    return m.group(1) if m else cmd.split(" ")[0]


def _judge(ctx, area, label, cmd, extra=""):
    """Rates an autostart entry and reports it if needed."""
    exe = _exe_from_cmd(cmd)
    reasons = []
    if SUSP_CMD.search(cmd or ""):
        reasons.append("suspicious command line (hidden or obfuscated execution)")
    if exe and SUSP_DIRS.search(exe) and not MS_OK.search(exe):
        reasons.append("program is located in a user or temp folder")
    if exe and not os.path.exists(exe) and exe.lower().endswith(".exe") and ":" in exe:
        reasons.append("target file is missing (leftover or disguised entry)")
    if reasons:
        ctx.add(WARN, area, f"Suspicious autostart: {label}",
                f"Command: {cmd}\nReason: {'; '.join(reasons)}{extra}\n\nIf in doubt, disable it with Sysinternals Autoruns.",
                path=exe if exe and os.path.isfile(exe) else None,
                action={"type": "quarantine", "path": exe} if exe and os.path.isfile(exe) else None)
        return True
    return False


def check_autostart(ctx):
    import winreg  # only available on Windows
    keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    ]
    entries = []
    for hive, path in keys:
        try:
            with winreg.OpenKey(hive, path) as k:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    entries.append((("HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM") + "\\" + path, name, str(val)))
                    i += 1
        except OSError:
            continue
    flagged = sum(_judge(ctx, "Autostart", f"{n}  ({k})", v) for k, n, v in entries)
    # Winlogon and debugger hijacking (typical persistence tricks)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon") as k:
            for name, normal in (("Shell", "explorer.exe"), ("Userinit", r"c:\windows\system32\userinit.exe,")):
                try:
                    val = str(winreg.QueryValueEx(k, name)[0])
                    if val.strip().lower().rstrip(",") != normal.rstrip(","):
                        flagged += 1
                        ctx.add(WARN, "Autostart", f"Winlogon {name} modified", f"Value: {val}\nNormal: {normal}")
                except OSError:
                    pass
    except OSError:
        pass
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options") as k:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(k, sub) as s:
                        dbg = winreg.QueryValueEx(s, "Debugger")[0]
                        flagged += 1
                        ctx.add(WARN, "Autostart", f"Program redirect (Debugger) for {sub}",
                                f"When {sub} starts, this runs instead:\n{dbg}\nMalware uses this to hijack programs.")
                except OSError:
                    pass
    except OSError:
        pass
    # Startup folders
    for folder in (os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
                   os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), r"Microsoft\Windows\Start Menu\Programs\StartUp")):
        if os.path.isdir(folder):
            for f in os.listdir(folder):
                if f.lower() == "desktop.ini":
                    continue
                p = os.path.join(folder, f)
                entries.append((folder, f, p))
                if os.path.splitext(f)[1].lower() in (".vbs", ".js", ".bat", ".cmd", ".ps1", ".hta", ".exe", ".scr"):
                    flagged += 1
                    ctx.add(WARN, "Autostart", f"Script or program in the Startup folder: {f}", p, path=p,
                            action={"type": "quarantine", "path": p})
    baseline.seen(ctx, "autostart")
    for _, n, v in entries:
        baseline.note(ctx, "autostart", f"{n} = {v}")
    lines = "\n".join(f"{n:30.30} {v}" for _, n, v in entries[:80])
    ctx.add(INFO if not flagged else WARN, "Autostart", f"{count(len(entries), 'autostart entry', 'autostart entries')}, {flagged} suspicious", lines)


def check_tasks(ctx):
    rows = ps_json("Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | ForEach-Object { [pscustomobject]@{"
                   "n=($_.TaskPath + $_.TaskName); e=(($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' ; ')} }")
    flagged = 0
    baseline.seen(ctx, "tasks")
    for r in rows:
        name, cmd = r.get("n", ""), (r.get("e") or "").strip()
        if not cmd or name.startswith("\\Microsoft\\"):
            continue
        baseline.note(ctx, "tasks", f"{name} → {cmd}")
        flagged += _judge(ctx, "Scheduled tasks", name, cmd)
    ctx.add(OK if not flagged else WARN, "Scheduled tasks", f"{count(len(rows), 'active task')} checked, {flagged} suspicious")


def check_services(ctx):
    rows = ps_json("Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,StartMode,State")
    flagged = 0
    baseline.seen(ctx, "services")
    for r in rows:
        path = r.get("PathName") or ""
        if r.get("StartMode") == "Disabled" or not path:
            continue
        if re.search(r"\\windows\\system32\\svchost\.exe", path, re.I):
            continue
        baseline.note(ctx, "services", f"{r.get('Name')}: {path}")
        flagged += _judge(ctx, "Services", f"{r.get('DisplayName')} ({r.get('Name')})", path)
    ctx.add(OK if not flagged else WARN, "Services", f"{count(len(rows), 'service')} checked, {flagged} suspicious")


def load_processes(ctx):
    rows = ps_json("Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,CommandLine")
    ctx.processes = [{"pid": r.get("ProcessId"), "name": r.get("Name") or "", "path": r.get("ExecutablePath") or "",
                      "cmd": r.get("CommandLine") or ""} for r in rows]
    for p in ctx.processes:
        if p["cmd"] and SUSP_CMD.search(p["cmd"]):
            ctx.add(WARN, "Processes", f"Suspicious command line: {p['name']} (PID {p['pid']})", p["cmd"][:1500])
        elif p["path"] and SUSP_DIRS.search(p["path"]) and not MS_OK.search(p["path"]) and p["name"].lower().endswith((".exe",)):
            if re.search(r"\\(temp|tmp|users\\public|\$recycle\.bin)\\", p["path"], re.I):
                ctx.add(WARN, "Processes", f"Program running from a temp folder: {p['name']}", p["path"], path=p["path"],
                        action={"type": "quarantine", "path": p["path"]})


def check_signatures(ctx):
    """Full scan: checks the signature of running programs outside the Windows folder."""
    paths = sorted({p["path"] for p in ctx.processes if p.get("path") and not re.match(r"^c:\\windows\\", p["path"], re.I)})[:400]
    if not paths:
        return
    lst = ",".join("'" + p.replace("'", "''") + "'" for p in paths)
    rows = ps_json(f"@({lst}) | ForEach-Object {{ $s=Get-AuthenticodeSignature -LiteralPath $_; "
                   "[pscustomobject]@{p=$_; s=[string]$s.Status; n=[string]$s.SignerCertificate.Subject} }", timeout=400)
    unsigned = [r for r in rows if r.get("s") not in ("Valid",)]
    if unsigned:
        ctx.add(WARN, "Signatures", f"{count(len(unsigned), 'running program')} without a valid signature",
                "Unsigned programs are not automatically malicious (many hobby tools are unsigned), but you should recognise each one:\n" +
                "\n".join(f"{r.get('s'):14} {r.get('p')}" for r in unsigned[:80]))
    ctx.add(OK, "Signatures", f"{count(len(rows), 'program')} checked for a valid signature")


def check_routing(ctx):
    """VPN adapters and profiles, proxy settings, DNS servers, trusted root certificates."""
    adapters = ps_json("Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name,InterfaceDescription,Status")
    active, configured, servers = [], [], []
    for a in adapters:
        label = f"{a.get('Name')} ({a.get('InterfaceDescription')})"
        if net.VPN_NAME.search(label) and "miniport" not in label.lower():
            configured.append(f"Adapter: {label} – {a.get('Status')}")
            if a.get("Status") == "Up":
                active.append(a.get("Name") or label)
    profiles = ps_json("$a=@(); try { $a += Get-VpnConnection -ErrorAction Stop } catch {}; "
                       "try { $a += Get-VpnConnection -AllUserConnection -ErrorAction Stop } catch {}; "
                       "$a | Select-Object Name,ServerAddress,ConnectionStatus,TunnelType")
    for p in profiles:
        configured.append(f"Windows VPN profile: {p.get('Name')} → {p.get('ServerAddress')} ({p.get('TunnelType')}, {p.get('ConnectionStatus')})")
        servers.append((p.get("Name"), p.get("ServerAddress")))
        if str(p.get("ConnectionStatus")) == "Connected":
            active.append(p.get("Name"))
    net.report_vpn(ctx, active, configured)
    net.check_vpn_servers(ctx, servers)

    proxies = []
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as k:
            def val(name):
                try:
                    return winreg.QueryValueEx(k, name)[0]
                except OSError:
                    return None
            if val("ProxyEnable") == 1 and val("ProxyServer"):
                proxies.append(("System proxy", str(val("ProxyServer"))))
            if val("AutoConfigURL"):
                proxies.append(("Proxy auto-config script (PAC)", str(val("AutoConfigURL"))))
    except (ImportError, OSError):
        pass
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        if os.environ.get(var):
            proxies.append((f"Environment variable {var}", os.environ[var]))
    net.judge_proxy(ctx, proxies)

    dns = ps_json("Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | "
                  "Select-Object InterfaceAlias,ServerAddresses")
    dns_servers = []
    for d in dns:
        iface = d.get("InterfaceAlias") or ""
        if iface.lower().startswith(("loopback pseudo", "isatap")):
            continue
        addrs = d.get("ServerAddresses") or []
        for ip in (addrs if isinstance(addrs, list) else [addrs]):
            ip_s = str(ip)
            if ip_s.lower().startswith("fec0:0:0:ffff"):
                continue  # Windows placeholder addresses for unconfigured IPv6 DNS
            dns_servers.append((ip_s, iface))
    net.judge_dns(ctx, dns_servers)

    certs = ps_json("Get-ChildItem -Path Cert:\\LocalMachine\\Root, Cert:\\CurrentUser\\Root -ErrorAction SilentlyContinue | "
                    "Select-Object Subject")
    net.judge_certs(ctx, [c.get("Subject") or "" for c in certs], "Windows certificate store (Trusted Root Certification Authorities)")


def check_dns(ctx):
    rows = ps_json("Get-DnsClientCache | Select-Object Entry")
    names = [(r.get("Entry") or "", "") for r in rows]
    from .common import match_urls
    vpn_note = ("\nVPN active: name lookups made by the VPN app itself are not recorded here." if ctx.vpn else "")
    n = match_urls(ctx, "DNS", names, "Windows DNS cache (recent name lookups)")
    ctx.add(OK, "DNS", f"{count(n, 'DNS cache entry', 'DNS cache entries')} checked", vpn_note.strip())
    # DNS event log (like Zero Breach) – goes further back if it is enabled
    rc, out, err = ps("try { Get-WinEvent -LogName 'Microsoft-Windows-DNS-Client/Operational' -MaxEvents "
                      + ("200000" if ctx.full else "30000") +
                      " -ErrorAction Stop | Where-Object {$_.Id -eq 3008 -or $_.Id -eq 3006} | ForEach-Object { $_.Properties[0].Value } } "
                      "catch { 'SCS_ERR ' + $_.Exception.Message }", timeout=600)
    if "SCS_ERR" in out:
        ctx.add(SKIP, "DNS", "DNS history (event log) not available",
                out.split("SCS_ERR", 1)[1].strip()[:300] +
                "\n\nTip: enable it as administrator so that future lookups are recorded:\n"
                "wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true")
        return
    q = [(ln.strip(), "") for ln in out.splitlines() if ln.strip()]
    n = match_urls(ctx, "DNS", q, "DNS client event log (history)")
    ctx.add(OK, "DNS", f"{count(n, 'stored DNS query', 'stored DNS queries')} checked", vpn_note.strip())


def check_network(ctx):
    rows = ps_json("Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select-Object RemoteAddress,OwningProcess")
    from .common import check_remote_ips
    check_remote_ips(ctx, [r.get("RemoteAddress") for r in rows if r.get("RemoteAddress")], "active TCP connections")


def check_defender(ctx):
    rows = ps_json("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge,IsTamperProtected")
    if not rows:
        ctx.add(SKIP, "Defender", "Microsoft Defender status not readable", "Another antivirus product may be active.")
        return
    s = rows[0]
    probs = []
    if not s.get("AntivirusEnabled"):
        probs.append("antivirus off")
    if not s.get("RealTimeProtectionEnabled"):
        probs.append("real-time protection off")
    if (s.get("AntivirusSignatureAge") or 0) > 7:
        probs.append(f"signatures {s.get('AntivirusSignatureAge')} days old")
    if s.get("IsTamperProtected") is False:
        probs.append("tamper protection off")
    ctx.add(WARN if probs else OK, "Defender", "Defender: " + (", ".join(probs) if probs else "active and up to date"),
            "Malware likes to switch Defender off. Settings › Windows Security › Virus & threat protection." if probs else "")
    if is_admin():
        ex = ps_json("Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension")
        if ex:
            items = []
            for k in ("ExclusionPath", "ExclusionProcess", "ExclusionExtension"):
                v = ex[0].get(k)
                if v:
                    items += [f"{k}: {x}" for x in (v if isinstance(v, list) else [v])]
            if items:
                ctx.add(WARN, "Defender", f"{count(len(items), 'exclusion')} configured in Defender",
                        "Malware adds itself here to avoid being scanned:\n" + "\n".join(items))
    else:
        ctx.add(SKIP, "Defender", "Defender exclusions not checkable", "Readable with administrator rights only.")


def check_ads(ctx):
    """Full scan: hidden data streams (Alternate Data Streams) in user folders."""
    dirs = [os.path.join(HOME, d) for d in ("Desktop", "Documents", "Downloads", "Pictures", "Videos")]
    lst = ",".join("'" + d.replace("'", "''") + "'" for d in dirs if os.path.isdir(d))
    if not lst:
        return
    rows = ps_json(f"Get-ChildItem -LiteralPath @({lst}) -Recurse -File -ErrorAction SilentlyContinue | "
                   "Get-Item -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -notin @(':$DATA','Zone.Identifier','SmartScreen','com.dropbox.attrs','ms-properties') } | "
                   "Select-Object FileName,Stream,Length", timeout=900)
    if rows:
        ctx.add(WARN, "Hidden data streams", f"{count(len(rows), 'hidden data stream')} (ADS) found",
                "Data that is invisibly attached to ordinary files:\n" +
                "\n".join(f"{r.get('Length', 0):>10}  {r.get('FileName')}:{r.get('Stream')}" for r in rows[:80]) +
                "\n\nView a stream: Get-Content -Path FILE -Stream NAME")
    else:
        ctx.add(OK, "Hidden data streams", "No hidden data streams in the user folders")


def check_recycle(ctx):
    rc, out, _ = ps("(New-Object -ComObject Shell.Application).NameSpace(10).Items().Count")
    if out.strip().isdigit():
        ctx.add(INFO, "Recycle Bin", f"{count(int(out.strip()), 'item')} in the Recycle Bin",
                "Deleted files in the Recycle Bin can be fully restored.")


def run_checks(ctx):
    ctx.step("Windows: autostart", 20)
    ctx.section("Autostart", check_autostart)
    ctx.step("Windows: scheduled tasks", 25)
    ctx.section("Scheduled tasks", check_tasks)
    ctx.step("Windows: services", 30)
    ctx.section("Services", check_services)
    ctx.step("Windows: processes", 35)
    ctx.section("Processes", load_processes)
    if ctx.full:
        ctx.step("Windows: signatures", 38)
        ctx.section("Signatures", check_signatures)
    ctx.step("Windows: VPN, proxy, DNS servers, certificates", 40)
    ctx.section("VPN", check_routing)
    ctx.step("Windows: DNS history", 43)
    ctx.section("DNS", check_dns)
    ctx.section("Network", check_network)
    ctx.step("Windows: Defender", 47)
    ctx.section("Defender", check_defender)
    ctx.section("Recycle Bin", check_recycle)
    if ctx.full:
        ctx.step("Windows: hidden data streams", 50)
        ctx.section("Hidden data streams", check_ads)
