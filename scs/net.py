"""Traffic routing checks shared by all platforms: VPN, proxy, DNS servers, trusted root certificates.

A VPN or proxy sees – and can redirect – all internet traffic. The scanner therefore lists what is
configured, flags what looks foreign, and explains how an active VPN limits the network part of a scan.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import threading
from urllib.parse import urlparse

from . import baseline
from .core import HIT, INFO, OK, WARN, count

AREA_VPN = "VPN"
AREA_DNS = "DNS servers"
AREA_PROXY = "Proxy"
AREA_CERT = "Root certificates"

# Adapter/app names that indicate a VPN (Windows adapter descriptions, macOS/Android app names)
VPN_NAME = re.compile(
    r"tap-windows|tap adapter|wintun|wireguard|openvpn|anyconnect|forticlient|fortinet ssl|nordlynx|nordvpn|protonvpn|"
    r"proton vpn|mullvad|windscribe|expressvpn|surfshark|cyberghost|private internet access|tunnelbear|hotspot shield|"
    r"globalprotect|pangp|juniper|pulse secure|ivanti|sonicwall|check ?point|zscaler|tailscale|zerotier|hamachi|"
    r"softether|\bvpn\b", re.I)
# Network interface names that indicate a VPN tunnel (Linux, Android)
VPN_IFACE = re.compile(r"^(tun|tap|wg|ppp|ipsec|vti|nordlynx|proton|mullvad|wg-mullvad|tailscale|zt|cscotun|gpd|vpn)", re.I)

VPN_EFFECT = (
    "Traffic is routed through a VPN tunnel. What that means for this scan:\n"
    "• Active connections show the VPN server, not the real destinations – the connection check is limited.\n"
    "• Name lookups made by the VPN app itself (e.g. DNS-over-HTTPS) do not appear in the system's DNS history.\n"
    "• Network analysis from outside the device (e.g. TinyCheck, PiRogue) only sees encrypted tunnel traffic.\n"
    "• On-device checks (autostart, processes, files, browser history, phone apps) are not affected.\n\n"
    "A VPN provider can see and redirect your traffic. Only use VPN apps you installed yourself from a trustworthy source.")

KNOWN_RESOLVERS = {
    "8.8.8.8": "Google Public DNS", "8.8.4.4": "Google Public DNS",
    "2001:4860:4860::8888": "Google Public DNS", "2001:4860:4860::8844": "Google Public DNS",
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "1.1.1.2": "Cloudflare (malware filter)", "1.0.0.2": "Cloudflare (malware filter)",
    "1.1.1.3": "Cloudflare (family filter)", "1.0.0.3": "Cloudflare (family filter)",
    "2606:4700:4700::1111": "Cloudflare", "2606:4700:4700::1001": "Cloudflare",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "9.9.9.10": "Quad9", "9.9.9.11": "Quad9", "2620:fe::fe": "Quad9", "2620:fe::9": "Quad9",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS", "208.67.222.123": "OpenDNS FamilyShield", "208.67.220.123": "OpenDNS FamilyShield",
    "94.140.14.14": "AdGuard DNS", "94.140.15.15": "AdGuard DNS", "94.140.14.15": "AdGuard DNS (family)", "94.140.15.16": "AdGuard DNS (family)",
    "185.228.168.9": "CleanBrowsing", "185.228.169.9": "CleanBrowsing",
    "76.76.2.0": "Control D", "76.76.10.0": "Control D",
    "194.242.2.2": "Mullvad DNS", "103.86.96.100": "NordVPN DNS", "103.86.99.100": "NordVPN DNS",
}
PREFIX_RESOLVERS = (("45.90.28.", "NextDNS"), ("45.90.30.", "NextDNS"))

# Root certificates known for HTTPS interception: (pattern, severity, explanation)
CERT_RISK = [
    (r"superfish", WARN, "Superfish – adware root certificate (Lenovo, 2015) that lets attackers read HTTPS traffic"),
    (r"edellroot|dsdtestprovider", WARN, "eDellRoot – insecure root certificate shipped on Dell laptops (2015)"),
    (r"komodia", WARN, "Komodia – HTTPS interception component used by adware"),
    (r"privdog", WARN, "PrivDog – adware with HTTPS interception"),
    (r"mitmproxy", WARN, "mitmproxy – tool that intercepts HTTPS traffic"),
    (r"fiddler", WARN, "Fiddler – HTTPS debugging proxy that intercepts traffic"),
    (r"charles proxy|charles ssl", WARN, "Charles Proxy – HTTPS debugging proxy that intercepts traffic"),
    (r"portswigger", WARN, "Burp Suite (PortSwigger) – HTTPS interception proxy"),
    (r"proxyman", WARN, "Proxyman – HTTPS debugging proxy"),
    (r"http ?toolkit", WARN, "HTTP Toolkit – HTTPS interception proxy"),
    (r"kaspersky|avast|\bavg\b|eset ssl|bitdefender|sophos|dr\.?web|g data|f-secure|webroot", INFO,
     "HTTPS scanning by an antivirus program – usually intended"),
    (r"zscaler|netskope|forcepoint|fortigate|palo alto|umbrella|blue ?coat|websense", INFO,
     "Company HTTPS inspection – normal on work devices, unusual on private ones"),
]


def _reverse(ip, timeout=2.0):
    """Reverse DNS name of an IP with a hard time limit (may return None)."""
    out = {}

    def job():
        try:
            out["name"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
    t = threading.Thread(target=job, daemon=True)
    t.start()
    t.join(timeout)
    return out.get("name")


def classify(ip):
    """Returns (kind, description) – kind is 'local', 'known' or 'unknown'."""
    raw = ip.split("%")[0].strip()
    try:
        a = ipaddress.ip_address(raw)
    except ValueError:
        return "unknown", "not an IP address"
    if a.is_loopback:
        return "local", "resolver on this device (e.g. VPN client, ad blocker, systemd-resolved)"
    if a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10"):
        return "local", "carrier-grade NAT / VPN range (e.g. Tailscale)"
    if a.is_private or a.is_link_local:
        return "local", "local network (router) or VPN"
    if raw in KNOWN_RESOLVERS:
        return "known", KNOWN_RESOLVERS[raw]
    for prefix, name in PREFIX_RESOLVERS:
        if raw.startswith(prefix):
            return "known", name
    name = _reverse(raw)
    return "unknown", (f"public server ({name})" if name else "unknown public server")


def _ioc_host(ctx, host):
    if not ctx.ioc or not host:
        return None
    return ctx.ioc.match_domain(host)


def report_vpn(ctx, active, configured, extra_detail=""):
    """active: list of active tunnel names; configured: list of text lines (profiles, apps)."""
    ctx.vpn = list(dict.fromkeys(active))
    ctx.meta["vpn"] = ", ".join(ctx.vpn) if ctx.vpn else "none active"
    baseline.seen(ctx, "vpn")
    for line in configured:
        baseline.note(ctx, "vpn", line)
    if ctx.vpn:
        ctx.add(INFO, AREA_VPN, f"VPN active: {', '.join(ctx.vpn)}", VPN_EFFECT + (f"\n\n{extra_detail}" if extra_detail else ""))
    if configured:
        ctx.add(INFO, AREA_VPN, f"{count(len(configured), 'VPN connection or VPN app', 'VPN connections or VPN apps')} configured",
                "Check that you set up each of these yourself:\n" + "\n".join(configured[:60]))
    if not ctx.vpn and not configured:
        ctx.add(OK, AREA_VPN, "No VPN active or configured")
    elif not ctx.vpn:
        ctx.add(OK, AREA_VPN, "No VPN tunnel active at the moment")


def check_vpn_servers(ctx, servers):
    """servers: list of (profile name, server address)."""
    for name, server in servers:
        host = (server or "").strip()
        m = _ioc_host(ctx, host)
        if m:
            ctx.add(HIT, AREA_VPN, f"VPN server is a known spyware address: {host}",
                    f"VPN profile: {name}\nAttributed to: {m[1][1]}\nAll traffic of this device can be read by that server.",
                    source=m[1][0])


def judge_dns(ctx, servers):
    """servers: list of (ip, interface)."""
    baseline.seen(ctx, "dns")
    if not servers:
        ctx.add(INFO, AREA_DNS, "No DNS servers could be read")
        return
    lines, seen = [], set()
    for ip, iface in servers:
        ip = ip.strip()
        if not ip or (ip, iface) in seen:
            continue
        seen.add((ip, iface))
        baseline.note(ctx, "dns", f"{ip} ({iface})")
        on_vpn = bool(iface and (VPN_NAME.search(iface) or VPN_IFACE.search(iface) or iface in ctx.vpn))
        if ctx.ioc and ip in ctx.ioc.data["ipv4"]:
            feed, mal = ctx.ioc.data["ipv4"][ip]
            ctx.add(HIT, AREA_DNS, f"DNS server is a known spyware address: {ip}", f"Interface: {iface}\nAttributed to: {mal}", source=feed)
            continue
        kind, desc = classify(ip)
        if on_vpn:
            desc += " – provided by the VPN"
        lines.append(f"{ip:40} {iface or '':28} {desc}")
        if kind == "unknown" and ":" not in ip and not on_vpn:
            ctx.add(WARN, AREA_DNS, f"Unknown DNS server: {ip}",
                    f"Interface: {iface}\n{desc}\n\nThis server answers all name lookups of the device. If neither you, your internet "
                    "provider nor your VPN set it, malware may have changed it (DNS hijacking, e.g. DNSChanger). "
                    "Check the DNS settings of the network adapter.")
    ctx.add(INFO, AREA_DNS, f"{count(len(lines), 'DNS server entry', 'DNS server entries')} configured",
            "Address                                  Interface                    Type\n" + "\n".join(lines))


def judge_proxy(ctx, entries):
    """entries: list of (kind, value) – e.g. ('HTTP proxy', '127.0.0.1:8888'), ('PAC script', 'http://…')."""
    baseline.seen(ctx, "proxy")
    if not entries:
        ctx.add(OK, AREA_PROXY, "No proxy configured")
        return
    for kind, value in entries:
        baseline.note(ctx, "proxy", f"{kind}: {value}")
        host = urlparse(value if "://" in value else "http://" + value).hostname
        m = _ioc_host(ctx, host)
        if m:
            ctx.add(HIT, AREA_PROXY, f"{kind} points to a known spyware address: {host}", f"Value: {value}\nAttributed to: {m[1][1]}",
                    source=m[1][0])
            continue
        local = host in ("127.0.0.1", "localhost", "::1")
        ctx.add(WARN, AREA_PROXY, f"{kind} configured: {value}",
                "All web traffic is sent through this server. That is normal in some companies and with some security or VPN tools; "
                "otherwise it is a classic trick of banking trojans and adware to read or alter traffic."
                + ("\nThe proxy runs on this device itself (e.g. a debugging tool, ad blocker – or adware)." if local else ""))


def judge_certs(ctx, names, where=""):
    """names: list of certificate subjects/names that are trusted as root certificates."""
    hits = 0
    baseline.seen(ctx, "certs")
    for name in names:
        baseline.note(ctx, "certs", name)
        for pat, sev, why in CERT_RISK:
            if re.search(pat, name or "", re.I):
                hits += 1
                ctx.add(sev, AREA_CERT, f"Root certificate for HTTPS interception: {name[:90]}",
                        f"{why}.\nStore: {where}\nA trusted interception certificate lets the holder read encrypted (HTTPS) traffic. "
                        "If you do not recognise it, remove it from the certificate store.")
                break
    if not hits:
        ctx.add(OK, AREA_CERT, f"{count(len(names), 'trusted root certificate')} checked, none known for interception", where)
