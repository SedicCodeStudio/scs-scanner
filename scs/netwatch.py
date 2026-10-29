"""Live network watch.

For a few minutes, every new name lookup (Windows DNS cache) and every new connection is compared with
the spyware indicators. Use the device normally meanwhile – open messengers, mail and the browser – so
that hidden spyware has a chance to contact its servers.
"""
from __future__ import annotations

import time

from . import common, ioc
from .core import HIT, INFO, OK, SKIP, count, os_name, ps_json, run

AREA = "Network watch"


def _dns():
    if os_name() != "windows":
        return set()
    return {str(r.get("Entry")).lower() for r in ps_json("Get-DnsClientCache | Select-Object Entry", timeout=60) if r.get("Entry")}


def _connections():
    o = os_name()
    if o == "windows":
        rows = ps_json("Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select-Object RemoteAddress", timeout=60)
        return {str(r.get("RemoteAddress")) for r in rows if r.get("RemoteAddress")}
    if o == "linux":
        from .lin import _proc_net
        return {ip for ip, port, st in _proc_net() if st == "01"}
    rc, out, _ = run(["netstat", "-an", "-p", "tcp"], timeout=30)
    ips = set()
    for ln in out.splitlines():
        if "ESTABLISHED" in ln:
            parts = ln.split()
            if len(parts) >= 5:
                ips.add(parts[4].rsplit(".", 1)[0])
    return ips


def watch(ctx, minutes=10, interval=5):
    minutes = max(1, min(int(minutes), 240))
    interval = max(2, min(int(interval), 60))
    ctx.step("Loading indicators", 2)
    ctx.ioc = ioc.load()
    common.check_ioc_status(ctx)
    ctx.add(INFO, AREA, f"Watching for {count(minutes, 'minute')}",
            "New name lookups and connections are compared with the spyware indicators every few seconds. Use the device "
            "normally meanwhile – open messengers, mail and the browser.\nWith an active VPN only the VPN server is visible "
            "as a connection; name lookups are still recorded by Windows.")
    if os_name() != "windows":
        ctx.add(SKIP, AREA, "Name lookups can only be watched on Windows", "Connections are watched on this system.")
    start = time.time()
    end = start + minutes * 60
    seen_dom, seen_ip, hits = set(), set(), set()
    next_report = start + 60
    while time.time() < end and not ctx.cancel:
        try:
            for d in _dns() - seen_dom:
                seen_dom.add(d)
                m = ctx.ioc.match_domain(d) if ctx.ioc else None
                if m and m[0] not in hits:
                    hits.add(m[0])
                    ctx.add(HIT, AREA, f"Lookup of a known spyware address: {m[0]}",
                            f"Name looked up: {d}\nAttributed to: {m[1][1]}\nTime: {time.strftime('%H:%M:%S')}\n\n"
                            "A program on this computer just contacted this address. Save the report and consult experts.",
                            source=m[1][0])
            for ip in _connections() - seen_ip:
                seen_ip.add(ip)
                if ctx.ioc and ip in ctx.ioc.data["ipv4"] and ip not in hits:
                    hits.add(ip)
                    feed, mal = ctx.ioc.data["ipv4"][ip]
                    ctx.add(HIT, AREA, f"Connection to a known spyware IP: {ip}",
                            f"Attributed to: {mal}\nTime: {time.strftime('%H:%M:%S')}", source=feed)
        except Exception as e:  # noqa: BLE001 – keep watching
            ctx.log(f"Network watch: {e}")
        now = time.time()
        if now >= next_report:
            next_report = now + 60
            pct = min(99, int((now - start) / (end - start) * 100))
            ctx.step(f"Network watch: {count(len(seen_dom), 'lookup')}, {count(len(seen_ip), 'remote host')} so far", pct)
        slept = 0.0
        while slept < interval and not ctx.cancel:
            time.sleep(0.5)
            slept += 0.5
    ctx.step("Done", 100)
    ctx.add(OK if not hits else INFO, AREA,
            f"Watched {count(round((time.time() - start) / 60) or 1, 'minute')}: {count(len(seen_dom), 'name lookup')} and "
            f"{count(len(seen_ip), 'remote host')} checked" + (f", {count(len(hits), 'hit')}" if hits else ""),
            "A watch without hits is no guarantee: spyware may stay quiet while it is being watched.")
