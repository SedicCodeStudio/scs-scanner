"""Combined report for several devices.

Run the scanner on each of your devices, save a JSON report there, then combine all reports here into one
overview – without remote access to any device.
"""
from __future__ import annotations

import html
import json

from .core import HIT, SKIP, WARN, count
from .report import CSS, COLORS


def load_reports(paths):
    reports = []
    for p in paths:
        with open(p, encoding="utf-8-sig") as fh:  # also accepts files saved with a byte order mark
            data = json.load(fh)
        if not isinstance(data, dict) or "findings" not in data:
            raise ValueError(f"Not an SCS Scanner JSON report: {p}")
        reports.append((p, data))
    return reports


def merge(paths, out_path):
    reports = load_reports(paths)
    rows, sections = [], []
    for p, r in reports:
        meta, c = r.get("meta", {}), r.get("counts", {})
        device = meta.get("android") or meta.get("iphone") or meta.get("host") or p
        rows.append(f"<tr><td><b>{html.escape(str(device))}</b></td><td>{html.escape(str(meta.get('system', '')))}</td>"
                    f"<td>{html.escape(str(meta.get('mode', '')))}</td><td>{html.escape(str(meta.get('started', '')))}</td>"
                    f"<td style='color:{COLORS[HIT]};font-weight:bold'>{c.get(HIT, 0)}</td>"
                    f"<td style='color:{COLORS[WARN]};font-weight:bold'>{c.get(WARN, 0)}</td><td>{c.get(SKIP, 0)}</td></tr>")
        items = [f for f in r["findings"] if f.get("sev") in (HIT, WARN)]
        body = "".join(f"<tr><td style='color:{COLORS.get(f['sev'], '#000')};font-weight:bold'>{html.escape(f['sev'])}</td>"
                       f"<td>{html.escape(f.get('area', ''))}</td><td><b>{html.escape(f.get('title', ''))}</b>"
                       f"<pre>{html.escape(f.get('detail') or '')}</pre></td></tr>" for f in items)
        sections.append(f"<h3>{html.escape(str(device))}</h3>" + (
            f"<table><tr><th style='width:110px'>Status</th><th style='width:150px'>Area</th><th>Finding</th></tr>{body}</table>"
            if items else "<p>No detections and no warnings.</p>"))
    total_hits = sum(r.get("counts", {}).get(HIT, 0) for _, r in reports)
    doc = (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><title>SCS Scanner – combined report</title><style>{CSS}"
           f"h3{{margin:18px 0 6px}}</style></head><body><div class='win'><div class='bar'>SCS Scanner – combined report "
           f"({count(len(reports), 'device')})</div><div class='in'>"
           f"<p class='sum'><span style='color:{COLORS[HIT]}'>Detections on all devices: {total_hits}</span></p>"
           "<table><tr><th>Device</th><th>System</th><th>Mode</th><th>Scanned</th><th>Detected</th><th>Warnings</th><th>Not checked</th></tr>"
           + "".join(rows) + "</table>" + "".join(sections) + "</div></div></body></html>")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return len(reports)
