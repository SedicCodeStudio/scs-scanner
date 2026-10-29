"""Reports as HTML (retro look) and JSON."""
from __future__ import annotations

import html
import json

from .core import HIT, INFO, OK, SEV_ORDER, SKIP, WARN

COLORS = {HIT: "#C00000", WARN: "#806000", SKIP: "#404040", INFO: "#000080", OK: "#006000"}

CSS = """
body{background:#008080;margin:0;padding:24px;font:13px Tahoma,"MS Sans Serif",Arial,sans-serif;color:#000}
.win{background:#C0C0C0;border:2px solid;border-color:#FFF #404040 #404040 #FFF;max-width:1100px;margin:auto}
.bar{background:#000080;color:#FFF;font-weight:bold;padding:4px 8px}
.in{padding:12px} table{border-collapse:collapse;width:100%;background:#FFF;border:2px solid;border-color:#808080 #FFF #FFF #808080}
td,th{border:1px solid #C0C0C0;padding:4px 6px;vertical-align:top;text-align:left}
th{background:#C0C0C0} pre{margin:4px 0 0;font:12px "Courier New",monospace;white-space:pre-wrap;word-break:break-all}
.src{font-size:11px;color:#404040} .sum span{display:inline-block;margin-right:18px;font-weight:bold}
.note{border:2px solid;border-color:#808080 #FFF #FFF #808080;background:#FFFFE1;padding:8px;margin:10px 0}
"""
NOTE = ("A result without detections is no guarantee. High-end spyware is built to survive checks like this, and many traces "
        "disappear within a few weeks. If you have a well-founded suspicion, contact the Access Now Digital Security Helpline "
        "or the Amnesty International Security Lab.")
GUIDE = "https://github.com/SedicCodeStudio/scs-scanner/blob/main/docs/WHAT-TO-DO.md"


def save_json(ctx, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"meta": ctx.meta, "counts": ctx.counts(),
                   "findings": [f.to_dict() for f in ctx.findings]}, fh, ensure_ascii=False, indent=1)


def save_html(ctx, path):
    c = ctx.counts()
    rows = []
    for f in sorted(ctx.findings, key=lambda f: SEV_ORDER.get(f.sev, 9)):
        rows.append(
            f"<tr><td style='color:{COLORS.get(f.sev, '#000')};font-weight:bold'>{html.escape(f.sev)}</td>"
            f"<td>{html.escape(f.area)}</td><td><b>{html.escape(f.title)}</b>"
            f"<pre>{html.escape(f.detail or '')}</pre>"
            + (f"<div class='src'>Source: {html.escape(f.source)}</div>" if f.source else "")
            + "</td></tr>")
    meta = "".join(f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>" for k, v in ctx.meta.items())
    doc = (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><title>SCS Scanner Report</title><style>{CSS}</style></head>"
           f"<body><div class='win'><div class='bar'>SCS Scanner – Scan report</div><div class='in'>"
           f"<p class='sum'><span style='color:{COLORS[HIT]}'>Detected: {c[HIT]}</span><span style='color:{COLORS[WARN]}'>Warnings: {c[WARN]}</span>"
           f"<span>Not checked: {c[SKIP]}</span><span style='color:{COLORS[INFO]}'>Info: {c[INFO]}</span>"
           f"<span style='color:{COLORS[OK]}'>OK: {c[OK]}</span></p><div class='note'>{html.escape(NOTE)} <a href='{GUIDE}'>What to do if something was found</a></div>"
           f"<table><tr><th colspan='2'>Scan</th></tr>{meta}</table><br>"
           f"<table><tr><th style='width:110px'>Status</th><th style='width:150px'>Area</th><th>Finding</th></tr>{''.join(rows)}</table>"
           f"</div></div></body></html>")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
