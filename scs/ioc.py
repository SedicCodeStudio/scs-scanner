"""Loading and matching indicators of compromise (IOCs).

Sources: the public MVT list (mvt-project/mvt-indicators) – Pegasus, Predator, stalkerware,
Candiru and more – plus the AdFection feed from Zero Breach. No third-party code is reused;
the STIX2 files are downloaded straight from their sources during an update.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import ssl
import time
import urllib.request

from .core import DATA_DIR, ensure_dir

INDEX_URL = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml"
EXTRA_FEEDS = [
    ("Zero Breach – AdFection / Candiru (2026)",
     "https://github.com/interplains/zero-breach/releases/latest/download/adfection.stix.json"),
]
IOC_DIR = os.path.join(DATA_DIR, "indicators")

# Built-in, harmless self-test indicator (content of the self-test file)
SELFTEST_CONTENT = b"SCS-SELFTEST: harmless test file of the SCS Scanner. Safe to delete.\n"
SELFTEST_SHA256 = hashlib.sha256(SELFTEST_CONTENT).hexdigest()

_PAT = re.compile(r"([a-z0-9\-]+:[a-z0-9_.\-']+)\s*=\s*'((?:[^'\\]|\\.)*)'", re.I)

TYPES = ("domain", "ipv4", "sha256", "sha1", "md5", "app_id", "cert_sha1", "cert_sha256",
         "process", "file_path", "file_name", "email", "url", "profile_id", "android_prop")


def _norm_key(key: str, value: str):
    k = key.lower().replace("'", "")
    v = value.replace("\\'", "'").replace("\\\\", "\\").strip()
    if k.startswith("domain-name"):
        return "domain", v.lower().strip(".")
    if k.startswith("ipv4-addr"):
        return "ipv4", v.split("/")[0]
    if k.startswith("file:hashes"):
        v = v.lower()
        return {64: "sha256", 40: "sha1", 32: "md5"}.get(len(v), "sha256"), v
    if k == "app:id":
        return "app_id", v.lower()
    if k.startswith("app:cert.sha1"):
        return "cert_sha1", v.lower().replace(":", "")
    if k.startswith("app:cert.sha256"):
        return "cert_sha256", v.lower().replace(":", "")
    if k.startswith("process:name"):
        return "process", v
    if k == "file:path":
        return "file_path", v
    if k == "file:name":
        return "file_name", v
    if k.startswith("email-addr"):
        return "email", v.lower()
    if k.startswith("url"):
        return "url", v
    if k.startswith("configuration-profile"):
        return "profile_id", v
    if k.startswith("android-property"):
        return "android_prop", v
    return None, None


class IOCIndex:
    def __init__(self):
        self.data = {t: {} for t in TYPES}
        self.feeds = []   # (name, count)

    def total(self):
        return sum(len(v) for v in self.data.values())

    def add(self, typ, value, feed, malware):
        if typ and value and value not in self.data[typ]:
            self.data[typ][value] = (feed, malware)

    def load_stix(self, path, feed_name):
        with open(path, "r", encoding="utf-8") as fh:
            bundle = json.load(fh)
        objs = bundle.get("objects", [])
        malware = {o["id"]: o.get("name", "?") for o in objs if o.get("type") in ("malware", "tool", "threat-actor", "campaign")}
        ind2mal = {}
        for o in objs:
            if o.get("type") == "relationship" and o.get("source_ref", "").startswith("indicator--"):
                if o.get("target_ref") in malware:
                    ind2mal[o["source_ref"]] = malware[o["target_ref"]]
        n = 0
        default = next(iter(malware.values()), feed_name)
        for o in objs:
            if o.get("type") != "indicator":
                continue
            mal = ind2mal.get(o["id"]) or o.get("name") or default
            for key, val in _PAT.findall(o.get("pattern", "")):
                typ, v = _norm_key(key, val)
                if typ:
                    self.add(typ, v, feed_name, mal)
                    n += 1
        self.feeds.append((feed_name, n))
        return n

    def load_dir(self, directory=IOC_DIR):
        meta = load_meta()
        names = {m["file"]: m["name"] for m in meta.get("feeds", [])}
        for p in sorted(glob.glob(os.path.join(directory, "*.stix*")) + glob.glob(os.path.join(directory, "*.json"))):
            base = os.path.basename(p)
            if base == "feeds.json":
                continue
            try:
                self.load_stix(p, names.get(base, base))
            except Exception:
                continue
        self.add("sha256", SELFTEST_SHA256, "SCS self-test", "SCS self-test (harmless)")
        return self

    # --- matching -------------------------------------------------------
    def get(self, typ, value):
        if not value:
            return None
        v = value if typ in ("process", "file_path", "file_name", "profile_id", "android_prop", "url") else value.lower()
        return self.data[typ].get(v)

    def match_domain(self, host):
        """Checks a domain and all parent domains (sub.evil.com → evil.com)."""
        if not host:
            return None
        host = host.lower().strip().strip(".")
        if ":" in host and not host.startswith("["):
            host = host.split(":")[0]
        if host in self.data["ipv4"]:
            return host, self.data["ipv4"][host]
        parts = host.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            hit = self.data["domain"].get(cand)
            if hit:
                return cand, hit
        return None


def load_meta():
    try:
        with open(os.path.join(IOC_DIR, "feeds.json"), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


MAX_DOWNLOAD = 64 * 1024 * 1024


def _get(url, timeout=60, limit=MAX_DOWNLOAD):
    """HTTPS download with a size limit (proxy settings of the system are used automatically)."""
    if not url.startswith("https://"):
        raise ValueError("Only HTTPS downloads are allowed.")
    req = urllib.request.Request(url, headers={"User-Agent": "SCS-Scanner/0.2"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read(limit + 1)
            if len(data) > limit:
                raise RuntimeError(f"Download larger than {limit // (1024 * 1024)} MB – aborted.")
            return data
    except ssl.SSLError as e:
        raise RuntimeError(f"SSL error ({e}). On a Mac, run 'Install Certificates.command' in the Python folder once.")


def parse_index(text: str):
    feeds = []
    for block in re.split(r"\n\s*-\s*\n", text):
        n = re.search(r"\bname:\s*(.+)", block)
        o = re.search(r"\bowner:\s*(\S+)", block)
        r = re.search(r"\brepo:\s*(\S+)", block)
        b = re.search(r"\bbranch:\s*(\S+)", block)
        p = re.search(r"\bpath:\s*(\S+)", block)
        if n and o and r and b and p:
            feeds.append((n.group(1).strip(), f"https://raw.githubusercontent.com/{o.group(1)}/{r.group(1)}/{b.group(1)}/{p.group(1)}"))
    return feeds


def update(log=print):
    """Downloads all indicator feeds again. Returns (number_ok, list_of_errors)."""
    ensure_dir(IOC_DIR)
    log("Loading feed list from mvt-project/mvt-indicators …")
    feeds = parse_index(_get(INDEX_URL).decode("utf-8", "replace")) + EXTRA_FEEDS
    ok, fails, meta = 0, [], {"updated": time.strftime("%Y-%m-%d %H:%M"), "feeds": []}
    for name, url in feeds:
        fname = re.sub(r"[^A-Za-z0-9]+", "_", url.split("/", 3)[-1])[-90:] + ".stix2"
        try:
            data = _get(url)
            json.loads(data)  # only store valid JSON
            with open(os.path.join(IOC_DIR, fname), "wb") as fh:
                fh.write(data)
            meta["feeds"].append({"name": name, "file": fname, "url": url})
            ok += 1
            log(f"  ok     {name}")
        except Exception as e:  # noqa: BLE001
            fails.append(f"{name}: {e}")
            log(f"  ERROR  {name}: {e}")
    with open(os.path.join(IOC_DIR, "feeds.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, ensure_ascii=False, indent=1)
    return ok, fails


def load():
    return IOCIndex().load_dir()
