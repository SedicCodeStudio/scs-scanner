from scs import baseline
from scs.core import INFO, OK, WARN, Context


def _scan(items, scope="test-device"):
    ctx = Context(log=lambda m: None)
    for cat, values in items.items():
        baseline.seen(ctx, cat)
        for v in values:
            baseline.note(ctx, cat, v)
    baseline.compare_and_save(ctx, scope)
    return [f for f in ctx.findings if f.area == "Changes"]


def test_baseline_cycle():
    state = {"autostart": ["Updater = C:\\Program Files\\Updater\\up.exe"], "vpn": ["Adapter: NordLynx (NordLynx Tunnel) - Up"],
             "dns": ["9.9.9.9 (Ethernet)"]}
    first = _scan(state)
    assert first[0].sev == INFO and first[0].title == "Baseline created"
    # the same state with a different connection status is not a change
    state["vpn"] = ["Adapter: NordLynx (NordLynx Tunnel) - Disconnected"]
    again = _scan(state)
    assert again[0].sev == OK and again[0].title.startswith("No changes since")
    # a new autostart entry is reported as a warning, a new DNS server only as info
    state["autostart"].append("Sync = C:\\Users\\Max\\AppData\\Roaming\\sync.exe")
    state["dns"].append("45.77.1.2 (Ethernet)")
    changed = _scan(state)
    titles = {f.title.split(" since ")[0]: f.sev for f in changed}
    assert titles["1 new autostart entry"] == WARN
    assert titles["1 new DNS server"] == INFO
    assert any("sync.exe" in f.detail for f in changed)


def test_empty_category_reports_first_item():
    _scan({"proxy": []}, scope="proxy-device")
    changed = _scan({"proxy": ["System proxy: 203.0.113.66:8080"]}, scope="proxy-device")
    assert changed[0].sev == WARN and changed[0].title.startswith("1 new proxy setting")


def test_no_baseline_option():
    ctx = Context(log=lambda m: None)
    ctx.no_baseline = True
    baseline.note(ctx, "autostart", "x")
    baseline.compare_and_save(ctx, "skipped-device")
    assert baseline.load("skipped-device") is None


def test_scope_names_are_safe():
    import os
    path = baseline._path("../../etc/evil scope")
    assert os.path.dirname(path) == baseline.BASE_DIR
    assert ".." not in os.path.basename(path)
