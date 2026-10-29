import json

from scs import fleet, report
from scs.core import HIT, WARN, Context


def _ctx(host):
    ctx = Context(log=lambda m: None)
    ctx.meta["host"] = host
    ctx.add(HIT, "Browser", "Known spyware address: <script>alert(1)</script>", "detail & more", source="Test feed")
    ctx.add(WARN, "Autostart", "Suspicious autostart: Updater")
    return ctx


def test_json_and_html_reports(tmp_path):
    ctx = _ctx("laptop")
    j, h = tmp_path / "r.json", tmp_path / "r.html"
    report.save_json(ctx, str(j))
    report.save_html(ctx, str(h))
    data = json.loads(j.read_text(encoding="utf-8"))
    assert data["counts"][HIT] == 1 and data["meta"]["host"] == "laptop"
    page = h.read_text(encoding="utf-8")
    assert "<script>alert(1)" not in page          # everything is escaped
    assert "&lt;script&gt;" in page


def test_combined_report(tmp_path):
    paths = []
    for host in ("laptop", "phone"):
        p = tmp_path / f"{host}.json"
        report.save_json(_ctx(host), str(p))
        paths.append(str(p))
    bom = tmp_path / "bom.json"
    bom.write_bytes(b"\xef\xbb\xbf" + (tmp_path / "phone.json").read_bytes())
    out = tmp_path / "all.html"
    assert fleet.merge(paths + [str(bom)], str(out)) == 3
    page = out.read_text(encoding="utf-8")
    assert "laptop" in page and "phone" in page and "3 devices" in page


def test_merge_rejects_other_json(tmp_path):
    p = tmp_path / "other.json"
    p.write_text('{"hello": 1}', encoding="utf-8")
    try:
        fleet.merge([str(p)], str(tmp_path / "x.html"))
    except ValueError as e:
        assert "Not an SCS Scanner JSON report" in str(e)
    else:
        raise AssertionError("expected ValueError")
