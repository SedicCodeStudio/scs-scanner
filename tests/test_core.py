from scs.core import HIT, OK, SKIP, WARN, count, fmt, human


def test_count_and_plurals():
    assert count(1, "file") == "1 file"
    assert count(0, "file") == "0 files"
    assert count(2, "entry", "entries") == "2 entries"
    assert count(12345, "indicator") == "12,345 indicators"


def test_number_formatting():
    assert fmt(1234567) == "1,234,567"
    assert human(512) == "512 B"
    assert human(1536) == "1.5 KB"
    assert human(5 * 1024 * 1024) == "5.0 MB"


def test_failing_check_does_not_abort(ctx):
    def no_permission(c):
        raise PermissionError("access denied")

    def broken(c):
        raise RuntimeError("boom")

    def fine(c):
        c.add(OK, "Area", "fine")

    ctx.section("A", no_permission)
    ctx.section("B", broken)
    ctx.section("C", fine)
    assert [f.sev for f in ctx.findings] == [SKIP, SKIP, OK]
    assert ctx.findings[0].title == "No permission"
    assert "RuntimeError: boom" in ctx.findings[1].detail


def test_counts(ctx):
    ctx.add(HIT, "X", "a")
    ctx.add(WARN, "X", "b")
    ctx.add(WARN, "X", "c")
    c = ctx.counts()
    assert c[HIT] == 1 and c[WARN] == 2
