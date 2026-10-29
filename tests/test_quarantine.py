import os

import pytest

from scs import quarantine


def test_round_trip(tmp_path):
    f = tmp_path / "invoice.pdf.exe"
    f.write_bytes(b"MZ harmless test")
    qid = quarantine.quarantine(str(f), "test")
    assert not f.exists()
    entry = [e for e in quarantine.entries() if e["id"] == qid][0]
    assert entry["original"] == str(f) and len(entry["sha256"]) == 64
    stored = [n for n in os.listdir(os.path.join(quarantine.QDIR, qid)) if n.endswith(quarantine.SUFFIX)]
    assert stored == ["invoice.pdf.exe" + quarantine.SUFFIX]
    assert quarantine.restore(qid) == str(f)
    assert f.read_bytes() == b"MZ harmless test"


def test_same_name_twice_gets_unique_ids(tmp_path):
    ids = set()
    for sub in ("a", "b"):
        d = tmp_path / sub
        d.mkdir()
        p = d / "same.txt"
        p.write_text("x")
        ids.add(quarantine.quarantine(str(p)))
    assert len(ids) == 2
    for qid in ids:
        quarantine.delete(qid)
    assert not [e for e in quarantine.entries() if e["id"] in ids]


def test_odd_file_names_are_sanitised(tmp_path):
    p = tmp_path / "bad..name; rm -rf.txt"
    p.write_text("x")
    qid = quarantine.quarantine(str(p))
    assert ".." not in qid and " " not in qid and ";" not in qid
    quarantine.delete(qid)


@pytest.mark.parametrize("bad", ["..", "../x", "a/b", "a\\b", "", "C:x", "x/../../y"])
def test_invalid_ids_are_refused(bad):
    with pytest.raises(ValueError):
        quarantine.restore(bad)
    with pytest.raises(ValueError):
        quarantine.delete(bad)
