import json

import pytest

from scs import ioc

SHA = "a" * 64
BUNDLE = {
    "type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000000",
    "objects": [
        {"type": "malware", "id": "malware--1", "name": "TestSpy", "is_family": True},
        {"type": "indicator", "id": "indicator--1", "pattern": "[domain-name:value = 'evil-test.example']"},
        {"type": "indicator", "id": "indicator--2", "pattern": f"[file:hashes.sha256 = '{SHA.upper()}']"},
        {"type": "indicator", "id": "indicator--3", "pattern": "[app:id = 'com.evil.test']"},
        {"type": "indicator", "id": "indicator--4", "pattern": "[ipv4-addr:value = '203.0.113.66']"},
        {"type": "indicator", "id": "indicator--5", "pattern": "[process:name = 'evilspy']"},
        {"type": "indicator", "id": "indicator--6", "pattern": "[email-addr:value = 'Spy@Evil-Test.example']"},
        {"type": "relationship", "id": "relationship--1", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "malware--1"},
    ],
}


@pytest.fixture
def index(tmp_path):
    p = tmp_path / "test.stix2"
    p.write_text(json.dumps(BUNDLE), encoding="utf-8")
    idx = ioc.IOCIndex()
    assert idx.load_stix(str(p), "Test feed") == 6
    return idx


def test_types_are_normalised(index):
    assert index.get("sha256", SHA) == ("Test feed", "TestSpy")
    assert index.get("app_id", "COM.EVIL.TEST")
    assert index.get("email", "spy@evil-test.example")
    assert index.get("process", "evilspy")
    assert index.get("process", "EvilSpy") is None  # process names are case sensitive


def test_domain_matching_includes_subdomains(index):
    assert index.match_domain("cdn.login.evil-test.example")[0] == "evil-test.example"
    assert index.match_domain("EVIL-TEST.example.")[0] == "evil-test.example"
    assert index.match_domain("evil-test.example.com") is None
    assert index.match_domain("notevil-test.example") is None
    assert index.match_domain("203.0.113.66:443")[0] == "203.0.113.66"


def test_parse_index():
    text = """indicators:
  -
    type: github
    name: First feed
    github:
      owner: someone
      repo: iocs
      branch: main
      path: a/first.stix2

  -
    type: github
    name: Second feed
    github:
      owner: other
      repo: data
      branch: master
      path: second.stix2
"""
    assert ioc.parse_index(text) == [
        ("First feed", "https://raw.githubusercontent.com/someone/iocs/main/a/first.stix2"),
        ("Second feed", "https://raw.githubusercontent.com/other/data/master/second.stix2"),
    ]


def test_only_https_downloads():
    with pytest.raises(ValueError):
        ioc._get("http://example.org/feed.json")
    with pytest.raises(ValueError):
        ioc._get("file:///etc/passwd")


def test_selftest_hash_is_known():
    idx = ioc.IOCIndex().load_dir(directory="/nonexistent-folder")
    assert idx.get("sha256", ioc.SELFTEST_SHA256)
