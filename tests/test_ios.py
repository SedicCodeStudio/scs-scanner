import plistlib
import sqlite3

from scs import ioc, ios
from scs.core import HIT, INFO


def _make_backup(root):
    root.mkdir()
    plistlib.dump({"IsEncrypted": False, "Applications": {"com.evil.test": {}, "net.whatsapp.WhatsApp": {}}},
                  (root / "Manifest.plist").open("wb"))
    plistlib.dump({"Device Name": "Test iPhone", "Product Type": "iPhone15,2", "Product Version": "16.5"},
                  (root / "Info.plist").open("wb"))
    sms_id = "3d0d7e5fb2ce288813306e4d4636395e047a3d28"
    ne_id = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
    con = sqlite3.connect(root / "Manifest.db")
    con.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    con.execute("INSERT INTO Files VALUES (?,?,?,1,NULL)", (sms_id, "HomeDomain", "Library/SMS/sms.db"))
    con.execute("INSERT INTO Files VALUES (?,?,?,1,NULL)", (ne_id, "SystemPreferencesDomain",
                                                           "SystemConfiguration/com.apple.networkextension.plist"))
    con.commit()
    con.close()
    (root / sms_id[:2]).mkdir()
    sms = sqlite3.connect(root / sms_id[:2] / sms_id)
    sms.execute("CREATE TABLE message (text TEXT)")
    sms.execute("CREATE TABLE handle (id TEXT)")
    sms.execute("INSERT INTO message VALUES ('Your parcel: https://track.evil-test.example/p/123')")
    sms.execute("INSERT INTO message VALUES ('See you at 8')")
    sms.execute("INSERT INTO handle VALUES ('+491701234567')")
    sms.commit()
    sms.close()
    (root / ne_id[:2]).mkdir()
    plistlib.dump({"VPN": {"com.evil.test.tunnel": {"Name": "Free VPN"}}, "Other": ["com.apple.something.internal"]},
                  (root / ne_id[:2] / ne_id).open("wb"))
    return root


def test_backup_checks(ctx, tmp_path):
    backup = _make_backup(tmp_path / "00008110-TEST")
    idx = ioc.IOCIndex()
    idx.add("domain", "evil-test.example", "Test feed", "TestSpy")
    idx.add("app_id", "com.evil.test", "Test feed", "TestSpy")
    idx.add("app_id", "com.evil.test.tunnel", "Test feed", "TestSpy")
    ctx.ioc = idx
    ios.check_backup(ctx, str(backup))
    hits = [f.title for f in ctx.findings if f.sev == HIT]
    assert "Known spyware app: com.evil.test" in hits
    assert any("evil-test.example" in t for t in hits)                      # link in an SMS
    assert "VPN/network extension of a known spyware: com.evil.test.tunnel" in hits
    assert any(f.title == "iOS 16.5 is out of date" for f in ctx.findings)
    assert ctx.scope == "iphone-00008110-TEST"
    assert any(f.sev == INFO and f.title.startswith("Test iPhone") for f in ctx.findings)


def test_not_a_backup(ctx, tmp_path):
    ios.check_backup(ctx, str(tmp_path))
    assert ctx.findings[-1].title == "Folder is not an iPhone backup"
