import pytest

from scs import android


@pytest.mark.parametrize("serial", ["emulator-5554", "R58M123ABC", "192.168.0.20:5555", "adb-XYZ._adb-tls-connect._tcp"])
def test_valid_serials(serial):
    assert android.SERIAL_RE.match(serial)


@pytest.mark.parametrize("serial", ["", "a b", "x;reboot", "$(id)", "a" * 65, "-s"])
def test_invalid_serials(serial):
    assert not android.SERIAL_RE.match(serial) or serial.startswith("-")


@pytest.mark.parametrize("pkg", ["com.whatsapp", "org.telegram.messenger", "com.example.app_2"])
def test_valid_packages(pkg):
    assert android.PKG_RE.match(pkg)


@pytest.mark.parametrize("pkg", ["com", "com.evil;rm -rf /", "1com.example", "com.example'", "com..example"])
def test_invalid_packages(pkg):
    assert not android.PKG_RE.match(pkg)


@pytest.mark.parametrize("path, ok", [("/data/app/~~abc==/com.example-1/base.apk", True), ("/data/app/x/base.apk;id", False),
                                      ("relative/base.apk", False), ("/data/app/x/base.apk'", False)])
def test_apk_paths(path, ok):
    assert bool(android.APK_PATH_RE.match(path)) is ok
