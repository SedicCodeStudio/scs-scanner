import pytest

from scs import ioc, net
from scs.core import HIT, OK, WARN


@pytest.fixture(autouse=True)
def no_reverse_lookup(monkeypatch):
    monkeypatch.setattr(net, "_reverse", lambda ip, timeout=2.0: None)


def test_classify():
    assert net.classify("192.168.1.1")[0] == "local"
    assert net.classify("127.0.0.53")[0] == "local"
    assert net.classify("100.100.100.100")[0] == "local"
    assert net.classify("9.9.9.9") == ("known", "Quad9")
    assert net.classify("1.1.1.1") == ("known", "Cloudflare")
    assert net.classify("45.77.1.2") == ("unknown", "unknown public server")
    assert net.classify("not-an-ip")[0] == "unknown"


def test_dns_servers(ctx):
    net.judge_dns(ctx, [("192.168.1.1", "Ethernet"), ("9.9.9.9", "Ethernet"), ("45.77.1.2", "Ethernet"),
                        ("45.77.1.3", "wg0")])
    warns = [f.title for f in ctx.findings if f.sev == WARN]
    assert warns == ["Unknown DNS server: 45.77.1.2"]  # wg0 is a VPN interface – its DNS server is expected


def test_certificates(ctx):
    net.judge_certs(ctx, ["CN=Superfish, Inc.", "CN=DigiCert Global Root G2"], "test store")
    assert [f.sev for f in ctx.findings] == [WARN]
    net.judge_certs(ctx, ["CN=ISRG Root X1"], "test store")
    assert ctx.findings[-1].sev == OK and ctx.findings[-1].title.startswith("1 trusted root certificate checked")


def test_proxy_and_vpn_server_hits(ctx):
    idx = ioc.IOCIndex()
    idx.add("domain", "evil-test.example", "Test feed", "TestSpy")
    ctx.ioc = idx
    net.judge_proxy(ctx, [("System proxy", "proxy.evil-test.example:8080"), ("PAC script", "http://127.0.0.1:9000/proxy.pac")])
    assert [f.sev for f in ctx.findings] == [HIT, WARN]
    net.check_vpn_servers(ctx, [("Work", "gw.evil-test.example"), ("Home", "vpn.example.org")])
    assert ctx.findings[-1].sev == HIT and "gw.evil-test.example" in ctx.findings[-1].title


def test_vpn_report(ctx):
    net.report_vpn(ctx, ["NordLynx", "NordLynx"], ["Adapter: NordLynx (NordLynx Tunnel) - Up"])
    assert ctx.vpn == ["NordLynx"] and ctx.meta["vpn"] == "NordLynx"
    titles = [f.title for f in ctx.findings]
    assert "VPN active: NordLynx" in titles
    assert "1 VPN connection or VPN app configured" in titles
