import pytest

import link_preview_warden as lw

PUBLIC = "93.184.216.34"


class FakeNet:
    def __init__(self, resolver_map, routes):
        self.resolver_map = resolver_map
        self.routes = routes
        self.resolve_calls = []
        self.fetch_calls = []

    def resolve(self, host):
        self.resolve_calls.append(host)
        seq = self.resolver_map[host]
        if isinstance(seq[0], list):
            if len(seq) > 1:
                return seq.pop(0)
            return seq[0]
        return seq

    def fetch(self, url, address):
        self.fetch_calls.append((url, address))
        return self.routes[url]


def warden(net, **kw):
    return lw.LinkPreviewWarden(net.resolve, net.fetch, **kw)


def test_public_preview_is_returned():
    net = FakeNet(
        {"cdn.example.net": [PUBLIC]},
        {"https://cdn.example.net/a.png": {"status": 200, "digest": "abc", "size": 10}},
    )
    out = warden(net).inspect("https://cdn.example.net/a.png")
    assert out["final_url"] == "https://cdn.example.net/a.png"
    assert out["hops"] == 0
    assert out["address"] == PUBLIC
    assert out["digest"] == "abc"


def test_plain_scheme_is_rejected():
    net = FakeNet({"cdn.example.net": [PUBLIC]}, {})
    with pytest.raises(lw.PreviewError) as exc:
        warden(net).inspect("http://cdn.example.net/a.png")
    assert exc.value.code == "scheme_not_allowed"


def test_userinfo_is_rejected():
    net = FakeNet({"cdn.example.net": [PUBLIC]}, {})
    with pytest.raises(lw.PreviewError) as exc:
        warden(net).inspect("https://user:pw@cdn.example.net/a.png")
    assert exc.value.code == "userinfo_not_allowed"


def test_non_default_port_is_rejected():
    net = FakeNet({"cdn.example.net": [PUBLIC]}, {})
    with pytest.raises(lw.PreviewError) as exc:
        warden(net).inspect("https://cdn.example.net:8443/a.png")
    assert exc.value.code == "port_not_allowed"


def test_bare_address_literal_is_rejected():
    net = FakeNet({PUBLIC: [PUBLIC]}, {})
    with pytest.raises(lw.PreviewError) as exc:
        warden(net).inspect("https://" + PUBLIC + "/a.png")
    assert exc.value.code == "ip_literal"


def test_loopback_resolution_is_rejected():
    net = FakeNet({"cdn.example.net": ["127.0.0.1"]}, {})
    with pytest.raises(lw.PreviewError) as exc:
        warden(net).inspect("https://cdn.example.net/a.png")
    assert exc.value.code == "private_address"


def test_mixed_public_and_private_resolution_is_rejected():
    net = FakeNet({"cdn.example.net": [PUBLIC, "10.0.0.5"]}, {})
    with pytest.raises(lw.PreviewError) as exc:
        warden(net).inspect("https://cdn.example.net/a.png")
    assert exc.value.code == "private_address"


def test_ipv6_loopback_is_rejected():
    net = FakeNet({"cdn.example.net": ["::1"]}, {})
    with pytest.raises(lw.PreviewError) as exc:
        warden(net).inspect("https://cdn.example.net/a.png")
    assert exc.value.code == "private_address"


def test_redirect_to_metadata_address_is_rejected():
    net = FakeNet(
        {"cdn.example.net": [PUBLIC], "meta.example.net": ["169.254.169.254"]},
        {"https://cdn.example.net/a.png": {"status": 302, "location": "https://meta.example.net/latest"}},
    )
    with pytest.raises(lw.PreviewError) as exc:
        warden(net).inspect("https://cdn.example.net/a.png")
    assert exc.value.code == "private_address"


def test_hop_limit_is_enforced():
    net = FakeNet(
        {"cdn.example.net": [PUBLIC]},
        {
            "https://cdn.example.net/1.png": {"status": 302, "location": "/2.png"},
            "https://cdn.example.net/2.png": {"status": 302, "location": "/3.png"},
            "https://cdn.example.net/3.png": {"status": 302, "location": "/4.png"},
            "https://cdn.example.net/4.png": {"status": 200, "digest": "d", "size": 1},
        },
    )
    with pytest.raises(lw.PreviewError) as exc:
        warden(net, max_hops=2).inspect("https://cdn.example.net/1.png")
    assert exc.value.code == "too_many_hops"


def test_redirect_loop_is_rejected():
    net = FakeNet(
        {"cdn.example.net": [PUBLIC]},
        {
            "https://cdn.example.net/1.png": {"status": 302, "location": "/2.png"},
            "https://cdn.example.net/2.png": {"status": 302, "location": "/1.png"},
        },
    )
    with pytest.raises(lw.PreviewError) as exc:
        warden(net, max_hops=5).inspect("https://cdn.example.net/1.png")
    assert exc.value.code == "redirect_loop"


def test_relative_location_is_joined():
    net = FakeNet(
        {"cdn.example.net": [PUBLIC]},
        {
            "https://cdn.example.net/a.png": {"status": 302, "location": "/b.png"},
            "https://cdn.example.net/b.png": {"status": 200, "digest": "bee", "size": 4},
        },
    )
    out = warden(net).inspect("https://cdn.example.net/a.png")
    assert out["final_url"] == "https://cdn.example.net/b.png"
    assert out["hops"] == 1


def test_oversized_payload_is_rejected():
    net = FakeNet(
        {"cdn.example.net": [PUBLIC]},
        {"https://cdn.example.net/a.png": {"status": 200, "digest": "big", "size": 5000}},
    )
    with pytest.raises(lw.PreviewError) as exc:
        warden(net, max_bytes=2048).inspect("https://cdn.example.net/a.png")
    assert exc.value.code == "payload_too_large"


def test_resolution_drift_is_rejected():
    net = FakeNet(
        {"cdn.example.net": [[PUBLIC], ["1.1.1.1"]]},
        {"https://cdn.example.net/a.png": {"status": 302, "location": "/b.png"}},
    )
    with pytest.raises(lw.PreviewError) as exc:
        warden(net).inspect("https://cdn.example.net/a.png")
    assert exc.value.code == "dns_rebind"


def test_snapshot_counts_and_copy():
    net = FakeNet(
        {"cdn.example.net": [PUBLIC]},
        {"https://cdn.example.net/a.png": {"status": 200, "digest": "abc", "size": 10}},
    )
    w = warden(net)
    w.inspect("https://cdn.example.net/a.png")
    with pytest.raises(lw.PreviewError):
        w.inspect("http://cdn.example.net/a.png")
    snap = w.snapshot()
    assert snap["inspected"] == 1
    assert snap["blocked"] == 1
    assert snap["last_code"] == "scheme_not_allowed"
    snap["inspected"] = 0
    assert w.snapshot()["inspected"] == 1
