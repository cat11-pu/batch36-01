import threading

import pytest

import vhost_route_guard as vr

SITES = {
    "shop.example.com": {"site": "shop", "aliases": ["www.shop.example.com"]},
    "admin.example.com": {"site": "admin", "aliases": []},
}


def router(**kw):
    return vr.VirtualHostRouter(SITES, **kw)


def req(host="shop.example.com", target="/login", extra=None, sni="shop.example.com",
        scheme="https", host_headers=None, client_ip="203.0.113.9"):
    headers = list(host_headers) if host_headers is not None else []
    if host_headers is None and host is not None:
        headers.append(["Host", host])
    if extra:
        headers.extend(extra)
    return {
        "scheme": scheme,
        "target": target,
        "headers": headers,
        "sni": sni,
        "client_ip": client_ip,
    }


def test_known_host_resolves_site():
    out = router().resolve(req())
    assert out["site"] == "shop"
    assert out["host"] == "shop.example.com"


def test_host_case_and_trailing_dot_are_normalized():
    out = router().resolve(req(host="SHOP.Example.COM."))
    assert out["site"] == "shop"
    assert out["host"] == "shop.example.com"


def test_alias_resolves_to_canonical_site():
    out = router().resolve(req(host="www.shop.example.com"))
    assert out["site"] == "shop"


def test_missing_host_is_rejected():
    with pytest.raises(vr.HostRouteError) as exc:
        router().resolve(req(host=None))
    assert exc.value.code == "missing_host"


def test_duplicate_host_is_rejected():
    headers = [["Host", "shop.example.com"], ["host", "admin.example.com"]]
    with pytest.raises(vr.HostRouteError) as exc:
        router().resolve(req(host=None, host_headers=headers))
    assert exc.value.code == "duplicate_host"


def test_comma_and_userinfo_hosts_are_rejected():
    r = router()
    for host in ["shop.example.com,admin.example.com", "user@shop.example.com"]:
        with pytest.raises(vr.HostRouteError) as exc:
            r.resolve(req(host=host))
        assert exc.value.code == "bad_host"


def test_unknown_host_is_rejected():
    with pytest.raises(vr.HostRouteError) as exc:
        router().resolve(req(host="ghost.example.net"))
    assert exc.value.code == "unknown_host"


def test_non_default_port_is_rejected():
    with pytest.raises(vr.HostRouteError) as exc:
        router().resolve(req(host="shop.example.com:8443"))
    assert exc.value.code == "bad_port"


def test_absolute_target_with_other_authority_is_rejected():
    with pytest.raises(vr.HostRouteError) as exc:
        router().resolve(req(target="https://admin.example.com/login"))
    assert exc.value.code == "authority_mismatch"


def test_absolute_target_with_matching_authority_is_accepted():
    out = router().resolve(req(target="https://shop.example.com/login"))
    assert out["site"] == "shop"


def test_untrusted_forwarded_host_is_ignored():
    out = router().resolve(req(extra=[["X-Forwarded-Host", "admin.example.com"]]))
    assert out["site"] == "shop"


def test_trusted_proxy_conflict_is_rejected():
    r = router(trusted_proxies=("10.0.0.1",))
    with pytest.raises(vr.HostRouteError) as exc:
        r.resolve(req(extra=[["X-Forwarded-Host", "admin.example.com"]], client_ip="10.0.0.1"))
    assert exc.value.code == "forwarded_host_mismatch"


def test_sni_mismatch_is_rejected():
    with pytest.raises(vr.HostRouteError) as exc:
        router().resolve(req(sni="admin.example.com"))
    assert exc.value.code == "sni_mismatch"


def test_host_with_whitespace_is_rejected():
    with pytest.raises(vr.HostRouteError) as exc:
        router().resolve(req(host="shop.example.com "))
    assert exc.value.code == "bad_host"


def test_concurrent_resolution_is_counted_and_detached():
    r = router()
    results = []
    problems = []

    def worker():
        try:
            for _ in range(2):
                results.append(r.resolve(req())["site"])
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert results == ["shop"] * 10
    snap = r.snapshot()
    assert snap["resolved"] == 10
    snap["resolved"] = 0
    assert r.snapshot()["resolved"] == 10
