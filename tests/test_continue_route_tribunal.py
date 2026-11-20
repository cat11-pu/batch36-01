import threading

import pytest

import continue_route_tribunal as cr

ALLOWED = ["app.example.com", "billing.example.com"]


def gate(**kw):
    return cr.ContinueRouteTribunal(ALLOWED, **kw)


def test_relative_path_is_accepted():
    out = gate().resolve("/orders/7?x=1")
    assert out["url"] == "/orders/7?x=1"
    assert out["host"] is None
    assert out["hops"] == 1


def test_allowed_absolute_url_is_accepted():
    out = gate().resolve("https://app.example.com/orders/7")
    assert out["host"] == "app.example.com"
    assert out["url"] == "https://app.example.com/orders/7"


def test_empty_value_returns_fallback():
    out = gate().resolve("")
    assert out["url"] == "/home"
    assert out["fallback"] is True


def test_network_path_is_rejected():
    with pytest.raises(cr.RouteTribunalError) as exc:
        gate().resolve("//evil.example.net/take")
    assert exc.value.code == "network_path"


def test_backslash_path_is_rejected():
    with pytest.raises(cr.RouteTribunalError) as exc:
        gate().resolve("/\\evil.example.net/take")
    assert exc.value.code == "backslash"


def test_userinfo_is_rejected():
    with pytest.raises(cr.RouteTribunalError) as exc:
        gate().resolve("https://user@app.example.com/orders")
    assert exc.value.code == "userinfo"


def test_plain_http_is_rejected():
    with pytest.raises(cr.RouteTribunalError) as exc:
        gate().resolve("http://app.example.com/orders")
    assert exc.value.code == "bad_scheme"


def test_javascript_scheme_is_rejected():
    with pytest.raises(cr.RouteTribunalError) as exc:
        gate().resolve("javascript:alert(1)")
    assert exc.value.code == "bad_scheme"


def test_non_default_port_is_rejected():
    with pytest.raises(cr.RouteTribunalError) as exc:
        gate().resolve("https://app.example.com:8443/orders")
    assert exc.value.code == "bad_port"


def test_suffix_host_is_rejected():
    with pytest.raises(cr.RouteTribunalError) as exc:
        gate().resolve("https://app.example.com.evil.net/orders")
    assert exc.value.code == "host_not_allowed"


def test_encoded_separator_is_rejected():
    g = gate()
    for value in ["/%2f%2fevil.example.net", "/%252f%252fevil.example.net"]:
        with pytest.raises(cr.RouteTribunalError) as exc:
            g.resolve(value)
        assert exc.value.code == "encoded_separator"


def test_fragment_is_rejected():
    with pytest.raises(cr.RouteTribunalError) as exc:
        gate().resolve("https://app.example.com/orders#frag")
    assert exc.value.code == "fragment"


def test_control_character_is_rejected():
    with pytest.raises(cr.RouteTribunalError) as exc:
        gate().resolve("/orders\r\nX-Evil: 1")
    assert exc.value.code == "control_char"


def test_path_escape_is_rejected():
    with pytest.raises(cr.RouteTribunalError) as exc:
        gate().resolve("/a/../../etc/passwd")
    assert exc.value.code == "path_escape"


def test_concurrent_resolution_is_counted_and_detached():
    g = gate()
    problems = []
    urls = []

    def worker():
        try:
            for _ in range(3):
                urls.append(g.resolve("/orders/7")["url"])
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert urls == ["/orders/7"] * 12
    snap = g.audit()
    assert snap["resolved"] == 12
    snap["resolved"] = 0
    assert g.audit()["resolved"] == 12
