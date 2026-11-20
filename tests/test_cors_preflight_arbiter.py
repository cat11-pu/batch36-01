import threading

import pytest

import cors_preflight_arbiter as cp

ORIGINS = ["https://app.example.com", "https://admin.example.com"]


def arbiter(**kw):
    base = {
        "allowed_origins": ORIGINS,
        "allowed_methods": ("GET", "POST", "PUT"),
        "allowed_headers": ("content-type", "x-trace"),
        "max_age": 600,
        "credentials": True,
    }
    base.update(kw)
    return cp.CorsPreflightArbiter(**base)


def actual(**over):
    r = {"origin": "https://app.example.com", "method": "GET", "preflight": False}
    r.update(over)
    return r


def preflight(**over):
    r = {
        "origin": "https://app.example.com",
        "method": "PUT",
        "requested_headers": ["x-trace"],
        "preflight": True,
        "max_age": 300,
    }
    r.update(over)
    return r


def test_allowed_actual_request_gets_origin_and_credentials():
    out = arbiter().decide(actual())
    headers = out["headers"]
    assert headers["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert headers["Access-Control-Allow-Credentials"] == "true"
    assert headers["Vary"] == "Origin"
    assert "Access-Control-Allow-Methods" not in headers


def test_allowed_preflight_gets_methods_and_headers():
    out = arbiter().decide(preflight())
    headers = out["headers"]
    assert headers["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert headers["Access-Control-Allow-Methods"] == "GET, POST, PUT"
    assert headers["Access-Control-Allow-Headers"] == "content-type, x-trace"
    assert headers["Vary"] == "Origin"


def test_null_origin_is_rejected():
    with pytest.raises(cp.CorsPolicyError) as exc:
        arbiter().decide(actual(origin="null"))
    assert exc.value.code == "null_origin"


def test_missing_origin_is_rejected():
    with pytest.raises(cp.CorsPolicyError) as exc:
        arbiter().decide(actual(origin=None))
    assert exc.value.code == "origin_missing"


def test_suffix_host_is_not_trusted():
    with pytest.raises(cp.CorsPolicyError) as exc:
        arbiter().decide(actual(origin="https://app.example.com.evil.net"))
    assert exc.value.code == "origin_not_allowed"


def test_origin_with_trailing_slash_is_rejected():
    with pytest.raises(cp.CorsPolicyError) as exc:
        arbiter().decide(actual(origin="https://app.example.com/"))
    assert exc.value.code == "bad_origin"


def test_comma_joined_origin_is_rejected():
    with pytest.raises(cp.CorsPolicyError) as exc:
        arbiter().decide(actual(origin="https://app.example.com, https://evil.example.net"))
    assert exc.value.code == "bad_origin"


def test_disallowed_method_is_rejected():
    with pytest.raises(cp.CorsPolicyError) as exc:
        arbiter().decide(preflight(method="DELETE"))
    assert exc.value.code == "method_not_allowed"


def test_disallowed_header_is_rejected():
    with pytest.raises(cp.CorsPolicyError) as exc:
        arbiter().decide(preflight(requested_headers=["x-trace", "x-evil"]))
    assert exc.value.code == "header_not_allowed"


def test_max_age_is_capped():
    out = arbiter().decide(preflight(max_age=9999))
    assert out["headers"]["Access-Control-Max-Age"] == "600"


def test_wildcard_with_credentials_is_rejected_at_construction():
    with pytest.raises(ValueError):
        cp.CorsPreflightArbiter(["*"], credentials=True)


def test_wildcard_without_credentials_is_allowed():
    a = cp.CorsPreflightArbiter(["*"], credentials=False)
    out = a.decide(actual(origin="https://any.example.net"))
    assert out["headers"]["Access-Control-Allow-Origin"] == "*"
    assert "Access-Control-Allow-Credentials" not in out["headers"]


def test_private_network_request_is_rejected():
    with pytest.raises(cp.CorsPolicyError) as exc:
        arbiter().decide(preflight(private_network=True))
    assert exc.value.code == "private_network_denied"


def test_error_response_has_no_cors_permission():
    out = arbiter().render_error()
    assert "Access-Control-Allow-Origin" not in out["headers"]
    assert "Access-Control-Allow-Credentials" not in out["headers"]


def test_concurrent_decisions_are_counted_and_detached():
    a = arbiter()
    problems = []
    origins = []

    def worker():
        try:
            for _ in range(2):
                origins.append(a.decide(actual())["headers"]["Access-Control-Allow-Origin"])
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert origins == ["https://app.example.com"] * 8
    snap = a.snapshot()
    assert snap["decisions"] == 8
    snap["decisions"] = 0
    assert a.snapshot()["decisions"] == 8
