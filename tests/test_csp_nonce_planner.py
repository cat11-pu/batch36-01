import itertools
import threading

import pytest

import csp_nonce_planner as cn

NONCE = "A" * 22


def policy(**over):
    p = {
        "directives": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "'unsafe-inline'"],
        },
        "report_only": False,
        "nonce_directive": "script-src",
    }
    p.update(over)
    return p


def planner(source=None, **kw):
    return cn.CspNoncePlanner(source or (lambda: NONCE), **kw)


def test_policy_gets_nonce_and_drops_unsafe_inline():
    out = planner().build(policy())
    assert out["header_name"] == "Content-Security-Policy"
    assert "nonce-%s" % NONCE in out["header"]
    assert "unsafe-inline" not in out["directives"]["script-src"]
    assert out["unsafe_inline_removed"] is True


def test_report_only_header_name():
    out = planner().build(policy(report_only=True))
    assert out["header_name"] == "Content-Security-Policy-Report-Only"


def test_short_nonce_is_rejected():
    with pytest.raises(cn.CspPlanError) as exc:
        planner(lambda: "short").build(policy())
    assert exc.value.code == "bad_nonce_source"


def test_nonce_with_invalid_characters_is_rejected():
    with pytest.raises(cn.CspPlanError) as exc:
        planner(lambda: "A" * 20 + "+=").build(policy())
    assert exc.value.code == "bad_nonce_source"


def test_nonce_reuse_inside_window_is_rejected():
    p = planner()
    p.build(policy(), now=0)
    with pytest.raises(cn.CspPlanError) as exc:
        p.build(policy(), now=10)
    assert exc.value.code == "nonce_reused"


def test_nonce_reuse_after_window_is_allowed():
    p = planner()
    first = p.build(policy(), now=0)
    second = p.build(policy(), now=400)
    assert first["nonce"] == second["nonce"]


def test_strict_dynamic_without_script_nonce_is_rejected():
    bad = policy(
        directives={"script-src": ["'strict-dynamic'"]},
        nonce_directive="style-src",
    )
    with pytest.raises(cn.CspPlanError) as exc:
        planner().build(bad)
    assert exc.value.code == "strict_dynamic_without_nonce"


def test_duplicate_directive_values_are_removed():
    out = planner().build(
        policy(directives={"script-src": ["'self'", "'self'", "https://cdn.example.com"]})
    )
    assert out["directives"]["script-src"].count("'self'") == 1


def test_invalid_directive_name_is_rejected():
    bad = policy(directives={"Script Src": ["'self'"]})
    with pytest.raises(cn.CspPlanError) as exc:
        planner().build(bad)
    assert exc.value.code == "bad_directive"


def test_empty_directive_value_is_rejected():
    bad = policy(directives={"script-src": [""]})
    with pytest.raises(cn.CspPlanError) as exc:
        planner().build(bad)
    assert exc.value.code == "bad_directive"


def test_report_is_normalized_and_truncated():
    payload = {
        "type": "csp-violation",
        "blocked-uri": "https://evil.example.net/" + "x" * 300,
        "document-uri": "https://app.example.com/page",
        "line-number": 12,
    }
    out = planner().report(payload)
    assert out["type"] == "csp-violation"
    assert len(out["blocked-uri"]) <= 200
    assert "line-number" in out


def test_report_with_sensitive_field_is_rejected():
    payload = {
        "type": "csp-violation",
        "blocked-uri": "https://evil.example.net/x",
        "authorization": "Bearer secret",
    }
    with pytest.raises(cn.CspPlanError) as exc:
        planner().report(payload)
    assert exc.value.code == "sensitive_field"


def test_oversized_report_is_rejected():
    payload = {
        "type": "csp-violation",
        "blocked-uri": "https://evil.example.net/x",
        "sample": "s" * 5000,
    }
    with pytest.raises(cn.CspPlanError) as exc:
        planner().report(payload)
    assert exc.value.code == "report_too_large"


def test_nonce_is_placed_in_configured_directive():
    out = planner().build(
        policy(
            directives={"script-src": ["'self'"], "style-src": ["'self'"]},
            nonce_directive="style-src",
        )
    )
    assert any(v.startswith("'nonce-") for v in out["directives"]["style-src"])
    assert not any(v.startswith("'nonce-") for v in out["directives"]["script-src"])


def test_concurrent_builds_are_unique_and_counted():
    counter = itertools.count()
    lock = threading.Lock()

    def source():
        with lock:
            n = next(counter)
        return "N" * 10 + str(n).zfill(12)

    p = planner(source)
    problems = []
    nonces = []

    def worker():
        try:
            nonces.append(p.build(policy(), now=0)["nonce"])
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert len(set(nonces)) == 8
    snap = p.snapshot()
    assert snap["built"] == 8
    snap["built"] = 0
    assert p.snapshot()["built"] == 8
