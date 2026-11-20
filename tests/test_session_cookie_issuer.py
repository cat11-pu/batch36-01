import threading

import pytest

import session_cookie_issuer as sc


def attrs(**over):
    a = {"Secure": True, "HttpOnly": True, "Path": "/", "SameSite": "Lax"}
    a.update(over)
    return a


def issuer(**kw):
    return sc.SessionCookieIssuer(**kw)


def test_host_prefix_cookie_is_rendered():
    out = issuer().issue("__Host-sid", "abc", attrs())
    assert out["header"].startswith("__Host-sid=abc")
    assert "Secure" in out["header"]
    assert "Path=/" in out["header"]
    assert "Domain" not in out["header"]


def test_host_prefix_with_domain_is_rejected():
    with pytest.raises(sc.CookieIssueError) as exc:
        issuer().issue("__Host-sid", "abc", attrs(Domain="example.com"))
    assert exc.value.code == "host_prefix_domain"


def test_host_prefix_with_non_root_path_is_rejected():
    with pytest.raises(sc.CookieIssueError) as exc:
        issuer().issue("__Host-sid", "abc", attrs(Path="/admin"))
    assert exc.value.code == "host_prefix_path"


def test_host_prefix_without_secure_is_rejected():
    a = attrs()
    del a["Secure"]
    with pytest.raises(sc.CookieIssueError) as exc:
        issuer().issue("__Host-sid", "abc", a)
    assert exc.value.code == "secure_required"


def test_secure_prefix_without_secure_is_rejected():
    a = attrs()
    del a["Secure"]
    with pytest.raises(sc.CookieIssueError) as exc:
        issuer().issue("__Secure-sid", "abc", a)
    assert exc.value.code == "secure_required"


def test_secure_prefix_with_domain_is_accepted():
    out = issuer().issue("__Secure-sid", "abc", attrs(Domain="example.com"))
    assert "__Secure-sid=abc" in out["header"]


def test_samesite_none_without_secure_is_rejected():
    a = attrs(SameSite="None")
    del a["Secure"]
    with pytest.raises(sc.CookieIssueError) as exc:
        issuer(require_secure=False).issue("sid", "abc", a)
    assert exc.value.code == "samesite_none_insecure"


def test_partitioned_without_secure_is_rejected():
    a = {"Path": "/", "SameSite": "None", "Partitioned": True}
    with pytest.raises(sc.CookieIssueError) as exc:
        issuer(require_secure=False).issue("sid", "abc", a)
    assert exc.value.code == "partitioned_insecure"


def test_invalid_cookie_name_is_rejected():
    with pytest.raises(sc.CookieIssueError) as exc:
        issuer().issue("sid x", "abc", attrs())
    assert exc.value.code == "bad_name"


def test_invalid_cookie_value_is_rejected():
    with pytest.raises(sc.CookieIssueError) as exc:
        issuer().issue("sid", "a;b", attrs())
    assert exc.value.code == "bad_value"


def test_unknown_attribute_is_rejected():
    with pytest.raises(sc.CookieIssueError) as exc:
        issuer().issue("sid", "abc", attrs(Bogus=True))
    assert exc.value.code == "unknown_attribute"


def test_negative_max_age_is_rejected():
    with pytest.raises(sc.CookieIssueError) as exc:
        issuer().issue("sid", "abc", attrs(**{"Max-Age": "-1"}))
    assert exc.value.code == "bad_max_age"


def test_parse_two_cookies():
    out = issuer().parse([
        "sid=abc; Path=/; Secure; HttpOnly",
        "__Host-token=xyz; Path=/; Secure",
    ])
    assert [c["name"] for c in out] == ["sid", "__Host-token"]


def test_parse_duplicate_cookie_name_is_rejected():
    with pytest.raises(sc.CookieIssueError) as exc:
        issuer().parse(["sid=a; Path=/", "sid=b; Path=/"])
    assert exc.value.code == "duplicate_cookie"


def test_concurrent_issue_is_counted_and_detached():
    s = issuer()
    problems = []
    headers = []

    def worker():
        try:
            for _ in range(2):
                headers.append(s.issue("sid", "abc", attrs())["header"])
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert len(headers) == 10
    snap = s.snapshot()
    assert snap["issued"] == 10
    snap["issued"] = 0
    assert s.snapshot()["issued"] == 10
