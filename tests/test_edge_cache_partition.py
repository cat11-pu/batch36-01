import threading

import pytest

import edge_cache_partition as ep


def request(**over):
    r = {
        "method": "GET",
        "scheme": "https",
        "host": "shop.example.com",
        "path": "/p/1",
        "query": [["b", "2"], ["a", "1"]],
        "headers": {"accept-language": "en", "x-forwarded-host": "evil.example.net"},
    }
    r.update(over)
    return r


def policy(**over):
    p = {"keyed_query": ["a", "b"], "vary": ["accept-language"]}
    p.update(over)
    return p


def partition(**kw):
    return ep.EdgeCachePartition(["shop.example.com", "cdn.example.com"], **kw)


def test_public_key_is_canonical():
    out = partition().derive(request(), policy())
    assert out["visibility"] == "public"
    assert out["cacheable"] is True
    assert out["key"] == "https://shop.example.com/p/1?a=1&b=2|accept-language=en"


def test_duplicate_query_name_is_rejected():
    bad = request(query=[["a", "1"], ["a", "2"]])
    with pytest.raises(ep.CacheKeyError) as exc:
        partition().derive(bad, policy())
    assert exc.value.code == "duplicate_query"


def test_query_outside_allowlist_is_rejected():
    bad = request(query=[["a", "1"], ["utm_source", "x"]])
    with pytest.raises(ep.CacheKeyError) as exc:
        partition().derive(bad, policy())
    assert exc.value.code == "unkeyed_query"


def test_untrusted_host_is_rejected():
    with pytest.raises(ep.CacheKeyError) as exc:
        partition().derive(request(host="evil.example.net"), policy())
    assert exc.value.code == "untrusted_host"


def test_forwarded_host_does_not_change_key():
    clean = request(headers={"accept-language": "en"})
    poisoned = request(headers={"accept-language": "en", "x-forwarded-host": "evil.example.net"})
    p = partition()
    assert p.derive(clean, policy())["key"] == p.derive(poisoned, policy())["key"]
    assert "x-forwarded-host" in p.derive(poisoned, policy())["ignored_headers"]


def test_authorization_forces_private():
    out = partition().derive(request(headers={"authorization": "Bearer x"}), policy())
    assert out["cacheable"] is False
    assert out["visibility"] == "private"


def test_cookie_forces_private():
    out = partition().derive(request(headers={"cookie": "sid=1"}), policy())
    assert out["cacheable"] is False
    assert out["visibility"] == "private"


def test_post_is_not_cacheable():
    with pytest.raises(ep.CacheKeyError) as exc:
        partition().derive(request(method="POST"), policy())
    assert exc.value.code == "method_not_cacheable"


def test_dot_segment_path_is_rejected():
    with pytest.raises(ep.CacheKeyError) as exc:
        partition().derive(request(path="/p/../admin"), policy())
    assert exc.value.code == "bad_path"


def test_encoded_separator_path_is_rejected():
    with pytest.raises(ep.CacheKeyError) as exc:
        partition().derive(request(path="/p%2fadmin"), policy())
    assert exc.value.code == "bad_path"


def test_vary_header_changes_key():
    p = partition()
    en = p.derive(request(), policy())["key"]
    fr = p.derive(request(headers={"accept-language": "fr"}), policy())["key"]
    assert en != fr
    assert fr.endswith("accept-language=fr")


def test_vary_star_is_rejected():
    with pytest.raises(ep.CacheKeyError) as exc:
        partition().derive(request(), policy(vary=["*"]))
    assert exc.value.code == "vary_star"


def test_host_case_and_trailing_dot_are_normalized():
    p = partition()
    a = p.derive(request(host="SHOP.Example.COM."), policy())["key"]
    b = p.derive(request(host="shop.example.com"), policy())["key"]
    assert a == b


def test_overlong_key_is_rejected():
    with pytest.raises(ep.CacheKeyError) as exc:
        partition(max_key_len=40).derive(request(path="/very/long/product/path"), policy())
    assert exc.value.code == "key_too_long"


def test_concurrent_derivation_is_consistent_and_counted():
    p = partition()
    keys = []
    problems = []

    def worker():
        try:
            for _ in range(2):
                keys.append(p.derive(request(), policy())["key"])
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert len(keys) == 8
    assert len(set(keys)) == 1
    snap = p.snapshot()
    assert snap["derived"] == 8
    snap["derived"] = 0
    assert p.snapshot()["derived"] == 8
