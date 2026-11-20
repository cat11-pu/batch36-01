import base64
import hashlib
import threading

import pytest

import asset_digest_sentinel as ag

CONTENT = b"console.log('v1');"


def digest(alg, content=CONTENT):
    return base64.b64encode(hashlib.new(alg, content).digest()).decode("ascii")


def token(alg, content=CONTENT):
    return "%s-%s" % (alg, digest(alg, content))


def tag(integrity=None, **over):
    t = {
        "src": "https://cdn.example.com/app.js",
        "integrity": integrity if integrity is not None else token("sha256"),
        "crossorigin": "anonymous",
    }
    t.update(over)
    return t


def gate(**kw):
    return ag.AssetDigestSentinel(**kw)


def test_sha256_integrity_passes():
    out = gate().verify(tag(), CONTENT)
    assert out["ok"] is True
    assert out["algorithm"] == "sha256"
    assert out["index"] == 0


def test_sha384_integrity_passes():
    out = gate().verify(tag(token("sha384")), CONTENT)
    assert out["algorithm"] == "sha384"


def test_missing_integrity_is_rejected():
    t = tag()
    del t["integrity"]
    with pytest.raises(ag.DigestSentinelError) as exc:
        gate().verify(t, CONTENT)
    assert exc.value.code == "missing_integrity"


def test_empty_integrity_is_rejected():
    with pytest.raises(ag.DigestSentinelError) as exc:
        gate().verify(tag(""), CONTENT)
    assert exc.value.code == "missing_integrity"


def test_md5_only_is_rejected():
    with pytest.raises(ag.DigestSentinelError) as exc:
        gate().verify(tag("md5-%s" % digest("md5")), CONTENT)
    assert exc.value.code == "unsupported_algorithm"


def test_token_without_dash_is_rejected():
    with pytest.raises(ag.DigestSentinelError) as exc:
        gate().verify(tag("deadbeef"), CONTENT)
    assert exc.value.code == "bad_integrity"


def test_invalid_base64_is_rejected():
    with pytest.raises(ag.DigestSentinelError) as exc:
        gate().verify(tag("sha256-%%%%"), CONTENT)
    assert exc.value.code == "bad_digest"


def test_wrong_digest_length_is_rejected():
    with pytest.raises(ag.DigestSentinelError) as exc:
        gate().verify(tag("sha256-YWJj"), CONTENT)
    assert exc.value.code == "bad_digest"


def test_digest_mismatch_is_rejected():
    other = token("sha256", b"other")
    with pytest.raises(ag.DigestSentinelError) as exc:
        gate().verify(tag(other), CONTENT)
    assert exc.value.code == "digest_mismatch"


def test_strongest_algorithm_wins():
    value = "%s %s" % (token("sha512", b"other"), token("sha256"))
    with pytest.raises(ag.DigestSentinelError) as exc:
        gate().verify(tag(value), CONTENT)
    assert exc.value.code == "digest_mismatch"


def test_any_matching_digest_of_same_strength_passes():
    value = "%s %s" % (token("sha256", b"other"), token("sha256"))
    out = gate().verify(tag(value), CONTENT)
    assert out["ok"] is True
    assert out["index"] == 1


def test_unknown_algorithm_is_ignored_with_supported_match():
    value = "md5-%s %s" % (digest("md5"), token("sha256"))
    out = gate().verify(tag(value), CONTENT)
    assert out["algorithm"] == "sha256"


def test_missing_crossorigin_is_rejected():
    t = tag()
    del t["crossorigin"]
    with pytest.raises(ag.DigestSentinelError) as exc:
        gate().verify(t, CONTENT)
    assert exc.value.code == "missing_crossorigin"


def test_insecure_source_is_rejected():
    with pytest.raises(ag.DigestSentinelError) as exc:
        gate().verify(tag(src="http://cdn.example.com/app.js"), CONTENT)
    assert exc.value.code == "insecure_source"


def test_concurrent_verification_is_counted_and_detached():
    g = gate()
    problems = []
    results = []

    def worker():
        try:
            for _ in range(2):
                results.append(g.verify(tag(), CONTENT)["ok"])
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert results == [True] * 10
    snap = g.snapshot()
    assert snap["verified"] == 10
    snap["verified"] = 0
    assert g.snapshot()["verified"] == 10
