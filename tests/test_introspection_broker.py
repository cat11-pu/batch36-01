import threading

import pytest

import introspection_broker as ib

ISS = "https://as.example.com"
AUD = "https://api.example.com"


def claims(**over):
    c = {
        "sub": "user-1",
        "iss": ISS,
        "aud": AUD,
        "exp": 500,
        "nbf": 0,
        "token_type": "access_token",
        "scope": ["read", "write"],
        "jti": "j-1",
    }
    c.update(over)
    return c


def make(raw_claims):
    def verify(token):
        return raw_claims.get(token)

    return ib.IntrospectionBroker(ISS, [AUD], verify, {"web": "s3cret-value"}, cache_ttl=120)


def broker():
    return make({"at-good": claims()})


def test_valid_token_reports_active_claims():
    r = broker().introspect("at-good", "web", "s3cret-value", now=10)
    assert r["active"] is True
    assert r["sub"] == "user-1"
    assert r["scope"] == ["read", "write"]


def test_unknown_token_returns_only_inactive():
    r = broker().introspect("at-missing", "web", "s3cret-value", now=10)
    assert r == {"active": False}


def test_expired_token_is_inactive():
    b = make({"at-old": claims(exp=100)})
    assert b.introspect("at-old", "web", "s3cret-value", now=200)["active"] is False


def test_not_yet_valid_token_is_inactive():
    b = make({"at-early": claims(nbf=999)})
    assert b.introspect("at-early", "web", "s3cret-value", now=10)["active"] is False


def test_foreign_audience_is_inactive():
    b = make({"at-other": claims(aud="https://other.example.com")})
    assert b.introspect("at-other", "web", "s3cret-value", now=10)["active"] is False


def test_foreign_issuer_is_inactive():
    b = make({"at-iss": claims(iss="https://evil.example.com")})
    assert b.introspect("at-iss", "web", "s3cret-value", now=10)["active"] is False


def test_signature_failure_is_inactive():
    b = make({"at-forged": None})
    assert b.introspect("at-forged", "web", "s3cret-value", now=10)["active"] is False


def test_missing_client_secret_is_rejected():
    with pytest.raises(ib.IntrospectionError) as exc:
        broker().introspect("at-good", "web", "", now=10)
    assert exc.value.code == "client_auth_required"


def test_wrong_client_secret_is_rejected():
    with pytest.raises(ib.IntrospectionError) as exc:
        broker().introspect("at-good", "web", "wrong-secret", now=10)
    assert exc.value.code == "invalid_client"


def test_unknown_hint_is_a_parameter_error():
    with pytest.raises(ValueError):
        broker().introspect("at-good", "web", "s3cret-value", token_type_hint="magic", now=10)


def test_hint_mismatch_does_not_block_valid_token():
    r = broker().introspect("at-good", "web", "s3cret-value", token_type_hint="refresh_token", now=10)
    assert r["active"] is True
    assert r["token_type"] == "access_token"


def test_revoke_invalidates_cached_result():
    b = broker()
    assert b.introspect("at-good", "web", "s3cret-value", now=10)["active"] is True
    b.revoke("at-good", now=11)
    assert b.introspect("at-good", "web", "s3cret-value", now=12)["active"] is False


def test_returned_claims_are_a_deep_copy():
    b = broker()
    first = b.introspect("at-good", "web", "s3cret-value", now=10)
    first["scope"].append("admin")
    second = b.introspect("at-good", "web", "s3cret-value", now=11)
    assert second["scope"] == ["read", "write"]


def test_snapshot_is_detached_from_internal_state():
    b = broker()
    b.introspect("at-good", "web", "s3cret-value", now=10)
    snap = b.snapshot()
    snap["revoked"].append("at-good")
    assert "at-good" not in b.snapshot()["revoked"]
    assert "at-good" not in str(snap.get("tokens", {}))


def test_concurrent_introspection_after_revoke_all_inactive():
    b = broker()
    b.introspect("at-good", "web", "s3cret-value", now=10)
    b.revoke("at-good", now=11)
    results = []

    def worker():
        results.append(b.introspect("at-good", "web", "s3cret-value", now=12)["active"])

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == [False, False, False, False]
