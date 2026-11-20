import re

import pytest

import dpop_binding as db

TOKEN_URL = "https://as.example.com/token"


def service():
    return db.DpopBoundTokenService(
        {"spa": {"origin": "https://app.example.com"}},
        lambda jwk: jwk["x"],
        nonce_ttl=60,
        proof_skew=60,
        jti_window=300,
    )


def proof(nonce, **over):
    p = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {"kty": "EC", "crv": "P-256", "x": "key-a", "y": "key-y"},
        "jti": "j-1",
        "htm": "POST",
        "htu": TOKEN_URL,
        "iat": 10,
        "nonce": nonce,
    }
    p.update(over)
    return p


def test_challenge_returns_expiring_nonce():
    out = service().challenge(now=0)
    assert re.fullmatch(r"[0-9a-f]{32}", out["nonce"])
    assert out["expires_at"] == 60


def test_valid_issue_returns_bound_tokens():
    s = service()
    nonce = s.challenge(now=0)["nonce"]
    res = s.issue("spa", "alice", proof(nonce), now=10)
    assert res["token_type"] == "DPoP"
    assert res["jkt"] == "key-a"
    assert res["expires_in"] == 300
    assert re.fullmatch(r"[0-9a-f]{64}", res["access_token"])


def test_unknown_client_cannot_issue():
    s = service()
    nonce = s.challenge(now=0)["nonce"]
    with pytest.raises(db.DpopError) as exc:
        s.issue("cli", "alice", proof(nonce), now=10)
    assert exc.value.code == "invalid_client"


def test_missing_proof_is_rejected():
    s = service()
    with pytest.raises(db.DpopError) as exc:
        s.issue("spa", "alice", None, now=10)
    assert exc.value.code == "invalid_proof"


def test_wrong_proof_type_is_rejected():
    s = service()
    nonce = s.challenge(now=0)["nonce"]
    with pytest.raises(db.DpopError) as exc:
        s.issue("spa", "alice", proof(nonce, typ="JWT"), now=10)
    assert exc.value.code == "invalid_proof_type"


def test_private_key_material_is_rejected():
    s = service()
    nonce = s.challenge(now=0)["nonce"]
    jwk = {"kty": "EC", "crv": "P-256", "x": "key-a", "y": "key-y", "d": "secret"}
    with pytest.raises(db.DpopError) as exc:
        s.issue("spa", "alice", proof(nonce, jwk=jwk), now=10)
    assert exc.value.code == "private_key_exposed"


def test_unknown_nonce_is_rejected():
    s = service()
    with pytest.raises(db.DpopError) as exc:
        s.issue("spa", "alice", proof("0" * 32), now=10)
    assert exc.value.code == "invalid_nonce"


def test_expired_nonce_is_rejected():
    s = service()
    nonce = s.challenge(now=0)["nonce"]
    with pytest.raises(db.DpopError) as exc:
        s.issue("spa", "alice", proof(nonce, iat=61), now=61)
    assert exc.value.code == "invalid_nonce"


def test_lowercase_method_is_rejected():
    s = service()
    nonce = s.challenge(now=0)["nonce"]
    with pytest.raises(db.DpopError) as exc:
        s.issue("spa", "alice", proof(nonce, htm="post"), now=10)
    assert exc.value.code == "invalid_method"


def test_target_with_query_string_is_rejected():
    s = service()
    nonce = s.challenge(now=0)["nonce"]
    with pytest.raises(db.DpopError) as exc:
        s.issue("spa", "alice", proof(nonce, htu=TOKEN_URL + "?a=1"), now=10)
    assert exc.value.code == "invalid_target"


def test_stale_iat_is_rejected():
    s = service()
    nonce = s.challenge(now=120)["nonce"]
    with pytest.raises(db.DpopError) as exc:
        s.issue("spa", "alice", proof(nonce, iat=0), now=120)
    assert exc.value.code == "invalid_proof_time"


def test_replayed_jti_is_rejected():
    s = service()
    first = s.challenge(now=0)["nonce"]
    second = s.challenge(now=0)["nonce"]
    s.issue("spa", "alice", proof(first, iat=10, jti="dup"), now=10)
    with pytest.raises(db.DpopError) as exc:
        s.issue("spa", "alice", proof(second, iat=11, jti="dup"), now=11)
    assert exc.value.code == "replay_detected"


def test_refresh_rotates_and_keeps_binding():
    s = service()
    nonce = s.challenge(now=0)["nonce"]
    issued = s.issue("spa", "alice", proof(nonce, jti="j-1"), now=10)
    out = s.refresh(issued["refresh_token"], proof(nonce, iat=11, jti="j-2"), now=11)
    assert out["token_type"] == "DPoP"
    assert out["jkt"] == "key-a"
    assert out["access_token"] != issued["access_token"]
    assert out["refresh_token"] != issued["refresh_token"]


def test_refresh_with_another_key_is_rejected():
    s = service()
    nonce = s.challenge(now=0)["nonce"]
    issued = s.issue("spa", "alice", proof(nonce, jti="j-1"), now=10)
    other = {"kty": "EC", "crv": "P-256", "x": "key-b", "y": "key-y"}
    with pytest.raises(db.DpopError) as exc:
        s.refresh(issued["refresh_token"], proof(nonce, iat=11, jti="j-2", jwk=other), now=11)
    assert exc.value.code == "binding_mismatch"


def test_used_refresh_token_cannot_be_replayed():
    s = service()
    nonce = s.challenge(now=0)["nonce"]
    issued = s.issue("spa", "alice", proof(nonce, jti="j-1"), now=10)
    s.refresh(issued["refresh_token"], proof(nonce, iat=11, jti="j-2"), now=11)
    with pytest.raises(db.DpopError) as exc:
        s.refresh(issued["refresh_token"], proof(nonce, iat=12, jti="j-3"), now=12)
    assert exc.value.code == "refresh_reused"
