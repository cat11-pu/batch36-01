import re

import pytest

import oidc_code_exchange as oe

ISSUER = "https://idp.example.com"
CLIENT = "portal"
REDIRECT = "https://portal.example.com/callback"
ALT_REDIRECT = "https://portal.example.com/alt"


def broker():
    return oe.AuthorizationCodeBroker(
        ISSUER,
        {CLIENT: [REDIRECT, ALT_REDIRECT]},
        {"kid-1": {"alg": "RS256", "status": "active"}},
        required_acr="urn:mfa",
        max_age=300,
    )


def claims(**over):
    c = {
        "iss": ISSUER,
        "aud": CLIENT,
        "azp": CLIENT,
        "sub": "alice",
        "sid": "sid-1",
        "acr": "urn:mfa",
        "amr": ["pwd", "otp"],
        "auth_time": 50,
        "iat": 60,
        "exp": 600,
    }
    c.update(over)
    return c


def response(nonce, **over):
    merged = claims(nonce=nonce)
    merged.update(over)
    return {"kid": "kid-1", "token_type": "Bearer", "expires_in": 3600, "id_token": merged}


def started(now=0, ttl=120):
    b = broker()
    issued = b.begin(CLIENT, REDIRECT, now=now, ttl=ttl)
    return b, issued


def test_begin_returns_one_time_material():
    issued = broker().begin(CLIENT, REDIRECT, now=0)
    assert re.fullmatch(r"[0-9a-f]{64}", issued["code"])
    assert re.fullmatch(r"[0-9a-f]{64}", issued["verifier"])
    assert re.fullmatch(r"[0-9a-f]{32}", issued["nonce"])
    assert issued["expires_at"] == 120


def test_unknown_client_cannot_begin():
    with pytest.raises(oe.ExchangeError) as exc:
        broker().begin("ghost", REDIRECT, now=0)
    assert exc.value.code == "invalid_client"


def test_unregistered_redirect_is_rejected():
    with pytest.raises(oe.ExchangeError) as exc:
        broker().begin(CLIENT, "https://portal.example.com/evil", now=0)
    assert exc.value.code == "invalid_redirect"


def test_valid_redemption_creates_session():
    b, issued = started()
    res = b.redeem(CLIENT, REDIRECT, issued["code"], issued["verifier"], response(issued["nonce"]), now=60)
    assert res["sub"] == "alice"
    assert res["sid"] == "sid-1"
    assert res["acr"] == "urn:mfa"
    assert res["expires_at"] == 3660
    assert b.sessions()["sid-1"]["sub"] == "alice"


def test_redeemed_code_cannot_be_used_again():
    b, issued = started()
    b.redeem(CLIENT, REDIRECT, issued["code"], issued["verifier"], response(issued["nonce"]), now=60)
    with pytest.raises(oe.ExchangeError) as exc:
        b.redeem(CLIENT, REDIRECT, issued["code"], issued["verifier"], response(issued["nonce"]), now=61)
    assert exc.value.code == "code_reused"


def test_expired_code_is_rejected():
    b, issued = started(now=0, ttl=120)
    with pytest.raises(oe.ExchangeError) as exc:
        b.redeem(CLIENT, REDIRECT, issued["code"], issued["verifier"], response(issued["nonce"], auth_time=110, iat=120, exp=900), now=121)
    assert exc.value.code == "code_expired"


def test_verifier_mismatch_is_rejected():
    b, issued = started()
    with pytest.raises(oe.ExchangeError) as exc:
        b.redeem(CLIENT, REDIRECT, issued["code"], "0" * 64, response(issued["nonce"]), now=60)
    assert exc.value.code == "pkce_failed"


def test_redemption_redirect_must_match_begin():
    b, issued = started()
    with pytest.raises(oe.ExchangeError) as exc:
        b.redeem(CLIENT, ALT_REDIRECT, issued["code"], issued["verifier"], response(issued["nonce"]), now=60)
    assert exc.value.code == "invalid_redirect"


def test_unknown_key_id_is_rejected():
    b, issued = started()
    token = response(issued["nonce"])
    token["kid"] = "kid-9"
    with pytest.raises(oe.ExchangeError) as exc:
        b.redeem(CLIENT, REDIRECT, issued["code"], issued["verifier"], token, now=60)
    assert exc.value.code == "unknown_key"


def test_issuer_must_match_local_config():
    b, issued = started()
    with pytest.raises(oe.ExchangeError) as exc:
        b.redeem(CLIENT, REDIRECT, issued["code"], issued["verifier"], response(issued["nonce"], iss="https://idp.test.example.com"), now=60)
    assert exc.value.code == "issuer_mismatch"


def test_audience_must_contain_client():
    b, issued = started()
    with pytest.raises(oe.ExchangeError) as exc:
        b.redeem(CLIENT, REDIRECT, issued["code"], issued["verifier"], response(issued["nonce"], aud="api"), now=60)
    assert exc.value.code == "audience_mismatch"


def test_multiple_audiences_require_azp():
    b, issued = started()
    with pytest.raises(oe.ExchangeError) as exc:
        b.redeem(CLIENT, REDIRECT, issued["code"], issued["verifier"], response(issued["nonce"], aud=[CLIENT, "api"], azp="api"), now=60)
    assert exc.value.code == "azp_mismatch"


def test_nonce_must_match_the_authorization():
    b, issued = started()
    with pytest.raises(oe.ExchangeError) as exc:
        b.redeem(CLIENT, REDIRECT, issued["code"], issued["verifier"], response("0" * 32), now=60)
    assert exc.value.code == "nonce_mismatch"


def test_stale_auth_time_requires_reauthentication():
    b, issued = started(now=300, ttl=120)
    with pytest.raises(oe.ExchangeError) as exc:
        b.redeem(CLIENT, REDIRECT, issued["code"], issued["verifier"], response(issued["nonce"], auth_time=0, iat=350, exp=900), now=350)
    assert exc.value.code == "reauth_required"


def test_session_snapshot_is_isolated():
    b, issued = started()
    b.redeem(CLIENT, REDIRECT, issued["code"], issued["verifier"], response(issued["nonce"]), now=60)
    snap = b.sessions()
    snap["sid-1"]["sub"] = "mallory"
    assert b.sessions()["sid-1"]["sub"] == "alice"
