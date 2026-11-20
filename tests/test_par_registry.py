import re

import pytest

import par_registry as pr

MOBILE = "mobile"
WEB = "web"
REDIRECT = "https://app.example.com/cb"
OTHER = "https://app.example.com/other"


def registry():
    return pr.PushedRequestRegistry(
        {
            MOBILE: {"redirect_uris": [REDIRECT, OTHER], "public": True},
            WEB: {"redirect_uris": ["https://web.example.com/cb"], "public": False},
        },
        {"code", "code id_token"},
        {"openid", "profile", "offline_access"},
        max_ttl=90,
    )


def params(**over):
    p = {
        "client_id": MOBILE,
        "response_type": "code",
        "redirect_uri": REDIRECT,
        "scope": "openid profile",
        "state": "s" * 16,
        "code_challenge": "a" * 43,
        "code_challenge_method": "S256",
    }
    p.update(over)
    return p


def test_push_returns_prefixed_high_entropy_handle():
    grant = registry().push(MOBILE, params(), now=0, ttl=30)
    assert grant["request_uri"].startswith("urn:ietf:params:oauth:request_uri:")
    assert re.fullmatch(r"[0-9a-f]{32}", grant["request_uri"].rsplit(":", 1)[-1])
    assert grant["expires_in"] == 30
    assert grant["expires_at"] == 30


def test_unknown_client_cannot_push():
    with pytest.raises(pr.ParError) as exc:
        registry().push("ghost", params(client_id="ghost"), now=0)
    assert exc.value.code == "invalid_client"


def test_unlisted_response_type_is_rejected():
    with pytest.raises(pr.ParError) as exc:
        registry().push(MOBILE, params(response_type="token"), now=0)
    assert exc.value.code == "unsupported_response_type"


def test_scope_outside_allowlist_is_rejected():
    with pytest.raises(pr.ParError) as exc:
        registry().push(MOBILE, params(scope="openid admin"), now=0)
    assert exc.value.code == "invalid_scope"


def test_public_client_must_supply_pkce():
    p = params()
    del p["code_challenge"]
    del p["code_challenge_method"]
    with pytest.raises(pr.ParError) as exc:
        registry().push(MOBILE, p, now=0)
    assert exc.value.code == "pkce_required"


def test_plain_challenge_method_is_rejected():
    with pytest.raises(pr.ParError) as exc:
        registry().push(MOBILE, params(code_challenge_method="plain"), now=0)
    assert exc.value.code == "invalid_challenge_method"


def test_nested_request_parameter_is_rejected():
    with pytest.raises(pr.ParError) as exc:
        registry().push(MOBILE, params(request="eyJhbGciOiJub25lIn0"), now=0)
    assert exc.value.code == "nested_request"


def test_redirect_uri_must_match_registration_exactly():
    with pytest.raises(pr.ParError) as exc:
        registry().push(MOBILE, params(redirect_uri="https://app.example.com.evil.com/cb"), now=0)
    assert exc.value.code == "invalid_redirect"


def test_missing_state_is_rejected():
    p = params()
    del p["state"]
    with pytest.raises(pr.ParError) as exc:
        registry().push(MOBILE, p, now=0)
    assert exc.value.code == "missing_state"


def test_request_lifetime_is_clamped_to_server_cap():
    grant = registry().push(MOBILE, params(), now=0, ttl=3600)
    assert grant["expires_in"] == 90
    assert grant["expires_at"] == 90


def test_consume_returns_normalized_parameter_copy():
    r = registry()
    grant = r.push(MOBILE, params(), now=0)
    out = r.consume(grant["request_uri"], MOBILE, now=10)
    assert out["client_id"] == MOBILE
    assert out["scope"] == ["openid", "profile"]
    assert out["state"] == "s" * 16
    assert out["redirect_uri"] == REDIRECT


def test_request_uri_is_single_use():
    r = registry()
    grant = r.push(MOBILE, params(), now=0)
    r.consume(grant["request_uri"], MOBILE, now=10)
    with pytest.raises(pr.ParError) as exc:
        r.consume(grant["request_uri"], MOBILE, now=11)
    assert exc.value.code == "request_uri_used"


def test_expired_request_uri_is_rejected():
    r = registry()
    grant = r.push(MOBILE, params(), now=0)
    with pytest.raises(pr.ParError) as exc:
        r.consume(grant["request_uri"], MOBILE, now=61)
    assert exc.value.code == "expired_request_uri"


def test_other_client_cannot_consume_the_handle():
    r = registry()
    grant = r.push(MOBILE, params(), now=0)
    with pytest.raises(pr.ParError) as exc:
        r.consume(grant["request_uri"], WEB, now=10)
    assert exc.value.code == "invalid_client"


def test_unknown_request_uri_is_rejected():
    with pytest.raises(pr.ParError) as exc:
        registry().consume("urn:ietf:params:oauth:request_uri:" + "0" * 32, MOBILE, now=10)
    assert exc.value.code == "invalid_request_uri"
