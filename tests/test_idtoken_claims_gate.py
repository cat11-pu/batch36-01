import pytest

import idtoken_claims_gate as ig

ISS = "https://idp.example.com"
CLIENT = "portal-client"


def gate(clock_skew=60):
    return ig.IdTokenGate(
        ISS,
        CLIENT,
        lambda token: token.get("signature") == "sig-ok",
        {"k-1", "k-2"},
        clock_skew=clock_skew,
    )


def tok(**over):
    t = {
        "header": {"alg": "RS256", "kid": "k-1"},
        "claims": {
            "iss": ISS,
            "aud": CLIENT,
            "sub": "user-1",
            "exp": 500,
            "iat": 100,
            "nonce": "n-1",
        },
        "signature": "sig-ok",
    }
    for key, value in over.items():
        if key in ("alg", "kid"):
            t["header"][key] = value
        elif key == "signature":
            t["signature"] = value
        else:
            t["claims"][key] = value
    return t


def test_valid_token_returns_claims():
    claims = gate().validate(tok(), "n-1", now=200)
    assert claims["sub"] == "user-1"
    assert claims["iss"] == ISS


def test_alg_none_is_rejected():
    with pytest.raises(ig.IdTokenError) as exc:
        gate().validate(tok(alg="none"), "n-1", now=200)
    assert exc.value.code == "bad_alg"


def test_alg_outside_allow_list_is_rejected():
    with pytest.raises(ig.IdTokenError) as exc:
        gate().validate(tok(alg="HS256"), "n-1", now=200)
    assert exc.value.code == "bad_alg"


def test_unknown_key_id_is_rejected():
    with pytest.raises(ig.IdTokenError) as exc:
        gate().validate(tok(kid="k-9"), "n-1", now=200)
    assert exc.value.code == "unknown_key"


def test_bad_signature_is_rejected():
    with pytest.raises(ig.IdTokenError) as exc:
        gate().validate(tok(signature="forged"), "n-1", now=200)
    assert exc.value.code == "bad_signature"


def test_issuer_must_match_exactly():
    with pytest.raises(ig.IdTokenError) as exc:
        gate().validate(tok(iss=ISS + "/"), "n-1", now=200)
    assert exc.value.code == "bad_issuer"


def test_foreign_audience_is_rejected():
    with pytest.raises(ig.IdTokenError) as exc:
        gate().validate(tok(aud="other-client"), "n-1", now=200)
    assert exc.value.code == "bad_audience"


def test_audience_list_containing_client_is_accepted():
    claims = gate().validate(tok(aud=[CLIENT, "other-client"], azp=CLIENT), "n-2", now=200)
    assert claims["aud"] == [CLIENT, "other-client"]


def test_multiple_audiences_require_azp():
    with pytest.raises(ig.IdTokenError) as exc:
        gate().validate(tok(aud=[CLIENT, "other-client"]), "n-3", now=200)
    assert exc.value.code == "missing_azp"


def test_azp_must_be_this_client():
    with pytest.raises(ig.IdTokenError) as exc:
        gate().validate(tok(aud=[CLIENT, "other-client"], azp="other-client"), "n-4", now=200)
    assert exc.value.code == "bad_azp"


def test_expired_token_is_rejected():
    with pytest.raises(ig.IdTokenError) as exc:
        gate().validate(tok(exp=150), "n-5", now=300)
    assert exc.value.code == "expired"


def test_issued_at_in_future_beyond_skew_is_rejected():
    with pytest.raises(ig.IdTokenError) as exc:
        gate().validate(tok(iat=400), "n-6", now=200)
    assert exc.value.code == "issued_in_future"


def test_nonce_mismatch_is_rejected():
    with pytest.raises(ig.IdTokenError) as exc:
        gate().validate(tok(), "n-wrong", now=200)
    assert exc.value.code == "bad_nonce"


def test_nonce_cannot_be_replayed():
    g = gate()
    g.validate(tok(), "n-7", now=200)
    with pytest.raises(ig.IdTokenError) as exc:
        g.validate(tok(), "n-7", now=201)
    assert exc.value.code == "nonce_reused"


def test_blank_subject_is_rejected():
    with pytest.raises(ig.IdTokenError) as exc:
        gate().validate(tok(sub="   "), "n-8", now=200)
    assert exc.value.code == "bad_subject"
