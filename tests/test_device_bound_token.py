import hashlib
import re

import pytest

import device_bound_token as dt

AUDIENCE = "api.example.com"
ORDER_URL = "https://api.example.com/orders"


def authority():
    return dt.DeviceBindingAuthority(
        AUDIENCE,
        verify_proof=lambda key, data, sig: sig == "sig-ok",
    )


def enrolled(auth):
    return auth.enroll("pk-a", now=0)["device_id"]


def token_hash(token):
    return hashlib.sha256(token["token"].encode()).hexdigest()


def proof(token, **over):
    p = {
        "device_id": token["device_id"],
        "htm": "POST",
        "htu": ORDER_URL,
        "iat": 100,
        "jti": "jti-1",
        "ath": token_hash(token),
        "signature": "sig-ok",
    }
    p.update(over)
    return p


def test_enroll_is_idempotent_per_public_key():
    a = authority()
    rec = a.enroll("pk-a", now=0)
    assert re.fullmatch(r"[0-9a-f]{64}", rec["device_id"])
    assert rec["public_key"] == "pk-a"
    assert rec["status"] == "active"
    again = a.enroll("pk-a", now=1)
    assert again["device_id"] == rec["device_id"]


def test_empty_device_public_key_is_rejected():
    with pytest.raises(ValueError):
        authority().enroll("", now=0)


def test_issue_to_unknown_device_is_rejected():
    with pytest.raises(dt.BindingError) as exc:
        authority().issue("f" * 64, "alice", now=100)
    assert exc.value.code == "unknown_device"


def test_issue_with_empty_subject_is_rejected():
    a = authority()
    dev = enrolled(a)
    with pytest.raises(ValueError):
        a.issue(dev, "", now=100)


def test_issued_token_has_bound_fields():
    a = authority()
    tok = a.issue(enrolled(a), "alice", now=100)
    assert re.fullmatch(r"[0-9a-f]{64}", tok["token"])
    assert tok["device_id"] == enrolled(a)
    assert tok["audience"] == AUDIENCE
    assert tok["issued_at"] == 100
    assert tok["expires_at"] == 700


def test_valid_proof_returns_subject():
    a = authority()
    tok = a.issue(enrolled(a), "alice", now=100)
    res = a.verify(tok, proof(tok), now=110, method="POST", url=ORDER_URL)
    assert res["subject"] == "alice"
    assert res["device_id"] == tok["device_id"]
    assert res["remaining"] == 590


def test_missing_proof_is_rejected():
    a = authority()
    tok = a.issue(enrolled(a), "alice", now=100)
    with pytest.raises(ValueError):
        a.verify(tok, None, now=110)


def test_proof_device_must_match_token():
    a = authority()
    tok = a.issue(enrolled(a), "alice", now=100)
    with pytest.raises(dt.BindingError) as exc:
        a.verify(tok, proof(tok, device_id="e" * 64), now=110)
    assert exc.value.code == "device_mismatch"


def test_bad_proof_signature_is_rejected():
    a = authority()
    tok = a.issue(enrolled(a), "alice", now=100)
    with pytest.raises(dt.BindingError) as exc:
        a.verify(tok, proof(tok, signature="forged"), now=110)
    assert exc.value.code == "bad_proof"


def test_wrong_request_method_is_rejected():
    a = authority()
    tok = a.issue(enrolled(a), "alice", now=100)
    with pytest.raises(dt.BindingError) as exc:
        a.verify(tok, proof(tok), now=110, method="GET", url=ORDER_URL)
    assert exc.value.code == "method_mismatch"


def test_wrong_request_url_is_rejected():
    a = authority()
    tok = a.issue(enrolled(a), "alice", now=100)
    with pytest.raises(dt.BindingError) as exc:
        a.verify(tok, proof(tok), now=110, method="POST", url=ORDER_URL + "/9")
    assert exc.value.code == "url_mismatch"


def test_stale_and_future_proofs_are_rejected():
    a = authority()
    tok = a.issue(enrolled(a), "alice", now=100)
    with pytest.raises(dt.BindingError) as exc:
        a.verify(tok, proof(tok, iat=0), now=110)
    assert exc.value.code == "stale_proof"
    with pytest.raises(dt.BindingError) as exc:
        a.verify(tok, proof(tok, iat=200), now=110)
    assert exc.value.code == "stale_proof"


def test_proof_id_is_single_use():
    a = authority()
    tok = a.issue(enrolled(a), "alice", now=100)
    a.verify(tok, proof(tok, jti="jti-1"), now=110)
    with pytest.raises(dt.BindingError) as exc:
        a.verify(tok, proof(tok, jti="jti-1"), now=111)
    assert exc.value.code == "replayed_proof"
    assert a.verify(tok, proof(tok, jti="jti-2"), now=112)["subject"] == "alice"


def test_expired_token_and_revoked_device_are_rejected():
    a = dt.DeviceBindingAuthority(AUDIENCE, verify_proof=lambda key, data, sig: sig == "sig-ok", ttl=10)
    dev = a.enroll("pk-a", now=0)["device_id"]
    tok = a.issue(dev, "alice", now=100)
    with pytest.raises(dt.BindingError) as exc:
        a.verify(tok, proof(tok), now=111)
    assert exc.value.code == "expired_token"
    fresh = a.issue(dev, "alice", now=100)
    a.revoke_device(dev, now=105)
    with pytest.raises(dt.BindingError) as exc:
        a.verify(fresh, proof(fresh, jti="jti-9"), now=106)
    assert exc.value.code == "device_revoked"
    with pytest.raises(dt.BindingError) as exc:
        a.enroll("pk-a", now=107)
    assert exc.value.code == "device_revoked"


def test_unknown_token_and_token_hash_mismatch_are_rejected():
    a = authority()
    dev = enrolled(a)
    ghost = {"token": "0" * 64, "device_id": dev, "subject": "alice", "audience": AUDIENCE, "issued_at": 100, "expires_at": 700}
    with pytest.raises(dt.BindingError) as exc:
        a.verify(ghost, proof(ghost), now=110)
    assert exc.value.code == "unknown_token"
    tok = a.issue(dev, "alice", now=100)
    with pytest.raises(dt.BindingError) as exc:
        a.verify(tok, proof(tok, ath="0" * 64), now=110)
    assert exc.value.code == "token_hash_mismatch"
