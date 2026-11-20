import hashlib
import re

import pytest

import webauthn_attestation as wa

RP_ID = "login.example.com"
RP_HASH = hashlib.sha256(RP_ID.encode()).hexdigest()


def verifier(allow_none=False):
    return wa.AttestationVerifier(
        RP_ID,
        ["https://login.example.com"],
        {"fp-root": {"name": "corp-ca", "not_after": 10000}},
        verify_signature=lambda alg, cred, data, sig: sig == "valid",
        allow_none=allow_none,
    )


def response(challenge, **over):
    r = {
        "challenge": challenge,
        "type": "webauthn.create",
        "origin": "https://login.example.com",
        "rp_id_hash": RP_HASH,
        "client_data_hash": "cd" * 32,
        "credential_id": "cred-1",
        "fmt": "packed",
        "att_stmt": {"alg": -7, "sig": "valid", "x5c": ["fp-leaf", "fp-root"]},
        "auth_data": {"aaguid": "aa" * 16, "sign_count": 0},
        "user_verified": True,
    }
    r.update(over)
    return r


def test_issue_returns_high_entropy_challenge():
    issued = verifier().issue("alice", now=0)
    assert re.fullmatch(r"[0-9a-f]{64}", issued["challenge"])
    assert issued["user_handle"] == "alice"
    assert issued["expires_at"] == 120


def test_valid_packed_registration_is_stored():
    v = verifier()
    issued = v.issue("alice", now=0)
    res = v.verify("alice", response(issued["challenge"]), now=5)
    assert res["credential_id"] == "cred-1"
    creds = v.credentials()
    assert creds["cred-1"]["user_handle"] == "alice"
    creds["cred-1"]["user_handle"] = "mallory"
    assert v.credentials()["cred-1"]["user_handle"] == "alice"


def test_challenge_mismatch_is_rejected():
    v = verifier()
    v.issue("alice", now=0)
    with pytest.raises(ValueError):
        v.verify("alice", response("00" * 32), now=5)


def test_unknown_user_handle_is_rejected():
    v = verifier()
    issued = v.issue("alice", now=0)
    with pytest.raises(ValueError):
        v.verify("bob", response(issued["challenge"]), now=5)


def test_replayed_response_is_rejected():
    v = verifier()
    issued = v.issue("alice", now=0)
    v.verify("alice", response(issued["challenge"]), now=5)
    with pytest.raises(ValueError):
        v.verify("alice", response(issued["challenge"]), now=6)


def test_expired_challenge_is_rejected():
    v = verifier()
    issued = v.issue("alice", now=0)
    with pytest.raises(ValueError):
        v.verify("alice", response(issued["challenge"]), now=121)


def test_disallowed_origin_is_rejected():
    v = verifier()
    issued = v.issue("alice", now=0)
    with pytest.raises(ValueError):
        v.verify("alice", response(issued["challenge"], origin="https://login.example.com.evil.com"), now=5)


def test_rp_id_hash_mismatch_is_rejected():
    v = verifier()
    issued = v.issue("alice", now=0)
    with pytest.raises(ValueError):
        v.verify("alice", response(issued["challenge"], rp_id_hash="00" * 32), now=5)


def test_wrong_ceremony_type_is_rejected():
    v = verifier()
    issued = v.issue("alice", now=0)
    with pytest.raises(ValueError):
        v.verify("alice", response(issued["challenge"], type="webauthn.get"), now=5)


def test_unsupported_attestation_format_is_rejected():
    v = verifier()
    issued = v.issue("alice", now=0)
    with pytest.raises(ValueError):
        v.verify("alice", response(issued["challenge"], fmt="tpm"), now=5)


def test_none_format_is_rejected_by_default():
    v = verifier()
    issued = v.issue("alice", now=0)
    with pytest.raises(ValueError):
        v.verify("alice", response(issued["challenge"], fmt="none", att_stmt={}), now=5)


def test_none_format_is_allowed_by_opt_in():
    v = verifier(allow_none=True)
    issued = v.issue("alice", now=0)
    res = v.verify("alice", response(issued["challenge"], fmt="none", att_stmt={}), now=5)
    assert res["fmt"] == "none"


def test_packed_statement_requires_signature():
    v = verifier()
    issued = v.issue("alice", now=0)
    bad = response(issued["challenge"])
    bad["att_stmt"] = {"alg": -7, "x5c": ["fp-leaf", "fp-root"]}
    with pytest.raises(ValueError):
        v.verify("alice", bad, now=5)


def test_untrusted_certificate_root_is_rejected():
    v = verifier()
    issued = v.issue("alice", now=0)
    bad = response(issued["challenge"])
    bad["att_stmt"] = {"alg": -7, "sig": "valid", "x5c": ["fp-leaf", "fp-unknown"]}
    with pytest.raises(ValueError):
        v.verify("alice", bad, now=5)


def test_bad_attestation_signature_is_rejected():
    v = verifier()
    issued = v.issue("alice", now=0)
    bad = response(issued["challenge"])
    bad["att_stmt"] = {"alg": -7, "sig": "forged", "x5c": ["fp-leaf", "fp-root"]}
    with pytest.raises(ValueError):
        v.verify("alice", bad, now=5)
