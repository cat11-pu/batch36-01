import threading

import pytest

import ocsp_staple_check as oc

ISSUER = {
    "subject": "CN=Issuing CA",
    "fingerprint": "fp-issuer",
    "not_before": 0,
    "not_after": 10000,
}
CERT = {"serial": "0a1b", "issuer": "CN=Issuing CA"}


def entry(**over):
    e = {
        "serial": "0a1b",
        "status": "good",
        "this_update": 95,
        "next_update": 200,
        "revocation_time": None,
    }
    e.update(over)
    return e


def responder(**over):
    r = {
        "subject": "CN=Issuing CA",
        "issued_by": "CN=Issuing CA",
        "eku": [],
        "not_before": 0,
        "not_after": 10000,
        "fingerprint": "fp-issuer",
    }
    r.update(over)
    return r


def staple(**over):
    s = {
        "response_status": "successful",
        "response_type": "basic",
        "produced_at": 100,
        "entries": [entry()],
        "responder": responder(),
        "signature_ok": True,
        "nonce": "n-1",
    }
    s.update(over)
    return s


def stapler(**kw):
    base = {"max_age": 300, "clock_skew": 60, "require_nonce": True}
    base.update(kw)
    return oc.OcspStapler(**base)


def test_valid_staple_returns_entry_summary():
    out = stapler().validate(staple(), CERT, ISSUER, now=150, nonce="n-1")
    assert out["serial"] == "0a1b"
    assert out["status"] == "good"
    assert out["responder"] == "fp-issuer"
    assert out["next_update"] == 200


def test_revoked_certificate_is_rejected():
    s = staple(entries=[entry(status="revoked", revocation_time=120)])
    with pytest.raises(oc.StapleError) as exc:
        stapler().validate(s, CERT, ISSUER, now=150, nonce="n-1")
    assert exc.value.code == "cert_revoked"


def test_unknown_certificate_status_is_rejected():
    s = staple(entries=[entry(status="unknown")])
    with pytest.raises(oc.StapleError) as exc:
        stapler().validate(s, CERT, ISSUER, now=150, nonce="n-1")
    assert exc.value.code == "cert_unknown"


def test_stale_next_update_is_rejected():
    s = staple(entries=[entry(this_update=0, next_update=80)])
    with pytest.raises(oc.StapleError) as exc:
        stapler().validate(s, CERT, ISSUER, now=150, nonce="n-1")
    assert exc.value.code == "stale"


def test_future_this_update_is_rejected():
    s = staple(entries=[entry(this_update=300, next_update=400)])
    with pytest.raises(oc.StapleError) as exc:
        stapler().validate(s, CERT, ISSUER, now=150, nonce="n-1")
    assert exc.value.code == "not_yet_valid"


def test_old_produced_at_is_rejected():
    s = staple(produced_at=0)
    with pytest.raises(oc.StapleError) as exc:
        stapler(max_age=100, clock_skew=10).validate(
            s, CERT, ISSUER, now=150, nonce="n-1"
        )
    assert exc.value.code == "stale"


def test_try_later_response_is_rejected():
    s = staple(response_status="tryLater")
    with pytest.raises(oc.StapleError) as exc:
        stapler().validate(s, CERT, ISSUER, now=150, nonce="n-1")
    assert exc.value.code == "try_later"


def test_entry_for_another_serial_is_rejected():
    s = staple(entries=[entry(serial="ffff")])
    with pytest.raises(oc.StapleError) as exc:
        stapler().validate(s, CERT, ISSUER, now=150, nonce="n-1")
    assert exc.value.code == "serial_mismatch"


def test_duplicate_entries_for_serial_are_rejected():
    s = staple(entries=[entry(), entry()])
    with pytest.raises(oc.StapleError) as exc:
        stapler().validate(s, CERT, ISSUER, now=150, nonce="n-1")
    assert exc.value.code == "duplicate_entry"


def test_nonce_mismatch_is_rejected():
    with pytest.raises(oc.StapleError) as exc:
        stapler().validate(staple(), CERT, ISSUER, now=150, nonce="n-2")
    assert exc.value.code == "nonce_mismatch"


def test_missing_nonce_is_rejected():
    with pytest.raises(oc.StapleError) as exc:
        stapler().validate(staple(), CERT, ISSUER, now=150, nonce=None)
    assert exc.value.code == "nonce_missing"


def test_delegated_responder_without_signing_usage_is_rejected():
    delegated = responder(
        subject="CN=Delegated",
        issued_by="CN=Issuing CA",
        eku=[],
        fingerprint="fp-deleg",
    )
    with pytest.raises(oc.StapleError) as exc:
        stapler().validate(
            staple(responder=delegated), CERT, ISSUER, now=150, nonce="n-1"
        )
    assert exc.value.code == "unauthorized_responder"


def test_valid_delegated_responder_is_accepted():
    delegated = responder(
        subject="CN=Delegated",
        issued_by="CN=Issuing CA",
        eku=["OCSPSigning"],
        fingerprint="fp-deleg",
    )
    out = stapler().validate(
        staple(responder=delegated), CERT, ISSUER, now=150, nonce="n-1"
    )
    assert out["responder"] == "fp-deleg"


def test_bad_signature_is_rejected():
    with pytest.raises(oc.StapleError) as exc:
        stapler().validate(
            staple(signature_ok=False), CERT, ISSUER, now=150, nonce="n-1"
        )
    assert exc.value.code == "bad_signature"


def test_snapshot_counts_every_check_under_concurrency():
    s = stapler()
    problems = []

    def worker():
        try:
            for _ in range(5):
                s.validate(staple(), CERT, ISSUER, now=150, nonce="n-1")
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    snap = s.snapshot()
    assert snap["checks"] == 20
    snap["checks"] = 0
    assert s.snapshot()["checks"] == 20
