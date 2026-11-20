import json
import threading

import pytest

import email_otp_service as ev


def verifier(**kw):
    return ev.EmailOtpService(**kw)


def sent(v, email="user@example.com", now=0):
    return v.send(email, now=now)


def test_send_returns_six_digit_code():
    rec = sent(verifier())
    assert len(rec["code"]) == 6
    assert rec["code"].isdigit()
    assert rec["expires_at"] == 600


def test_email_is_normalized_before_verification():
    v = verifier()
    rec = sent(v, email="  User@Example.COM  ")
    assert v.verify("user@example.com", rec["code"], now=1)["ok"] is True


def test_code_can_only_be_used_once():
    v = verifier()
    rec = sent(v)
    assert v.verify("user@example.com", rec["code"], now=1)["ok"] is True
    with pytest.raises(ev.EmailOtpError) as exc:
        v.verify("user@example.com", rec["code"], now=2)
    assert exc.value.code == "code_used"


def test_expired_code_is_rejected():
    v = verifier(ttl=600)
    rec = sent(v)
    with pytest.raises(ev.EmailOtpError) as exc:
        v.verify("user@example.com", rec["code"], now=601)
    assert exc.value.code == "code_expired"


def test_wrong_code_does_not_consume_challenge():
    v = verifier()
    rec = sent(v)
    wrong = "000000" if rec["code"] != "000000" else "111111"
    with pytest.raises(ev.EmailOtpError) as exc:
        v.verify("user@example.com", wrong, now=1)
    assert exc.value.code == "bad_code"
    assert v.verify("user@example.com", rec["code"], now=2)["ok"] is True


def test_lockout_after_max_attempts():
    v = verifier(max_attempts=5)
    rec = sent(v)
    wrong = "000000" if rec["code"] != "000000" else "111111"
    for _ in range(5):
        with pytest.raises(ev.EmailOtpError):
            v.verify("user@example.com", wrong, now=1)
    with pytest.raises(ev.EmailOtpError) as exc:
        v.verify("user@example.com", rec["code"], now=2)
    assert exc.value.code == "locked"


def test_resend_cooldown_is_enforced():
    v = verifier(resend_cooldown=60)
    sent(v, now=0)
    with pytest.raises(ev.EmailOtpError) as exc:
        sent(v, now=30)
    assert exc.value.code == "resend_too_soon"


def test_resend_supersedes_old_code():
    v = verifier(resend_cooldown=60)
    old = sent(v, now=0)
    fresh = sent(v, now=61)
    with pytest.raises(ev.EmailOtpError) as exc:
        v.verify("user@example.com", old["code"], now=62)
    assert exc.value.code == "code_superseded"
    assert v.verify("user@example.com", fresh["code"], now=63)["ok"] is True


def test_malformed_code_is_a_parameter_error():
    v = verifier()
    sent(v)
    with pytest.raises(ValueError):
        v.verify("user@example.com", "12a456", now=1)


def test_unknown_email_has_no_challenge():
    with pytest.raises(ev.EmailOtpError) as exc:
        verifier().verify("ghost@example.com", "123456", now=1)
    assert exc.value.code == "no_challenge"


def test_revoke_clears_challenge():
    v = verifier()
    rec = sent(v)
    v.revoke("USER@example.com")
    with pytest.raises(ev.EmailOtpError) as exc:
        v.verify("user@example.com", rec["code"], now=1)
    assert exc.value.code == "no_challenge"


def test_snapshot_contains_no_plaintext_code():
    v = verifier()
    rec = sent(v)
    snap = v.snapshot()
    assert rec["code"] not in json.dumps(snap)
    assert "code_hash" in json.dumps(snap)


def test_snapshot_is_detached_from_internal_state():
    v = verifier()
    rec = sent(v)
    snap = v.snapshot()
    snap["challenges"].clear()
    assert v.verify("user@example.com", rec["code"], now=1)["ok"] is True


def test_challenges_are_isolated_per_email():
    v = verifier()
    a = sent(v, email="a@example.com")
    b = sent(v, email="b@example.com")
    assert v.verify("a@example.com", a["code"], now=1)["ok"] is True
    assert v.verify("b@example.com", b["code"], now=2)["ok"] is True


def test_concurrent_verification_has_one_winner():
    v = verifier()
    rec = sent(v)
    outcomes = []

    def worker():
        try:
            v.verify("user@example.com", rec["code"], now=1)
            outcomes.append(True)
        except ev.EmailOtpError:
            outcomes.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count(True) == 1
