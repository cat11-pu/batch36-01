import hashlib
import threading

import pytest

import pq_kem_session as pk

POLICY = ["X25519MLKEM768", "P256MLKEM768", "X25519"]
CLIENT_PUBLIC = b"p" * 1216


class FakeKem:
    def __init__(self, ct_len=1120, ss=b"s" * 32):
        self.ct_len = ct_len
        self.ss = ss
        self.calls = []

    def encapsulate(self, suite, public):
        self.calls.append((suite, public))
        return (b"c" * self.ct_len, self.ss)


def mac(key, msg):
    return hashlib.sha256(key + msg).hexdigest()


def broker(**kw):
    base = {
        "policy": POLICY,
        "kem": FakeKem(),
        "mac": mac,
        "require_hybrid": True,
    }
    base.update(kw)
    return pk.HybridKemBroker(**base)


def negotiated(suites=None, **kw):
    b = broker(**kw)
    return b, b.negotiate(suites or ["X25519MLKEM768"], now=0)


def connected(**kw):
    b, n = negotiated(**kw)
    resp = b.respond(n, CLIENT_PUBLIC, b"hello", now=10)
    return b, resp


def tag_for(session_id):
    return mac(b"s" * 32, b"hello" + b"|" + session_id.encode("ascii"))


def test_negotiation_follows_client_preference():
    b, n = negotiated(["P256MLKEM768", "X25519MLKEM768"])
    assert n["suite"] == "P256MLKEM768"
    assert n["expires_at"] == 300
    assert n["negotiation_id"]


def test_no_common_suite_is_rejected():
    b = broker(policy=["X25519MLKEM768"])
    with pytest.raises(pk.KemError) as exc:
        b.negotiate(["X25519"], now=0)
    assert exc.value.code == "no_common_suite"


def test_classical_suite_is_blocked_in_hybrid_mode():
    with pytest.raises(pk.KemError) as exc:
        broker().negotiate(["X25519"], now=0)
    assert exc.value.code == "downgrade_blocked"


def test_classical_suite_allowed_when_policy_permits():
    b, n = negotiated(["X25519"], require_hybrid=False)
    assert n["suite"] == "X25519"


def test_unknown_suite_is_rejected():
    with pytest.raises(pk.KemError) as exc:
        broker().negotiate(["X448"], now=0)
    assert exc.value.code == "unknown_suite"


def test_duplicate_suite_is_rejected():
    with pytest.raises(pk.KemError) as exc:
        broker().negotiate(
            ["X25519MLKEM768", "X25519MLKEM768"], now=0
        )
    assert exc.value.code == "duplicate_suite"


def test_short_client_public_key_is_rejected():
    b, n = negotiated()
    with pytest.raises(pk.KemError) as exc:
        b.respond(n, b"p" * 10, b"hello", now=10)
    assert exc.value.code == "bad_public_key"


def test_empty_transcript_is_rejected():
    b, n = negotiated()
    with pytest.raises(pk.KemError) as exc:
        b.respond(n, CLIENT_PUBLIC, b"", now=10)
    assert exc.value.code == "bad_transcript"


def test_bad_ciphertext_length_is_rejected():
    b, n = negotiated(kem=FakeKem(ct_len=5))
    with pytest.raises(pk.KemError) as exc:
        b.respond(n, CLIENT_PUBLIC, b"hello", now=10)
    assert exc.value.code == "bad_ciphertext"


def test_bad_shared_secret_length_is_rejected():
    b, n = negotiated(kem=FakeKem(ss=b"s" * 16))
    with pytest.raises(pk.KemError) as exc:
        b.respond(n, CLIENT_PUBLIC, b"hello", now=10)
    assert exc.value.code == "bad_shared_secret"


def test_valid_confirmation_establishes_session():
    b, resp = connected()
    sid = resp["session_id"]
    out = b.confirm(sid, tag_for(sid), b"hello", now=11)
    assert out["established"] is True
    assert out["suite"] == "X25519MLKEM768"
    assert out["session_id"] == sid


def test_wrong_confirm_tag_is_rejected():
    b, resp = connected()
    with pytest.raises(pk.KemError) as exc:
        b.confirm(resp["session_id"], "bad-tag", b"hello", now=11)
    assert exc.value.code == "bad_confirm_tag"


def test_transcript_mismatch_at_confirm_is_rejected():
    b, resp = connected()
    sid = resp["session_id"]
    with pytest.raises(pk.KemError) as exc:
        b.confirm(sid, tag_for(sid), b"other", now=11)
    assert exc.value.code == "transcript_mismatch"


def test_session_cannot_be_confirmed_twice():
    b, resp = connected()
    sid = resp["session_id"]
    b.confirm(sid, tag_for(sid), b"hello", now=11)
    with pytest.raises(pk.KemError) as exc:
        b.confirm(sid, tag_for(sid), b"hello", now=12)
    assert exc.value.code == "session_replayed"


def test_concurrent_confirmation_has_one_winner():
    b, resp = connected()
    sid = resp["session_id"]
    outcomes = []

    def worker():
        try:
            b.confirm(sid, tag_for(sid), b"hello", now=11)
            outcomes.append(True)
        except pk.KemError:
            outcomes.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count(True) == 1
