import base64
import json
import threading

import pytest

import kms_envelope_ledger as ke


class FakeCrypto:
    def __init__(self):
        self.n = 0

    def generate(self):
        self.n += 1
        return "dek-%d" % self.n

    def wrap(self, key_id, dek):
        return "%s|%s" % (key_id, dek)

    def unwrap(self, token):
        if token == "broken":
            return None
        return token.split("|", 1)[1]

    def seal(self, dek, plaintext, aad):
        body = base64.b64encode(plaintext.encode("utf-8")).decode("ascii")
        return "%s::%s::%s" % (dek, aad, body)

    def open(self, dek, sealed, aad):
        prefix = "%s::%s::" % (dek, aad)
        if not sealed.startswith(prefix):
            return None
        return base64.b64decode(sealed[len(prefix):]).decode("utf-8")


KEYS = {
    "k-main": {"state": "enabled", "created_at": 0, "retire_at": None},
    "k-second": {"state": "enabled", "created_at": 0, "retire_at": None},
    "k-off": {"state": "disabled", "created_at": 0, "retire_at": None},
    "k-dead": {"state": "destroyed", "created_at": 0, "retire_at": None},
    "k-future": {"state": "enabled", "created_at": 100, "retire_at": None},
    "k-old": {"state": "enabled", "created_at": 0, "retire_at": 50},
}
CTX = {"tenant": "acme", "purpose": "backup"}


def cipher(**kw):
    base = {
        "keys": {k: dict(v) for k, v in KEYS.items()},
        "crypto": FakeCrypto(),
        "max_dek_uses": 3,
    }
    base.update(kw)
    return ke.EnvelopeCipher(**base)


def test_encrypt_and_decrypt_roundtrip():
    c = cipher()
    blob = c.encrypt("k-main", "payload", CTX, now=10)
    assert blob["key_id"] == "k-main"
    assert blob["dek_id"]
    assert "payload" not in json.dumps(blob)
    assert c.decrypt(blob, CTX, now=11) == "payload"


def test_context_mismatch_is_rejected():
    c = cipher()
    blob = c.encrypt("k-main", "payload", CTX, now=10)
    with pytest.raises(ke.EnvelopeError) as exc:
        c.decrypt(blob, {"tenant": "other", "purpose": "backup"}, now=11)
    assert exc.value.code == "context_mismatch"


def test_tampered_context_digest_is_rejected():
    c = cipher()
    blob = c.encrypt("k-main", "payload", CTX, now=10)
    blob["context_digest"] = "0" * 64
    with pytest.raises(ke.EnvelopeError) as exc:
        c.decrypt(blob, CTX, now=11)
    assert exc.value.code == "context_mismatch"


def test_unknown_key_is_rejected():
    with pytest.raises(ke.EnvelopeError) as exc:
        cipher().encrypt("k-ghost", "payload", CTX, now=10)
    assert exc.value.code == "unknown_key"


def test_disabled_key_cannot_encrypt():
    with pytest.raises(ke.EnvelopeError) as exc:
        cipher().encrypt("k-off", "payload", CTX, now=10)
    assert exc.value.code == "key_disabled"


def test_destroyed_key_cannot_decrypt():
    c = cipher()
    blob = c.encrypt("k-main", "payload", CTX, now=10)
    c.revoke_key("k-main", now=11)
    with pytest.raises(ke.EnvelopeError) as exc:
        c.decrypt(blob, CTX, now=12)
    assert exc.value.code == "key_destroyed"


def test_future_key_is_not_yet_active():
    with pytest.raises(ke.EnvelopeError) as exc:
        cipher().encrypt("k-future", "payload", CTX, now=10)
    assert exc.value.code == "key_not_yet_active"


def test_retired_key_cannot_encrypt():
    with pytest.raises(ke.EnvelopeError) as exc:
        cipher().encrypt("k-old", "payload", CTX, now=60)
    assert exc.value.code == "key_retired"


def test_broken_wrapped_dek_is_rejected():
    c = cipher()
    blob = c.encrypt("k-main", "payload", CTX, now=10)
    blob["wrapped_dek"] = "broken"
    with pytest.raises(ke.EnvelopeError) as exc:
        c.decrypt(blob, CTX, now=11)
    assert exc.value.code == "bad_wrapped_dek"


def test_integrity_failure_is_rejected():
    c = cipher()
    blob = c.encrypt("k-main", "payload", CTX, now=10)
    blob["sealed"] = "tampered"
    with pytest.raises(ke.EnvelopeError) as exc:
        c.decrypt(blob, CTX, now=11)
    assert exc.value.code == "integrity_failed"


def test_failed_decrypt_does_not_consume_use():
    c = cipher()
    blob = c.encrypt("k-main", "payload", CTX, now=10)
    bad = dict(blob)
    bad["sealed"] = "tampered"
    with pytest.raises(ke.EnvelopeError):
        c.decrypt(bad, CTX, now=11)
    assert c.decrypt(blob, CTX, now=12) == "payload"
    assert c.snapshot()["uses"][blob["dek_id"]] == 2


def test_rewrap_moves_blob_to_new_key():
    c = cipher()
    blob = c.encrypt("k-main", "payload", CTX, now=10)
    moved = c.rewrap(blob, "k-second", now=11)
    assert moved["key_id"] == "k-second"
    assert c.decrypt(moved, CTX, now=12) == "payload"
    assert c.decrypt(blob, CTX, now=13) == "payload"


def test_revoked_key_cannot_encrypt():
    c = cipher()
    c.revoke_key("k-main", now=10)
    with pytest.raises(ke.EnvelopeError) as exc:
        c.encrypt("k-main", "payload", CTX, now=11)
    assert exc.value.code == "key_destroyed"


def test_concurrent_decrypt_of_single_use_dek_has_one_winner():
    c = cipher(max_dek_uses=1)
    blob = c.encrypt("k-main", "payload", CTX, now=10)
    outcomes = []

    def worker():
        try:
            c.decrypt(blob, CTX, now=11)
            outcomes.append(True)
        except ke.EnvelopeError:
            outcomes.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count(True) == 1


def test_snapshot_is_detached_and_hides_plaintext():
    c = cipher()
    blob = c.encrypt("k-main", "payload", CTX, now=10)
    snap = c.snapshot()
    assert "payload" not in json.dumps(snap)
    assert snap["uses"]
    snap["uses"].clear()
    snap["keys"]["k-main"]["state"] = "disabled"
    assert c.snapshot()["uses"]
    assert c.snapshot()["keys"]["k-main"]["state"] == "enabled"
    assert c.decrypt(blob, CTX, now=11) == "payload"
