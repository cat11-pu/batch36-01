import threading

import pytest

import dual_key_secret_rotation as dk


class FakeCipher:
    def seal(self, key_id, plaintext):
        return "%s|%s" % (key_id, plaintext)

    def open(self, key_id, ciphertext):
        parts = ciphertext.split("|", 1)
        if parts[0] != key_id:
            return None
        return parts[1]


def ring(**kw):
    base = {"crypto": FakeCipher(), "max_grace": 3600, "min_interval": 60}
    base.update(kw)
    return dk.DualKeyRing(**base)


def test_install_creates_standby_key():
    rec = ring().install(1, "key-a", now=0)
    assert rec["version"] == 1
    assert rec["key_id"] == "key-a"
    assert rec["state"] == "standby"


def test_version_order_is_enforced():
    r = ring()
    r.install(2, "key-b", now=0)
    with pytest.raises(dk.DualKeyError) as exc:
        r.install(1, "key-a", now=1)
    assert exc.value.code == "version_order"


def test_duplicate_key_id_is_rejected():
    r = ring()
    r.install(1, "key-a", now=0)
    r.promote(1, now=0)
    with pytest.raises(dk.DualKeyError) as exc:
        r.install(2, "key-a", now=100)
    assert exc.value.code == "duplicate_key_id"


def test_second_standby_is_rejected():
    r = ring()
    r.install(1, "key-a", now=0)
    with pytest.raises(dk.DualKeyError) as exc:
        r.install(2, "key-b", now=1)
    assert exc.value.code == "standby_exists"


def test_promote_first_key_without_previous():
    r = ring()
    r.install(1, "key-a", now=0)
    out = r.promote(1, now=0)
    assert out["active"] == 1
    assert out["previous"] is None


def test_promotion_interval_is_enforced():
    r = ring(min_interval=60)
    r.install(1, "key-a", now=0)
    r.promote(1, now=0)
    r.install(2, "key-b", now=1)
    with pytest.raises(dk.DualKeyError) as exc:
        r.promote(2, now=30)
    assert exc.value.code == "promotion_too_soon"


def test_previous_key_decrypts_within_grace():
    r = ring(max_grace=3600)
    r.install(1, "key-a", now=0)
    r.promote(1, now=0)
    blob = r.encrypt("secret", now=10)
    r.install(2, "key-b", now=20)
    r.promote(2, now=100)
    assert r.decrypt(blob, now=200) == "secret"


def test_previous_key_fails_after_grace():
    r = ring(max_grace=100)
    r.install(1, "key-a", now=0)
    r.promote(1, now=0)
    blob = r.encrypt("secret", now=10)
    r.install(2, "key-b", now=20)
    r.promote(2, now=100)
    with pytest.raises(dk.DualKeyError) as exc:
        r.decrypt(blob, now=201)
    assert exc.value.code == "key_retired"


def test_explicitly_retired_previous_key_fails():
    r = ring()
    r.install(1, "key-a", now=0)
    r.promote(1, now=0)
    blob = r.encrypt("secret", now=10)
    r.install(2, "key-b", now=20)
    r.promote(2, now=100)
    r.retire(1, now=150)
    with pytest.raises(dk.DualKeyError) as exc:
        r.decrypt(blob, now=200)
    assert exc.value.code == "key_retired"


def test_encrypt_without_active_key_is_rejected():
    with pytest.raises(dk.DualKeyError) as exc:
        ring().encrypt("secret", now=0)
    assert exc.value.code == "no_active_key"


def test_encrypt_and_decrypt_roundtrip():
    r = ring()
    r.install(1, "key-a", now=0)
    r.promote(1, now=0)
    blob = r.encrypt("secret", now=10)
    assert blob["version"] == 1
    assert r.decrypt(blob, now=11) == "secret"


def test_active_key_cannot_be_retired():
    r = ring()
    r.install(1, "key-a", now=0)
    r.promote(1, now=0)
    with pytest.raises(dk.DualKeyError) as exc:
        r.retire(1, now=1)
    assert exc.value.code == "active_key"


def test_compromised_active_key_stops_encryption_and_decryption():
    r = ring()
    r.install(1, "key-a", now=0)
    r.promote(1, now=0)
    blob = r.encrypt("secret", now=10)
    r.compromise(1, now=11)
    with pytest.raises(dk.DualKeyError) as exc:
        r.decrypt(blob, now=12)
    assert exc.value.code == "key_revoked"
    with pytest.raises(dk.DualKeyError) as exc2:
        r.encrypt("next", now=13)
    assert exc2.value.code == "no_active_key"


def test_promoting_standby_recovers_after_compromise():
    r = ring()
    r.install(1, "key-a", now=0)
    r.promote(1, now=0)
    r.install(2, "key-b", now=1)
    r.compromise(1, now=10)
    out = r.promote(2, now=100)
    assert out["active"] == 2
    assert r.encrypt("secret", now=101)["version"] == 2


def test_concurrent_promotion_has_one_winner():
    r = ring()
    r.install(1, "key-a", now=0)
    r.promote(1, now=0)
    r.install(2, "key-b", now=1)
    outcomes = []

    def worker():
        try:
            r.promote(2, now=100)
            outcomes.append(True)
        except dk.DualKeyError:
            outcomes.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count(True) == 1
