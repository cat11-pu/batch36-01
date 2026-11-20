import json
import re
import threading

import pytest

import backup_code_vault as bv


def vault(**over):
    opts = {"max_failures": 5, "ttl": 3600, "lock_seconds": 300}
    opts.update(over)
    return bv.BackupCodeVault(**opts)


def batch(v, user="alice", count=10, now=0):
    return v.generate(user, count=count, now=now)


def test_generated_codes_are_unique_and_formatted():
    out = batch(vault())
    codes = out["codes"]
    assert len(codes) == 10
    for code in codes:
        assert re.fullmatch(r"[A-Z2-9]{4}(-[A-Z2-9]{4}){3}", code)
    assert len(set(codes)) == 10
    assert out["expires_at"] == 3600


def test_code_count_is_bounded():
    v = vault()
    with pytest.raises(ValueError):
        v.generate("alice", count=0, now=0)
    with pytest.raises(ValueError):
        v.generate("alice", count=21, now=0)
    assert len(v.generate("alice", count=5, now=0)["codes"]) == 5


def test_export_never_contains_plaintext_or_salt():
    v = vault()
    codes = batch(v)["codes"]
    state = json.dumps(v.export_state())
    for code in codes:
        assert code not in state
    assert "salt" not in state.lower()


def test_consume_reduces_remaining():
    v = vault()
    codes = batch(v)["codes"]
    res = v.consume("alice", codes[0], now=1)
    assert res["remaining"] == 9
    assert v.remaining("alice") == 9


def test_consumed_code_cannot_be_reused():
    v = vault()
    codes = batch(v)["codes"]
    v.consume("alice", codes[0], now=1)
    with pytest.raises(bv.BackupCodeError) as exc:
        v.consume("alice", codes[0], now=2)
    assert exc.value.code == "already_used"
    assert v.remaining("alice") == 9


def test_wrong_code_is_rejected_without_consuming():
    v = vault()
    batch(v)
    with pytest.raises(bv.BackupCodeError) as exc:
        v.consume("alice", "0000-0000-0000-0000", now=1)
    assert exc.value.code == "invalid_code"
    assert v.remaining("alice") == 10


def test_code_input_is_normalized():
    v = vault()
    codes = batch(v)["codes"]
    messy = codes[1].lower().replace("-", " ")
    assert v.consume("alice", messy, now=1)["remaining"] == 9


def test_expired_batch_is_rejected():
    v = vault(ttl=100)
    codes = batch(v, now=0)["codes"]
    with pytest.raises(bv.BackupCodeError) as exc:
        v.consume("alice", codes[0], now=101)
    assert exc.value.code == "expired"


def test_regeneration_invalidates_previous_batch():
    v = vault()
    old = batch(v)["codes"]
    fresh = batch(v, now=10)["codes"]
    assert set(old).isdisjoint(set(fresh))
    with pytest.raises(bv.BackupCodeError):
        v.consume("alice", old[0], now=11)
    assert v.consume("alice", fresh[0], now=12)["remaining"] == 9


def test_lockout_after_repeated_failures():
    v = vault()
    codes = batch(v)["codes"]
    for i in range(5):
        with pytest.raises(bv.BackupCodeError):
            v.consume("alice", "0000-0000-0000-0000", now=1)
    with pytest.raises(bv.BackupCodeError) as exc:
        v.consume("alice", codes[0], now=2)
    assert exc.value.code == "locked"


def test_success_resets_failure_counter():
    v = vault()
    codes = batch(v)["codes"]
    for i in range(4):
        with pytest.raises(bv.BackupCodeError):
            v.consume("alice", "0000-0000-0000-0000", now=1)
    assert v.consume("alice", codes[0], now=2)["remaining"] == 9
    for i in range(4):
        with pytest.raises(bv.BackupCodeError):
            v.consume("alice", "0000-0000-0000-0000", now=3)
    assert v.consume("alice", codes[1], now=4)["remaining"] == 8


def test_unknown_user_and_empty_code_are_rejected():
    v = vault()
    batch(v)
    with pytest.raises(bv.BackupCodeError) as exc:
        v.consume("bob", "AAAA-AAAA-AAAA-AAAA", now=1)
    assert exc.value.code == "unknown_user"
    with pytest.raises(ValueError):
        v.consume("alice", "", now=1)


def test_concurrent_consume_allows_only_one_winner():
    v = vault()
    codes = batch(v)["codes"]
    outcomes = []

    def worker():
        try:
            v.consume("alice", codes[0], now=1)
            outcomes.append(True)
        except bv.BackupCodeError:
            outcomes.append(False)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count(True) == 1
    assert v.remaining("alice") == 9


def test_exhausted_batch_is_rejected():
    v = vault()
    codes = batch(v, count=2)["codes"]
    v.consume("alice", codes[0], now=1)
    v.consume("alice", codes[1], now=2)
    assert v.remaining("alice") == 0
    with pytest.raises(bv.BackupCodeError) as exc:
        v.consume("alice", "0000-0000-0000-0000", now=3)
    assert exc.value.code == "exhausted"


def test_lockout_expires_after_window():
    v = vault(lock_seconds=300)
    codes = batch(v)["codes"]
    for i in range(5):
        with pytest.raises(bv.BackupCodeError):
            v.consume("alice", "0000-0000-0000-0000", now=10)
    with pytest.raises(bv.BackupCodeError) as exc:
        v.consume("alice", codes[0], now=20)
    assert exc.value.code == "locked"
    assert v.consume("alice", codes[0], now=311)["remaining"] == 9
