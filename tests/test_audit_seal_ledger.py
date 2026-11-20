import copy
import hashlib
import json
import threading

import pytest

import audit_seal_ledger as al

KEY = "test-chain-key-0001"


def ledger(**kw):
    return al.AuditSealLedger(KEY, **kw)


def canonical(entry):
    return json.dumps(
        entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def test_append_links_records():
    led = ledger()
    first = led.append({"action": "login"})
    second = led.append({"action": "logout"})
    assert first["seq"] == 1
    assert second["seq"] == 2
    assert first["prev"] == "0" * 64
    assert second["prev"] == first["mac"]
    assert first["digest"] == hashlib.sha256(canonical({"action": "login"})).hexdigest()
    assert len(first["mac"]) == 64


def test_key_order_does_not_change_digest():
    a = ledger().append({"b": 1, "a": 2})
    b = ledger().append({"a": 2, "b": 1})
    assert a["digest"] == b["digest"]


def test_unicode_is_not_escaped():
    rec = ledger().append({"msg": "你好"})
    assert rec["digest"] == hashlib.sha256('{"msg":"你好"}'.encode("utf-8")).hexdigest()


def test_verify_accepts_untouched_chain():
    led = ledger()
    records = [led.append({"n": 1}), led.append({"n": 2})]
    out = led.verify(records)
    assert out["ok"] is True
    assert out["length"] == 2
    assert out["broken_at"] is None
    assert out["reason"] is None


def test_tampered_event_is_detected_at_its_sequence():
    led = ledger()
    records = [led.append({"action": "login"}), led.append({"action": "logout"})]
    bad = copy.deepcopy(records)
    bad[1]["event"]["action"] = "delete"
    out = led.verify(bad)
    assert out["ok"] is False
    assert out["broken_at"] == 2
    assert out["reason"] == "digest_mismatch"


def test_tampered_mac_is_detected():
    led = ledger()
    records = [led.append({"n": 1}), led.append({"n": 2})]
    records[0]["mac"] = "0" * 64
    out = led.verify(records)
    assert out["ok"] is False
    assert out["broken_at"] == 1
    assert out["reason"] == "mac_mismatch"


def test_reordered_records_are_detected():
    led = ledger()
    records = [led.append({"n": 1}), led.append({"n": 2})]
    out = led.verify([records[1], records[0]])
    assert out["ok"] is False
    assert out["broken_at"] == 2
    assert out["reason"] == "seq_mismatch"


def test_truncated_chain_is_detected_against_checkpoint():
    led = ledger()
    records = [led.append({"n": 1}), led.append({"n": 2}), led.append({"n": 3})]
    cp = led.checkpoint()
    assert cp["seq"] == 3
    assert cp["head"] == records[-1]["mac"]
    out = led.verify(records[:2], cp)
    assert out["ok"] is False
    assert out["length"] == 2
    assert out["reason"] == "truncated"
    assert out["broken_at"] is None


def test_middle_deletion_is_detected():
    led = ledger()
    records = [led.append({"n": 1}), led.append({"n": 2}), led.append({"n": 3})]
    out = led.verify([records[0], records[2]])
    assert out["ok"] is False
    assert out["broken_at"] == 3
    assert out["reason"] == "seq_mismatch"


def test_wrong_key_fails_verification():
    records = [ledger().append({"n": 1})]
    other = al.AuditSealLedger("another-chain-key")
    out = other.verify(records)
    assert out["ok"] is False
    assert out["broken_at"] == 1
    assert out["reason"] == "mac_mismatch"


def test_empty_chain_is_rejected():
    out = ledger().verify([])
    assert out["ok"] is False
    assert out["length"] == 0
    assert out["broken_at"] is None
    assert out["reason"] == "empty_chain"


def test_checkpoint_head_mismatch_is_detected():
    led = ledger()
    records = [led.append({"n": 1}), led.append({"n": 2})]
    out = led.verify(records, {"seq": 2, "head": "f" * 64})
    assert out["ok"] is False
    assert out["reason"] == "checkpoint_mismatch"


def test_non_dict_or_empty_entry_is_rejected():
    led = ledger()
    for bad in ["text", {}, []]:
        with pytest.raises(al.AuditSealError) as exc:
            led.append(bad)
        assert exc.value.code == "bad_entry"


def test_float_value_is_rejected():
    with pytest.raises(al.AuditSealError) as exc:
        ledger().append({"amount": 1.5})
    assert exc.value.code == "bad_value"


def test_concurrent_appends_are_unique_and_counted():
    led = ledger()
    records = []
    guard = threading.Lock()
    problems = []

    def worker():
        try:
            for _ in range(3):
                rec = led.append({"action": "touch"})
                with guard:
                    records.append(rec)
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    seqs = sorted(rec["seq"] for rec in records)
    assert seqs == list(range(1, 25))
    ordered = sorted(records, key=lambda rec: rec["seq"])
    assert led.verify(ordered)["ok"] is True
    snap = led.snapshot()
    assert snap["appended"] == 24
    snap["appended"] = 0
    assert led.snapshot()["appended"] == 24
