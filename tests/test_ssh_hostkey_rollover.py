import threading

import pytest

import ssh_hostkey_rollover as hk


def key(fp, typ="ssh-ed25519", nb=0, na=1000):
    return {"type": typ, "fingerprint": fp, "not_before": nb, "not_after": na}


def ledger(**kw):
    return hk.HostKeyRolloverLedger(**kw)


def test_publish_creates_generation_with_primary():
    out = ledger().publish("host-a", 1, [key("SHA256:aaa")], now=0)
    assert out["generation"] == 1
    assert out["primary"] == "SHA256:aaa"
    assert out["keys"][0]["fingerprint"] == "SHA256:aaa"


def test_duplicate_fingerprint_in_generation_is_rejected():
    with pytest.raises(hk.HostKeyError) as exc:
        ledger().publish(
            "host-a", 1, [key("SHA256:aaa"), key("SHA256:aaa")], now=0
        )
    assert exc.value.code == "duplicate_key"


def test_same_key_cannot_be_published_for_two_hosts():
    l = ledger()
    l.publish("host-a", 1, [key("SHA256:aaa")], now=0)
    with pytest.raises(hk.HostKeyError) as exc:
        l.publish("host-b", 1, [key("SHA256:aaa")], now=0)
    assert exc.value.code == "key_shared"


def test_generation_gap_is_rejected():
    l = ledger()
    l.publish("host-a", 1, [key("SHA256:aaa")], now=0)
    with pytest.raises(hk.HostKeyError) as exc:
        l.publish("host-a", 3, [key("SHA256:bbb")], now=1)
    assert exc.value.code == "generation_gap"


def test_generation_cannot_be_reused():
    l = ledger()
    l.publish("host-a", 1, [key("SHA256:aaa")], now=0)
    with pytest.raises(hk.HostKeyError) as exc:
        l.publish("host-a", 1, [key("SHA256:bbb")], now=1)
    assert exc.value.code == "generation_reused"


def test_client_with_primary_is_current():
    l = ledger()
    l.publish("host-a", 1, [key("SHA256:aaa")], now=0)
    out = l.assess("host-a", ["SHA256:aaa"], now=10)
    assert out["status"] == "current"
    assert out["primary"] == "SHA256:aaa"


def test_client_with_old_key_gets_update_available():
    l = ledger()
    l.publish("host-a", 1, [key("SHA256:aaa")], now=0)
    l.publish("host-a", 2, [key("SHA256:bbb")], now=10)
    out = l.assess("host-a", ["SHA256:aaa"], now=20)
    assert out["status"] == "update_available"
    assert out["primary"] == "SHA256:bbb"
    assert out["keys"] == ["SHA256:bbb"]


def test_key_belonging_to_other_host_is_foreign():
    l = ledger()
    l.publish("host-a", 1, [key("SHA256:aaa")], now=0)
    l.publish("host-b", 1, [key("SHA256:bbb")], now=0)
    with pytest.raises(hk.HostKeyError) as exc:
        l.assess("host-a", ["SHA256:bbb"], now=10)
    assert exc.value.code == "foreign_key"


def test_revoked_key_is_rejected_by_assess():
    l = ledger()
    l.publish("host-a", 1, [key("SHA256:aaa"), key("SHA256:bbb")], now=0)
    l.revoke("host-a", "SHA256:bbb", now=1)
    with pytest.raises(hk.HostKeyError) as exc:
        l.assess("host-a", ["SHA256:bbb"], now=10)
    assert exc.value.code == "host_key_revoked"


def test_unknown_host_is_rejected():
    with pytest.raises(hk.HostKeyError) as exc:
        ledger().assess("ghost", ["SHA256:aaa"], now=0)
    assert exc.value.code == "unknown_host"


def test_merge_keeps_new_primary_and_valid_old_key():
    l = ledger()
    l.publish("host-a", 1, [key("SHA256:aaa")], now=0)
    l.publish("host-a", 2, [key("SHA256:bbb")], now=10)
    out = l.merge_update("host-a", ["SHA256:aaa"], ["SHA256:bbb"], now=20)
    assert out["keys"][0] == "SHA256:bbb"
    assert "SHA256:aaa" in out["keys"]
    assert out["changed"] is True


def test_merge_rejects_key_never_published_for_host():
    l = ledger()
    l.publish("host-a", 1, [key("SHA256:aaa")], now=0)
    with pytest.raises(hk.HostKeyError) as exc:
        l.merge_update("host-a", [], ["SHA256:zzz"], now=10)
    assert exc.value.code == "unknown_proposed_key"


def test_merge_respects_key_cap():
    l = ledger(max_keys_per_host=1)
    l.publish("host-a", 1, [key("SHA256:aaa")], now=0)
    l.publish("host-a", 2, [key("SHA256:bbb")], now=10)
    with pytest.raises(hk.HostKeyError) as exc:
        l.merge_update("host-a", ["SHA256:aaa"], ["SHA256:bbb"], now=20)
    assert exc.value.code == "too_many_keys"


def test_last_active_key_cannot_be_revoked():
    l = ledger()
    l.publish("host-a", 1, [key("SHA256:aaa")], now=0)
    with pytest.raises(hk.HostKeyError) as exc:
        l.revoke("host-a", "SHA256:aaa", now=1)
    assert exc.value.code == "last_key"


def test_concurrent_generation_publish_has_one_winner():
    l = ledger()
    l.publish("host-a", 1, [key("SHA256:aaa")], now=0)
    outcomes = []

    def worker(fp):
        try:
            l.publish("host-a", 2, [key(fp)], now=10)
            outcomes.append(True)
        except hk.HostKeyError:
            outcomes.append(False)

    threads = [
        threading.Thread(target=worker, args=("SHA256:bbb",)),
        threading.Thread(target=worker, args=("SHA256:ccc",)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count(True) == 1
