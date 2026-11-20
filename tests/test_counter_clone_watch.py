import threading

import pytest

import counter_clone_watch as cw


def watch(**kw):
    return cw.CounterCloneWatch(**kw)


def registered(counter=5):
    w = watch()
    w.register("cred-1", "dev-a", counter=counter, now=0)
    return w


def test_register_creates_active_credential():
    rec = watch().register("cred-1", "dev-a", counter=5, now=1)
    assert rec["credential_id"] == "cred-1"
    assert rec["device_id"] == "dev-a"
    assert rec["state"] == "active"
    assert rec["last_counter"] == 5


def test_duplicate_registration_is_rejected():
    w = registered()
    with pytest.raises(cw.CounterWatchError) as exc:
        w.register("cred-1", "dev-b", counter=1, now=2)
    assert exc.value.code == "credential_exists"


def test_increasing_counter_updates_baseline():
    w = registered(counter=1)
    w.observe("cred-1", "dev-a", 2, signature_ok=True, now=1)
    out = w.observe("cred-1", "dev-a", 3, signature_ok=True, now=2)
    assert out["accepted"] is True
    assert w.status("cred-1")["last_counter"] == 3


def test_equal_counter_marks_clone():
    w = registered(counter=5)
    with pytest.raises(cw.CounterWatchError) as exc:
        w.observe("cred-1", "dev-a", 5, signature_ok=True, now=1)
    assert exc.value.code == "clone_detected"
    assert w.status("cred-1")["state"] == "quarantined"


def test_decreasing_counter_marks_clone():
    w = registered(counter=5)
    with pytest.raises(cw.CounterWatchError) as exc:
        w.observe("cred-1", "dev-a", 4, signature_ok=True, now=1)
    assert exc.value.code == "clone_detected"


def test_quarantined_credential_rejects_further_observations():
    w = registered(counter=5)
    with pytest.raises(cw.CounterWatchError):
        w.observe("cred-1", "dev-a", 5, signature_ok=True, now=1)
    with pytest.raises(cw.CounterWatchError) as exc:
        w.observe("cred-1", "dev-a", 9, signature_ok=True, now=2)
    assert exc.value.code == "credential_quarantined"


def test_bad_signature_is_rejected_without_state_change():
    w = registered(counter=5)
    with pytest.raises(cw.CounterWatchError) as exc:
        w.observe("cred-1", "dev-a", 6, signature_ok=False, now=1)
    assert exc.value.code == "bad_signature"
    assert w.status("cred-1")["last_counter"] == 5


def test_unknown_credential_is_rejected():
    with pytest.raises(cw.CounterWatchError) as exc:
        watch().observe("cred-x", "dev-a", 1, signature_ok=True, now=1)
    assert exc.value.code == "unknown_credential"


def test_zero_counter_keeps_existing_baseline():
    w = registered(counter=5)
    out = w.observe("cred-1", "dev-a", 0, signature_ok=True, now=1)
    assert out["accepted"] is True
    assert w.status("cred-1")["last_counter"] == 5


def test_zero_counter_is_accepted_for_legacy_authenticator():
    w = watch()
    w.register("cred-1", "dev-a", counter=0, now=0)
    out = w.observe("cred-1", "dev-a", 0, signature_ok=True, now=1)
    assert out["accepted"] is True


def test_device_mismatch_is_rejected():
    w = registered()
    with pytest.raises(cw.CounterWatchError) as exc:
        w.observe("cred-1", "dev-b", 6, signature_ok=True, now=1)
    assert exc.value.code == "device_mismatch"


def test_large_jump_is_flagged_but_accepted():
    w = watch(jump_threshold=1000)
    w.register("cred-1", "dev-a", counter=0, now=0)
    out = w.observe("cred-1", "dev-a", 5000, signature_ok=True, now=1)
    assert out["accepted"] is True
    alerts = w.status("cred-1")["alerts"]
    assert any(a["type"] == "counter_jump" for a in alerts)


def test_recover_clears_quarantine_with_higher_baseline():
    w = registered(counter=5)
    with pytest.raises(cw.CounterWatchError):
        w.observe("cred-1", "dev-a", 4, signature_ok=True, now=1)
    w.recover("cred-1", "dev-a", 10, now=2)
    assert w.status("cred-1")["state"] == "active"
    assert w.status("cred-1")["last_counter"] == 10


def test_recover_cannot_lower_baseline():
    w = registered(counter=5)
    with pytest.raises(cw.CounterWatchError):
        w.observe("cred-1", "dev-a", 4, signature_ok=True, now=1)
    with pytest.raises(cw.CounterWatchError) as exc:
        w.recover("cred-1", "dev-a", 3, now=2)
    assert exc.value.code == "baseline_regression"
    assert w.status("cred-1")["state"] == "quarantined"


def test_concurrent_observations_have_one_winner():
    w = registered(counter=5)
    outcomes = []

    def worker():
        try:
            w.observe("cred-1", "dev-a", 6, signature_ok=True, now=1)
            outcomes.append(True)
        except cw.CounterWatchError:
            outcomes.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count(True) == 1
