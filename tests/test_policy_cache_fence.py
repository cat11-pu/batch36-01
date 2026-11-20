import threading
import time

import pytest

import policy_cache_fence as pc

CALLS = []


def evaluator(policy, subject, action, resource):
    CALLS.append(policy["tag"])
    return policy["allow"].get((subject, action, resource), False)


def cache(ttl=10):
    CALLS.clear()
    return pc.PolicyDecisionCache(evaluator, ttl=ttl)


def policy(tag, allow):
    return {"tag": tag, "allow": allow}


def test_first_decision_calls_evaluator():
    c = cache()
    c.publish("t1", 1, policy("v1", {("alice", "read", "doc1"): True}))
    out = c.decide("t1", "alice", "read", "doc1", now=0)
    assert out == {"allowed": True, "version": 1, "cached": False}
    assert len(CALLS) == 1


def test_second_decision_is_cached():
    c = cache()
    c.publish("t1", 1, policy("v1", {("alice", "read", "doc1"): True}))
    c.decide("t1", "alice", "read", "doc1", now=0)
    out = c.decide("t1", "alice", "read", "doc1", now=1)
    assert out["cached"] is True
    assert out["allowed"] is True
    assert c.stats()["hits"] == 1
    assert c.stats()["evaluations"] == 1


def test_new_version_invalidates_old_entries():
    c = cache()
    c.publish("t1", 1, policy("v1", {("alice", "read", "doc1"): True}))
    c.decide("t1", "alice", "read", "doc1", now=0)
    c.publish("t1", 2, policy("v2", {("alice", "read", "doc1"): False}))
    out = c.decide("t1", "alice", "read", "doc1", now=1)
    assert out == {"allowed": False, "version": 2, "cached": False}
    assert len(CALLS) == 2


def test_negative_result_is_cached():
    c = cache()
    c.publish("t1", 1, policy("v1", {}))
    first = c.decide("t1", "bob", "read", "doc9", now=0)
    second = c.decide("t1", "bob", "read", "doc9", now=1)
    assert first["allowed"] is False
    assert second["cached"] is True
    assert len(CALLS) == 1


def test_ttl_expiry_forces_recompute():
    c = cache(ttl=10)
    c.publish("t1", 1, policy("v1", {("alice", "read", "doc1"): True}))
    c.decide("t1", "alice", "read", "doc1", now=0)
    out = c.decide("t1", "alice", "read", "doc1", now=11)
    assert out["cached"] is False
    assert len(CALLS) == 2


def test_invalidate_subject_keeps_other_subjects():
    c = cache()
    c.publish("t1", 1, policy("v1", {("alice", "read", "doc1"): True, ("bob", "read", "doc1"): True}))
    c.decide("t1", "alice", "read", "doc1", now=0)
    c.decide("t1", "bob", "read", "doc1", now=0)
    c.invalidate("t1", subject="alice")
    alice = c.decide("t1", "alice", "read", "doc1", now=1)
    bob = c.decide("t1", "bob", "read", "doc1", now=1)
    assert alice["cached"] is False
    assert bob["cached"] is True


def test_invalidate_tenant_clears_all_subjects():
    c = cache()
    c.publish("t1", 1, policy("v1", {("alice", "read", "doc1"): True, ("bob", "read", "doc1"): True}))
    c.decide("t1", "alice", "read", "doc1", now=0)
    c.decide("t1", "bob", "read", "doc1", now=0)
    c.invalidate("t1")
    assert c.decide("t1", "alice", "read", "doc1", now=1)["cached"] is False
    assert c.decide("t1", "bob", "read", "doc1", now=1)["cached"] is False


def test_tenants_keep_independent_versions():
    c = cache()
    c.publish("t1", 1, policy("v1", {("alice", "read", "doc1"): True}))
    c.publish("t2", 7, policy("t2v7", {("alice", "read", "doc1"): True}))
    a = c.decide("t1", "alice", "read", "doc1", now=0)
    b = c.decide("t2", "alice", "read", "doc1", now=0)
    assert a["version"] == 1
    assert b["version"] == 7


def test_version_regression_is_rejected():
    c = cache()
    c.publish("t1", 2, policy("v2", {}))
    with pytest.raises(pc.PolicyCacheError) as exc:
        c.publish("t1", 1, policy("v1", {}))
    assert exc.value.code == "version_regression"


def test_same_version_different_policy_is_rejected():
    c = cache()
    c.publish("t1", 1, policy("v1", {}))
    with pytest.raises(pc.PolicyCacheError) as exc:
        c.publish("t1", 1, policy("other", {}))
    assert exc.value.code == "duplicate_version"


def test_same_version_same_policy_is_idempotent():
    c = cache()
    c.publish("t1", 1, policy("v1", {}))
    assert c.publish("t1", 1, policy("v1", {})) == 0
    assert c.decide("t1", "alice", "read", "doc1", now=0)["version"] == 1


def test_decide_without_published_policy_is_rejected():
    c = cache()
    with pytest.raises(pc.PolicyCacheError) as exc:
        c.decide("t1", "alice", "read", "doc1", now=0)
    assert exc.value.code == "no_policy"


def test_cache_key_separates_resources_and_actions():
    c = cache()
    c.publish("t1", 1, policy("v1", {("alice", "read", "doc1"): True}))
    assert c.decide("t1", "alice", "read", "doc1", now=0)["allowed"] is True
    assert c.decide("t1", "alice", "read", "doc2", now=0)["allowed"] is False
    assert c.decide("t1", "alice", "write", "doc1", now=0)["allowed"] is False
    assert len(CALLS) == 3


def test_concurrent_misses_evaluate_once():
    c = cache()
    c.publish("t1", 1, policy("v1", {("alice", "read", "doc1"): True}))
    results = []
    lock = threading.Lock()

    def worker():
        out = c.decide("t1", "alice", "read", "doc1", now=0)
        with lock:
            results.append(out)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(CALLS) == 1
    assert all(r["allowed"] is True for r in results)


def test_publish_during_evaluation_fences_stale_result():
    started = threading.Event()
    release = threading.Event()

    def slow(policy_value, subject, action, resource):
        CALLS.append(policy_value["tag"])
        if policy_value["tag"] == "v1":
            started.set()
            release.wait(2)
            return True
        return False

    c = pc.PolicyDecisionCache(slow, ttl=30)
    c.publish("t1", 1, policy("v1", {}))
    out = []
    thread = threading.Thread(
        target=lambda: out.append(c.decide("t1", "alice", "read", "doc1", now=0))
    )
    thread.start()
    started.wait(2)
    c.publish("t1", 2, policy("v2", {}))
    release.set()
    thread.join()
    assert out[0]["version"] == 2
    assert out[0]["allowed"] is False
    assert out[0]["cached"] is False
