import threading

import pytest

import delegation_depth_witness as dw

SECRET = "mesh-secret"


def witness(**kw):
    return dw.DelegationWitness(SECRET, **kw)


def root(w=None, **kw):
    return (w or witness()).issue(
        "svc-a", "api", ["read"], ttl=100, now=0, **kw
    )


def test_root_token_verifies():
    out = witness().verify(root(), "api", "read", now=10)
    assert out["subject"] == "svc-a"
    assert out["depth"] == 0
    assert out["audience"] == "api"


def test_chain_of_root_is_single_subject():
    out = witness().chain(root())
    assert out == {"subjects": ["svc-a"], "depth": 0}


def test_redelegation_increments_depth():
    w = witness()
    child = w.redelegate(root(w), "svc-b", "api", ["read"], ttl=50, now=10)
    claims = w.verify(child, "api", "read", now=20)
    assert claims["depth"] == 1
    assert w.chain(child) == {"subjects": ["svc-a", "svc-b"], "depth": 1}


def test_depth_limit_is_enforced():
    w = witness(max_depth=1)
    child = w.redelegate(root(w), "svc-b", "api", ["read"], ttl=50, now=10)
    with pytest.raises(dw.DelegationError) as exc:
        w.redelegate(child, "svc-c", "api", ["read"], ttl=10, now=20)
    assert exc.value.code == "depth_exceeded"


def test_scope_escalation_is_rejected():
    w = witness()
    with pytest.raises(dw.DelegationError) as exc:
        w.redelegate(root(w), "svc-b", "api", ["read", "write"], ttl=50, now=10)
    assert exc.value.code == "scope_escalation"


def test_narrowed_scope_is_accepted():
    w = witness()
    child = w.redelegate(root(w), "svc-b", "api", ["read"], ttl=50, now=10)
    claims = w.verify(child, "api", "read", now=15)
    assert claims["scopes"] == ["read"]


def test_child_cannot_outlive_parent():
    w = witness()
    with pytest.raises(dw.DelegationError) as exc:
        w.redelegate(root(w), "svc-b", "api", ["read"], ttl=120, now=10)
    assert exc.value.code == "expiry_exceeds_parent"


def test_no_redelegate_flag_blocks_child():
    w = witness()
    parent = w.issue("svc-a", "api", ["read"], ttl=100, now=0, allow_redelegate=False)
    with pytest.raises(dw.DelegationError) as exc:
        w.redelegate(parent, "svc-b", "api", ["read"], ttl=10, now=1)
    assert exc.value.code == "redelegation_forbidden"


def test_expired_token_is_rejected():
    w = witness()
    with pytest.raises(dw.DelegationError) as exc:
        w.verify(root(w), "api", "read", now=101)
    assert exc.value.code == "expired"


def test_clock_skew_is_tolerated_within_limit():
    w = witness(clock_skew=5)
    token = root(w)
    assert w.verify(token, "api", "read", now=104)["subject"] == "svc-a"
    with pytest.raises(dw.DelegationError) as exc:
        w.verify(token, "api", "read", now=106)
    assert exc.value.code == "expired"


def test_audience_mismatch_is_rejected():
    with pytest.raises(dw.DelegationError) as exc:
        witness().verify(root(), "billing", "read", now=1)
    assert exc.value.code == "audience_mismatch"


def test_missing_required_scope_is_rejected():
    with pytest.raises(dw.DelegationError) as exc:
        witness().verify(root(), "api", "write", now=1)
    assert exc.value.code == "scope_missing"


def test_tampered_token_is_rejected():
    w = witness()
    token = root(w)
    bad = dict(token)
    bad["scopes"] = ["read", "write"]
    with pytest.raises(dw.DelegationError) as exc:
        w.verify(bad, "api", "read", now=1)
    assert exc.value.code == "signature_mismatch"


def test_revoked_ancestor_invalidates_child():
    w = witness()
    parent = root(w)
    child = w.redelegate(parent, "svc-b", "api", ["read"], ttl=50, now=10)
    with pytest.raises(dw.DelegationError) as exc:
        w.verify(child, "api", "read", now=20, revoked=[parent["token_id"]])
    assert exc.value.code == "revoked"


def test_concurrent_children_have_unique_ids_and_verify():
    w = witness(max_depth=2)
    parent = root(w)
    tokens = []
    lock = threading.Lock()

    def worker(i):
        token = w.redelegate(parent, f"svc-{i}", "api", ["read"], ttl=30, now=5)
        with lock:
            tokens.append(token)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len({t["token_id"] for t in tokens}) == 8
    for token in tokens:
        assert w.verify(token, "api", "read", now=10)["depth"] == 1
