import threading

import pytest

import nested_role_tree as rt


def policy():
    return {
        "roles": {
            "viewer": {"parents": []},
            "editor": {"parents": ["viewer"]},
            "manager": {"parents": ["editor"]},
            "contractor": {"parents": ["viewer"], "boundary": ["read"]},
            "admin": {"parents": []},
        },
        "nodes": {
            "root": {"parent": None},
            "team": {"parent": "root"},
            "doc1": {"parent": "team"},
            "secret": {"parent": "doc1"},
            "trash": {"parent": "team", "deleted": True},
        },
        "actions": ["read", "write", "delete", "share"],
        "grants": [
            {"role": "viewer", "action": "read", "node": "root"},
            {"role": "editor", "action": "write", "node": "team"},
            {"role": "manager", "action": "delete", "node": "root"},
            {"role": "contractor", "action": "write", "node": "team"},
            {"role": "admin", "action": "*", "node": "root"},
        ],
        "denies": [
            {"role": "contractor", "action": "read", "node": "secret"},
        ],
    }


def guard(p=None):
    return rt.RoleTreeGuard(policy() if p is None else p)


def test_inherited_read_covers_descendants():
    out = guard().check(["viewer"], "read", "doc1")
    assert out["allowed"] is True
    assert out["reason"] == "grant"
    assert out["role"] == "viewer"
    assert out["node"] == "doc1"


def test_grant_does_not_leak_toward_ancestors():
    out = guard().check(["editor"], "write", "root")
    assert out["allowed"] is False
    assert out["reason"] == "no_grant"


def test_role_inheritance_is_transitive():
    out = guard().check(["manager"], "delete", "secret")
    assert out["allowed"] is True
    assert out["role"] == "manager"


def test_ancestor_deny_beats_descendant_grant():
    p = policy()
    p["denies"].append({"role": "viewer", "action": "write", "node": "root"})
    out = guard(p).check(["editor"], "write", "doc1")
    assert out["allowed"] is False
    assert out["reason"] == "deny"
    assert out["node"] == "root"


def test_descendant_deny_beats_ancestor_grant():
    out = guard().check(["contractor"], "read", "secret")
    assert out["allowed"] is False
    assert out["reason"] == "deny"
    assert out["role"] == "contractor"


def test_node_cycle_is_rejected():
    p = policy()
    p["nodes"]["a"] = {"parent": "b"}
    p["nodes"]["b"] = {"parent": "a"}
    with pytest.raises(rt.RoleTreeError) as exc:
        guard(p)
    assert exc.value.code == "node_cycle"


def test_role_cycle_is_rejected():
    p = policy()
    p["roles"]["loop_a"] = {"parents": ["loop_b"]}
    p["roles"]["loop_b"] = {"parents": ["loop_a"]}
    with pytest.raises(rt.RoleTreeError) as exc:
        guard(p)
    assert exc.value.code == "role_cycle"


def test_unknown_role_is_rejected():
    with pytest.raises(rt.RoleTreeError) as exc:
        guard().check(["ghost"], "read", "doc1")
    assert exc.value.code == "unknown_role"


def test_unknown_action_is_rejected():
    with pytest.raises(rt.RoleTreeError) as exc:
        guard().check(["viewer"], "publish", "doc1")
    assert exc.value.code == "unknown_action"


def test_unknown_node_is_rejected():
    with pytest.raises(rt.RoleTreeError) as exc:
        guard().check(["viewer"], "read", "missing")
    assert exc.value.code == "unknown_node"


def test_empty_identity_is_denied():
    out = guard().check([], "read", "doc1")
    assert out["allowed"] is False
    assert out["reason"] == "no_roles"


def test_permission_boundary_caps_role():
    out = guard().check(["contractor"], "write", "team")
    assert out["allowed"] is False
    assert out["reason"] == "boundary"


def test_deleted_node_denies_manager():
    out = guard().check(["manager"], "delete", "trash")
    assert out["allowed"] is False
    assert out["reason"] == "deleted"


def test_wildcard_admin_can_write_anywhere():
    out = guard().check(["admin"], "write", "secret")
    assert out["allowed"] is True
    assert out["role"] == "admin"


def test_state_copy_and_concurrent_checks_are_stable():
    g = guard()
    snapshot = g.state()
    snapshot["roles"]["viewer"]["parents"].append("admin")
    assert g.check(["viewer"], "read", "doc1")["allowed"] is True
    results = []

    def worker():
        for _ in range(20):
            results.append(g.check(["manager"], "delete", "secret")["allowed"])

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == [True] * 160
