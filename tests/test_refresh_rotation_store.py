import threading

import pytest

import refresh_rotation_store as rs


def ledger(**kw):
    return rs.RefreshRotationStore(**kw)


def issued(store, **kw):
    args = {"client_id": "app-1", "subject": "user-1", "scopes": ["read", "write"], "now": 0}
    args.update(kw)
    return store.issue(**args)


def test_issue_normalizes_record():
    rec = issued(ledger())
    assert rec["scopes"] == ["read", "write"]
    assert rec["expires_at"] == 3600
    assert rec["token"]
    assert rec["family_id"]


def test_rotation_issues_new_token_in_same_family():
    s = ledger()
    first = issued(s)
    second = s.rotate(first["token"], "app-1", now=10)
    assert second["token"] != first["token"]
    assert second["family_id"] == first["family_id"]
    assert second["subject"] == "user-1"
    assert s.inspect(first["token"])["used"] is True


def test_reused_token_revokes_whole_family():
    s = ledger()
    first = issued(s)
    second = s.rotate(first["token"], "app-1", now=10)
    with pytest.raises(rs.RefreshError) as exc:
        s.rotate(first["token"], "app-1", now=11)
    assert exc.value.code == "token_reuse"
    with pytest.raises(rs.RefreshError) as exc2:
        s.rotate(second["token"], "app-1", now=12)
    assert exc2.value.code == "family_revoked"


def test_expired_token_is_rejected():
    s = ledger(token_ttl=10)
    first = issued(s)
    with pytest.raises(rs.RefreshError) as exc:
        s.rotate(first["token"], "app-1", now=11)
    assert exc.value.code == "expired"


def test_unknown_token_is_rejected():
    with pytest.raises(rs.RefreshError) as exc:
        ledger().rotate("nope", "app-1", now=1)
    assert exc.value.code == "unknown_token"


def test_client_mismatch_is_rejected():
    s = ledger()
    first = issued(s)
    with pytest.raises(rs.RefreshError) as exc:
        s.rotate(first["token"], "app-2", now=1)
    assert exc.value.code == "client_mismatch"


def test_scope_narrowing_is_allowed():
    s = ledger()
    first = issued(s)
    second = s.rotate(first["token"], "app-1", scopes=["read"], now=1)
    assert second["scopes"] == ["read"]


def test_scope_widening_is_rejected():
    s = ledger()
    first = issued(s)
    with pytest.raises(rs.RefreshError) as exc:
        s.rotate(first["token"], "app-1", scopes=["read", "admin"], now=1)
    assert exc.value.code == "scope_escalation"


def test_rotation_deduplicates_scopes():
    s = ledger()
    first = issued(s)
    second = s.rotate(first["token"], "app-1", scopes=["read", "read"], now=1)
    assert second["scopes"] == ["read"]


def test_issue_requires_non_empty_scopes():
    with pytest.raises(ValueError):
        issued(ledger(), scopes=[])


def test_scopes_must_be_a_list():
    with pytest.raises(ValueError):
        issued(ledger(), scopes="read")


def test_revoked_family_cannot_rotate():
    s = ledger()
    first = issued(s)
    s.revoke_family(first["family_id"])
    with pytest.raises(rs.RefreshError) as exc:
        s.rotate(first["token"], "app-1", now=1)
    assert exc.value.code == "family_revoked"


def test_family_chain_length_is_capped():
    s = ledger(max_family_len=2)
    first = issued(s)
    second = s.rotate(first["token"], "app-1", now=1)
    with pytest.raises(rs.RefreshError) as exc:
        s.rotate(second["token"], "app-1", now=2)
    assert exc.value.code == "family_exhausted"


def test_snapshot_is_a_deep_copy():
    s = ledger()
    rec = issued(s)
    snap = s.snapshot()
    snap["tokens"].clear()
    assert s.inspect(rec["token"])["subject"] == "user-1"
    assert rec["token"] not in str(s.snapshot().get("tokens", {}))


def test_concurrent_rotation_has_one_winner():
    s = ledger()
    first = issued(s)
    outcomes = []

    def worker():
        try:
            s.rotate(first["token"], "app-1", now=5)
            outcomes.append(True)
        except rs.RefreshError:
            outcomes.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count(True) == 1
