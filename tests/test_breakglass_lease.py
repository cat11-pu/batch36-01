import threading

import pytest

import breakglass_lease as bl


def service(**kw):
    return bl.BreakglassLease(**kw)


def opened(service_value=None):
    s = service_value or service()
    return s, s.request("alice", "INC-1001", 30, "database outage mitigation", now=0)


def activated(**kw):
    s = service(**kw)
    request_id = s.request("alice", "INC-1001", 30, "database outage mitigation", now=0)
    s.approve(request_id, "bob", now=1)
    s.approve(request_id, "carol", now=2)
    return s, request_id


def test_request_stays_inactive_before_approval():
    s, _ = opened()
    assert s.check("alice", now=1) is False


def test_single_approval_does_not_activate():
    s, request_id = opened()
    s.approve(request_id, "bob", now=1)
    assert s.check("alice", now=2) is False


def test_two_distinct_approvals_activate():
    s, _ = activated()
    out = s.check("alice", now=10)
    assert out["user"] == "alice"
    assert out["ticket"] == "INC-1001"
    assert out["expires_at"] == 32
    assert out["remaining_minutes"] == 22


def test_self_approval_is_rejected():
    s, request_id = opened()
    with pytest.raises(bl.BreakglassError) as exc:
        s.approve(request_id, "alice", now=1)
    assert exc.value.code == "cannot_self_approve"


def test_duplicate_approver_is_rejected():
    s, request_id = opened()
    s.approve(request_id, "bob", now=1)
    with pytest.raises(bl.BreakglassError) as exc:
        s.approve(request_id, "bob", now=2)
    assert exc.value.code == "duplicate_approver"


def test_short_justification_is_rejected():
    s = service()
    with pytest.raises(bl.BreakglassError) as exc:
        s.request("alice", "INC-1001", 30, "fix", now=0)
    assert exc.value.code == "bad_justification"


def test_duration_above_cap_is_rejected():
    s = service(max_minutes=60)
    with pytest.raises(bl.BreakglassError) as exc:
        s.request("alice", "INC-1001", 61, "database outage mitigation", now=0)
    assert exc.value.code == "bad_duration"


def test_ticket_format_is_validated():
    s = service()
    with pytest.raises(bl.BreakglassError) as exc:
        s.request("alice", "TICKET-1001", 30, "database outage mitigation", now=0)
    assert exc.value.code == "bad_ticket"


def test_active_lease_allows_admin_actions():
    s, _ = activated()
    assert s.check("alice", now=5, action="read") is True
    assert s.check("alice", now=5, action="admin") is True


def test_active_lease_forbids_policy_changes():
    s, _ = activated()
    assert s.check("alice", now=5, action="grant_role") is False
    assert s.check("alice", now=5, action="policy_edit") is False
    assert s.check("alice", now=5, action="edit_audit") is False


def test_expired_lease_is_inactive():
    s, _ = activated()
    assert s.check("alice", now=33) is False


def test_close_ticket_kills_lease():
    s, _ = activated()
    s.close_ticket("INC-1001", now=10)
    assert s.check("alice", now=11) is False


def test_revoke_kills_lease_immediately():
    s, request_id = activated()
    s.revoke(request_id, now=10)
    assert s.check("alice", now=11) is False


def test_renew_extends_once_then_hits_limit():
    s, request_id = activated()
    s.renew(request_id, "bob", 15, now=10)
    assert s.check("alice", now=40) is True
    with pytest.raises(bl.BreakglassError) as exc:
        s.renew(request_id, "bob", 5, now=20)
    assert exc.value.code == "renew_limit"


def test_concurrent_requests_for_same_user_allow_one():
    s = service()
    ids = []
    codes = []
    lock = threading.Lock()

    def worker():
        try:
            value = s.request("alice", "INC-2002", 30, "database outage mitigation", now=0)
            with lock:
                ids.append(value)
        except bl.BreakglassError as exc:
            with lock:
                codes.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(ids) == 1
    assert codes == ["already_pending"]
