import json
import threading

import pytest

import recovery_case_binder as rb


def binder(**kw):
    return rb.RecoveryCaseBinder(**kw)


def opened(b, account="acct-1", requester="user-1", evidence="doc-1", now=0):
    return b.open_case(account, requester, evidence, now=now)


def approved(b, case_id, now=0):
    b.approve(case_id, "rev-1", now=now)
    b.approve(case_id, "rev-2", now=now)


def test_open_case_starts_in_open_state():
    rec = opened(binder())
    assert rec["account_id"] == "acct-1"
    assert rec["requester"] == "user-1"
    assert rec["state"] == "open"


def test_evidence_cannot_bind_two_accounts():
    b = binder()
    opened(b, account="acct-1", evidence="doc-1")
    with pytest.raises(rb.RecoveryError) as exc:
        opened(b, account="acct-2", requester="user-2", evidence="doc-1")
    assert exc.value.code == "evidence_reused"


def test_requester_cannot_approve_own_case():
    b = binder()
    case = opened(b)
    with pytest.raises(rb.RecoveryError) as exc:
        b.approve(case["case_id"], "user-1", now=1)
    assert exc.value.code == "self_approval"


def test_duplicate_approver_counts_once():
    b = binder()
    case = opened(b)
    b.approve(case["case_id"], "rev-1", now=1)
    with pytest.raises(rb.RecoveryError) as exc:
        b.approve(case["case_id"], "rev-1", now=2)
    assert exc.value.code == "duplicate_approval"


def test_quorum_must_be_reached_before_token():
    b = binder()
    case = opened(b)
    b.approve(case["case_id"], "rev-1", now=1)
    with pytest.raises(rb.RecoveryError) as exc:
        b.issue_token(case["case_id"], now=2)
    assert exc.value.code == "insufficient_approvals"


def test_token_issued_after_quorum():
    b = binder()
    case = opened(b)
    approved(b, case["case_id"])
    out = b.issue_token(case["case_id"], now=2)
    assert out["token"]
    assert out["expires_at"] == 86400
    assert b.snapshot()["cases"][case["case_id"]]["state"] == "approved"


def test_complete_consumes_token():
    b = binder()
    case = opened(b)
    approved(b, case["case_id"])
    tok = b.issue_token(case["case_id"], now=2)["token"]
    out = b.complete(case["case_id"], tok, now=3)
    assert out["account_id"] == "acct-1"
    assert out["state"] == "completed"


def test_token_cannot_be_redeemed_twice():
    b = binder()
    case = opened(b)
    approved(b, case["case_id"])
    tok = b.issue_token(case["case_id"], now=2)["token"]
    b.complete(case["case_id"], tok, now=3)
    with pytest.raises(rb.RecoveryError) as exc:
        b.complete(case["case_id"], tok, now=4)
    assert exc.value.code == "token_used"


def test_expired_case_cannot_issue_token():
    b = binder(ttl=100)
    case = opened(b)
    approved(b, case["case_id"])
    with pytest.raises(rb.RecoveryError) as exc:
        b.issue_token(case["case_id"], now=101)
    assert exc.value.code == "case_expired"


def test_unknown_case_is_rejected():
    with pytest.raises(rb.RecoveryError) as exc:
        binder().approve("case-404", "rev-1", now=1)
    assert exc.value.code == "unknown_case"


def test_complete_before_approval_is_rejected():
    b = binder()
    case = opened(b)
    with pytest.raises(rb.RecoveryError) as exc:
        b.complete(case["case_id"], "anything", now=1)
    assert exc.value.code == "not_approved"


def test_empty_account_id_is_rejected():
    with pytest.raises(ValueError):
        binder().open_case("", "user-1", "doc-1", now=0)


def test_denied_case_cannot_issue_token():
    b = binder()
    case = opened(b)
    b.deny(case["case_id"], "rev-1", now=1)
    with pytest.raises(rb.RecoveryError) as exc:
        b.issue_token(case["case_id"], now=2)
    assert exc.value.code == "case_closed"


def test_snapshot_is_detached_and_has_no_raw_token():
    b = binder()
    case = opened(b)
    approved(b, case["case_id"])
    tok = b.issue_token(case["case_id"], now=2)["token"]
    snap = b.snapshot()
    assert tok not in json.dumps(snap)
    snap["cases"].clear()
    assert b.snapshot()["cases"]


def test_concurrent_complete_has_one_winner():
    b = binder()
    case = opened(b)
    approved(b, case["case_id"])
    tok = b.issue_token(case["case_id"], now=2)["token"]
    outcomes = []

    def worker():
        try:
            b.complete(case["case_id"], tok, now=3)
            outcomes.append(True)
        except rb.RecoveryError:
            outcomes.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count(True) == 1
