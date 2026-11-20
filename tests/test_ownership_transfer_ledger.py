import threading

import pytest

import ownership_transfer_ledger as ol

USERS = {
    "alice": {"admin": False},
    "bob": {"admin": False},
    "carol": {"admin": False},
    "root": {"admin": True},
}

OBJECTS = {
    "doc1": {"owner": "alice", "deleted": False},
    "gone": {"owner": "alice", "deleted": True},
}


def ledger():
    return ol.OwnershipLedger(
        {k: dict(v) for k, v in OBJECTS.items()},
        {k: dict(v) for k, v in USERS.items()},
    )


def test_owner_has_full_access():
    l = ledger()
    assert l.check("doc1", "alice", "read") is True
    assert l.check("doc1", "alice", "delete") is True
    assert l.check("doc1", "bob", "read") is False


def test_read_share_allows_read_only():
    l = ledger()
    l.share("doc1", "alice", "bob", "read")
    assert l.check("doc1", "bob", "read") is True
    assert l.check("doc1", "bob", "write") is False


def test_write_share_allows_write_not_delete():
    l = ledger()
    l.share("doc1", "alice", "bob", "write")
    assert l.check("doc1", "bob", "write") is True
    assert l.check("doc1", "bob", "delete") is False


def test_non_owner_cannot_share():
    l = ledger()
    with pytest.raises(ol.OwnershipError) as exc:
        l.share("doc1", "bob", "carol", "read")
    assert exc.value.code == "not_owner"


def test_non_owner_cannot_start_transfer():
    l = ledger()
    with pytest.raises(ol.OwnershipError) as exc:
        l.request_transfer("doc1", "bob", "carol", now=0)
    assert exc.value.code == "not_owner"


def test_transfer_needs_target_acceptance():
    l = ledger()
    l.request_transfer("doc1", "alice", "bob", now=0)
    assert l.check("doc1", "alice", "delete") is True
    assert l.check("doc1", "bob", "delete") is False


def test_accept_moves_ownership():
    l = ledger()
    transfer = l.request_transfer("doc1", "alice", "bob", now=0)
    l.accept_transfer(transfer, "bob", now=10)
    assert l.check("doc1", "bob", "delete") is True
    assert l.check("doc1", "alice", "delete") is False


def test_wrong_user_cannot_accept():
    l = ledger()
    transfer = l.request_transfer("doc1", "alice", "bob", now=0)
    with pytest.raises(ol.OwnershipError) as exc:
        l.accept_transfer(transfer, "carol", now=10)
    assert exc.value.code == "not_target"


def test_duplicate_accept_is_rejected():
    l = ledger()
    transfer = l.request_transfer("doc1", "alice", "bob", now=0)
    l.accept_transfer(transfer, "bob", now=10)
    with pytest.raises(ol.OwnershipError) as exc:
        l.accept_transfer(transfer, "bob", now=11)
    assert exc.value.code == "transfer_not_pending"


def test_second_transfer_while_pending_is_rejected():
    l = ledger()
    l.request_transfer("doc1", "alice", "bob", now=0)
    with pytest.raises(ol.OwnershipError) as exc:
        l.request_transfer("doc1", "alice", "carol", now=1)
    assert exc.value.code == "transfer_pending"


def test_expired_transfer_cannot_be_accepted():
    l = ledger()
    transfer = l.request_transfer("doc1", "alice", "bob", now=0, ttl=5)
    with pytest.raises(ol.OwnershipError) as exc:
        l.accept_transfer(transfer, "bob", now=6)
    assert exc.value.code == "transfer_expired"


def test_admin_without_ticket_is_denied():
    l = ledger()
    assert l.check("doc1", "root", "delete") is False


def test_admin_with_ticket_is_allowed():
    l = ledger()
    assert l.check("doc1", "root", "delete", ticket="INC-77") is True


def test_deleted_object_denies_everyone():
    l = ledger()
    assert l.check("gone", "alice", "read") is False
    assert l.check("gone", "root", "read", ticket="INC-77") is False


def test_concurrent_accept_only_one_wins():
    l = ledger()
    transfer = l.request_transfer("doc1", "alice", "bob", now=0)
    results = []
    lock = threading.Lock()

    def worker():
        try:
            l.accept_transfer(transfer, "bob", now=10)
            with lock:
                results.append(True)
        except ol.OwnershipError:
            with lock:
                results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1
    assert l.check("doc1", "bob", "delete") is True
