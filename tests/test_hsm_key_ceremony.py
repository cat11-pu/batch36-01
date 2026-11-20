import threading

import pytest

import hsm_key_ceremony as hc


def ceremony(**kw):
    base = {"threshold": 2, "total_shares": 3, "ceremony_ttl": 600}
    base.update(kw)
    return hc.HsmKeyCeremony(**base)


def opened(c=None, cid="cer-1", holders=None, now=0):
    c = c or ceremony()
    rec = c.open(cid, holders or ["alice", "bob", "carol"], now=now)
    return c, rec


def test_open_assigns_distinct_share_slots():
    c, rec = opened()
    assert rec["state"] == "open"
    assert sorted(rec["shares"]) == ["alice", "bob", "carol"]
    assert len(set(rec["shares"].values())) == 3
    assert rec["expires_at"] == 600


def test_threshold_above_total_is_rejected():
    with pytest.raises(ValueError):
        hc.HsmKeyCeremony(4, 3)


def test_duplicate_holders_are_rejected():
    c = ceremony()
    with pytest.raises(hc.CeremonyError) as exc:
        c.open("cer-1", ["alice", "alice", "bob"], now=0)
    assert exc.value.code == "duplicate_holder"


def test_holder_count_must_match_total():
    with pytest.raises(ValueError):
        ceremony().open("cer-1", ["alice", "bob"], now=0)


def test_ceremony_id_cannot_be_reused():
    c, rec = opened()
    c.abort("cer-1", "done", now=1)
    with pytest.raises(hc.CeremonyError) as exc:
        c.open("cer-1", ["dave", "eve", "frank"], now=2)
    assert exc.value.code == "ceremony_exists"


def test_second_active_ceremony_is_rejected():
    c, rec = opened()
    with pytest.raises(hc.CeremonyError) as exc:
        c.open("cer-2", ["dave", "eve", "frank"], now=1)
    assert exc.value.code == "ceremony_busy"


def test_share_submission_counts_distinct_holders():
    c, rec = opened()
    shares = rec["shares"]
    first = c.submit_share("cer-1", "alice", shares["alice"], now=1)
    second = c.submit_share("cer-1", "bob", shares["bob"], now=2)
    assert first["collected"] == 1
    assert second["collected"] == 2


def test_unknown_holder_is_rejected():
    c, rec = opened()
    with pytest.raises(hc.CeremonyError) as exc:
        c.submit_share("cer-1", "mallory", "share-1", now=1)
    assert exc.value.code == "unknown_holder"


def test_wrong_share_slot_is_rejected():
    c, rec = opened()
    with pytest.raises(hc.CeremonyError) as exc:
        c.submit_share("cer-1", "alice", "share-999", now=1)
    assert exc.value.code == "wrong_share"


def test_holder_cannot_submit_twice():
    c, rec = opened()
    shares = rec["shares"]
    c.submit_share("cer-1", "alice", shares["alice"], now=1)
    with pytest.raises(hc.CeremonyError) as exc:
        c.submit_share("cer-1", "alice", shares["alice"], now=2)
    assert exc.value.code == "duplicate_holder"


def test_expired_ceremony_rejects_shares():
    c, rec = opened(now=0)
    with pytest.raises(hc.CeremonyError) as exc:
        c.submit_share("cer-1", "alice", rec["shares"]["alice"], now=601)
    assert exc.value.code == "ceremony_expired"


def test_seal_requires_threshold_shares():
    c, rec = opened()
    c.submit_share("cer-1", "alice", rec["shares"]["alice"], now=1)
    with pytest.raises(hc.CeremonyError) as exc:
        c.seal("cer-1", now=2)
    assert exc.value.code == "insufficient_shares"


def test_seal_returns_handle_and_witnesses():
    c, rec = opened()
    shares = rec["shares"]
    c.submit_share("cer-1", "alice", shares["alice"], now=1)
    c.submit_share("cer-1", "bob", shares["bob"], now=2)
    out = c.seal("cer-1", now=3)
    assert out["key_handle"]
    assert sorted(out["witnesses"]) == ["alice", "bob"]
    events = c.audit("cer-1")
    assert [e["event"] for e in events] == ["open", "share", "share", "seal"]
    events.clear()
    assert [e["event"] for e in c.audit("cer-1")] == [
        "open",
        "share",
        "share",
        "seal",
    ]


def test_aborted_ceremony_is_closed():
    c, rec = opened()
    c.abort("cer-1", "operator cancelled", now=1)
    with pytest.raises(hc.CeremonyError) as exc:
        c.submit_share("cer-1", "alice", rec["shares"]["alice"], now=2)
    assert exc.value.code == "ceremony_closed"
    with pytest.raises(hc.CeremonyError) as exc2:
        c.seal("cer-1", now=3)
    assert exc2.value.code == "ceremony_closed"


def test_concurrent_seal_has_one_winner():
    c, rec = opened()
    shares = rec["shares"]
    c.submit_share("cer-1", "alice", shares["alice"], now=1)
    c.submit_share("cer-1", "bob", shares["bob"], now=2)
    outcomes = []

    def worker():
        try:
            c.seal("cer-1", now=3)
            outcomes.append(True)
        except hc.CeremonyError:
            outcomes.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count(True) == 1
