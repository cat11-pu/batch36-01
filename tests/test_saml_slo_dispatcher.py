import threading

import pytest

import saml_slo_dispatcher as sd

SP = "https://sp.example.com/slo"
IDP = "https://idp.example.com"


def dispatcher():
    return sd.SamlSloDispatcher(SP, IDP, lambda req: req.get("signature") == "sig-ok")


def seeded():
    d = dispatcher()
    d.register_session("s-1", "user-1", "app-a")
    d.register_session("s-2", "user-1", "app-b")
    d.register_session("s-3", "user-2", "app-a")
    return d


def req(**over):
    r = {
        "id": "r-1",
        "issuer": IDP,
        "destination": SP,
        "not_on_or_after": 1000,
        "signature": "sig-ok",
        "session_indexes": ["s-1"],
        "name_id": "user-1",
    }
    r.update(over)
    return r


def test_valid_request_removes_listed_sessions():
    d = seeded()
    out = d.handle_request(req(), now=0)
    assert out["status"] == "success"
    assert out["removed"] == ["s-1"]
    assert "s-1" not in d.state()["sessions"]


def test_foreign_issuer_is_rejected():
    with pytest.raises(sd.SamlSloError) as exc:
        seeded().handle_request(req(issuer="https://evil.example.com"), now=0)
    assert exc.value.code == "bad_issuer"


def test_destination_mismatch_is_rejected():
    with pytest.raises(sd.SamlSloError) as exc:
        seeded().handle_request(req(destination="https://sp.example.com/other"), now=0)
    assert exc.value.code == "bad_destination"


def test_expired_request_is_rejected():
    with pytest.raises(sd.SamlSloError) as exc:
        seeded().handle_request(req(not_on_or_after=50), now=100)
    assert exc.value.code == "request_expired"


def test_empty_request_id_is_rejected():
    with pytest.raises(ValueError):
        seeded().handle_request(req(id=""), now=0)


def test_request_id_cannot_be_replayed():
    d = seeded()
    d.handle_request(req(), now=0)
    with pytest.raises(sd.SamlSloError) as exc:
        d.handle_request(req(session_indexes=["s-2"]), now=1)
    assert exc.value.code == "request_replayed"


def test_bad_signature_is_rejected():
    with pytest.raises(sd.SamlSloError) as exc:
        seeded().handle_request(req(signature="forged"), now=0)
    assert exc.value.code == "bad_signature"


def test_missing_signature_is_rejected():
    with pytest.raises(sd.SamlSloError) as exc:
        seeded().handle_request(req(signature=None), now=0)
    assert exc.value.code == "bad_signature"


def test_unknown_session_index_aborts_whole_request():
    d = seeded()
    with pytest.raises(sd.SamlSloError) as exc:
        d.handle_request(req(session_indexes=["s-1", "s-404"]), now=0)
    assert exc.value.code == "unknown_session_index"
    assert "s-1" in d.state()["sessions"]


def test_session_index_of_another_subject_is_rejected():
    d = seeded()
    with pytest.raises(sd.SamlSloError) as exc:
        d.handle_request(req(session_indexes=["s-1", "s-3"]), now=0)
    assert exc.value.code == "subject_mismatch"
    assert "s-1" in d.state()["sessions"]


def test_empty_session_index_list_is_rejected():
    with pytest.raises(sd.SamlSloError) as exc:
        seeded().handle_request(req(session_indexes=[]), now=0)
    assert exc.value.code == "empty_session_indexes"


def test_response_references_request():
    d = seeded()
    d.handle_request(req(), now=0)
    resp = d.build_response("r-1")
    assert resp["in_response_to"] == "r-1"
    assert resp["destination"] == IDP


def test_response_for_unknown_request_is_rejected():
    with pytest.raises(sd.SamlSloError) as exc:
        seeded().build_response("r-404")
    assert exc.value.code == "unknown_request"


def test_state_is_a_detached_copy():
    d = seeded()
    snapshot = d.state()
    snapshot["sessions"].clear()
    assert d.state()["sessions"]


def test_concurrent_same_request_id_has_one_winner():
    d = seeded()
    outcomes = []

    def worker():
        try:
            d.handle_request(req(), now=0)
            outcomes.append(True)
        except sd.SamlSloError:
            outcomes.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count(True) == 1
