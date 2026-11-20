import base64
import threading

import pytest

import saml_artifact_vault as sv

SP = "https://sp.example.com"
SOURCE = b"S" * 20


def vault(**kw):
    return sv.ArtifactVault(SP, SOURCE, **kw)


def raw_artifact(artifact):
    return bytearray(base64.b64decode(artifact))


def recode(raw):
    return base64.b64encode(bytes(raw)).decode()


def test_issued_artifact_has_expected_layout():
    art = vault().issue(SP, "assert-1", now=0)
    raw = base64.b64decode(art)
    assert len(raw) == 44
    assert raw[:2] == b"\x00\x04"


def test_resolve_returns_assertion_reference():
    v = vault()
    art = v.issue(SP, "assert-1", now=0)
    out = v.resolve(art, SP, now=1)
    assert out["assertion_ref"] == "assert-1"
    assert out["sp_entity_id"] == SP


def test_artifact_is_single_use():
    v = vault()
    art = v.issue(SP, "assert-1", now=0)
    v.resolve(art, SP, now=1)
    with pytest.raises(sv.SamlArtifactError) as exc:
        v.resolve(art, SP, now=2)
    assert exc.value.code == "artifact_reused"


def test_expired_artifact_is_rejected():
    v = vault(ttl=60)
    art = v.issue(SP, "assert-1", now=0)
    with pytest.raises(sv.SamlArtifactError) as exc:
        v.resolve(art, SP, now=61)
    assert exc.value.code == "artifact_expired"


def test_tampered_source_id_is_rejected():
    v = vault()
    art = v.issue(SP, "assert-1", now=0)
    raw = raw_artifact(art)
    raw[4:24] = b"X" * 20
    with pytest.raises(sv.SamlArtifactError) as exc:
        v.resolve(recode(raw), SP, now=1)
    assert exc.value.code == "source_mismatch"


def test_endpoint_index_mismatch_is_rejected():
    v = vault()
    art = v.issue(SP, "assert-1", endpoint_index=0, now=0)
    with pytest.raises(sv.SamlArtifactError) as exc:
        v.resolve(art, SP, endpoint_index=1, now=1)
    assert exc.value.code == "endpoint_mismatch"


def test_wrong_type_code_is_rejected():
    raw = bytearray(44)
    raw[0:2] = b"\x00\x03"
    with pytest.raises(sv.SamlArtifactError) as exc:
        vault().resolve(recode(raw), SP, now=1)
    assert exc.value.code == "bad_artifact_type"


def test_wrong_length_is_rejected():
    with pytest.raises(sv.SamlArtifactError) as exc:
        vault().resolve(base64.b64encode(b"short").decode(), SP, now=1)
    assert exc.value.code == "bad_artifact_length"


def test_invalid_base64_is_rejected():
    with pytest.raises(sv.SamlArtifactError) as exc:
        vault().resolve("!!!not-base64!!!", SP, now=1)
    assert exc.value.code == "bad_artifact_encoding"


def test_artifact_issued_for_another_sp_is_rejected():
    v = vault()
    art = v.issue("https://other-sp.example.com", "assert-1", now=0)
    with pytest.raises(sv.SamlArtifactError) as exc:
        v.resolve(art, SP, now=1)
    assert exc.value.code == "sp_mismatch"


def test_issue_rejects_empty_assertion_reference():
    with pytest.raises(ValueError):
        vault().issue(SP, "", now=0)


def test_issue_rejects_empty_sp_entity_id():
    with pytest.raises(ValueError):
        vault().issue("", "assert-1", now=0)


def test_discarded_artifact_is_unknown():
    v = vault()
    art = v.issue(SP, "assert-1", now=0)
    v.discard(art)
    with pytest.raises(sv.SamlArtifactError) as exc:
        v.resolve(art, SP, now=1)
    assert exc.value.code == "unknown_artifact"


def test_snapshot_is_detached_from_pending_table():
    v = vault()
    v.issue(SP, "assert-1", now=0)
    snap = v.snapshot()
    snap["pending"].clear()
    assert v.snapshot()["pending"]


def test_concurrent_resolve_has_one_winner():
    v = vault()
    art = v.issue(SP, "assert-1", now=0)
    outcomes = []

    def worker():
        try:
            v.resolve(art, SP, now=1)
            outcomes.append(True)
        except sv.SamlArtifactError:
            outcomes.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count(True) == 1
