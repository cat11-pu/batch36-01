import hashlib
import json
import threading

import pytest

import backup_encryption_context as bc

REQUIRED = ["tenant", "cluster", "backup_id", "schema"]
CTX = {"tenant": "acme", "cluster": "prod", "backup_id": "bk-1", "schema": "v3"}


def chunks():
    return [
        {"id": "c1", "data": "alpha"},
        {"id": "c2", "data": "beta"},
        {"id": "c3", "data": "gamma"},
    ]


def binder(**kw):
    base = {
        "required_keys": REQUIRED,
        "signer": lambda payload: "sig-ok",
        "verifier": lambda manifest, signature: signature == "sig-ok",
        "ttl": 86400,
    }
    base.update(kw)
    return bc.BackupContextBinder(**base)


def sealed(b=None, ctx=None, now=0):
    b = b or binder()
    return b, b.seal_manifest("bk-1", dict(ctx or CTX), chunks(), now=now)


def test_seal_and_open_roundtrip():
    b, m = sealed()
    assert m["context_digest"]
    assert [c["id"] for c in m["chunks"]] == ["c1", "c2", "c3"]
    out = b.open_manifest(m, dict(CTX), chunks(), now=10)
    assert out["backup_id"] == "bk-1"
    assert out["tenant"] == "acme"
    assert out["chunks"] == ["c1", "c2", "c3"]


def test_missing_context_key_is_rejected():
    ctx = dict(CTX)
    del ctx["schema"]
    with pytest.raises(bc.BackupContextError) as exc:
        binder().seal_manifest("bk-1", ctx, chunks(), now=0)
    assert exc.value.code == "missing_context_key"


def test_extra_context_key_is_rejected():
    ctx = dict(CTX)
    ctx["region"] = "us"
    with pytest.raises(bc.BackupContextError) as exc:
        binder().seal_manifest("bk-1", ctx, chunks(), now=0)
    assert exc.value.code == "unexpected_context_key"


def test_blank_context_value_is_rejected():
    ctx = dict(CTX)
    ctx["tenant"] = "   "
    with pytest.raises(bc.BackupContextError) as exc:
        binder().seal_manifest("bk-1", ctx, chunks(), now=0)
    assert exc.value.code == "bad_context_value"


def test_backup_id_must_match_context():
    with pytest.raises(bc.BackupContextError) as exc:
        binder().seal_manifest("bk-2", dict(CTX), chunks(), now=0)
    assert exc.value.code == "backup_id_mismatch"


def test_duplicate_chunk_id_is_rejected():
    bad = [{"id": "c1", "data": "a"}, {"id": "c1", "data": "b"}]
    with pytest.raises(bc.BackupContextError) as exc:
        binder().seal_manifest("bk-1", dict(CTX), bad, now=0)
    assert exc.value.code == "duplicate_chunk"


def test_tampered_context_digest_is_rejected():
    b, m = sealed()
    m["context"]["tenant"] = "evil"
    with pytest.raises(bc.BackupContextError) as exc:
        b.open_manifest(m, dict(CTX), chunks(), now=10)
    assert exc.value.code == "context_digest_mismatch"


def test_cross_tenant_restore_is_rejected():
    b, m = sealed()
    with pytest.raises(bc.BackupContextError) as exc:
        b.open_manifest(m, {**CTX, "tenant": "other"}, chunks(), now=10)
    assert exc.value.code == "tenant_mismatch"


def test_expired_manifest_is_rejected():
    b, m = sealed(now=0)
    with pytest.raises(bc.BackupContextError) as exc:
        b.open_manifest(m, dict(CTX), chunks(), now=90000)
    assert exc.value.code == "manifest_expired"


def test_bad_manifest_signature_is_rejected():
    b = binder(verifier=lambda manifest, signature: False)
    _, m = sealed(b)
    with pytest.raises(bc.BackupContextError) as exc:
        b.open_manifest(m, dict(CTX), chunks(), now=10)
    assert exc.value.code == "bad_manifest_signature"


def test_missing_chunk_is_rejected():
    b, m = sealed()
    with pytest.raises(bc.BackupContextError) as exc:
        b.open_manifest(m, dict(CTX), chunks()[:2], now=10)
    assert exc.value.code == "missing_chunk"


def test_unexpected_chunk_is_rejected():
    b, m = sealed()
    extra = chunks() + [{"id": "c4", "data": "delta"}]
    with pytest.raises(bc.BackupContextError) as exc:
        b.open_manifest(m, dict(CTX), extra, now=10)
    assert exc.value.code == "unexpected_chunk"


def test_corrupt_chunk_is_rejected():
    b, m = sealed()
    bad = chunks()
    bad[1]["data"] = "tampered"
    with pytest.raises(bc.BackupContextError) as exc:
        b.open_manifest(m, dict(CTX), bad, now=10)
    assert exc.value.code == "chunk_corrupt"


def test_reordered_chunk_is_rejected():
    b, m = sealed()
    bad = [chunks()[1], chunks()[0], chunks()[2]]
    with pytest.raises(bc.BackupContextError) as exc:
        b.open_manifest(m, dict(CTX), bad, now=10)
    assert exc.value.code == "chunk_context_mismatch"


def test_concurrent_open_counts_are_serialized():
    b, m = sealed()
    problems = []
    results = []

    def worker():
        try:
            results.append(b.open_manifest(m, dict(CTX), chunks(), now=10)["backup_id"])
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert results == ["bk-1"] * 4
    snap = b.snapshot()
    assert snap["opened"] == 4
    snap["opened"] = 0
    assert b.snapshot()["opened"] == 4
