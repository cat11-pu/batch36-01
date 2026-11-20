import pytest

import passkey_sync_ledger as pl

RP = "https://id.example.com"


def ledger(max_holders=3):
    return pl.PasskeySyncLedger(
        RP,
        verify_signature=lambda device, bundle, sig: sig == "sig-ok",
        max_holders=max_holders,
    )


def proof(**over):
    p = {"public_key": "pk-a", "not_after": 1000, "signature": "sig-ok"}
    p.update(over)
    return p


def bundle(**over):
    b = {
        "rp_id": RP,
        "credential_id": "cred-1",
        "revision": 1,
        "sign_count": 3,
        "backup_eligible": True,
        "backup_state": True,
        "signature": "sig-ok",
    }
    b.update(over)
    return b


def test_enroll_device_returns_active_record():
    rec = ledger().enroll_device("dev-a", proof(), now=10)
    assert rec["device_id"] == "dev-a"
    assert rec["state"] == "active"
    assert rec["public_key"] == "pk-a"
    assert rec["enrolled_at"] == 10


def test_duplicate_device_id_is_rejected():
    g = ledger()
    g.enroll_device("dev-a", proof(), now=10)
    with pytest.raises(pl.PasskeySyncError) as exc:
        g.enroll_device("dev-a", proof(public_key="pk-b"), now=11)
    assert exc.value.code == "device_exists"


def test_empty_device_id_is_rejected():
    with pytest.raises(ValueError):
        ledger().enroll_device("", proof(), now=10)


def test_expired_device_proof_is_rejected():
    with pytest.raises(pl.PasskeySyncError) as exc:
        ledger().enroll_device("dev-a", proof(not_after=50), now=60)
    assert exc.value.code == "device_proof_expired"


def test_device_proof_without_public_key_is_rejected():
    with pytest.raises(ValueError):
        ledger().enroll_device("dev-a", proof(public_key=""), now=10)


def test_bundle_from_unknown_device_is_rejected():
    with pytest.raises(pl.PasskeySyncError) as exc:
        ledger().apply_bundle("ghost", bundle(), now=10)
    assert exc.value.code == "unknown_device"


def test_bundle_relying_party_mismatch_is_rejected():
    g = ledger()
    g.enroll_device("dev-a", proof(), now=10)
    with pytest.raises(pl.PasskeySyncError) as exc:
        g.apply_bundle("dev-a", bundle(rp_id="https://other.example.com"), now=11)
    assert exc.value.code == "rp_mismatch"


def test_credential_without_backup_eligibility_is_rejected():
    g = ledger()
    g.enroll_device("dev-a", proof(), now=10)
    with pytest.raises(pl.PasskeySyncError) as exc:
        g.apply_bundle("dev-a", bundle(backup_eligible=False), now=11)
    assert exc.value.code == "not_syncable"


def test_credential_not_backed_up_is_rejected():
    g = ledger()
    g.enroll_device("dev-a", proof(), now=10)
    with pytest.raises(pl.PasskeySyncError) as exc:
        g.apply_bundle("dev-a", bundle(backup_state=False), now=11)
    assert exc.value.code == "not_syncable"


def test_bad_bundle_signature_is_rejected():
    g = ledger()
    g.enroll_device("dev-a", proof(), now=10)
    with pytest.raises(pl.PasskeySyncError) as exc:
        g.apply_bundle("dev-a", bundle(signature="forged"), now=11)
    assert exc.value.code == "bad_signature"


def test_revision_rollback_and_replay_are_rejected():
    g = ledger()
    g.enroll_device("dev-a", proof(), now=10)
    g.enroll_device("dev-b", proof(public_key="pk-b"), now=10)
    g.apply_bundle("dev-a", bundle(revision=2), now=11)
    with pytest.raises(pl.PasskeySyncError) as exc:
        g.apply_bundle("dev-b", bundle(revision=1, sign_count=9), now=12)
    assert exc.value.code == "stale_revision"
    with pytest.raises(pl.PasskeySyncError) as exc:
        g.apply_bundle("dev-b", bundle(revision=2, sign_count=9), now=13)
    assert exc.value.code == "stale_revision"


def test_resolve_merges_holders_and_max_counter():
    g = ledger()
    g.enroll_device("dev-a", proof(), now=10)
    g.enroll_device("dev-b", proof(public_key="pk-b"), now=10)
    g.apply_bundle("dev-a", bundle(revision=1, sign_count=7), now=11)
    g.apply_bundle("dev-b", bundle(revision=2, sign_count=9), now=12)
    res = g.resolve("cred-1", now=13)
    assert res["revision"] == 2
    assert res["sign_count"] == 9
    assert sorted(res["holders"]) == ["dev-a", "dev-b"]
    res["holders"].append("mallory")
    assert sorted(g.resolve("cred-1", now=14)["holders"]) == ["dev-a", "dev-b"]
    snap = g.snapshot()
    snap["rp_id"] = "tampered"
    assert g.snapshot()["rp_id"] == RP


def test_per_device_counter_regression_is_rejected():
    g = ledger()
    g.enroll_device("dev-a", proof(), now=10)
    g.apply_bundle("dev-a", bundle(revision=1, sign_count=9), now=11)
    with pytest.raises(pl.PasskeySyncError) as exc:
        g.apply_bundle("dev-a", bundle(revision=2, sign_count=4), now=12)
    assert exc.value.code == "counter_regression"
    g.apply_bundle("dev-a", bundle(revision=3, sign_count=10), now=13)
    assert g.resolve("cred-1", now=14)["sign_count"] == 10


def test_revoked_device_is_removed_from_holders():
    g = ledger()
    g.enroll_device("dev-a", proof(), now=10)
    g.enroll_device("dev-b", proof(public_key="pk-b"), now=10)
    g.apply_bundle("dev-a", bundle(credential_id="cred-a", revision=1), now=11)
    g.apply_bundle("dev-a", bundle(credential_id="cred-shared", revision=2), now=12)
    g.apply_bundle("dev-b", bundle(credential_id="cred-shared", revision=3), now=13)
    out = g.revoke_device("dev-a", now=14)
    assert out["dropped_credentials"] == 1
    with pytest.raises(pl.PasskeySyncError) as exc:
        g.resolve("cred-a", now=15)
    assert exc.value.code == "unknown_credential"
    assert g.resolve("cred-shared", now=15)["holders"] == ["dev-b"]
    with pytest.raises(pl.PasskeySyncError) as exc:
        g.apply_bundle("dev-a", bundle(revision=4), now=16)
    assert exc.value.code == "device_revoked"
    with pytest.raises(pl.PasskeySyncError) as exc:
        g.revoke_device("dev-a", now=17)
    assert exc.value.code == "unknown_device"


def test_holder_limit_is_enforced():
    g = ledger(max_holders=2)
    for name in ("dev-a", "dev-b", "dev-c"):
        g.enroll_device(name, proof(public_key="pk-" + name), now=10)
    g.apply_bundle("dev-a", bundle(revision=1), now=11)
    g.apply_bundle("dev-b", bundle(revision=2), now=12)
    with pytest.raises(pl.PasskeySyncError) as exc:
        g.apply_bundle("dev-c", bundle(revision=3), now=13)
    assert exc.value.code == "too_many_holders"
