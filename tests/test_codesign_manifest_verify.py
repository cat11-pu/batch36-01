import threading

import pytest

import codesign_manifest_verify as cs

SIGNERS = {
    "builder@example.com": {"channels": ["stable", "beta"], "key_id": "sign-key-1"}
}
LOGS = ("log-a",)
ARTIFACTS = {
    "app.tar.gz": "sha256:" + "a" * 64,
    "docs.zip": "sha256:" + "b" * 64,
}


def manifest(**over):
    m = {
        "channel": "stable",
        "version": 6,
        "artifacts": [
            {"name": "app.tar.gz", "digest": ARTIFACTS["app.tar.gz"]},
            {"name": "docs.zip", "digest": ARTIFACTS["docs.zip"]},
        ],
        "signature": {
            "signer": "builder@example.com",
            "key_id": "sign-key-1",
            "serial": "cert-1",
            "signed_at": 100,
            "cert_not_before": 50,
            "cert_not_after": 2000,
            "timestamp": {
                "time": 120,
                "serial": "ts-1",
                "cert_not_before": 0,
                "cert_not_after": 5000,
                "signature": "ts-ok",
            },
            "value": "sig-ok",
        },
        "log_inclusion": {"verified": True, "log_id": "log-a"},
    }
    m.update(over)
    return m


def verifier(**kw):
    base = {
        "trusted_signers": SIGNERS,
        "revoked_serials": (),
        "verify_signature": lambda signer, key_id, value: value == "sig-ok",
        "verify_timestamp": lambda signer, serial, value: value == "ts-ok",
        "digest_of": lambda name: ARTIFACTS[name],
        "max_manifest_age": 86400,
        "known_logs": LOGS,
    }
    base.update(kw)
    return cs.ReleaseManifestVerifier(**base)


def test_valid_manifest_is_accepted():
    out = verifier().verify(manifest(), ARTIFACTS, now=200)
    assert out["channel"] == "stable"
    assert out["version"] == 6
    assert out["artifacts"] == ["app.tar.gz", "docs.zip"]


def test_unknown_signer_is_rejected():
    m = manifest()
    m["signature"]["signer"] = "evil@example.com"
    with pytest.raises(cs.CodesignError) as exc:
        verifier().verify(m, ARTIFACTS, now=200)
    assert exc.value.code == "unknown_signer"


def test_signer_without_channel_permission_is_rejected():
    signers = {
        "builder@example.com": {"channels": ["beta"], "key_id": "sign-key-1"}
    }
    with pytest.raises(cs.CodesignError) as exc:
        verifier(trusted_signers=signers).verify(manifest(), ARTIFACTS, now=200)
    assert exc.value.code == "channel_denied"


def test_missing_signature_is_rejected():
    m = manifest()
    del m["signature"]
    with pytest.raises(cs.CodesignError) as exc:
        verifier().verify(m, ARTIFACTS, now=200)
    assert exc.value.code == "unsigned"


def test_bad_signature_is_rejected():
    m = manifest()
    m["signature"]["value"] = "forged"
    with pytest.raises(cs.CodesignError) as exc:
        verifier().verify(m, ARTIFACTS, now=200)
    assert exc.value.code == "bad_signature"


def test_certificate_must_be_valid_at_signing_time():
    m = manifest()
    m["signature"]["cert_not_before"] = 150
    with pytest.raises(cs.CodesignError) as exc:
        verifier().verify(m, ARTIFACTS, now=200)
    assert exc.value.code == "cert_not_valid_at_signing"


def test_expired_certificate_with_fresh_timestamp_is_accepted():
    m = manifest()
    m["signature"]["cert_not_after"] = 200
    out = verifier().verify(m, ARTIFACTS, now=3000)
    assert out["version"] == 6


def test_timestamp_outside_certificate_window_is_rejected():
    m = manifest()
    m["signature"]["cert_not_after"] = 200
    m["signature"]["timestamp"]["time"] = 250
    with pytest.raises(cs.CodesignError) as exc:
        verifier().verify(m, ARTIFACTS, now=3000)
    assert exc.value.code == "bad_timestamp"


def test_revoked_signing_certificate_is_rejected():
    with pytest.raises(cs.CodesignError) as exc:
        verifier(revoked_serials=("cert-1",)).verify(manifest(), ARTIFACTS, now=200)
    assert exc.value.code == "revoked"


def test_stale_manifest_is_rejected():
    m = manifest()
    m["signature"].pop("timestamp")
    m["signature"]["cert_not_after"] = 1000000
    with pytest.raises(cs.CodesignError) as exc:
        verifier().verify(m, ARTIFACTS, now=86501)
    assert exc.value.code == "stale_manifest"


def test_artifact_digest_mismatch_is_rejected():
    m = manifest()
    m["artifacts"][0]["digest"] = "sha256:" + "c" * 64
    with pytest.raises(cs.CodesignError) as exc:
        verifier().verify(m, ARTIFACTS, now=200)
    assert exc.value.code == "digest_mismatch"


def test_missing_local_artifact_is_rejected():
    provided = {"app.tar.gz": ARTIFACTS["app.tar.gz"]}
    with pytest.raises(cs.CodesignError) as exc:
        verifier().verify(manifest(), provided, now=200)
    assert exc.value.code == "missing_artifact"


def test_duplicate_artifact_name_is_rejected():
    m = manifest()
    m["artifacts"].append(
        {"name": "app.tar.gz", "digest": ARTIFACTS["app.tar.gz"]}
    )
    with pytest.raises(cs.CodesignError) as exc:
        verifier().verify(m, ARTIFACTS, now=200)
    assert exc.value.code == "duplicate_artifact"


def test_version_rollback_is_rejected():
    v = verifier()
    v.verify(manifest(), ARTIFACTS, now=200)
    with pytest.raises(cs.CodesignError) as exc:
        v.verify(manifest(version=5), ARTIFACTS, now=201)
    assert exc.value.code == "rollback"


def test_concurrent_same_version_has_one_winner():
    v = verifier()
    outcomes = []

    def worker():
        try:
            v.verify(manifest(), ARTIFACTS, now=200)
            outcomes.append(True)
        except cs.CodesignError:
            outcomes.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count(True) == 1
    assert v.snapshot()["channels"]["stable"] == 6
