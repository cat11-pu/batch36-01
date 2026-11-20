import pytest

import ssh_cert_authority as sc

CAS = [
    {"key_id": "ca-old", "public_key": "pk-old", "not_before": 0, "not_after": 100},
    {"key_id": "ca-new", "public_key": "pk-new", "not_before": 50, "not_after": 300},
]
ALLOWED = {"alice", "deploy"}


def authority(allow_wildcard=False):
    return sc.SshUserCertAuthority(
        CAS,
        ALLOWED,
        verify_signature=lambda ca, cert, sig: sig == "sig-valid",
        allow_wildcard=allow_wildcard,
    )


def cert(**over):
    c = {
        "cert_type": "user",
        "ca_key_id": "ca-old",
        "key_id": "alice-key",
        "principals": ["alice", "deploy"],
        "valid_after": 10,
        "valid_before": 90,
        "critical_options": {"source-address": "10.0.0.0/8", "force-command": "/usr/bin/backup"},
        "extensions": {"permit-pty": ""},
        "signature": "sig-valid",
    }
    c.update(over)
    return c


def test_valid_user_certificate_is_accepted():
    res = authority().verify(cert(), "10.1.2.3", now=60)
    assert res["key_id"] == "alice-key"
    assert res["ca_key_id"] == "ca-old"
    assert set(res["principals"]) == {"alice", "deploy"}
    assert res["force_command"] == "/usr/bin/backup"


def test_host_certificate_is_rejected():
    with pytest.raises(ValueError):
        authority().verify(cert(cert_type="host"), "10.1.2.3", now=60)


def test_unknown_ca_is_rejected():
    with pytest.raises(sc.SshCertError) as exc:
        authority().verify(cert(ca_key_id="ca-ghost"), "10.1.2.3", now=60)
    assert exc.value.code == "unknown_ca"


def test_ca_before_activation_is_rejected():
    with pytest.raises(sc.SshCertError) as exc:
        authority().verify(cert(ca_key_id="ca-new", valid_before=300), "10.1.2.3", now=20)
    assert exc.value.code == "ca_inactive"


def test_retired_ca_is_rejected():
    with pytest.raises(sc.SshCertError) as exc:
        authority().verify(cert(valid_before=300), "10.1.2.3", now=120)
    assert exc.value.code == "ca_inactive"


def test_rotation_overlap_accepts_both_cas():
    g = authority()
    assert g.verify(cert(), "10.1.2.3", now=60)["ca_key_id"] == "ca-old"
    assert g.verify(cert(ca_key_id="ca-new"), "10.1.2.3", now=60)["ca_key_id"] == "ca-new"


def test_principal_outside_allowlist_is_rejected():
    with pytest.raises(sc.SshCertError) as exc:
        authority().verify(cert(principals=["alice", "root"]), "10.1.2.3", now=60)
    assert exc.value.code == "principal_denied"


def test_empty_principal_list_is_rejected():
    with pytest.raises(ValueError):
        authority().verify(cert(principals=[]), "10.1.2.3", now=60)


def test_wildcard_principal_is_rejected_by_default():
    with pytest.raises(sc.SshCertError) as exc:
        authority().verify(cert(principals=["*"]), "10.1.2.3", now=60)
    assert exc.value.code == "principal_denied"


def test_certificate_not_yet_valid_is_rejected():
    with pytest.raises(sc.SshCertError) as exc:
        authority().verify(cert(valid_after=80), "10.1.2.3", now=60)
    assert exc.value.code == "cert_inactive"


def test_expired_certificate_is_rejected():
    with pytest.raises(sc.SshCertError) as exc:
        authority().verify(cert(valid_before=50), "10.1.2.3", now=60)
    assert exc.value.code == "cert_inactive"


def test_unknown_critical_option_is_rejected():
    with pytest.raises(sc.SshCertError) as exc:
        authority().verify(cert(critical_options={"source-address": "10.0.0.0/8", "command": "/bin/sh"}), "10.1.2.3", now=60)
    assert exc.value.code == "bad_critical_option"


def test_source_address_mismatch_is_rejected():
    with pytest.raises(sc.SshCertError) as exc:
        authority().verify(cert(), "192.168.1.5", now=60)
    assert exc.value.code == "source_address_denied"


def test_malformed_source_address_is_rejected():
    with pytest.raises(ValueError):
        authority().verify(cert(critical_options={"source-address": "10.0.0.0/99"}), "10.1.2.3", now=60)


def test_bad_certificate_signature_is_rejected():
    with pytest.raises(sc.SshCertError) as exc:
        authority().verify(cert(signature="sig-forged"), "10.1.2.3", now=60)
    assert exc.value.code == "bad_signature"
