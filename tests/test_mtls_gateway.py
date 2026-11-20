import pytest

import mtls_gateway as mg

ACCOUNTS = {
    "svc-billing": {"uri": "spiffe://corp.example.com/billing", "enabled": True},
    "svc-old": {"uri": "spiffe://corp.example.com/old", "enabled": False},
}
TRUSTED = {"fp-root"}


def gateway():
    return mg.MutualTlsAuthenticator(TRUSTED, ACCOUNTS, revoked={"0002"}, max_chain_depth=1)


def cert(**over):
    c = {
        "issuer_fingerprint": "fp-root",
        "serial": "0001",
        "subject_cn": "svc-billing",
        "san_uri": "spiffe://corp.example.com/billing",
        "eku": ["clientAuth"],
        "key_usage": ["digitalSignature"],
        "not_before": 0,
        "not_after": 1000,
        "chain_depth": 1,
    }
    c.update(over)
    return c


def request(**over):
    r = {"tls_cert_serial": "0001", "forwarded_client_cert": None}
    r.update(over)
    return r


def test_valid_client_certificate_is_accepted():
    res = gateway().authenticate(cert(), request(), now=60)
    assert res["account"] == "svc-billing"
    assert res["uri"] == "spiffe://corp.example.com/billing"
    assert res["serial"] == "0001"


def test_missing_certificate_is_rejected():
    with pytest.raises(mg.MtlsError) as exc:
        gateway().authenticate(None, request(), now=60)
    assert exc.value.code == "no_certificate"


def test_untrusted_issuer_is_rejected():
    with pytest.raises(mg.MtlsError) as exc:
        gateway().authenticate(cert(issuer_fingerprint="fp-other"), request(), now=60)
    assert exc.value.code == "untrusted_issuer"


def test_server_only_usage_is_rejected():
    with pytest.raises(mg.MtlsError) as exc:
        gateway().authenticate(cert(eku=["serverAuth"]), request(), now=60)
    assert exc.value.code == "wrong_eku"


def test_missing_digital_signature_usage_is_rejected():
    with pytest.raises(mg.MtlsError) as exc:
        gateway().authenticate(cert(key_usage=["keyEncipherment"]), request(), now=60)
    assert exc.value.code == "bad_key_usage"


def test_expired_certificate_is_rejected():
    with pytest.raises(mg.MtlsError) as exc:
        gateway().authenticate(cert(not_after=50), request(), now=60)
    assert exc.value.code == "cert_inactive"


def test_not_yet_valid_certificate_is_rejected():
    with pytest.raises(mg.MtlsError) as exc:
        gateway().authenticate(cert(not_before=80), request(), now=60)
    assert exc.value.code == "cert_inactive"


def test_deep_chain_is_rejected():
    with pytest.raises(mg.MtlsError) as exc:
        gateway().authenticate(cert(chain_depth=3), request(), now=60)
    assert exc.value.code == "chain_too_deep"


def test_unregistered_subject_is_rejected():
    with pytest.raises(mg.MtlsError) as exc:
        gateway().authenticate(cert(subject_cn="svc-ghost"), request(), now=60)
    assert exc.value.code == "unknown_account"


def test_disabled_account_is_rejected():
    bad = cert(subject_cn="svc-old", san_uri="spiffe://corp.example.com/old")
    with pytest.raises(mg.MtlsError) as exc:
        gateway().authenticate(bad, request(), now=60)
    assert exc.value.code == "account_disabled"


def test_identity_uri_must_match_the_account():
    with pytest.raises(mg.MtlsError) as exc:
        gateway().authenticate(cert(san_uri="spiffe://corp.example.com/payments"), request(), now=60)
    assert exc.value.code == "identity_mismatch"


def test_revoked_serial_is_rejected():
    with pytest.raises(mg.MtlsError) as exc:
        gateway().authenticate(cert(serial="0002"), request(tls_cert_serial="0002"), now=60)
    assert exc.value.code == "revoked"


def test_connection_serial_must_match_certificate():
    with pytest.raises(mg.MtlsError) as exc:
        gateway().authenticate(cert(), request(tls_cert_serial="0009"), now=60)
    assert exc.value.code == "session_mismatch"


def test_forwarded_header_cannot_replace_missing_certificate():
    with pytest.raises(mg.MtlsError) as exc:
        gateway().authenticate(None, request(tls_cert_serial=None, forwarded_client_cert="fp-root:0001"), now=60)
    assert exc.value.code == "no_certificate"


def test_empty_serial_is_rejected():
    with pytest.raises(mg.MtlsError) as exc:
        gateway().authenticate(cert(serial=""), request(tls_cert_serial=""), now=60)
    assert exc.value.code == "bad_serial"
