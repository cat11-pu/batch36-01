import hashlib
import hmac
import threading

import pytest

import billing_metadata_gate as bm

KEY = b"settlement-key"
CALLERS = {
    "settlement": {
        "identity": "spiffe://acme/settlement",
        "key": KEY,
        "methods": ["/billing.v1.Ledger/Charge"],
        "tenants": ["acme"],
    }
}


def gate(**kw):
    return bm.BillingMetadataGate(CALLERS, **kw)


def token(exp=1100, nonce="n1", caller="settlement", key=KEY):
    body = caller + ":" + str(exp) + ":" + nonce
    sig = hmac.new(key, body.encode("utf-8"), hashlib.sha256).hexdigest()
    return "Bearer " + body + "." + sig


def meta(*items):
    return [list(item) for item in items]


def invocation(**over):
    inv = {
        "method": "/billing.v1.Ledger/Charge",
        "caller": "settlement",
        "peer": {"tls": True, "identity": "spiffe://acme/settlement"},
        "metadata": meta(
            ["authorization", token()],
            ["x-request-id", "0123456789abcdef"],
            ["x-tenant", "acme"],
            ["grpc-timeout", "1500m"],
        ),
    }
    inv.update(over)
    return inv


def test_valid_invocation_is_accepted():
    out = gate().check(invocation(), now=1000)
    assert out == {
        "caller": "settlement",
        "method": "/billing.v1.Ledger/Charge",
        "tenant": "acme",
        "request_id": "0123456789abcdef",
        "timeout_ms": 1500,
    }


def test_unknown_caller_is_rejected():
    with pytest.raises(bm.MetadataError) as exc:
        gate().check(invocation(caller="ghost"), now=1000)
    assert exc.value.code == "unknown_caller"


def test_method_outside_allowlist_is_rejected():
    with pytest.raises(bm.MetadataError) as exc:
        gate().check(invocation(method="/billing.v1.Ledger/Refund"), now=1000)
    assert exc.value.code == "method_not_allowed"


def test_insecure_peer_is_rejected():
    with pytest.raises(bm.MetadataError) as exc:
        gate().check(invocation(peer={"tls": False}), now=1000)
    assert exc.value.code == "insecure_peer"


def test_identity_mismatch_is_rejected():
    with pytest.raises(bm.MetadataError) as exc:
        gate().check(invocation(peer={"tls": True, "identity": "spiffe://acme/other"}), now=1000)
    assert exc.value.code == "identity_mismatch"


def test_forwarded_peer_header_is_ignored():
    with pytest.raises(bm.MetadataError) as exc:
        gate().check(
            invocation(
                peer={"tls": False},
                headers={"x-forwarded-peer": "spiffe://acme/settlement"},
            ),
            now=1000,
        )
    assert exc.value.code == "insecure_peer"


def test_bad_signature_is_rejected():
    with pytest.raises(bm.MetadataError) as exc:
        gate().check(
            invocation(metadata=meta(
                ["authorization", token(key=b"wrong-key")],
                ["x-request-id", "0123456789abcdef"],
                ["x-tenant", "acme"],
                ["grpc-timeout", "1500m"],
            )),
            now=1000,
        )
    assert exc.value.code == "bad_signature"


def test_expired_token_is_rejected():
    with pytest.raises(bm.MetadataError) as exc:
        gate().check(
            invocation(metadata=meta(
                ["authorization", token(exp=900)],
                ["x-request-id", "0123456789abcdef"],
                ["x-tenant", "acme"],
                ["grpc-timeout", "1500m"],
            )),
            now=1000,
        )
    assert exc.value.code == "token_expired"


def test_disallowed_tenant_is_rejected():
    with pytest.raises(bm.MetadataError) as exc:
        gate().check(
            invocation(metadata=meta(
                ["authorization", token()],
                ["x-request-id", "0123456789abcdef"],
                ["x-tenant", "globex"],
                ["grpc-timeout", "1500m"],
            )),
            now=1000,
        )
    assert exc.value.code == "tenant_not_allowed"


def test_uppercase_metadata_key_is_rejected():
    with pytest.raises(bm.MetadataError) as exc:
        gate().check(
            invocation(metadata=meta(
                ["authorization", token()],
                ["x-request-id", "0123456789abcdef"],
                ["X-Tenant", "acme"],
                ["grpc-timeout", "1500m"],
            )),
            now=1000,
        )
    assert exc.value.code == "bad_key"


def test_binary_metadata_key_is_rejected():
    with pytest.raises(bm.MetadataError) as exc:
        gate().check(
            invocation(metadata=meta(
                ["authorization", token()],
                ["x-request-id", "0123456789abcdef"],
                ["x-tenant", "acme"],
                ["grpc-timeout", "1500m"],
                ["trace-bin", "abc"],
            )),
            now=1000,
        )
    assert exc.value.code == "binary_metadata"


def test_duplicate_metadata_key_is_rejected():
    with pytest.raises(bm.MetadataError) as exc:
        gate().check(
            invocation(metadata=meta(
                ["authorization", token()],
                ["x-request-id", "0123456789abcdef"],
                ["x-tenant", "acme"],
                ["grpc-timeout", "1500m"],
                ["x-tenant", "acme"],
            )),
            now=1000,
        )
    assert exc.value.code == "duplicate_key"


def test_metadata_size_limit_is_enforced():
    with pytest.raises(bm.MetadataError) as exc:
        gate(max_metadata_bytes=16).check(invocation(), now=1000)
    assert exc.value.code == "metadata_too_large"


def test_timeout_limit_is_enforced():
    with pytest.raises(bm.MetadataError) as exc:
        gate().check(
            invocation(metadata=meta(
                ["authorization", token()],
                ["x-request-id", "0123456789abcdef"],
                ["x-tenant", "acme"],
                ["grpc-timeout", "9000m"],
            )),
            now=1000,
        )
    assert exc.value.code == "timeout_too_large"


def test_replayed_nonce_is_rejected_under_concurrency():
    g = gate()
    results = []
    problems = []

    def worker():
        try:
            g.check(invocation(), now=1000)
            results.append("ok")
        except bm.MetadataError as exc:
            results.append(exc.code)
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert results.count("ok") == 1
    assert results.count("nonce_replayed") == 7
    snap = g.snapshot()
    assert snap["accepted"] == 1
    assert snap["rejected"] == 7
    snap["accepted"] = 0
    assert g.snapshot()["accepted"] == 1
