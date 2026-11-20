import hashlib
import threading

import pytest

import ct_inclusion_proof as cp


def h(data):
    return hashlib.sha256(data).hexdigest()


def node(left, right):
    return h(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right))


def leaf_hash(cert):
    return h(b"\x00" + cert)


LEAVES = [b"cert-%d" % i for i in range(8)]
H = [leaf_hash(c) for c in LEAVES]
N01 = node(H[0], H[1])
N23 = node(H[2], H[3])
N45 = node(H[4], H[5])
N67 = node(H[6], H[7])
N03 = node(N01, N23)
N47 = node(N45, N67)
ROOT = node(N03, N47)
PATH3 = [H[2], N01, N47]

LOGS = {"log-a": {"key": "log-key-1", "state": "usable"}}


def verifier(**kw):
    base = {
        "logs": LOGS,
        "verify_signature": lambda key, msg, sig: key == "log-key-1"
        and sig in ("sig-ok", "sth-ok"),
        "max_sct_age": 1000,
    }
    base.update(kw)
    return cp.CtInclusionAudit(**base)


def sct(**over):
    s = {
        "log_id": "log-a",
        "version": 0,
        "timestamp": 100,
        "signature": "sig-ok",
        "leaf_hash": H[3],
        "extensions": b"",
    }
    s.update(over)
    return s


def sth(**over):
    s = {
        "tree_size": 8,
        "root_hash": ROOT,
        "timestamp": 150,
        "signature": "sth-ok",
    }
    s.update(over)
    return s


def proof(**over):
    p = {"tree_size": 8, "leaf_index": 3, "audit_path": list(PATH3)}
    p.update(over)
    return p


def test_valid_inclusion_proof_returns_root():
    out = verifier().verify(sct(), sth(), proof(), LEAVES[3], now=200)
    assert out["root_hash"] == ROOT
    assert out["leaf_index"] == 3
    assert out["tree_size"] == 8


def test_unknown_log_is_rejected():
    with pytest.raises(cp.CtProofError) as exc:
        verifier().verify(sct(log_id="log-x"), sth(), proof(), LEAVES[3], now=200)
    assert exc.value.code == "unknown_log"


def test_retired_log_is_rejected():
    logs = {"log-a": {"key": "log-key-1", "state": "retired"}}
    with pytest.raises(cp.CtProofError) as exc:
        verifier(logs=logs).verify(sct(), sth(), proof(), LEAVES[3], now=200)
    assert exc.value.code == "log_retired"


def test_unsupported_version_is_rejected():
    with pytest.raises(cp.CtProofError) as exc:
        verifier().verify(sct(version=1), sth(), proof(), LEAVES[3], now=200)
    assert exc.value.code == "bad_version"


def test_future_sct_is_rejected():
    with pytest.raises(cp.CtProofError) as exc:
        verifier().verify(sct(timestamp=300), sth(), proof(), LEAVES[3], now=200)
    assert exc.value.code == "sct_in_future"


def test_stale_sct_is_rejected():
    with pytest.raises(cp.CtProofError) as exc:
        verifier().verify(sct(), sth(), proof(), LEAVES[3], now=5000)
    assert exc.value.code == "sct_stale"


def test_bad_sct_signature_is_rejected():
    with pytest.raises(cp.CtProofError) as exc:
        verifier().verify(
            sct(signature="bad"), sth(), proof(), LEAVES[3], now=200
        )
    assert exc.value.code == "bad_sct_signature"


def test_leaf_hash_mismatch_is_rejected():
    with pytest.raises(cp.CtProofError) as exc:
        verifier().verify(sct(), sth(), proof(), LEAVES[4], now=200)
    assert exc.value.code == "leaf_hash_mismatch"


def test_tree_size_mismatch_is_rejected():
    with pytest.raises(cp.CtProofError) as exc:
        verifier().verify(sct(), sth(tree_size=4), proof(), LEAVES[3], now=200)
    assert exc.value.code == "size_mismatch"


def test_sth_before_sct_is_rejected():
    with pytest.raises(cp.CtProofError) as exc:
        verifier().verify(sct(), sth(timestamp=50), proof(), LEAVES[3], now=200)
    assert exc.value.code == "sth_before_sct"


def test_bad_sth_signature_is_rejected():
    with pytest.raises(cp.CtProofError) as exc:
        verifier().verify(
            sct(), sth(signature="bad"), proof(), LEAVES[3], now=200
        )
    assert exc.value.code == "bad_sth_signature"


def test_leaf_index_out_of_range_is_rejected():
    with pytest.raises(cp.CtProofError) as exc:
        verifier().verify(
            sct(), sth(), proof(leaf_index=8), LEAVES[3], now=200
        )
    assert exc.value.code == "bad_leaf_index"


def test_malformed_audit_path_is_rejected():
    with pytest.raises(cp.CtProofError) as exc:
        verifier().verify(
            sct(), sth(), proof(audit_path=["zz"]), LEAVES[3], now=200
        )
    assert exc.value.code == "bad_path"


def test_tampered_audit_path_does_not_match_root():
    with pytest.raises(cp.CtProofError) as exc:
        verifier().verify(
            sct(), sth(), proof(audit_path=[H[2], N01, N45]), LEAVES[3], now=200
        )
    assert exc.value.code == "root_mismatch"


def test_concurrent_verification_yields_one_root():
    v = verifier()
    roots = []
    problems = []

    def worker():
        try:
            roots.append(v.verify(sct(), sth(), proof(), LEAVES[3], now=200)["root_hash"])
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert len(roots) == 8
    assert set(roots) == {ROOT}
