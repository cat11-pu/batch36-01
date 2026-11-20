import threading

import pytest

import chain_build_audit as cb


def cert(fp, subject, issuer, spki, issuer_spki="", is_ca=False, path_len=None,
         nb=0, na=1000, dns=None, eku=None, crit=None, constraints=None,
         link_ok=True):
    return {
        "fingerprint": fp,
        "subject": subject,
        "issuer": issuer,
        "spki": spki,
        "issuer_spki": issuer_spki,
        "is_ca": is_ca,
        "path_len": path_len,
        "not_before": nb,
        "not_after": na,
        "dns_names": list(dns or []),
        "eku": list(eku or []),
        "critical_ext": list(crit or []),
        "name_constraints": dict(constraints or {}),
        "link_ok": link_ok,
    }


def _apply(c, over):
    aliases = {
        "nb": "not_before",
        "na": "not_after",
        "dns": "dns_names",
        "crit": "critical_ext",
        "constraints": "name_constraints",
    }
    for short, full in aliases.items():
        if short in over:
            over[full] = over.pop(short)
    c.update(over)
    return c


def root(**over):
    c = cert("root", "CN=Root", "CN=Root", "spki-root", is_ca=True)
    return _apply(c, over)


def intermediate(**over):
    c = cert(
        "int",
        "CN=Issuing",
        "CN=Root",
        "spki-int",
        issuer_spki="spki-root",
        is_ca=True,
    )
    return _apply(c, over)


def leaf(**over):
    c = cert(
        "leaf",
        "CN=api",
        "CN=Issuing",
        "spki-leaf",
        issuer_spki="spki-int",
        eku=["serverAuth"],
        dns=["api.corp.example.com"],
    )
    return _apply(c, over)


def builder(anchors=None, max_depth=4):
    return cb.ChainBuilder(
        anchors if anchors is not None else [root()],
        max_depth=max_depth,
        verify_link=lambda child, parent: child.get("link_ok", True),
    )


def test_builds_leaf_to_trusted_anchor():
    out = builder().build(leaf(), [intermediate()], now=10)
    assert [c["fingerprint"] for c in out["chain"]] == ["leaf", "int", "root"]
    assert out["anchor"] == "root"
    assert out["path_len"] == 1


def test_anchor_must_match_key_not_only_subject():
    evil = cert("evil", "CN=Root", "CN=Root", "spki-evil", is_ca=True)
    leafc = cert(
        "leaf",
        "CN=api",
        "CN=Root",
        "spki-leaf",
        issuer_spki="spki-evil",
        eku=["serverAuth"],
    )
    b = cb.ChainBuilder(
        [root()],
        4,
        lambda child, parent: child.get("issuer_spki") == parent["spki"],
    )
    with pytest.raises(cb.ChainError) as exc:
        b.build(leafc, [evil], now=10)
    assert exc.value.code == "untrusted_anchor"


def test_signature_link_failure_is_rejected():
    broken = leaf(link_ok=False)
    with pytest.raises(cb.ChainError) as exc:
        builder().build(broken, [intermediate()], now=10)
    assert exc.value.code == "bad_link"


def test_expired_intermediate_is_rejected():
    with pytest.raises(cb.ChainError) as exc:
        builder().build(leaf(), [intermediate(na=50)], now=60)
    assert exc.value.code == "expired"


def test_leaf_not_yet_valid_is_rejected():
    with pytest.raises(cb.ChainError) as exc:
        builder().build(leaf(nb=20), [intermediate()], now=10)
    assert exc.value.code == "not_yet_valid"


def test_non_ca_parent_is_rejected():
    with pytest.raises(cb.ChainError) as exc:
        builder().build(leaf(), [intermediate(is_ca=False)], now=10)
    assert exc.value.code == "not_ca"


def test_path_len_constraint_is_enforced():
    trust = root(path_len=0)
    b = cb.ChainBuilder([trust], 4, lambda child, parent: True)
    with pytest.raises(cb.ChainError) as exc:
        b.build(leaf(), [intermediate()], now=10)
    assert exc.value.code == "path_len_exceeded"


def test_name_constraint_applies_to_intermediate_names():
    trust = root(name_constraints={"permitted": [".corp.example.com"], "excluded": []})
    mid = intermediate(dns=["ca.other.example.com"])
    b = cb.ChainBuilder([trust], 4, lambda child, parent: True)
    with pytest.raises(cb.ChainError) as exc:
        b.build(leaf(), [mid], now=10)
    assert exc.value.code == "name_constraint"


def test_excluded_subtree_blocks_leaf():
    mid = intermediate(
        name_constraints={"permitted": [], "excluded": ["secret.corp.example.com"]}
    )
    bad_leaf = leaf(dns=["secret.corp.example.com"])
    with pytest.raises(cb.ChainError) as exc:
        builder().build(bad_leaf, [mid], now=10)
    assert exc.value.code == "name_constraint"


def test_leaf_eku_must_match_purpose():
    with pytest.raises(cb.ChainError) as exc:
        builder().build(leaf(eku=["clientAuth"]), [intermediate()], now=10)
    assert exc.value.code == "bad_eku"


def test_unknown_critical_extension_is_rejected():
    with pytest.raises(cb.ChainError) as exc:
        builder().build(leaf(crit=["customExtension"]), [intermediate()], now=10)
    assert exc.value.code == "unknown_critical"


def test_cross_signed_intermediate_reaches_real_anchor():
    good = intermediate()
    evil = cert(
        "int-evil",
        "CN=Issuing",
        "CN=EvilRoot",
        "spki-int",
        issuer_spki="spki-evilroot",
        is_ca=True,
    )
    evil_root = cert(
        "evilroot", "CN=EvilRoot", "CN=EvilRoot", "spki-evilroot", is_ca=True
    )
    b = cb.ChainBuilder(
        [root()],
        5,
        lambda child, parent: child.get("issuer_spki") == parent["spki"],
    )
    out = b.build(leaf(), [evil, good, evil_root], now=10)
    assert [c["fingerprint"] for c in out["chain"]] == ["leaf", "int", "root"]


def test_loop_without_anchor_is_rejected():
    a = cert("a", "CN=A", "CN=B", "spki-a", issuer_spki="spki-b", is_ca=True)
    b = cert("b", "CN=B", "CN=A", "spki-b", issuer_spki="spki-a", is_ca=True)
    leafc = cert(
        "leaf", "CN=api", "CN=A", "spki-leaf", issuer_spki="spki-a",
        eku=["serverAuth"],
    )
    chained = cb.ChainBuilder(
        [root()], 5, lambda child, parent: child.get("issuer_spki") == parent["spki"]
    )
    with pytest.raises(cb.ChainError) as exc:
        chained.build(leafc, [a, b], now=10)
    assert exc.value.code == "loop"


def test_chain_depth_limit_is_enforced():
    i1 = cert("i1", "CN=I1", "CN=Root", "spki-i1", issuer_spki="spki-root", is_ca=True)
    i2 = cert("i2", "CN=I2", "CN=I1", "spki-i2", issuer_spki="spki-i1", is_ca=True)
    leafc = cert(
        "leaf", "CN=api", "CN=I2", "spki-leaf", issuer_spki="spki-i2",
        eku=["serverAuth"],
    )
    b = cb.ChainBuilder(
        [root()], 1, lambda child, parent: child.get("issuer_spki") == parent["spki"]
    )
    with pytest.raises(cb.ChainError) as exc:
        b.build(leafc, [i1, i2], now=10)
    assert exc.value.code == "chain_too_deep"


def test_build_is_deterministic_and_audit_is_detached():
    b = builder()
    first = b.build(leaf(), [intermediate()], now=10)
    second = b.build(leaf(), [intermediate()], now=10)
    assert [c["fingerprint"] for c in first["chain"]] == [
        c["fingerprint"] for c in second["chain"]
    ]
    snap = b.audit()
    assert snap["rejected"] == []
    snap["rejected"].append({"fingerprint": "x", "code": "y"})
    assert b.audit()["rejected"] == []
