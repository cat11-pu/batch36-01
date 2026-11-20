import hashlib
import threading

import pytest

import tenant_file_vault as tv

ROOTS = {"acme": "/srv/vault/acme", "globex": "/srv/vault/globex"}
INDEX = {
    "acme": {"reports/q1.csv": b"a,b\n1,2\n", "reports/q2.csv": b"x,y\n3,4\n"},
    "globex": {"reports/q1.csv": b"secret\n"},
}


def vault():
    return tv.TenantFileVault(ROOTS, INDEX)


def test_read_returns_size_and_digest():
    out = vault().open_read("acme", "reports/q1.csv")
    body = b"a,b\n1,2\n"
    assert out["key"] == "reports/q1.csv"
    assert out["size"] == len(body)
    assert out["digest"] == hashlib.sha256(body).hexdigest()


def test_unknown_tenant_is_rejected():
    with pytest.raises(tv.VaultError) as exc:
        vault().open_read("initech", "reports/q1.csv")
    assert exc.value.code == "unknown_tenant"


def test_parent_segment_is_rejected():
    with pytest.raises(tv.VaultError) as exc:
        vault().open_read("acme", "../secret.csv")
    assert exc.value.code == "parent_segment"


def test_absolute_path_is_rejected():
    with pytest.raises(tv.VaultError) as exc:
        vault().open_read("acme", "/etc/passwd")
    assert exc.value.code == "absolute_path"


def test_backslash_is_rejected():
    with pytest.raises(tv.VaultError) as exc:
        vault().open_read("acme", "reports\\q1.csv")
    assert exc.value.code == "bad_separator"


def test_windows_drive_is_rejected():
    with pytest.raises(tv.VaultError) as exc:
        vault().open_read("acme", "C:/vault/q1.csv")
    assert exc.value.code == "drive_letter"


def test_percent_encoded_key_is_rejected():
    with pytest.raises(tv.VaultError) as exc:
        vault().open_read("acme", "reports/%2e%2e/q1.csv")
    assert exc.value.code == "encoded_key"


def test_empty_segment_is_rejected():
    with pytest.raises(tv.VaultError) as exc:
        vault().open_read("acme", "reports//q1.csv")
    assert exc.value.code == "empty_segment"


def test_segment_trailing_dot_is_rejected():
    with pytest.raises(tv.VaultError) as exc:
        vault().open_read("acme", "reports./q1.csv")
    assert exc.value.code == "bad_segment"


def test_depth_limit_is_enforced():
    with pytest.raises(tv.VaultError) as exc:
        vault().open_read("acme", "a/b/c/d/e/f/g/h/i.csv")
    assert exc.value.code == "too_deep"


def test_reserved_device_name_is_rejected():
    with pytest.raises(tv.VaultError) as exc:
        vault().open_read("acme", "nul.txt")
    assert exc.value.code == "reserved_name"


def test_unnormalized_unicode_key_is_rejected():
    with pytest.raises(tv.VaultError) as exc:
        vault().open_read("acme", "reports/cafe\u0301.csv")
    assert exc.value.code == "unnormalized_key"


def test_handle_is_single_use():
    v = vault()
    handle = v.issue_handle("acme", "reports/q1.csv")
    first = v.redeem(handle, "acme", now=1)
    assert first["key"] == "reports/q1.csv"
    with pytest.raises(tv.VaultError) as exc:
        v.redeem(handle, "acme", now=2)
    assert exc.value.code == "handle_reused"


def test_handle_tenant_binding_and_expiry():
    v = vault()
    handle = v.issue_handle("acme", "reports/q1.csv")
    with pytest.raises(tv.VaultError) as exc:
        v.redeem(handle, "globex", now=1)
    assert exc.value.code == "tenant_mismatch"
    short = v.issue_handle("acme", "reports/q2.csv", ttl=5, now=0)
    with pytest.raises(tv.VaultError) as exc2:
        v.redeem(short, "acme", now=6)
    assert exc2.value.code == "handle_expired"


def test_concurrent_handle_issue_is_counted():
    v = vault()
    handles = []
    problems = []

    def worker():
        try:
            handles.append(v.issue_handle("acme", "reports/q1.csv"))
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert len(set(handles)) == 8
    snap = v.snapshot()
    assert snap["handles"] == 8
    assert snap["reads"] == 0
    snap["handles"] = 0
    assert v.snapshot()["handles"] == 8
