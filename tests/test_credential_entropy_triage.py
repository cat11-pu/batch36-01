import threading

import pytest

import credential_entropy_triage as ce

SECRET = "Xk9Qm2Lp7Rt4Vw8Za1Bc3De6Fg0Hj5"


def scanner(**kw):
    return ce.CredentialEntropyTriage(**kw)


def source(secret, prefix='api = "'):
    return 'host = "db.internal"\n%s%s"\n' % (prefix, secret)


def test_high_entropy_secret_is_reported():
    out = scanner().scan(source(SECRET), "src/config.py")
    assert out["skipped"] is False
    assert len(out["findings"]) == 1
    found = out["findings"][0]
    assert found["path"] == "src/config.py"
    assert found["line"] == 2
    assert found["column"] == 8
    assert found["length"] == len(SECRET)
    assert found["kind"] == "high_entropy"
    assert found["entropy"] >= 4.0


def test_low_entropy_token_is_not_reported():
    out = scanner().scan(source("ab" * 15))
    assert out["findings"] == []


def test_short_token_is_not_reported():
    out = scanner().scan(source("aB3xY9zQ"))
    assert out["findings"] == []


def test_allowlisted_path_is_skipped():
    out = scanner(allow_prefixes=("vendor/",)).scan(source(SECRET), "vendor/lib.js")
    assert out["skipped"] is True
    assert out["reason"] == "allowlisted"
    assert out["findings"] == []


def test_bad_path_is_rejected():
    for bad in ["../etc/passwd", "C:/keys.txt", "\\\\server\\share"]:
        with pytest.raises(ce.SecretScanError) as exc:
            scanner().scan(source(SECRET), bad)
        assert exc.value.code == "bad_path"


def test_binary_input_is_rejected():
    with pytest.raises(ce.SecretScanError) as exc:
        scanner().scan("abc\x00def")
    assert exc.value.code == "binary_input"


def test_placeholder_token_is_suppressed():
    token = "Zx9QchangemeK2mP4vL8nR6t"
    out = scanner(placeholder_markers=("changeme",)).scan(source(token))
    assert out["findings"] == []
    assert scanner(placeholder_markers=("changeme",)).scan(source("Qw8Er7Ty6Ui5Op4As3Df2"))["findings"] != []


def test_repeated_character_token_is_suppressed():
    out = scanner().scan(source("A" * 30))
    assert out["findings"] == []


def test_known_prefix_is_reported_below_entropy_threshold():
    out = scanner(entropy_threshold=8.0).scan("aws = AKIA1234567890ABCDEF")
    assert len(out["findings"]) == 1
    assert out["findings"][0]["kind"] == "known_prefix"


def test_two_secrets_are_sorted_by_column():
    first = "Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0Lz9Xc"
    second = "Mn7Bv6Cx5Zl4Kj3Hg2Fd1Sa0Po9Iu8Yt"
    out = scanner().scan("a = %s b = %s" % (first, second))
    assert len(out["findings"]) == 2
    assert out["findings"][0]["line"] == 1
    assert out["findings"][0]["column"] < out["findings"][1]["column"]


def test_preview_masks_the_secret():
    found = scanner().scan(source(SECRET), "src/config.py")["findings"][0]
    assert found["preview"] == "Xk9Q...j5"
    assert SECRET not in found["preview"]


def test_entropy_value_is_computed():
    out = scanner(entropy_threshold=1.5).scan(source("abcd" * 5))
    assert len(out["findings"]) == 1
    assert round(out["findings"][0]["entropy"], 3) == 2.0


def test_overlong_candidate_is_dropped_not_truncated():
    blob = "QwErTyUiOpAsDfGhJkLzXcVbNm1234567890qwertyuiopasdfghjklzxcvbnmQWERTY"
    out = scanner(max_len=64).scan("k = " + blob)
    assert out["findings"] == []


def test_snapshot_counts_and_is_detached():
    s = scanner(allow_prefixes=("vendor/",))
    s.scan(source(SECRET), "src/a.py")
    s.scan(source(SECRET), "vendor/b.py")
    snap = s.snapshot()
    assert snap["scanned"] == 2
    assert snap["findings"] == 1
    assert snap["skipped"] == 1
    snap["scanned"] = 0
    assert s.snapshot()["scanned"] == 2


def test_concurrent_scan_is_counted_and_detached():
    s = scanner()
    problems = []
    counts = []

    def worker():
        try:
            for _ in range(2):
                counts.append(len(s.scan(source(SECRET))["findings"]))
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert counts == [1] * 8
    snap = s.snapshot()
    assert snap["scanned"] == 8
    assert snap["findings"] == 8
    snap["findings"] = 0
    assert s.snapshot()["findings"] == 8
