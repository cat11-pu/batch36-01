import threading

import pytest

import ids_signature_multimatch as im

RULES = [
    {"id": "r-union", "pattern": "union select", "severity": "high", "flags": ["nocase"]},
    {"id": "r-passwd", "pattern": "/etc/passwd", "severity": "medium", "flags": []},
    {"id": "r-or", "pattern": " or 1=1", "severity": "critical", "flags": ["nocase"]},
]

OVERLAP = [
    {"id": "r-aba", "pattern": "aba", "severity": "low", "flags": []},
    {"id": "r-bab", "pattern": "bab", "severity": "low", "flags": []},
]


def engine(rules=None, **kw):
    return im.SignatureMultimatch(RULES if rules is None else rules, **kw)


def test_plain_rule_reports_hit_details():
    out = engine().scan("id=1 union select name from users")
    assert out["truncated"] is False
    assert len(out["hits"]) == 1
    hit = out["hits"][0]
    assert hit["rule"] == "r-union"
    assert hit["offset"] == 5
    assert hit["length"] == 12
    assert hit["severity"] == "high"
    assert hit["matched"] == "union select"


def test_nocase_flag_ignores_letter_case():
    hit = engine().scan("UNION SELECT")["hits"][0]
    assert hit["rule"] == "r-union"
    assert hit["matched"] == "UNION SELECT"


def test_matching_is_case_sensitive_by_default():
    rules = [{"id": "r-token", "pattern": "Token", "severity": "low"}]
    assert engine(rules).scan("token")["hits"] == []
    assert engine(rules).scan("a Token b")["hits"][0]["offset"] == 2


def test_word_flag_requires_boundaries():
    rules = [{"id": "r-cat", "pattern": "cat", "severity": "low", "flags": ["word", "nocase"]}]
    eng = engine(rules)
    assert eng.scan("concatenate cat_1")["hits"] == []
    hit = eng.scan("a cat sat")["hits"][0]
    assert hit["offset"] == 2


def test_overlapping_rules_are_both_reported():
    out = engine(OVERLAP).scan("abab")
    assert [(h["rule"], h["offset"], h["length"]) for h in out["hits"]] == [
        ("r-aba", 0, 3),
        ("r-bab", 1, 3),
    ]


def test_repeated_overlapping_occurrences_are_all_reported():
    rules = [{"id": "r-aa", "pattern": "aa", "severity": "low"}]
    out = engine(rules).scan("aaaa")
    assert [h["offset"] for h in out["hits"]] == [0, 1, 2]
    assert {h["rule"] for h in out["hits"]} == {"r-aa"}


def test_max_hits_truncates_and_flags():
    rules = [{"id": "r-aa", "pattern": "aa", "severity": "low"}]
    out = engine(rules, max_hits=2).scan("aaaa")
    assert [h["offset"] for h in out["hits"]] == [0, 1]
    assert out["truncated"] is True


def test_oversized_payload_is_rejected():
    with pytest.raises(im.SignatureError) as exc:
        engine(max_payload=8).scan("x" * 9)
    assert exc.value.code == "payload_too_large"


def test_non_string_payload_is_rejected_and_counted():
    eng = engine()
    with pytest.raises(im.SignatureError) as exc:
        eng.scan(b"union select")
    assert exc.value.code == "bad_payload"
    assert eng.snapshot()["failures"] == 1


def test_duplicate_rule_id_is_rejected():
    rules = [
        {"id": "r-x", "pattern": "ab", "severity": "low"},
        {"id": "r-x", "pattern": "cd", "severity": "low"},
    ]
    with pytest.raises(im.SignatureError) as exc:
        engine(rules)
    assert exc.value.code == "duplicate_rule"


def test_empty_pattern_is_rejected():
    with pytest.raises(im.SignatureError) as exc:
        engine([{"id": "r-x", "pattern": "", "severity": "low"}])
    assert exc.value.code == "empty_pattern"


def test_unknown_flag_is_rejected():
    with pytest.raises(im.SignatureError) as exc:
        engine([{"id": "r-x", "pattern": "ab", "severity": "low", "flags": ["regex"]}])
    assert exc.value.code == "bad_flag"


def test_control_character_in_pattern_is_rejected():
    with pytest.raises(im.SignatureError) as exc:
        engine([{"id": "r-x", "pattern": "a\nb", "severity": "low"}])
    assert exc.value.code == "bad_pattern"


def test_unknown_severity_is_rejected():
    with pytest.raises(im.SignatureError) as exc:
        engine([{"id": "r-x", "pattern": "ab", "severity": "severe"}])
    assert exc.value.code == "bad_severity"


def test_concurrent_scan_is_counted_and_detached():
    eng = engine()
    problems = []
    counts = []

    def worker():
        try:
            for _ in range(3):
                counts.append(len(eng.scan("union select")["hits"]))
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert counts == [1] * 12
    snap = eng.snapshot()
    assert snap["scanned"] == 12
    assert snap["hits"] == 12
    snap["scanned"] = 0
    assert eng.snapshot()["scanned"] == 12
