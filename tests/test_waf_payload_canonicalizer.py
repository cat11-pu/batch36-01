import threading

import pytest

import waf_payload_canonicalizer as wc


def gate(**kw):
    return wc.WafPayloadCanonicalizer(**kw)


def test_plain_text_is_trimmed_and_collapsed():
    out = gate().canonicalize("  hello   world\n")
    assert out["canonical"] == "hello world"
    assert out["layers"] == 0
    assert out["stages"] == ["percent", "unicode", "comment", "whitespace"]


def test_double_encoded_quote_is_fully_decoded():
    out = gate().canonicalize("%2527")
    assert out["canonical"] == "'"
    assert out["layers"] == 2


def test_query_mode_converts_plus_to_space():
    out = gate(mode="query").canonicalize("a+b=c")
    assert out["canonical"] == "a b=c"
    assert out["stages"] == ["plus", "percent", "unicode", "comment", "whitespace"]


def test_text_mode_keeps_plus_literal():
    assert gate().canonicalize("a+b")["canonical"] == "a+b"


def test_fullwidth_letters_are_folded():
    out = gate().canonicalize("ＳＥＬＥＣＴ １２３")
    assert out["canonical"] == "SELECT 123"


def test_block_comment_becomes_single_space():
    assert gate().canonicalize("union/**/select")["canonical"] == "union select"


def test_unterminated_block_comment_is_rejected():
    with pytest.raises(wc.WafCanonError) as exc:
        gate().canonicalize("union /* select")
    assert exc.value.code == "bad_comment"


def test_nul_after_decoding_is_rejected():
    with pytest.raises(wc.WafCanonError) as exc:
        gate().canonicalize("a%00b")
    assert exc.value.code == "nul_byte"


def test_decode_depth_exceeded_is_rejected():
    with pytest.raises(wc.WafCanonError) as exc:
        gate(max_depth=1).canonicalize("%2527")
    assert exc.value.code == "decode_depth"


def test_invisible_character_is_rejected():
    with pytest.raises(wc.WafCanonError) as exc:
        gate().canonicalize("a\u200bb")
    assert exc.value.code == "invisible_char"


def test_json_unicode_escape_is_decoded():
    out = gate(mode="json").canonicalize(r"\u0041\u0042")
    assert out["canonical"] == "AB"
    assert out["layers"] == 0


def test_lone_surrogate_in_json_mode_is_rejected():
    with pytest.raises(wc.WafCanonError) as exc:
        gate(mode="json").canonicalize(r"\ud800")
    assert exc.value.code == "bad_json_escape"


def test_oversized_payload_is_rejected():
    with pytest.raises(wc.WafCanonError) as exc:
        gate(max_len=8).canonicalize("abcdefghi")
    assert exc.value.code == "payload_too_large"


def test_non_string_payload_is_rejected_and_counted():
    g = gate()
    with pytest.raises(wc.WafCanonError) as exc:
        g.canonicalize(b"a+b")
    assert exc.value.code == "bad_payload"
    assert g.snapshot()["rejected"] == 1


def test_concurrent_canonicalization_is_counted_and_detached():
    g = gate()
    problems = []
    results = []

    def worker():
        try:
            for _ in range(3):
                results.append(g.canonicalize("  UNION/**/select  ")["canonical"])
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert results == ["UNION select"] * 12
    snap = g.snapshot()
    assert snap["canonicalized"] == 12
    snap["canonicalized"] = 0
    assert g.snapshot()["canonicalized"] == 12
