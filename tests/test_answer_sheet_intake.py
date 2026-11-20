import threading

import pytest

import answer_sheet_intake as ai

KINDS = {
    "png": {"mime": "image/png", "ext": "png", "signature": b"\x89PNG\r\n\x1a\n"},
    "pdf": {"mime": "application/pdf", "ext": "pdf", "signature": b"%PDF-1.7"},
}


def intake(**kw):
    return ai.AnswerSheetIntake(KINDS, **kw)


def upload(**over):
    u = {
        "filename": "sheet.png",
        "declared": "image/png",
        "content": b"\x89PNG\r\n\x1a\n" + b"pixels",
    }
    u.update(over)
    return u


def test_png_is_stored_under_digest_name():
    out = intake().admit(upload())
    assert out["kind"] == "png"
    assert out["duplicate"] is False
    assert out["stored_name"].endswith(".png")
    assert "sheet" not in out["stored_name"]
    assert len(out["digest"]) == 64


def test_declared_type_mismatch_is_rejected():
    with pytest.raises(ai.IntakeError) as exc:
        intake().admit(upload(declared="application/pdf"))
    assert exc.value.code == "declared_mismatch"


def test_extension_mismatch_is_rejected():
    with pytest.raises(ai.IntakeError) as exc:
        intake().admit(upload(filename="sheet.pdf"))
    assert exc.value.code == "extension_mismatch"


def test_double_extension_is_rejected():
    with pytest.raises(ai.IntakeError) as exc:
        intake().admit(upload(filename="sheet.png.php"))
    assert exc.value.code == "extension_mismatch"


def test_path_separator_in_filename_is_rejected():
    with pytest.raises(ai.IntakeError) as exc:
        intake().admit(upload(filename="../sheet.png"))
    assert exc.value.code == "bad_filename"


def test_nul_byte_in_filename_is_rejected():
    with pytest.raises(ai.IntakeError) as exc:
        intake().admit(upload(filename="sheet\x00.png"))
    assert exc.value.code == "bad_filename"


def test_oversized_content_is_rejected():
    with pytest.raises(ai.IntakeError) as exc:
        intake(max_bytes=32).admit(upload(content=b"\x89PNG\r\n\x1a\n" + b"x" * 64))
    assert exc.value.code == "too_large"


def test_empty_content_is_rejected():
    with pytest.raises(ai.IntakeError) as exc:
        intake().admit(upload(content=b""))
    assert exc.value.code == "empty_payload"


def test_unknown_signature_is_rejected():
    with pytest.raises(ai.IntakeError) as exc:
        intake().admit(upload(content=b"GIF89a-not-allowed"))
    assert exc.value.code == "unsupported_type"


def test_embedded_second_signature_is_rejected():
    content = b"\x89PNG\r\n\x1a\n" + b"pixels" + b"%PDF-1.7"
    with pytest.raises(ai.IntakeError) as exc:
        intake().admit(upload(content=content))
    assert exc.value.code == "polyglot"


def test_duplicate_content_reuses_first_stored_name():
    s = intake()
    first = s.admit(upload())
    second = s.admit(upload(filename="again.png"))
    assert second["duplicate"] is True
    assert second["stored_name"] == first["stored_name"]


def test_non_bytes_content_is_rejected():
    with pytest.raises(ai.IntakeError) as exc:
        intake().admit(upload(content="not-bytes"))
    assert exc.value.code == "bad_content"


def test_uppercase_extension_is_accepted_and_lowered():
    out = intake().admit(upload(filename="SHEET.PNG"))
    assert out["kind"] == "png"
    assert out["stored_name"].endswith(".png")


def test_snapshot_counts_are_copied():
    s = intake()
    s.admit(upload())
    s.admit(upload())
    with pytest.raises(ai.IntakeError):
        s.admit(upload(content=b"GIF89a-not-allowed"))
    snap = s.snapshot()
    assert snap["admitted"] == 1
    assert snap["duplicates"] == 1
    assert snap["rejected"] == 1
    snap["admitted"] = 99
    assert s.snapshot()["admitted"] == 1


def test_concurrent_duplicate_submission_is_counted_once():
    s = intake()
    results = []
    problems = []

    def worker():
        try:
            results.append(s.admit(upload())["duplicate"])
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert results.count(False) == 1
    assert results.count(True) == 7
    assert s.snapshot()["admitted"] == 1
