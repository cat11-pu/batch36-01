import threading

import pytest

import http_frame_arbiter as hf


def req(headers=None, body=b"", version="HTTP/1.1", method="POST"):
    return {
        "method": method,
        "version": version,
        "headers": list(headers or []),
        "body": body,
    }


def test_content_length_is_parsed():
    out = hf.HttpFrameArbiter().frame(req([["Content-Length", "4"]], b"data"))
    assert out["mode"] == "content-length"
    assert out["length"] == 4


def test_request_without_framing_has_empty_body():
    out = hf.HttpFrameArbiter().frame(req())
    assert out["mode"] == "none"
    assert out["length"] == 0


def test_content_length_with_transfer_encoding_conflicts():
    bad = req([["Content-Length", "4"], ["Transfer-Encoding", "chunked"]], b"0\r\n\r\n")
    with pytest.raises(hf.FramingError) as exc:
        hf.HttpFrameArbiter().frame(bad)
    assert exc.value.code == "cl_te_conflict"


def test_duplicate_content_length_is_rejected():
    bad = req([["Content-Length", "4"], ["content-length", "4"]], b"data")
    with pytest.raises(hf.FramingError) as exc:
        hf.HttpFrameArbiter().frame(bad)
    assert exc.value.code == "duplicate_length"


def test_signed_content_length_is_rejected():
    with pytest.raises(hf.FramingError) as exc:
        hf.HttpFrameArbiter().frame(req([["Content-Length", "+4"]], b"data"))
    assert exc.value.code == "bad_content_length"


def test_comma_list_content_length_is_rejected():
    with pytest.raises(hf.FramingError) as exc:
        hf.HttpFrameArbiter().frame(req([["Content-Length", "4, 4"]], b"data"))
    assert exc.value.code == "bad_content_length"


def test_transfer_encoding_list_is_rejected():
    bad = req([["Transfer-Encoding", "gzip, chunked"]], b"4\r\nWiki\r\n0\r\n\r\n")
    with pytest.raises(hf.FramingError) as exc:
        hf.HttpFrameArbiter().frame(bad)
    assert exc.value.code == "bad_transfer_encoding"


def test_mixed_case_chunked_is_accepted():
    out = hf.HttpFrameArbiter().frame(
        req([["Transfer-Encoding", "Chunked"]], b"4\r\nWiki\r\n0\r\n\r\n")
    )
    assert out["mode"] == "chunked"
    assert out["length"] == 4


def test_chunked_on_http10_is_rejected():
    bad = req([["Transfer-Encoding", "chunked"]], b"0\r\n\r\n", version="HTTP/1.0")
    with pytest.raises(hf.FramingError) as exc:
        hf.HttpFrameArbiter().frame(bad)
    assert exc.value.code == "te_not_allowed"


def test_body_length_mismatch_is_rejected():
    with pytest.raises(hf.FramingError) as exc:
        hf.HttpFrameArbiter().frame(req([["Content-Length", "5"]], b"data"))
    assert exc.value.code == "body_length_mismatch"


def test_chunked_body_is_decoded():
    body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
    out = hf.HttpFrameArbiter().frame(req([["Transfer-Encoding", "chunked"]], body))
    assert out["mode"] == "chunked"
    assert out["length"] == 9


def test_chunked_body_without_terminator_is_rejected():
    bad = b"4\r\nWiki\r\n0\r\n"
    with pytest.raises(hf.FramingError) as exc:
        hf.HttpFrameArbiter().frame(req([["Transfer-Encoding", "chunked"]], bad))
    assert exc.value.code == "bad_chunked_body"


def test_obs_fold_is_rejected():
    bad = req([["X-Note", "a"], [" continued", "b"]], b"")
    with pytest.raises(hf.FramingError) as exc:
        hf.HttpFrameArbiter().frame(bad)
    assert exc.value.code == "obs_fold"


def test_h2_hop_by_hop_header_is_rejected():
    bad = req([["Connection", "keep-alive"]], b"", version="HTTP/2")
    with pytest.raises(hf.FramingError) as exc:
        hf.HttpFrameArbiter().frame(bad)
    assert exc.value.code == "h2_forbidden_header"


def test_concurrent_framing_is_counted():
    a = hf.HttpFrameArbiter()
    problems = []
    results = []

    def worker():
        try:
            for _ in range(2):
                results.append(a.frame(req([["Content-Length", "4"]], b"data")))
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert len(results) == 10
    snap = a.journal()
    assert snap["framed"] == 10
    snap["framed"] = 0
    assert a.journal()["framed"] == 10
