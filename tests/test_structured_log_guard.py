import threading

import pytest

import structured_log_guard as sl


def guard(**kw):
    return sl.StructuredLogGuard(**kw)


def record(**over):
    rec = {
        "level": "INFO",
        "event": "login_failed",
        "fields": {"user": "alice", "ip": "1.2.3.4"},
    }
    rec.update(over)
    return rec


def test_valid_record_renders_one_sorted_line():
    rec = record(fields={"user": "alice", "ip": "1.2.3.4", "attempt": 3, "mfa": False})
    out = guard().render(rec, now=1700000000)
    assert out["line"] == (
        'ts=1700000000 level=INFO event=login_failed '
        'attempt=3 ip="1.2.3.4" mfa=false user="alice"'
    )
    assert out["field_count"] == 4


def test_level_must_be_known_and_upper_case():
    for bad in ["info", "TRACE"]:
        with pytest.raises(sl.LogFieldError) as exc:
            guard().render(record(level=bad))
        assert exc.value.code == "bad_level"


def test_event_name_is_validated():
    for bad in ["Login Failed", "_hidden", "x" * 70]:
        with pytest.raises(sl.LogFieldError) as exc:
            guard().render(record(event=bad))
        assert exc.value.code == "bad_event"


def test_reserved_field_name_is_rejected():
    for bad in ["ts", "level", "event", "msg"]:
        with pytest.raises(sl.LogFieldError) as exc:
            guard().render(record(fields={bad: "x"}))
        assert exc.value.code == "reserved_field"


def test_bad_field_name_is_rejected():
    for bad in ["User", "x-y"]:
        with pytest.raises(sl.LogFieldError) as exc:
            guard().render(record(fields={bad: "v"}))
        assert exc.value.code == "bad_field_name"


def test_field_count_limit_is_enforced():
    with pytest.raises(sl.LogFieldError) as exc:
        guard(max_fields=1).render(record(fields={"a": "1", "b": "2"}))
    assert exc.value.code == "too_many_fields"


def test_value_length_limit_is_enforced():
    with pytest.raises(sl.LogFieldError) as exc:
        guard(max_value_len=4).render(record(fields={"a": "abcde"}))
    assert exc.value.code == "value_too_long"


def test_crlf_in_value_is_rejected():
    with pytest.raises(sl.LogFieldError) as exc:
        guard().render(record(fields={"note": "a\r\nb"}))
    assert exc.value.code == "control_char"


def test_nul_in_value_is_rejected():
    with pytest.raises(sl.LogFieldError) as exc:
        guard().render(record(fields={"note": "a\x00b"}))
    assert exc.value.code == "control_char"


def test_line_separator_in_value_is_rejected():
    with pytest.raises(sl.LogFieldError) as exc:
        guard().render(record(fields={"note": "a\u2028b"}))
    assert exc.value.code == "control_char"


def test_tab_backspace_and_escape_are_rejected():
    for bad in ["a\tb", "a\x08b", "a\x1bb"]:
        with pytest.raises(sl.LogFieldError) as exc:
            guard().render(record(fields={"note": bad}))
        assert exc.value.code == "control_char"


def test_quotes_and_backslashes_are_escaped():
    rec = record(event="note", fields={"note": 'he said "hi"\\path'})
    out = guard().render(rec, now=5)
    assert out["line"] == (
        'ts=5 level=INFO event=note note="he said \\"hi\\"\\\\path"'
    )


def test_unsupported_value_type_is_rejected():
    for bad in [1.5, None, ["a"], {"b": 1}]:
        with pytest.raises(sl.LogFieldError) as exc:
            guard().render(record(fields={"note": bad}))
        assert exc.value.code == "bad_value_type"


def test_scalars_and_empty_string_are_rendered():
    rec = record(level="WARN", event="quota_exceeded",
                 fields={"flag": True, "count": 7, "empty": ""})
    out = guard().render(rec, now=5)
    assert out["line"] == (
        'ts=5 level=WARN event=quota_exceeded count=7 empty="" flag=true'
    )


def test_concurrent_render_is_counted_and_detached():
    g = guard()
    problems = []
    lines = []

    def worker():
        try:
            for _ in range(2):
                lines.append(g.render(record(), now=1)["line"])
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert len(lines) == 8
    assert len(set(lines)) == 1
    snap = g.snapshot()
    assert snap["rendered"] == 8
    snap["rendered"] = 0
    assert g.snapshot()["rendered"] == 8
