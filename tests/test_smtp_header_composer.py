import threading

import pytest

import smtp_header_composer as sg


def addr(address, name=""):
    return {"address": address, "name": name}


def message(**over):
    m = {
        "from": addr("noreply@example.com", "订单中心"),
        "to": [addr("alice@example.com", "Alice")],
        "cc": [],
        "bcc": [addr("audit@example.com", "")],
        "subject": "您的订单已发货",
        "headers": [["X-Trace", "t-1"]],
        "body": "您好，订单已发出。",
    }
    m.update(over)
    return m


def gate(**kw):
    return sg.SmtpHeaderComposer(**kw)


def test_valid_message_is_assembled():
    out = gate().assemble(message())
    assert out["rendered"].startswith("From:")
    assert "Subject: 您的订单已发货" in out["rendered"]
    assert "X-Trace: t-1" in out["rendered"]
    assert out["bcc_omitted"] is True


def test_subject_with_crlf_is_rejected():
    with pytest.raises(sg.HeaderComposerError) as exc:
        gate().assemble(message(subject="Hi\r\nBcc: evil@example.org"))
    assert exc.value.code == "header_injection"


def test_display_name_with_lf_is_rejected():
    bad = message(**{"from": addr("noreply@example.com", "订单\nBcc: evil@example.org")})
    with pytest.raises(sg.HeaderComposerError) as exc:
        gate().assemble(bad)
    assert exc.value.code == "header_injection"


def test_custom_header_with_nul_is_rejected():
    with pytest.raises(sg.HeaderComposerError) as exc:
        gate().assemble(message(headers=[["X-Trace", "a\x00b"]]))
    assert exc.value.code == "header_injection"


def test_address_with_crlf_is_injection():
    bad = message(to=[addr("alice@example.com\r\nBcc: evil@example.org", "Alice")])
    with pytest.raises(sg.HeaderComposerError) as exc:
        gate().assemble(bad)
    assert exc.value.code == "header_injection"


def test_address_without_at_is_rejected():
    with pytest.raises(sg.HeaderComposerError) as exc:
        gate().assemble(message(to=[addr("alice.example.com", "Alice")]))
    assert exc.value.code == "bad_address"


def test_address_with_space_is_rejected():
    with pytest.raises(sg.HeaderComposerError) as exc:
        gate().assemble(message(to=[addr("ali ce@example.com", "Alice")]))
    assert exc.value.code == "bad_address"


def test_empty_subject_is_rejected():
    with pytest.raises(sg.HeaderComposerError) as exc:
        gate().assemble(message(subject="   "))
    assert exc.value.code == "empty_subject"


def test_recipient_limit_is_enforced():
    to = [addr("a@example.com"), addr("b@example.com")]
    cc = [addr("c@example.com")]
    with pytest.raises(sg.HeaderComposerError) as exc:
        gate(max_recipients=2).assemble(message(to=to, cc=cc))
    assert exc.value.code == "too_many_recipients"


def test_duplicate_recipient_is_rejected():
    cc = [addr("ALICE@example.com", "Alice clone")]
    with pytest.raises(sg.HeaderComposerError) as exc:
        gate().assemble(message(cc=cc))
    assert exc.value.code == "duplicate_recipient"


def test_bad_custom_header_name_is_rejected():
    with pytest.raises(sg.HeaderComposerError) as exc:
        gate().assemble(message(headers=[["X Bad", "v"]]))
    assert exc.value.code == "bad_header_name"


def test_reserved_header_override_is_rejected():
    with pytest.raises(sg.HeaderComposerError) as exc:
        gate().assemble(message(headers=[["Subject", "replaced"]]))
    assert exc.value.code == "reserved_header"


def test_bcc_is_not_rendered_but_is_in_envelope():
    out = gate().assemble(message())
    assert "audit@example.com" not in out["rendered"]
    assert "audit@example.com" in out["envelope_rcpt"]
    assert "Bcc:" not in out["rendered"]


def test_body_with_nul_is_rejected():
    with pytest.raises(sg.HeaderComposerError) as exc:
        gate().assemble(message(body="ok\x00bad"))
    assert exc.value.code == "bad_body"


def test_concurrent_assembly_is_counted():
    g = gate()
    problems = []
    rendered = []

    def worker():
        try:
            for _ in range(3):
                rendered.append(g.assemble(message())["rendered"])
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert len(rendered) == 12
    snap = g.audit()
    assert snap["assembled"] == 12
    snap["assembled"] = 0
    assert g.audit()["assembled"] == 12
