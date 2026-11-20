import pytest

import statement_xml_intake as si

HEAD = '<?xml version="1.0" encoding="utf-8"?>'


def doc(lines, id="000000000042", currency="CNY"):
    body = "".join(lines)
    return (
        HEAD
        + '<statement xmlns="urn:acme:statement:v2" id="'
        + id
        + '" currency="'
        + currency
        + '"><header><vendor>Acme</vendor></header><lines>'
        + body
        + "</lines></statement>"
    ).encode("utf-8")


def line(sku, qty="2", amount="12.34"):
    return "<line><sku>" + sku + "</sku><qty>" + qty + "</qty><amount>" + amount + "</amount></line>"


def test_valid_statement_is_parsed():
    raw = doc([line("A-1", "2", "12.34"), line("B-2", "1", "0.66")])
    out = si.StatementXmlIntake().parse(raw)
    assert out["id"] == "000000000042"
    assert out["currency"] == "CNY"
    assert out["lines"] == [
        {"sku": "A-1", "qty": 2, "amount_cents": 1234},
        {"sku": "B-2", "qty": 1, "amount_cents": 66},
    ]
    assert out["total_cents"] == 1300


def test_doctype_is_rejected():
    raw = b'<?xml version="1.0"?><!DOCTYPE statement><statement/>'
    with pytest.raises(si.XmlIntakeError) as exc:
        si.StatementXmlIntake().parse(raw)
    assert exc.value.code == "doctype_forbidden"


def test_entity_declaration_is_rejected():
    raw = b'<!ENTITY xxe SYSTEM "file:///etc/passwd">'
    with pytest.raises(si.XmlIntakeError) as exc:
        si.StatementXmlIntake().parse(raw)
    assert exc.value.code == "entity_forbidden"


def test_unknown_entity_reference_is_rejected():
    with pytest.raises(si.XmlIntakeError) as exc:
        si.StatementXmlIntake().parse(doc([line("&xxe;")]))
    assert exc.value.code == "entity_reference"


def test_stylesheet_instruction_is_rejected():
    raw = b'<?xml-stylesheet href="x"?>'
    with pytest.raises(si.XmlIntakeError) as exc:
        si.StatementXmlIntake().parse(raw)
    assert exc.value.code == "stylesheet_forbidden"


def test_invalid_utf8_is_rejected():
    with pytest.raises(si.XmlIntakeError) as exc:
        si.StatementXmlIntake().parse(b"\x80\x81\x82")
    assert exc.value.code == "bad_encoding"


def test_declared_encoding_must_be_utf8():
    raw = doc([line("A-1")]).replace(b'encoding="utf-8"', b'encoding="iso-8859-1"')
    with pytest.raises(si.XmlIntakeError) as exc:
        si.StatementXmlIntake().parse(raw)
    assert exc.value.code == "bad_encoding"


def test_size_limit_is_enforced():
    with pytest.raises(si.XmlIntakeError) as exc:
        si.StatementXmlIntake(max_bytes=50).parse(doc([line("A-1")]))
    assert exc.value.code == "too_large"


def test_missing_namespace_is_rejected():
    raw = doc([line("A-1")]).replace(b' xmlns="urn:acme:statement:v2"', b"")
    with pytest.raises(si.XmlIntakeError) as exc:
        si.StatementXmlIntake().parse(raw)
    assert exc.value.code == "bad_namespace"


def test_unknown_element_is_rejected():
    raw = doc([line("A-1")]).replace(b"</statement>", b"<extra/></statement>")
    with pytest.raises(si.XmlIntakeError) as exc:
        si.StatementXmlIntake().parse(raw)
    assert exc.value.code == "unexpected_element"


def test_duplicate_sku_is_rejected():
    raw = doc([line("A-1"), line("A-1", "1", "1.00")])
    with pytest.raises(si.XmlIntakeError) as exc:
        si.StatementXmlIntake().parse(raw)
    assert exc.value.code == "duplicate_sku"


def test_bad_amount_format_is_rejected():
    with pytest.raises(si.XmlIntakeError) as exc:
        si.StatementXmlIntake().parse(doc([line("A-1", "1", "12.3")]))
    assert exc.value.code == "bad_structure"


def test_line_count_limit_is_enforced():
    raw = doc([line("A-1"), line("B-2"), line("C-3")])
    with pytest.raises(si.XmlIntakeError) as exc:
        si.StatementXmlIntake(max_items=2).parse(raw)
    assert exc.value.code == "too_many_items"


def test_byte_order_mark_is_rejected():
    raw = b"\xef\xbb\xbf" + doc([line("A-1")])
    with pytest.raises(si.XmlIntakeError) as exc:
        si.StatementXmlIntake().parse(raw)
    assert exc.value.code == "bom_not_allowed"


def test_snapshot_counts_and_copy():
    p = si.StatementXmlIntake()
    p.parse(doc([line("A-1")]))
    with pytest.raises(si.XmlIntakeError):
        p.parse(b"<!DOCTYPE x>")
    snap = p.snapshot()
    assert snap["parsed"] == 1
    assert snap["rejected"] == 1
    snap["parsed"] = 0
    assert p.snapshot()["parsed"] == 1
