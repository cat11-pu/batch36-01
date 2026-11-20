import hashlib
import hmac
import json

import pytest

import draft_snapshot_reader as dr

SECRET = b"draft-secret"
TYPES = {
    "color": lambda v: isinstance(v, str) and v.startswith("#"),
    "point": lambda v: isinstance(v, list) and len(v) == 2,
}


def reader(**kw):
    return dr.DraftSnapshotReader(TYPES, SECRET, **kw)


def seal(value, **over):
    payload = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    return seal_raw(payload, **over)


def seal_raw(payload, **over):
    env = {
        "payload": payload,
        "mac": hmac.new(SECRET, payload.encode("utf-8"), hashlib.sha256).hexdigest(),
    }
    env.update(over)
    return env


def test_plain_snapshot_round_trips():
    value = {"title": "草稿", "items": [1, True, None], "n": 7}
    out = reader().read(seal(value))
    assert out["value"] == value
    assert out["kinds"] == []


def test_extra_envelope_field_is_rejected():
    with pytest.raises(dr.SnapshotError) as exc:
        reader().read(seal({"a": 1}, extra="x"))
    assert exc.value.code == "bad_envelope"


def test_uppercase_mac_is_rejected():
    env = seal({"a": 1})
    env["mac"] = env["mac"].upper()
    with pytest.raises(dr.SnapshotError) as exc:
        reader().read(env)
    assert exc.value.code == "bad_envelope"


def test_wrong_mac_is_rejected():
    with pytest.raises(dr.SnapshotError) as exc:
        reader().read(seal_raw('{"a":1}', mac="0" * 64))
    assert exc.value.code == "bad_signature"


def test_signature_is_checked_before_parsing():
    with pytest.raises(dr.SnapshotError) as exc:
        reader().read(seal_raw("{not json", mac="0" * 64))
    assert exc.value.code == "bad_signature"


def test_duplicate_keys_are_rejected():
    with pytest.raises(dr.SnapshotError) as exc:
        reader().read(seal_raw('{"a":1,"a":2}'))
    assert exc.value.code == "duplicate_key"


def test_non_finite_number_is_rejected():
    with pytest.raises(dr.SnapshotError) as exc:
        reader().read(seal_raw('{"a":NaN}'))
    assert exc.value.code == "non_finite"


def test_underscore_key_is_rejected():
    with pytest.raises(dr.SnapshotError) as exc:
        reader().read(seal_raw('{"__class__":1}'))
    assert exc.value.code == "forbidden_key"


def test_unknown_tag_is_rejected():
    with pytest.raises(dr.SnapshotError) as exc:
        reader().read(seal({"c": {"kind": "widget", "value": 1}}))
    assert exc.value.code == "unknown_type"


def test_invalid_tag_value_is_rejected():
    with pytest.raises(dr.SnapshotError) as exc:
        reader().read(seal({"c": {"kind": "color", "value": "red"}}))
    assert exc.value.code == "invalid_value"


def test_tag_with_extra_key_is_rejected():
    with pytest.raises(dr.SnapshotError) as exc:
        reader().read(seal({"c": {"kind": "color", "value": "#fff", "x": 1}}))
    assert exc.value.code == "bad_tag"


def test_depth_limit_is_enforced():
    with pytest.raises(dr.SnapshotError) as exc:
        reader(max_depth=2).read(seal({"a": {"b": {"c": 1}}}))
    assert exc.value.code == "too_deep"


def test_payload_size_limit_is_enforced():
    with pytest.raises(dr.SnapshotError) as exc:
        reader(max_bytes=64).read(seal({"text": "x" * 200}))
    assert exc.value.code == "payload_too_large"


def test_integer_range_is_enforced():
    with pytest.raises(dr.SnapshotError) as exc:
        reader().read(seal_raw('{"n":9223372036854775808}'))
    assert exc.value.code == "number_out_of_range"


def test_tag_conversion_and_snapshot_counts():
    r = reader()
    out = r.read(seal({"c": {"kind": "color", "value": "#0f0"}}))
    assert out["value"] == {"c": ("color", "#0f0")}
    assert out["kinds"] == ["color"]
    r.read(seal({"x": 1}))
    with pytest.raises(dr.SnapshotError):
        r.read(seal_raw('{"a":NaN}'))
    snap = r.snapshot()
    assert snap["reads"] == 2
    assert snap["rejected"] == 1
    snap["reads"] = 0
    assert r.snapshot()["reads"] == 2
