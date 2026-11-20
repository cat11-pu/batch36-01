import threading

import pytest

import postmessage_receiver as pm

ORIGINS = ["https://app.example.com", "https://preview.example.com"]
SOURCES = ["frame-1", "frame-2"]
CHANNELS = {"frame-1": "ch-1", "frame-2": "ch-2"}
NONCE = "N" * 22


def gateway(**kw):
    base = {
        "allowed_origins": ORIGINS,
        "allowed_sources": SOURCES,
        "allowed_types": ("ping", "resize"),
        "max_bytes": 4096,
        "reuse_window": 60,
        "max_sequence_gap": 1,
        "channels": CHANNELS,
    }
    base.update(kw)
    return pm.PostMessageReceiver(**base)


def event(**over):
    e = {
        "origin": "https://app.example.com",
        "source": "frame-1",
        "target_origin": "https://app.example.com",
        "channel": "ch-1",
        "type": "resize",
        "nonce": NONCE,
        "sequence": 1,
        "data": {"width": 800},
    }
    e.update(over)
    return e


def test_valid_message_is_accepted():
    out = gateway().accept(event())
    assert out["type"] == "resize"
    assert out["sequence"] == 1
    assert out["source"] == "frame-1"


def test_unlisted_origin_is_rejected():
    with pytest.raises(pm.MessageReceiverError) as exc:
        gateway().accept(event(origin="https://evil.example.net"))
    assert exc.value.code == "origin_not_allowed"


def test_null_origin_is_rejected():
    with pytest.raises(pm.MessageReceiverError) as exc:
        gateway().accept(event(origin="null"))
    assert exc.value.code == "null_origin"


def test_missing_origin_is_rejected():
    with pytest.raises(pm.MessageReceiverError) as exc:
        gateway().accept(event(origin=None))
    assert exc.value.code == "origin_missing"


def test_wildcard_target_origin_is_rejected():
    with pytest.raises(pm.MessageReceiverError) as exc:
        gateway().accept(event(target_origin="*"))
    assert exc.value.code == "target_wildcard"


def test_unregistered_source_is_rejected():
    with pytest.raises(pm.MessageReceiverError) as exc:
        gateway().accept(event(source="frame-9"))
    assert exc.value.code == "unknown_source"


def test_non_dict_payload_is_rejected():
    with pytest.raises(pm.MessageReceiverError) as exc:
        gateway().accept(event(data="not-a-dict"))
    assert exc.value.code == "bad_payload"


def test_prototype_key_is_rejected():
    with pytest.raises(pm.MessageReceiverError) as exc:
        gateway().accept(event(data={"a": {"__proto__": {"x": 1}}}))
    assert exc.value.code == "dangerous_key"


def test_oversized_payload_is_rejected():
    with pytest.raises(pm.MessageReceiverError) as exc:
        gateway().accept(event(data={"text": "x" * 5000}))
    assert exc.value.code == "payload_too_large"


def test_unknown_message_type_is_rejected():
    with pytest.raises(pm.MessageReceiverError) as exc:
        gateway().accept(event(type="eval"))
    assert exc.value.code == "bad_type"


def test_channel_mismatch_is_rejected():
    with pytest.raises(pm.MessageReceiverError) as exc:
        gateway().accept(event(channel="ch-2"))
    assert exc.value.code == "channel_mismatch"


def test_missing_nonce_is_rejected():
    with pytest.raises(pm.MessageReceiverError) as exc:
        gateway().accept(event(nonce=""))
    assert exc.value.code == "nonce_missing"


def test_replayed_nonce_is_rejected():
    g = gateway()
    g.accept(event())
    with pytest.raises(pm.MessageReceiverError) as exc:
        g.accept(event(sequence=2))
    assert exc.value.code == "replay"


def test_sequence_gap_is_rejected():
    g = gateway()
    g.accept(event())
    with pytest.raises(pm.MessageReceiverError) as exc:
        g.accept(event(sequence=3, nonce="M" * 22))
    assert exc.value.code == "sequence_gap"


def test_concurrent_accepts_are_counted_in_isolation():
    sources = ["f%d" % i for i in range(8)]
    channels = {s: "ch-" + s for s in sources}
    g = gateway(allowed_sources=sources, channels=channels, max_sequence_gap=8)
    problems = []
    results = []

    def worker(i):
        try:
            results.append(
                g.accept(
                    event(
                        source=sources[i],
                        channel=channels[sources[i]],
                        nonce=("N" * 10) + str(i).zfill(12),
                        sequence=1,
                    )
                )["source"]
            )
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert len(results) == 8
    snap = g.snapshot()
    assert snap["accepted"] == 8
    snap["accepted"] = 0
    assert g.snapshot()["accepted"] == 8
