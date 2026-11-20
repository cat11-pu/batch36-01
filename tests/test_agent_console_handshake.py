import threading

import pytest

import agent_console_handshake as ah

ORIGINS = {
    "acme": {"origins": ["https://console.acme.com"], "protocols": ["reports.v2", "reports.v1"]},
    "globex": {"origins": ["https://desk.globex.com"], "protocols": ["reports.v2"]},
}
TICKETS = [
    {"tenant": "acme", "value": "t-1", "expires": 100},
    {"tenant": "acme", "value": "t-2", "expires": 50},
    {"tenant": "globex", "value": "t-3", "expires": 100},
]


def gate():
    return ah.AgentConsoleHandshake(ORIGINS, TICKETS)


def request(**over):
    r = {
        "path": "/ws/agent",
        "headers": {
            "origin": ["https://console.acme.com"],
            "host": ["console.acme.com"],
            "upgrade": ["websocket"],
            "connection": ["keep-alive, Upgrade"],
            "sec-websocket-version": ["13"],
            "sec-websocket-key": ["dGhlIHNhbXBsZSBub25jZQ=="],
            "x-console-ticket": ["t-1"],
        },
        "subprotocols": ["reports.v2", "reports.v1"],
    }
    r.update(over)
    return r


def test_valid_handshake_is_accepted():
    g = gate()
    out = g.accept("acme", request(), now=10)
    assert out["tenant"] == "acme"
    assert out["origin"] == "https://console.acme.com"
    assert out["protocol"] == "reports.v2"
    snap = g.snapshot()
    assert snap["accepted"] == 1
    assert snap["rejected"] == 0


def test_origin_outside_allowlist_is_rejected():
    bad = request(headers={"origin": ["https://evil.example.net"], "host": ["console.acme.com"],
                            "upgrade": ["websocket"], "connection": ["Upgrade"],
                            "sec-websocket-version": ["13"],
                            "sec-websocket-key": ["dGhlIHNhbXBsZSBub25jZQ=="],
                            "x-console-ticket": ["t-1"]})
    with pytest.raises(ah.HandshakeError) as exc:
        gate().accept("acme", bad, now=10)
    assert exc.value.code == "origin_not_allowed"


def test_null_origin_is_rejected():
    bad = request()
    bad["headers"]["origin"] = ["null"]
    with pytest.raises(ah.HandshakeError) as exc:
        gate().accept("acme", bad, now=10)
    assert exc.value.code == "origin_not_allowed"


def test_origin_with_path_is_rejected():
    bad = request()
    bad["headers"]["origin"] = ["https://console.acme.com/app"]
    with pytest.raises(ah.HandshakeError) as exc:
        gate().accept("acme", bad, now=10)
    assert exc.value.code == "bad_origin"


def test_origin_with_userinfo_is_rejected():
    bad = request()
    bad["headers"]["origin"] = ["https://user@console.acme.com"]
    with pytest.raises(ah.HandshakeError) as exc:
        gate().accept("acme", bad, now=10)
    assert exc.value.code == "bad_origin"


def test_host_mismatch_is_rejected():
    bad = request()
    bad["headers"]["host"] = ["desk.globex.com"]
    with pytest.raises(ah.HandshakeError) as exc:
        gate().accept("acme", bad, now=10)
    assert exc.value.code == "host_mismatch"


def test_wrong_version_is_rejected():
    bad = request()
    bad["headers"]["sec-websocket-version"] = ["8"]
    with pytest.raises(ah.HandshakeError) as exc:
        gate().accept("acme", bad, now=10)
    assert exc.value.code == "bad_version"


def test_bad_connection_key_is_rejected():
    bad = request()
    bad["headers"]["sec-websocket-key"] = ["short"]
    with pytest.raises(ah.HandshakeError) as exc:
        gate().accept("acme", bad, now=10)
    assert exc.value.code == "bad_key"


def test_missing_upgrade_token_is_rejected():
    bad = request()
    bad["headers"]["upgrade"] = ["h2c"]
    with pytest.raises(ah.HandshakeError) as exc:
        gate().accept("acme", bad, now=10)
    assert exc.value.code == "bad_upgrade"


def test_missing_subprotocol_is_rejected():
    bad = request()
    bad["subprotocols"] = []
    with pytest.raises(ah.HandshakeError) as exc:
        gate().accept("acme", bad, now=10)
    assert exc.value.code == "subprotocol_required"


def test_client_protocol_order_wins():
    out = gate().accept("acme", request(subprotocols=["reports.v1", "reports.v2"]), now=10)
    assert out["protocol"] == "reports.v1"


def test_ticket_replay_is_rejected():
    g = gate()
    g.accept("acme", request(), now=10)
    with pytest.raises(ah.HandshakeError) as exc:
        g.accept("acme", request(), now=11)
    assert exc.value.code == "ticket_replayed"


def test_expired_ticket_is_rejected():
    bad = request()
    bad["headers"]["x-console-ticket"] = ["t-2"]
    with pytest.raises(ah.HandshakeError) as exc:
        gate().accept("acme", bad, now=60)
    assert exc.value.code == "ticket_expired"


def test_ticket_from_other_tenant_is_rejected():
    bad = request()
    bad["headers"]["origin"] = ["https://desk.globex.com"]
    bad["headers"]["host"] = ["desk.globex.com"]
    with pytest.raises(ah.HandshakeError) as exc:
        gate().accept("globex", bad, now=10)
    assert exc.value.code == "ticket_unknown"


def test_concurrent_ticket_use_succeeds_once():
    g = gate()
    results = []
    problems = []

    def worker():
        try:
            g.accept("acme", request(), now=10)
            results.append("ok")
        except ah.HandshakeError as exc:
            results.append(exc.code)
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    assert results.count("ok") == 1
    assert results.count("ticket_replayed") == 7
    snap = g.snapshot()
    assert snap["accepted"] == 1
    assert snap["rejected"] == 7
    snap["accepted"] = 0
    assert g.snapshot()["accepted"] == 1
