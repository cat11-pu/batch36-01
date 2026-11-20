import re

import pytest

import oauth_device_flow as od

SCOPES = {"openid", "profile", "device"}


def flow():
    return od.DeviceAuthorization({"tv-app": {"name": "TV"}}, SCOPES, interval=5, ttl=600)


def test_start_returns_device_and_user_codes():
    grant = flow().start("tv-app", "openid device", now=0)
    assert re.fullmatch(r"[A-Z2-9]{4}-[A-Z2-9]{4}", grant["user_code"])
    assert len(grant["device_code"]) >= 32
    assert grant["expires_at"] == 600
    assert grant["interval"] == 5


def test_unknown_client_is_rejected():
    with pytest.raises(od.DeviceFlowError) as exc:
        flow().start("ghost", "openid", now=0)
    assert exc.value.code == "invalid_client"


def test_scope_outside_allowlist_is_rejected():
    with pytest.raises(od.DeviceFlowError) as exc:
        flow().start("tv-app", "openid admin", now=0)
    assert exc.value.code == "invalid_scope"


def test_unknown_user_code_is_rejected():
    with pytest.raises(od.DeviceFlowError) as exc:
        flow().approve("ZZZZ-ZZZZ", "alice", now=0)
    assert exc.value.code == "invalid_user_code"


def test_poll_before_approval_returns_pending():
    f = flow()
    grant = f.start("tv-app", "openid", now=0)
    assert f.poll(grant["device_code"], now=5) == {"status": "authorization_pending"}


def test_poll_after_approval_returns_token():
    f = flow()
    grant = f.start("tv-app", "openid", now=0)
    f.approve(grant["user_code"], "alice", now=10)
    res = f.poll(grant["device_code"], now=10)
    assert res["status"] == "approved"
    assert res["subject"] == "alice"
    assert re.fullmatch(r"[0-9a-f]{64}", res["access_token"])


def test_device_code_can_only_be_redeemed_once():
    f = flow()
    grant = f.start("tv-app", "openid", now=0)
    f.approve(grant["user_code"], "alice", now=10)
    f.poll(grant["device_code"], now=10)
    with pytest.raises(od.DeviceFlowError) as exc:
        f.poll(grant["device_code"], now=15)
    assert exc.value.code == "invalid_grant"


def test_expired_flow_cannot_be_polled():
    f = flow()
    grant = f.start("tv-app", "openid", now=0)
    with pytest.raises(od.DeviceFlowError) as exc:
        f.poll(grant["device_code"], now=601)
    assert exc.value.code == "expired_token"


def test_expired_flow_cannot_be_approved():
    f = flow()
    grant = f.start("tv-app", "openid", now=0)
    with pytest.raises(od.DeviceFlowError) as exc:
        f.approve(grant["user_code"], "alice", now=601)
    assert exc.value.code == "expired_token"


def test_too_fast_poll_returns_slow_down():
    f = flow()
    grant = f.start("tv-app", "openid", now=0)
    res = f.poll(grant["device_code"], now=1)
    assert res["status"] == "slow_down"
    assert res["interval"] == 10


def test_repeated_fast_poll_extends_the_interval():
    f = flow()
    grant = f.start("tv-app", "openid", now=0)
    f.poll(grant["device_code"], now=1)
    res = f.poll(grant["device_code"], now=6)
    assert res["status"] == "slow_down"
    assert res["interval"] == 15


def test_poll_is_allowed_after_the_cooldown():
    f = flow()
    grant = f.start("tv-app", "openid", now=0)
    f.poll(grant["device_code"], now=1)
    assert f.poll(grant["device_code"], now=11) == {"status": "authorization_pending"}


def test_user_code_is_case_insensitive():
    f = flow()
    grant = f.start("tv-app", "openid", now=0)
    f.approve(grant["user_code"].lower(), "alice", now=10)
    res = f.poll(grant["device_code"], now=10)
    assert res["subject"] == "alice"


def test_duplicate_approval_is_rejected():
    f = flow()
    grant = f.start("tv-app", "openid", now=0)
    f.approve(grant["user_code"], "alice", now=10)
    with pytest.raises(od.DeviceFlowError) as exc:
        f.approve(grant["user_code"], "bob", now=11)
    assert exc.value.code == "already_used"
    assert f.poll(grant["device_code"], now=15)["subject"] == "alice"


def test_unknown_device_code_is_rejected():
    with pytest.raises(od.DeviceFlowError) as exc:
        flow().poll("deadbeef", now=5)
    assert exc.value.code == "invalid_grant"
