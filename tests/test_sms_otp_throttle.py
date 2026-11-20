import threading

import pytest

import sms_otp_throttle as st


def throttle(**kw):
    base = {
        "per_phone": 3,
        "per_ip": 10,
        "global_limit": 100,
        "window": 3600,
        "cooldown": 0,
        "daily_cap": 100,
    }
    base.update(kw)
    return st.SmsOtpThrottle(**base)


def test_first_request_is_allowed_and_normalized():
    out = throttle().request(" +1 (380) 013-8000 ", "10.0.0.1", now=0)
    assert out["allowed"] is True
    assert out["phone"] == "+13800138000"


def test_cooldown_blocks_immediate_retry():
    t = throttle(cooldown=60)
    t.request("+13800138000", "10.0.0.1", now=0)
    with pytest.raises(st.SmsThrottleError) as exc:
        t.request("+13800138000", "10.0.0.2", now=5)
    assert exc.value.code == "cooldown"
    assert exc.value.retry_after == 55


def test_request_after_cooldown_is_allowed():
    t = throttle(cooldown=60)
    t.request("+13800138000", "10.0.0.1", now=0)
    assert t.request("+13800138000", "10.0.0.2", now=60)["allowed"] is True


def test_per_phone_window_limit():
    t = throttle(per_phone=2, cooldown=0)
    t.request("+13800138000", "10.0.0.1", now=0)
    t.request("+13800138000", "10.0.0.2", now=10)
    with pytest.raises(st.SmsThrottleError) as exc:
        t.request("+13800138000", "10.0.0.3", now=20)
    assert exc.value.code == "phone_limit"
    assert exc.value.retry_after == 3580


def test_per_ip_window_limit():
    t = throttle(per_ip=2, per_phone=99)
    t.request("+13800138001", "10.0.0.9", now=0)
    t.request("+13800138002", "10.0.0.9", now=5)
    with pytest.raises(st.SmsThrottleError) as exc:
        t.request("+13800138003", "10.0.0.9", now=10)
    assert exc.value.code == "ip_limit"


def test_global_limit():
    t = throttle(global_limit=2, per_phone=99, per_ip=99)
    t.request("+13800138001", "10.0.0.1", now=0)
    t.request("+13800138002", "10.0.0.2", now=1)
    with pytest.raises(st.SmsThrottleError) as exc:
        t.request("+13800138003", "10.0.0.3", now=2)
    assert exc.value.code == "global_limit"


def test_daily_cap_across_windows():
    t = throttle(daily_cap=1, window=60, cooldown=0)
    t.request("+13800138000", "10.0.0.1", now=0)
    with pytest.raises(st.SmsThrottleError) as exc:
        t.request("+13800138000", "10.0.0.1", now=100)
    assert exc.value.code == "daily_cap"


def test_blocked_prefix_is_rejected():
    t = throttle(blocked_prefixes=("+1900",))
    with pytest.raises(st.SmsThrottleError) as exc:
        t.request("+19005550100", "10.0.0.1", now=0)
    assert exc.value.code == "blocked_number"


def test_invalid_phone_is_an_argument_error():
    with pytest.raises(ValueError):
        throttle().request("+abc123", "10.0.0.1", now=0)
    with pytest.raises(ValueError):
        throttle().request("+123", "10.0.0.1", now=0)


def test_empty_ip_is_an_argument_error():
    with pytest.raises(ValueError):
        throttle().request("+13800138000", "", now=0)


def test_retry_after_is_positive_integer():
    t = throttle(per_phone=1, window=100, cooldown=0)
    t.request("+13800138000", "10.0.0.1", now=0)
    with pytest.raises(st.SmsThrottleError) as exc:
        t.request("+13800138000", "10.0.0.1", now=30)
    assert isinstance(exc.value.retry_after, int)
    assert exc.value.retry_after == 70


def test_sliding_window_releases_old_entries():
    t = throttle(per_phone=2, window=100, cooldown=0)
    t.request("+13800138000", "10.0.0.1", now=0)
    t.request("+13800138000", "10.0.0.1", now=50)
    assert t.request("+13800138000", "10.0.0.1", now=101)["allowed"] is True


def test_snapshot_is_detached_from_limit_table():
    t = throttle()
    t.request("+13800138000", "10.0.0.1", now=0)
    snap = t.snapshot()
    snap["phones"].clear()
    assert t.snapshot()["phones"]


def test_concurrent_requests_have_one_winner():
    t = throttle(per_phone=1, cooldown=0)
    outcomes = []

    def worker():
        try:
            t.request("+13800138000", "10.0.0.1", now=0)
            outcomes.append(True)
        except st.SmsThrottleError:
            outcomes.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t2 in threads:
        t2.start()
    for t2 in threads:
        t2.join()
    assert outcomes.count(True) == 1


def test_clock_regression_is_rejected():
    t = throttle()
    t.request("+13800138000", "10.0.0.1", now=100)
    with pytest.raises(st.SmsThrottleError) as exc:
        t.request("+13800138001", "10.0.0.2", now=50)
    assert exc.value.code == "clock_regression"
