import threading
from urllib.parse import parse_qs, urlparse

import pytest

import magic_link_dispenser as md

BASE = "https://login.example.com/magic"
CALLBACK = "https://app.example.com/welcome"


def dispenser():
    return md.MagicLinkDispenser(BASE, [CALLBACK], ttl=900, max_attempts=5)


def token_of(url):
    return parse_qs(urlparse(url).query)["token"][0]


def issued(d, email="user@example.com", binding="bind-1", now=0):
    rec = d.issue(email, CALLBACK, binding, now=now)
    return token_of(rec["url"]), rec


def test_issue_returns_link_with_expiry():
    token, rec = issued(dispenser())
    assert rec["expires_at"] == 900
    assert rec["url"].startswith(BASE)
    assert token


def test_email_is_normalized_for_subject():
    d = dispenser()
    token, _ = issued(d, email="  User@Example.COM  ")
    out = d.consume(token, "bind-1", now=1)
    assert out["email"] == "user@example.com"


def test_valid_consume_returns_redirect():
    d = dispenser()
    token, _ = issued(d)
    out = d.consume(token, "bind-1", now=10)
    assert out["email"] == "user@example.com"
    assert out["redirect_uri"] == CALLBACK


def test_token_cannot_be_consumed_twice():
    d = dispenser()
    token, _ = issued(d)
    d.consume(token, "bind-1", now=1)
    with pytest.raises(md.MagicLinkError) as exc:
        d.consume(token, "bind-1", now=2)
    assert exc.value.code == "token_used"


def test_expired_token_is_rejected():
    d = dispenser()
    token, _ = issued(d)
    with pytest.raises(md.MagicLinkError) as exc:
        d.consume(token, "bind-1", now=901)
    assert exc.value.code == "token_expired"


def test_binding_mismatch_is_rejected():
    d = dispenser()
    token, _ = issued(d)
    with pytest.raises(md.MagicLinkError) as exc:
        d.consume(token, "bind-2", now=1)
    assert exc.value.code == "binding_mismatch"


def test_unknown_token_is_rejected():
    with pytest.raises(md.MagicLinkError) as exc:
        dispenser().consume("nope", "bind-1", now=1)
    assert exc.value.code == "invalid_token"


def test_redirect_outside_allowlist_is_rejected():
    with pytest.raises(md.MagicLinkError) as exc:
        dispenser().issue("user@example.com", "https://evil.example.net/cb", "bind-1", now=0)
    assert exc.value.code == "redirect_not_allowed"


def test_redirect_suffix_spoofing_is_rejected():
    with pytest.raises(md.MagicLinkError) as exc:
        dispenser().issue("user@example.com", "https://app.example.com.evil.net/cb", "bind-1", now=0)
    assert exc.value.code == "redirect_not_allowed"


def test_new_issue_invalidates_previous_link():
    d = dispenser()
    old, _ = issued(d, now=0)
    new, _ = issued(d, now=10)
    with pytest.raises(md.MagicLinkError) as exc:
        d.consume(old, "bind-1", now=11)
    assert exc.value.code == "token_used"
    assert d.consume(new, "bind-1", now=12)["email"] == "user@example.com"


def test_invalidate_removes_all_links_for_email():
    d = dispenser()
    token, _ = issued(d)
    d.invalidate("USER@example.com")
    with pytest.raises(md.MagicLinkError) as exc:
        d.consume(token, "bind-1", now=1)
    assert exc.value.code == "token_used"


def test_attempt_limit_locks_email():
    d = dispenser()
    token, _ = issued(d)
    for _ in range(5):
        with pytest.raises(md.MagicLinkError):
            d.consume(token, "wrong-bind", now=1)
    with pytest.raises(md.MagicLinkError) as exc:
        d.consume(token, "bind-1", now=2)
    assert exc.value.code == "locked"


def test_empty_email_is_rejected():
    with pytest.raises(ValueError):
        dispenser().issue("   ", CALLBACK, "bind-1", now=0)


def test_snapshot_has_no_raw_token_and_is_detached():
    d = dispenser()
    token, _ = issued(d)
    snap = d.snapshot()
    assert token not in str(snap)
    snap["links"].clear()
    assert d.consume(token, "bind-1", now=1)["email"] == "user@example.com"


def test_concurrent_consume_has_one_winner():
    d = dispenser()
    token, _ = issued(d)
    outcomes = []

    def worker():
        try:
            d.consume(token, "bind-1", now=1)
            outcomes.append(True)
        except md.MagicLinkError:
            outcomes.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count(True) == 1
