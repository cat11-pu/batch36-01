import re
from urllib.parse import parse_qs, urlparse

import pytest

import frontchannel_logout as fl

ISSUER = "https://idp.example.com"
CLIENTS = [
    {"client_id": "crm", "logout_uri": "https://crm.example.com/sso/logout?tenant=acme", "origins": ["idp.example.com"]},
    {"client_id": "wiki", "logout_uri": "https://wiki.example.com/logout", "origins": ["idp.example.com"]},
]


def hub(clients=None):
    return fl.FrontChannelLogoutHub(ISSUER, clients if clients is not None else CLIENTS)


def opened(h, ttl=600):
    return h.open_session("sess-1", "alice", ["crm", "wiki"], now=0, ttl=ttl)


def test_plain_http_logout_uri_is_rejected():
    bad = [{"client_id": "crm", "logout_uri": "http://crm.example.com/logout", "origins": ["idp.example.com"]}]
    with pytest.raises(ValueError):
        hub(bad)


def test_logout_uri_with_fragment_is_rejected():
    bad = [{"client_id": "crm", "logout_uri": "https://crm.example.com/logout#done", "origins": ["idp.example.com"]}]
    with pytest.raises(ValueError):
        hub(bad)


def test_duplicate_client_and_wildcard_origin_are_rejected():
    with pytest.raises(ValueError):
        hub(CLIENTS + [{"client_id": "crm", "logout_uri": "https://other.example.com/x", "origins": ["idp.example.com"]}])
    with pytest.raises(ValueError):
        hub([{"client_id": "crm", "logout_uri": "https://crm.example.com/logout", "origins": ["*.example.com"]}])


def test_open_session_validates_inputs():
    with pytest.raises(ValueError):
        hub().open_session("sess-1", "", ["crm"], now=0)
    with pytest.raises(ValueError):
        hub().open_session("", "alice", ["crm"], now=0)
    with pytest.raises(ValueError):
        hub().open_session("sess-1", "alice", ["ghost"], now=0)


def test_open_session_issues_distinct_long_sids():
    sess = opened(hub())
    assert sess["expires_at"] == 600
    sids = [b["sid"] for b in sess["bindings"]]
    assert len(sids) == 2
    assert len(set(sids)) == 2
    for sid in sids:
        assert re.fullmatch(r"[0-9a-f]{32,}", sid)


def test_build_frames_covers_every_client():
    h = hub()
    opened(h)
    out = h.build_frames("sess-1", now=1)
    assert out["issuer"] == ISSUER
    assert sorted(f["client_id"] for f in out["frames"]) == ["crm", "wiki"]
    urls = {f["client_id"]: f["url"] for f in out["frames"]}
    assert urls["crm"].startswith("https://crm.example.com/sso/logout?")
    assert urls["wiki"].startswith("https://wiki.example.com/logout?")
    for url in urls.values():
        assert "iss=" in url
        assert "sid=" in url


def test_frames_keep_query_and_rotate_nonce():
    h = hub()
    opened(h)
    one = h.build_frames("sess-1", now=1)
    two = h.build_frames("sess-1", now=2)
    crm_one = [f for f in one["frames"] if f["client_id"] == "crm"][0]
    crm_two = [f for f in two["frames"] if f["client_id"] == "crm"][0]
    assert parse_qs(urlparse(crm_one["url"]).query)["tenant"] == ["acme"]
    assert parse_qs(urlparse(crm_one["url"]).query)["nonce"] != parse_qs(urlparse(crm_two["url"]).query)["nonce"]
    assert parse_qs(urlparse(crm_one["url"]).query)["sid"] == parse_qs(urlparse(crm_two["url"]).query)["sid"]


def test_unknown_session_cannot_build_frames():
    with pytest.raises(fl.LogoutError) as exc:
        hub().build_frames("ghost", now=1)
    assert exc.value.code == "unknown_session"


def test_expired_session_cannot_build_or_handle():
    h = hub()
    sess = opened(h, ttl=100)
    sid = sess["bindings"][0]["sid"]
    with pytest.raises(fl.LogoutError) as exc:
        h.build_frames("sess-1", now=101)
    assert exc.value.code == "expired"
    with pytest.raises(fl.LogoutError) as exc:
        h.handle_frame({"iss": ISSUER, "sid": sid}, "https://idp.example.com/frame", now=101)
    assert exc.value.code == "expired"


def test_valid_frame_logs_out_only_that_client():
    h = hub()
    sess = opened(h)
    sids = {b["client_id"]: b["sid"] for b in sess["bindings"]}
    first = h.handle_frame({"iss": ISSUER, "sid": sids["crm"]}, "https://idp.example.com/frame", now=1)
    assert first["client_id"] == "crm"
    assert first["status"] == "logged_out"
    assert first["remaining"] == 1
    second = h.handle_frame({"iss": ISSUER, "sid": sids["wiki"]}, "https://idp.example.com/frame", now=2)
    assert second["status"] == "logged_out"
    assert second["remaining"] == 0


def test_unknown_issuer_is_rejected():
    h = hub()
    sess = opened(h)
    sid = sess["bindings"][0]["sid"]
    with pytest.raises(fl.LogoutError) as exc:
        h.handle_frame({"iss": "https://evil.example.com", "sid": sid}, "https://idp.example.com/frame", now=1)
    assert exc.value.code == "bad_issuer"


def test_missing_sid_is_rejected():
    with pytest.raises(ValueError):
        hub().handle_frame({"iss": ISSUER}, "https://idp.example.com/frame", now=1)


def test_unlisted_referer_is_rejected():
    h = hub()
    sess = opened(h)
    sid = sess["bindings"][0]["sid"]
    with pytest.raises(fl.LogoutError) as exc:
        h.handle_frame({"iss": ISSUER, "sid": sid}, "https://evil.example.com/frame", now=1)
    assert exc.value.code == "bad_referer"


def test_replayed_frame_reports_already_logged_out():
    h = hub()
    sess = opened(h)
    sid = sess["bindings"][0]["sid"]
    params = {"iss": ISSUER, "sid": sid}
    h.handle_frame(params, "https://idp.example.com/frame", now=1)
    again = h.handle_frame(params, "https://idp.example.com/frame", now=2)
    assert again["status"] == "already_logged_out"


def test_global_logout_clears_all_bindings():
    h = hub()
    sess = opened(h)
    sids = {b["client_id"]: b["sid"] for b in sess["bindings"]}
    assert h.logout_session("sess-1", now=1)["cleared"] == 2
    for sid in sids.values():
        with pytest.raises(fl.LogoutError) as exc:
            h.handle_frame({"iss": ISSUER, "sid": sid}, "https://idp.example.com/frame", now=2)
        assert exc.value.code == "unknown_session"
    with pytest.raises(fl.LogoutError) as exc:
        h.logout_session("sess-1", now=3)
    assert exc.value.code == "unknown_session"
