import pytest

import kerberos_ticket as kt

SERVICES = {"HTTP/app.example.com@EXAMPLE.COM", "ldap/db.example.com@EXAMPLE.COM"}


def guard(max_skew=300, replay_window=600):
    return kt.KerberosTicketGuard("EXAMPLE.COM", SERVICES, max_skew=max_skew, replay_window=replay_window)


def ticket(**over):
    t = {
        "client": "alice@EXAMPLE.COM",
        "server": "HTTP/app.example.com@EXAMPLE.COM",
        "start": 1000,
        "end": 2000,
        "renew_till": 5000,
        "flags": ["forwardable", "renewable"],
        "session_key": "k" * 32,
    }
    t.update(over)
    return t


def authenticator(**over):
    a = {"client": "alice@EXAMPLE.COM", "ctime": 1500, "cusec": 1, "checksum": "c" * 32}
    a.update(over)
    return a


def test_valid_ticket_is_accepted():
    res = guard().validate(ticket(), authenticator(), now=1500)
    assert res["client"] == "alice@EXAMPLE.COM"
    assert res["server"] == "HTTP/app.example.com@EXAMPLE.COM"
    assert res["remaining"] == 500


def test_client_realm_must_match():
    with pytest.raises(kt.KerberosError) as exc:
        guard().validate(ticket(client="alice@OTHER.COM"), authenticator(client="alice@OTHER.COM"), now=1500)
    assert exc.value.code == "wrong_realm"


def test_service_must_be_in_allowlist():
    with pytest.raises(kt.KerberosError) as exc:
        guard().validate(ticket(server="HTTP/other.example.com@EXAMPLE.COM"), authenticator(), now=1500)
    assert exc.value.code == "unknown_service"


def test_service_principal_needs_realm_suffix():
    with pytest.raises(ValueError):
        guard().validate(ticket(server="HTTP/app.example.com"), authenticator(), now=1500)


def test_ticket_not_yet_valid_beyond_skew_is_rejected():
    with pytest.raises(kt.KerberosError) as exc:
        guard().validate(ticket(start=1900), authenticator(), now=1500)
    assert exc.value.code == "not_yet_valid"


def test_ticket_not_yet_valid_within_skew_is_accepted():
    res = guard().validate(ticket(start=1700), authenticator(), now=1500)
    assert res["client"] == "alice@EXAMPLE.COM"


def test_expired_ticket_beyond_skew_is_rejected():
    with pytest.raises(kt.KerberosError) as exc:
        guard().validate(ticket(end=1100), authenticator(), now=1500)
    assert exc.value.code == "expired"


def test_expired_ticket_within_skew_is_accepted():
    res = guard().validate(ticket(end=1300), authenticator(), now=1500)
    assert res["client"] == "alice@EXAMPLE.COM"


def test_stale_authenticator_is_rejected():
    with pytest.raises(kt.KerberosError) as exc:
        guard().validate(ticket(), authenticator(ctime=1100), now=1500)
    assert exc.value.code == "clock_skew"


def test_future_authenticator_is_rejected():
    with pytest.raises(kt.KerberosError) as exc:
        guard().validate(ticket(), authenticator(ctime=1900), now=1500)
    assert exc.value.code == "clock_skew"


def test_authenticator_client_must_match_ticket():
    with pytest.raises(kt.KerberosError) as exc:
        guard().validate(ticket(), authenticator(client="bob@EXAMPLE.COM"), now=1500)
    assert exc.value.code == "client_mismatch"


def test_replayed_authenticator_is_rejected():
    g = guard()
    g.validate(ticket(), authenticator(), now=1500)
    with pytest.raises(kt.KerberosError) as exc:
        g.validate(ticket(), authenticator(), now=1500)
    assert exc.value.code == "replay_detected"


def test_distinct_cusec_is_not_treated_as_replay():
    g = guard()
    g.validate(ticket(), authenticator(cusec=1), now=1500)
    res = g.validate(ticket(), authenticator(cusec=2), now=1500)
    assert res["client"] == "alice@EXAMPLE.COM"


def test_empty_checksum_is_rejected():
    with pytest.raises(kt.KerberosError) as exc:
        guard().validate(ticket(), authenticator(checksum=""), now=1500)
    assert exc.value.code == "bad_checksum"


def test_renew_requires_flag_and_live_window():
    g = guard()
    out = g.renew(ticket(end=1400), now=1500, lifetime=600)
    assert out["start"] == 1500
    assert out["end"] == 2100
    with pytest.raises(kt.KerberosError) as exc:
        g.renew(ticket(end=1400, flags=["forwardable"]), now=1500, lifetime=600)
    assert exc.value.code == "not_renewable"
