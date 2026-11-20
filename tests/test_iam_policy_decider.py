import pytest

import iam_policy_decider as ip

BUCKET = "arn:aws:s3:::bucket/data.txt"


def doc(statements):
    return {"Version": "2012-10-17", "Statement": statements}


def allow(action, resource, **extra):
    value = {"Effect": "Allow", "Action": action, "Resource": resource}
    value.update(extra)
    return value


def deny(action, resource, **extra):
    value = {"Effect": "Deny", "Action": action, "Resource": resource}
    value.update(extra)
    return value


def request(**over):
    value = {
        "principal": "arn:aws:iam::111:user/alice",
        "account": "111",
        "action": "s3:GetObject",
        "resource": BUCKET,
        "context": {},
    }
    value.update(over)
    return value


def decider(identity, resource=None, **kw):
    return ip.IamDecider(identity, resource or doc([]), **kw)


def test_identity_allow_is_enough_same_account():
    out = decider(doc([allow("s3:GetObject", "arn:aws:s3:::bucket/*")])).decide(request())
    assert out["allowed"] is True
    assert out["reason"] == "identity_allow"


def test_unrelated_action_has_no_allow():
    out = decider(doc([allow("s3:GetObject", "arn:aws:s3:::bucket/*")])).decide(
        request(action="s3:ListBucket")
    )
    assert out["allowed"] is False
    assert out["reason"] == "no_allow"


def test_identity_explicit_deny_beats_resource_allow():
    identity = doc([deny("s3:DeleteObject", "arn:aws:s3:::bucket/*")])
    resource = doc([allow("*", "*", Principal="*")])
    out = decider(identity, resource).decide(request(action="s3:DeleteObject"))
    assert out["allowed"] is False
    assert out["reason"] == "explicit_deny"


def test_resource_explicit_deny_beats_identity_allow():
    identity = doc([allow("s3:GetObject", "arn:aws:s3:::shared/*")])
    resource = doc([deny("s3:GetObject", "arn:aws:s3:::shared/secret/*", Principal="*")])
    out = decider(identity, resource).decide(
        request(resource="arn:aws:s3:::shared/secret/x")
    )
    assert out["allowed"] is False
    assert out["reason"] == "explicit_deny"


def test_not_action_excludes_delete():
    identity = doc(
        [{"Effect": "Allow", "NotAction": ["s3:Delete*"], "Resource": ["arn:aws:s3:::bucket/readonly/*"]}]
    )
    d = decider(identity)
    assert d.decide(request(resource="arn:aws:s3:::bucket/readonly/a"))["allowed"] is True
    assert d.decide(request(action="s3:DeleteObject", resource="arn:aws:s3:::bucket/readonly/a"))["allowed"] is False


def test_not_resource_excludes_locked_prefix():
    identity = doc(
        [{"Effect": "Allow", "Action": ["s3:GetObject"], "NotResource": ["arn:aws:s3:::bucket/locked/*"]}]
    )
    d = decider(identity)
    assert d.decide(request(resource="arn:aws:s3:::bucket/open/a"))["allowed"] is True
    assert d.decide(request(resource="arn:aws:s3:::bucket/locked/a"))["allowed"] is False


def test_wildcards_match_action_and_resource():
    identity = doc([allow("s3:*", "arn:aws:s3:::bucket/*")])
    assert decider(identity).decide(request(action="s3:PutObject"))["allowed"] is True


def test_resource_policy_alone_allows_same_account():
    resource = doc([allow("s3:GetObject", "arn:aws:s3:::bucket/*", Principal={"AWS": ["arn:aws:iam::111:user/alice"]})])
    out = decider(doc([]), resource).decide(request())
    assert out["allowed"] is True
    assert out["reason"] == "resource_allow"


def test_cross_account_identity_only_is_denied():
    identity = doc([allow("s3:GetObject", "arn:aws:s3:::partner/*")])
    out = decider(identity).decide(
        request(principal="arn:aws:iam::222:user/bob", account="222", resource="arn:aws:s3:::partner/x")
    )
    assert out["allowed"] is False


def test_cross_account_needs_both_sides():
    identity = doc([allow("s3:GetObject", "arn:aws:s3:::partner/*")])
    resource = doc([allow("s3:GetObject", "arn:aws:s3:::partner/*", Principal={"AWS": ["arn:aws:iam::222:user/bob"]})])
    out = decider(identity, resource).decide(
        request(principal="arn:aws:iam::222:user/bob", account="222", resource="arn:aws:s3:::partner/x")
    )
    assert out["allowed"] is True


def test_permission_boundary_caps_identity():
    identity = doc([allow("s3:*", "*")])
    boundary = doc([allow("s3:GetObject", "*")])
    d = decider(identity, boundary=boundary)
    assert d.decide(request())["allowed"] is True
    assert d.decide(request(action="s3:PutObject"))["allowed"] is False


def test_permission_boundary_explicit_deny():
    identity = doc([allow("s3:*", "*")])
    boundary = doc([deny("s3:GetObject", "*")])
    out = decider(identity, boundary=boundary).decide(request())
    assert out["allowed"] is False
    assert out["reason"] == "boundary_deny"


def test_session_policy_caps_identity():
    identity = doc([allow("s3:*", "*")])
    session = doc([allow("s3:GetObject", "*")])
    d = decider(identity, session=session)
    assert d.decide(request())["allowed"] is True
    assert d.decide(request(action="s3:PutObject"))["allowed"] is False


def test_string_equals_condition_and_missing_key():
    identity = doc(
        [
            allow(
                "s3:PutObject",
                "arn:aws:s3:::bucket/*",
                Condition={"StringEquals": {"s3:prefix": "uploads/"}},
            )
        ]
    )
    d = decider(identity)
    assert d.decide(request(action="s3:PutObject", context={"s3:prefix": "uploads/"}))["allowed"] is True
    assert d.decide(request(action="s3:PutObject", context={}))["allowed"] is False


def test_ip_address_condition():
    identity = doc(
        [allow("s3:GetObject", "*", Condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}})]
    )
    d = decider(identity)
    assert d.decide(request(context={"aws:SourceIp": "10.1.2.3"}))["allowed"] is True
    assert d.decide(request(context={"aws:SourceIp": "192.168.1.3"}))["allowed"] is False
