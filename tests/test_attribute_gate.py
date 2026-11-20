import pytest

import attribute_gate as ag


def policy():
    return {
        "rules": [
            {
                "id": "allow-fin-read",
                "effect": "allow",
                "action": "read",
                "resource": "report:*",
                "condition": {
                    "allOf": [
                        {"attr": "subject.dept", "op": "eq", "value": "finance"},
                        {"attr": "resource.class", "op": "in", "value": ["internal", "public"]},
                    ]
                },
                "obligations": ["log"],
            },
            {
                "id": "deny-contractor",
                "effect": "deny",
                "action": "*",
                "resource": "report:salaries",
                "condition": {
                    "allOf": [{"attr": "subject.contractor", "op": "eq", "value": True}]
                },
            },
            {
                "id": "allow-auditor",
                "effect": "allow",
                "action": "read",
                "resource": "report:*",
                "condition": {
                    "anyOf": [
                        {"attr": "subject.role", "op": "eq", "value": "auditor"},
                        {"attr": "subject.clearance", "op": "gte", "value": 4},
                    ]
                },
            },
            {
                "id": "allow-office-ip",
                "effect": "allow",
                "action": "read",
                "resource": "report:net",
                "condition": {
                    "allOf": [{"attr": "subject.ip", "op": "cidr", "value": "10.0.0.0/8"}]
                },
            },
            {
                "id": "allow-share",
                "effect": "allow",
                "action": "share",
                "resource": "report:*",
                "condition": {
                    "noneOf": [{"attr": "subject.blocked", "op": "exists"}]
                },
            },
        ]
    }


def gate():
    return ag.AttributeGate(policy())


def request(**over):
    value = {
        "subject": {
            "dept": "finance",
            "role": "analyst",
            "clearance": 2,
            "ip": "10.2.3.4",
        },
        "resource": {"type": "report", "name": "q3", "class": "internal"},
        "action": "read",
        "context": {},
    }
    value.update(over)
    return value


def test_matching_allow_rule_is_reported():
    out = gate().evaluate(request())
    assert out["allowed"] is True
    assert out["reason"] == "allow"
    assert out["matched"] == ["allow-fin-read"]
    assert out["obligations"] == ["log"]


def test_no_matching_rule_is_no_match():
    out = gate().evaluate(request(subject={"dept": "ops", "role": "analyst", "clearance": 2, "ip": "10.2.3.4"}))
    assert out["allowed"] is False
    assert out["reason"] == "no_match"
    assert out["matched"] == []


def test_explicit_deny_overrides_allow():
    out = gate().evaluate(
        request(
            subject={"dept": "finance", "role": "analyst", "clearance": 5, "ip": "10.2.3.4", "contractor": True},
            resource={"type": "report", "name": "salaries", "class": "internal"},
        )
    )
    assert out["allowed"] is False
    assert out["reason"] == "deny"
    assert "deny-contractor" in out["matched"]


def test_missing_attribute_makes_leaf_false():
    out = gate().evaluate(
        request(subject={"role": "analyst", "clearance": 2, "ip": "10.2.3.4"})
    )
    assert out["allowed"] is False
    assert out["reason"] == "no_match"


def test_any_of_allows_auditor_role():
    out = gate().evaluate(
        request(subject={"dept": "ops", "role": "auditor", "clearance": 1, "ip": "192.168.1.5"})
    )
    assert out["allowed"] is True
    assert out["matched"] == ["allow-auditor"]


def test_any_of_allows_high_clearance():
    out = gate().evaluate(
        request(subject={"dept": "ops", "role": "analyst", "clearance": 4, "ip": "192.168.1.5"})
    )
    assert out["allowed"] is True


def test_none_of_allows_when_attribute_absent():
    out = gate().evaluate(request(action="share"))
    assert out["allowed"] is True
    assert out["matched"] == ["allow-share"]


def test_none_of_blocks_when_attribute_present():
    out = gate().evaluate(request(action="share", subject={"dept": "finance", "role": "analyst", "clearance": 2, "ip": "10.2.3.4", "blocked": True}))
    assert out["allowed"] is False
    assert out["reason"] == "no_match"


def test_cidr_match_allows():
    out = gate().evaluate(
        request(resource={"type": "report", "name": "net", "class": "internal"})
    )
    assert out["allowed"] is True
    assert "allow-office-ip" in out["matched"]


def test_cidr_miss_is_rejected():
    out = gate().evaluate(
        request(
            subject={"dept": "ops", "role": "analyst", "clearance": 1, "ip": "192.168.1.5"},
            resource={"type": "report", "name": "net", "class": "internal"},
        )
    )
    assert out["allowed"] is False


def test_unknown_operator_is_rejected_at_load():
    p = policy()
    p["rules"][0]["condition"]["allOf"][0]["op"] = "approximately"
    with pytest.raises(ag.AttributeGateError) as exc:
        ag.AttributeGate(p)
    assert exc.value.code == "unknown_operator"


def test_duplicate_rule_id_is_rejected():
    p = policy()
    p["rules"].append(dict(p["rules"][0]))
    with pytest.raises(ag.AttributeGateError) as exc:
        ag.AttributeGate(p)
    assert exc.value.code == "duplicate_rule"


def test_bad_effect_is_rejected():
    p = policy()
    p["rules"][0]["effect"] = "permit"
    with pytest.raises(ag.AttributeGateError) as exc:
        ag.AttributeGate(p)
    assert exc.value.code == "bad_rule"


def test_request_without_action_is_rejected():
    bad = request()
    del bad["action"]
    with pytest.raises(ag.AttributeGateError) as exc:
        gate().evaluate(bad)
    assert exc.value.code == "bad_request"


def test_numeric_compare_with_string_is_rejected():
    with pytest.raises(ag.AttributeGateError) as exc:
        gate().evaluate(
            request(subject={"dept": "ops", "role": "analyst", "clearance": "4", "ip": "10.2.3.4"})
        )
    assert exc.value.code == "bad_operand"
