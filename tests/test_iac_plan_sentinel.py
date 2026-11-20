import threading

import pytest

import iac_plan_sentinel as ips

RULES = [
    {
        "id": "s3-public-acl",
        "resource_type": "aws_s3_bucket",
        "path": "acl",
        "op": "in",
        "value": ["public-read", "public-read-write"],
        "severity": "high",
    },
    {
        "id": "tags-required",
        "resource_type": "*",
        "path": "tags.Environment",
        "op": "missing",
        "severity": "medium",
    },
    {
        "id": "sg-world",
        "resource_type": "aws_security_group_rule",
        "path": "cidr_blocks",
        "op": "contains",
        "value": "0.0.0.0/0",
        "severity": "critical",
    },
    {
        "id": "vpc-cidr",
        "resource_type": "aws_vpc",
        "path": "cidr_block",
        "op": "not_in",
        "value": ["10.0.0.0/16", "10.1.0.0/16"],
        "severity": "high",
    },
    {
        "id": "iam-wild",
        "resource_type": "aws_iam_policy",
        "path": "policy.Statement.0.Action",
        "op": "contains",
        "value": "*",
        "severity": "critical",
    },
]


def resource(address, rtype, after, actions=None, unknown=None):
    return {
        "address": address,
        "type": rtype,
        "name": address.split(".")[-1],
        "change": {
            "actions": actions or ["create"],
            "after": after,
            "after_unknown": unknown or {},
        },
    }


def plan(*changes):
    return {"format_version": "1.2", "resource_changes": list(changes)}


def sentinel(waivers=None, now=0, rules=None):
    return ips.PlanSentinel(RULES if rules is None else rules, waivers=waivers, now=now)


def s3(address="aws_s3_bucket.pub", acl="private", tags=None):
    return resource(address, "aws_s3_bucket", {"acl": acl, "tags": {"Environment": "prod"} if tags is None else tags})


def test_clean_plan_passes():
    out = sentinel().scan(plan(s3()))
    assert out["ok"] is True
    assert out["violations"] == []


def test_public_acl_is_reported():
    out = sentinel().scan(plan(s3(acl="public-read")))
    assert out["ok"] is False
    assert out["violations"][0]["rule_id"] == "s3-public-acl"
    assert out["violations"][0]["address"] == "aws_s3_bucket.pub"


def test_unknown_value_fails_closed():
    change = resource("aws_s3_bucket.pub", "aws_s3_bucket", {"tags": {"Environment": "prod"}}, unknown={"acl": True})
    out = sentinel().scan(plan(change))
    assert out["ok"] is False
    assert out["violations"][0]["code"] == "unknown_value"


def test_wildcard_rule_applies_to_any_type():
    change = resource("aws_vpc.main", "aws_vpc", {"cidr_block": "10.0.0.0/16", "tags": {"Environment": "prod"}})
    out = sentinel().scan(plan(change))
    assert all(v["rule_id"] != "tags-required" for v in out["violations"])


def test_missing_required_tag_is_reported():
    out = sentinel().scan(plan(s3(tags={})))
    assert out["ok"] is False
    assert any(v["rule_id"] == "tags-required" and v["code"] == "missing_attribute" for v in out["violations"])


def test_present_required_tag_passes():
    out = sentinel().scan(plan(s3(tags={"Environment": "prod"})))
    assert out["violations"] == []


def test_world_open_security_group_is_reported():
    change = resource(
        "aws_security_group_rule.ssh",
        "aws_security_group_rule",
        {"cidr_blocks": ["0.0.0.0/0"], "tags": {"Environment": "prod"}},
    )
    out = sentinel().scan(plan(change))
    assert any(v["rule_id"] == "sg-world" for v in out["violations"])


def test_vpc_cidr_outside_allowlist_is_reported():
    change = resource(
        "aws_vpc.main", "aws_vpc", {"cidr_block": "10.9.0.0/16", "tags": {"Environment": "prod"}}
    )
    out = sentinel().scan(plan(change))
    assert any(v["rule_id"] == "vpc-cidr" for v in out["violations"])


def test_iam_wildcard_action_is_reported():
    change = resource(
        "aws_iam_policy.admin",
        "aws_iam_policy",
        {"policy": {"Statement": [{"Action": ["*"], "Resource": "*"}]}, "tags": {"Environment": "prod"}},
    )
    out = sentinel().scan(plan(change))
    assert any(v["rule_id"] == "iam-wild" for v in out["violations"])


def test_expired_waiver_does_not_suppress():
    waiver = {
        "rule_id": "s3-public-acl",
        "address": "aws_s3_bucket.pub",
        "ticket": "INC-1",
        "expires_at": 5,
    }
    out = sentinel([waiver], now=10).scan(plan(s3(acl="public-read")))
    assert out["ok"] is False
    assert out["waived"] == []


def test_valid_waiver_suppresses_exact_address():
    waiver = {
        "rule_id": "s3-public-acl",
        "address": "aws_s3_bucket.pub",
        "ticket": "INC-1",
        "expires_at": 20,
    }
    out = sentinel([waiver], now=10).scan(plan(s3(acl="public-read")))
    assert out["ok"] is True
    assert out["violations"] == []
    assert out["waived"] == [{"rule_id": "s3-public-acl", "address": "aws_s3_bucket.pub"}]


def test_waiver_for_other_address_does_not_apply():
    waiver = {
        "rule_id": "s3-public-acl",
        "address": "aws_s3_bucket.other",
        "ticket": "INC-1",
        "expires_at": 20,
    }
    out = sentinel([waiver], now=10).scan(plan(s3(acl="public-read")))
    assert out["ok"] is False
    assert out["violations"]


def test_destroy_is_skipped():
    change = resource("aws_s3_bucket.pub", "aws_s3_bucket", {"acl": "public-read"}, actions=["delete"])
    out = sentinel().scan(plan(change))
    assert out["ok"] is True


def test_bad_rules_and_bad_plan_are_rejected():
    with pytest.raises(ips.IacGateError) as exc:
        sentinel(rules=[RULES[0], dict(RULES[0])])
    assert exc.value.code == "duplicate_rule"
    with pytest.raises(ips.IacGateError) as exc2:
        sentinel().scan({"resource_changes": "nope"})
    assert exc2.value.code == "bad_plan"


def test_concurrent_scans_are_identical():
    p = plan(s3(acl="public-read"))
    scanner = sentinel()
    results = []
    lock = threading.Lock()

    def worker():
        for _ in range(10):
            out = scanner.scan(p)
            with lock:
                results.append(out)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 80
    assert all(r["ok"] is False for r in results)
    assert all(r["violations"] == results[0]["violations"] for r in results)
