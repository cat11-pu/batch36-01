import pytest

import partner_graphql_budget as pb


def budget(**kw):
    return pb.PartnerQueryBudget(**kw)


def leaf(field, **over):
    node = {"field": field}
    node.update(over)
    return node


def op(selections, operation="query", fragments=None):
    document = {"operation": operation, "name": "Q", "selections": selections}
    if fragments is not None:
        document["fragments"] = fragments
    return document


def test_single_field_is_measured():
    out = budget().measure(op([leaf("health")]))
    assert out["depth"] == 1
    assert out["cost"] == 1
    assert out["fields"] == 1
    assert out["aliases"] == 0


def test_nested_query_cost_and_depth():
    document = op(
        [
            {
                "field": "orders",
                "args": {"first": 3},
                "selections": [leaf("id"), leaf("total")],
            }
        ]
    )
    out = budget().measure(document)
    assert out["depth"] == 2
    assert out["cost"] == 7
    assert out["fields"] == 3


def test_depth_limit_is_enforced():
    document = op(
        [{"field": "orders", "selections": [{"field": "items", "selections": [leaf("sku")]}]}]
    )
    with pytest.raises(pb.BudgetError) as exc:
        budget(max_depth=2).measure(document)
    assert exc.value.code == "too_deep"


def test_introspection_field_is_rejected():
    with pytest.raises(pb.BudgetError) as exc:
        budget().measure(op([leaf("__schema")]))
    assert exc.value.code == "introspection"


def test_mutation_is_rejected():
    with pytest.raises(pb.BudgetError) as exc:
        budget().measure(op([leaf("charge")], operation="mutation"))
    assert exc.value.code == "operation_not_allowed"


def test_page_size_multiplies_child_cost():
    document = op([{"field": "orders", "args": {"first": 5}, "selections": [leaf("id")]}])
    out = budget().measure(document)
    assert out["cost"] == 6


def test_page_size_limit_is_enforced():
    document = op([{"field": "orders", "args": {"first": 999}, "selections": [leaf("id")]}])
    with pytest.raises(pb.BudgetError) as exc:
        budget(page_factor=10).measure(document)
    assert exc.value.code == "bad_pagination"


def test_cost_limit_is_enforced():
    document = op(
        [{"field": "orders", "args": {"first": 3}, "selections": [leaf("id"), leaf("total")]}]
    )
    with pytest.raises(pb.BudgetError) as exc:
        budget(max_cost=5).measure(document)
    assert exc.value.code == "cost_exceeded"


def test_alias_conflict_is_rejected():
    document = op([leaf("a", alias="x"), leaf("b", alias="x")])
    with pytest.raises(pb.BudgetError) as exc:
        budget().measure(document)
    assert exc.value.code == "alias_conflict"


def test_alias_count_limit_is_enforced():
    document = op([leaf("a", alias="x"), leaf("b", alias="y")])
    with pytest.raises(pb.BudgetError) as exc:
        budget(max_aliases=1).measure(document)
    assert exc.value.code == "too_many_aliases"


def test_fragment_is_expanded_into_cost():
    fragments = {"F": {"selections": [leaf("id"), leaf("total")]}}
    out = budget().measure(op([{"spread": "F"}], fragments=fragments))
    assert out["cost"] == 2
    assert out["fields"] == 2
    assert out["depth"] == 1


def test_fragment_cycle_is_rejected():
    fragments = {
        "F": {"selections": [{"spread": "G"}]},
        "G": {"selections": [{"spread": "F"}]},
    }
    with pytest.raises(pb.BudgetError) as exc:
        budget().measure(op([{"spread": "F"}], fragments=fragments))
    assert exc.value.code == "fragment_cycle"


def test_unknown_fragment_is_rejected():
    with pytest.raises(pb.BudgetError) as exc:
        budget().measure(op([{"spread": "Missing"}], fragments={}))
    assert exc.value.code == "unknown_fragment"


def test_partner_quota_is_charged_and_resets():
    document = op(
        [{"field": "orders", "args": {"first": 3}, "selections": [leaf("id"), leaf("total")]}]
    )
    b = budget(partner_quota=10)
    first = b.charge("acme", document, now=0)
    assert first["remaining"] == 3
    with pytest.raises(pb.BudgetError) as exc:
        b.charge("acme", document, now=1)
    assert exc.value.code == "quota_exceeded"
    again = b.charge("acme", document, now=61)
    assert again["remaining"] == 3


def test_snapshot_counts_and_copy():
    b = budget(partner_quota=2)
    b.charge("acme", op([leaf("health")]))
    b.charge("acme", op([leaf("health")]))
    with pytest.raises(pb.BudgetError):
        b.charge("acme", op([leaf("health")]))
    snap = b.snapshot()
    assert snap["charged"] == 2
    assert snap["rejected"] == 1
    snap["charged"] = 0
    assert b.snapshot()["charged"] == 2
