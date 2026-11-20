import threading

import pytest

import tenant_scope_planner as tp

TABLES = {
    "orders": {"tenant_column": "tenant_id"},
    "users": {"tenant_column": "tenant_id"},
    "countries": {},
}


def planner():
    return tp.TenantScopePlanner(TABLES, shared_tables={"countries"})


def query(**over):
    value = {
        "select": ["orders.id", "orders.total"],
        "from": "orders",
        "joins": [],
        "where": [{"column": "orders.status", "op": "=", "value": "paid"}],
    }
    value.update(over)
    return value


def test_tenant_predicate_is_injected():
    out = planner().plan("t1", query())
    assert "orders.tenant_id = ?" in out["sql"]
    assert out["params"][0] == "t1"
    assert out["cross_tenant"] is False


def test_existing_where_and_params_follow_tenant_value():
    out = planner().plan("t1", query())
    assert out["params"] == ["t1", "paid"]


def test_client_tenant_predicate_is_rejected():
    q = query(where=[{"column": "orders.tenant_id", "op": "=", "value": "t2"}])
    with pytest.raises(tp.TenantScopeError) as exc:
        planner().plan("t1", q)
    assert exc.value.code == "tenant_override"


def test_join_between_tenant_tables_gets_equality_predicate():
    q = query(joins=[{"table": "users", "on": "orders.user_id = users.id"}])
    out = planner().plan("t1", q)
    assert "users.tenant_id = orders.tenant_id" in out["sql"]
    assert out["params"] == ["t1", "t1", "paid"]


def test_shared_table_join_has_no_tenant_predicate():
    q = query(joins=[{"table": "countries", "on": "orders.country = countries.code"}])
    out = planner().plan("t1", q)
    assert "countries.tenant_id" not in out["sql"]
    assert out["tables"] == ["orders", "countries"]


def test_unregistered_shared_table_is_rejected():
    q = query(joins=[{"table": "regions", "on": "orders.region = regions.code"}])
    with pytest.raises(tp.TenantScopeError) as exc:
        planner().plan("t1", q)
    assert exc.value.code == "unknown_table"


def test_cache_key_differs_between_tenants():
    p = planner()
    a = p.plan("t1", query())["cache_key"]
    b = p.plan("t2", query())["cache_key"]
    assert a != b
    assert "t1" in a and "t2" in b


def test_cache_key_is_stable_for_same_request():
    p = planner()
    assert p.plan("t1", query())["cache_key"] == p.plan("t1", query())["cache_key"]


def test_empty_tenant_is_rejected():
    with pytest.raises(tp.TenantScopeError) as exc:
        planner().plan("   ", query())
    assert exc.value.code == "bad_tenant"


def test_unknown_base_table_is_rejected():
    with pytest.raises(tp.TenantScopeError) as exc:
        planner().plan("t1", query(**{"from": "invoices"}))
    assert exc.value.code == "unknown_table"


def test_union_is_rejected():
    with pytest.raises(tp.TenantScopeError) as exc:
        planner().plan("t1", query(union=[query()]))
    assert exc.value.code == "unsupported_union"


def test_cross_tenant_without_ticket_is_rejected():
    with pytest.raises(tp.TenantScopeError) as exc:
        planner().plan("t1", query(cross_tenant=True))
    assert exc.value.code == "cross_tenant_forbidden"


def test_cross_tenant_with_ticket_skips_predicates():
    out = planner().plan("t1", query(cross_tenant=True, audit_ticket="INC-2041"))
    assert out["cross_tenant"] is True
    assert "orders.tenant_id = ?" not in out["sql"]
    assert out["params"] == ["paid"]


def test_plan_is_independent_of_later_query_mutation():
    q = query()
    out = planner().plan("t1", q)
    q["where"][0]["value"] = "refunded"
    q["select"].append("orders.secret")
    assert out["params"] == ["t1", "paid"]


def test_concurrent_tenants_do_not_cross_parameters():
    p = planner()
    results = []
    lock = threading.Lock()

    def worker(name):
        for _ in range(15):
            out = p.plan(name, query())
            with lock:
                results.append((name, out["params"][0]))

    threads = [threading.Thread(target=worker, args=(f"t{i}",)) for i in range(1, 9)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 120
    assert all(name == first for name, first in results)
