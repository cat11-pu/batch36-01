import threading

import pytest

import k8s_rbac_resolver as kr


def data():
    return {
        "roles": {
            "team-a/reader": {
                "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]
            },
            "team-a/named": {
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["pods"],
                        "verbs": ["get"],
                        "resourceNames": ["special"],
                    }
                ]
            },
        },
        "cluster_roles": {
            "node-reader": {
                "rules": [{"apiGroups": [""], "resources": ["nodes"], "verbs": ["get"]}]
            },
            "logger": {
                "rules": [{"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]}]
            },
            "star": {"rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]},
            "url-reader": {"rules": [{"nonResourceURLs": ["/healthz"], "verbs": ["get"]}]},
            "aggregate": {
                "aggregationRule": {
                    "clusterRoleSelectors": [
                        {"matchLabels": {"rbac.example.com/aggregate": "true"}}
                    ]
                },
                "rules": [],
            },
            "labelled": {
                "labels": {"rbac.example.com/aggregate": "true"},
                "rules": [
                    {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["get"]}
                ],
            },
            "labelled-other": {
                "labels": {"rbac.example.com/aggregate": "false"},
                "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}],
            },
        },
        "role_bindings": [
            {
                "name": "rb-read",
                "namespace": "team-a",
                "roleRef": {"kind": "Role", "name": "reader"},
                "subjects": [
                    {"kind": "User", "name": "alice"},
                    {"kind": "Group", "name": "devs"},
                ],
            },
            {
                "name": "rb-cluster",
                "namespace": "team-a",
                "roleRef": {"kind": "ClusterRole", "name": "node-reader"},
                "subjects": [{"kind": "User", "name": "alice"}],
            },
            {
                "name": "rb-named",
                "namespace": "team-a",
                "roleRef": {"kind": "Role", "name": "named"},
                "subjects": [{"kind": "User", "name": "bob"}],
            },
            {
                "name": "rb-logger",
                "namespace": "team-a",
                "roleRef": {"kind": "ClusterRole", "name": "logger"},
                "subjects": [{"kind": "User", "name": "alice"}],
            },
            {
                "name": "rb-url",
                "namespace": "team-a",
                "roleRef": {"kind": "ClusterRole", "name": "url-reader"},
                "subjects": [{"kind": "User", "name": "bob"}],
            },
        ],
        "cluster_role_bindings": [
            {
                "name": "crb-node",
                "roleRef": {"kind": "ClusterRole", "name": "node-reader"},
                "subjects": [{"kind": "Group", "name": "ops"}],
            },
            {
                "name": "crb-sa",
                "roleRef": {"kind": "ClusterRole", "name": "node-reader"},
                "subjects": [
                    {"kind": "ServiceAccount", "name": "deployer", "namespace": "team-b"}
                ],
            },
            {
                "name": "crb-url",
                "roleRef": {"kind": "ClusterRole", "name": "url-reader"},
                "subjects": [{"kind": "User", "name": "alice"}],
            },
            {
                "name": "crb-star",
                "roleRef": {"kind": "ClusterRole", "name": "star"},
                "subjects": [{"kind": "User", "name": "frank"}],
            },
            {
                "name": "crb-aggregate",
                "roleRef": {"kind": "ClusterRole", "name": "aggregate"},
                "subjects": [{"kind": "User", "name": "alice"}],
            },
        ],
    }


def resolver(cluster_roles=None):
    d = data()
    return kr.KubeRBACResolver(
        d["roles"],
        d["cluster_roles"] if cluster_roles is None else cluster_roles,
        d["role_bindings"],
        d["cluster_role_bindings"],
    )


def user(name, groups=None):
    return {"kind": "User", "name": name, "groups": groups or []}


def test_namespaced_binding_allows_in_namespace():
    out = resolver().explain(user("alice"), "get", resource="pods", namespace="team-a")
    assert out["allowed"] is True
    assert out["matched"] == ["rb-read"]


def test_namespaced_binding_denies_other_namespace():
    assert resolver().allowed(user("alice"), "get", resource="pods", namespace="team-b") is False


def test_cluster_binding_applies_globally():
    out = resolver().explain(user("ops", ["ops"]), "get", resource="nodes")
    assert out["allowed"] is True
    assert out["matched"] == ["crb-node"]


def test_cluster_role_via_rolebinding_stays_namespaced():
    r = resolver()
    assert r.allowed(user("alice"), "get", resource="nodes", namespace="team-a") is True
    assert r.allowed(user("alice"), "get", resource="nodes", namespace="team-b") is False


def test_group_subject_matches():
    assert resolver().allowed(user("dave", ["devs"]), "get", resource="pods", namespace="team-a") is True


def test_service_account_requires_matching_namespace():
    r = resolver()
    good = {"kind": "ServiceAccount", "name": "deployer", "namespace": "team-b"}
    bad = {"kind": "ServiceAccount", "name": "deployer", "namespace": "team-c"}
    assert r.allowed(good, "get", resource="nodes") is True
    assert r.allowed(bad, "get", resource="nodes") is False


def test_resource_names_are_enforced():
    r = resolver()
    assert r.allowed(user("bob"), "get", resource="pods", namespace="team-a", name="special") is True
    assert r.allowed(user("bob"), "get", resource="pods", namespace="team-a", name="other") is False


def test_subresource_rule_matches_only_that_subresource():
    r = resolver()
    assert r.allowed(user("alice"), "get", resource="pods", namespace="team-a", subresource="log") is True
    assert r.allowed(user("alice"), "get", resource="pods", namespace="team-a", subresource="exec") is False


def test_wildcard_rule_allows_everything():
    assert resolver().allowed(user("frank"), "delete", resource="deployments", api_group="apps") is True


def test_non_resource_url_requires_cluster_binding():
    r = resolver()
    assert r.allowed(user("alice"), "get", non_resource_url="/healthz") is True
    assert r.allowed(user("alice"), "get", non_resource_url="/metrics") is False


def test_non_resource_url_via_rolebinding_is_ignored():
    assert resolver().allowed(user("bob"), "get", non_resource_url="/healthz", namespace="team-a") is False


def test_aggregation_collects_labelled_rules():
    out = resolver().explain(user("alice"), "get", resource="deployments", api_group="apps")
    assert out["allowed"] is True
    assert "crb-aggregate" in out["matched"]


def test_aggregation_selector_mismatch_grants_nothing():
    roles = data()["cluster_roles"]
    roles["labelled"]["labels"] = {"rbac.example.com/aggregate": "no"}
    assert resolver(roles).allowed(user("alice"), "get", resource="deployments", api_group="apps") is False


def test_missing_role_reference_is_rejected():
    d = data()
    d["role_bindings"].append(
        {
            "name": "broken",
            "namespace": "team-a",
            "roleRef": {"kind": "Role", "name": "ghost"},
            "subjects": [{"kind": "User", "name": "alice"}],
        }
    )
    with pytest.raises(kr.KubeRBACError) as exc:
        kr.KubeRBACResolver(
            d["roles"], d["cluster_roles"], d["role_bindings"], d["cluster_role_bindings"]
        )
    assert exc.value.code == "missing_role"


def test_concurrent_queries_are_stable():
    r = resolver()
    results = []
    lock = threading.Lock()

    def worker():
        for _ in range(10):
            value = r.allowed(user("alice"), "get", resource="pods", namespace="team-a")
            with lock:
                results.append(value)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == [True] * 80
