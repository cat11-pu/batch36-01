import pytest

import scim_directory as sd

TENANT = "t1"


def directory(max_page=100):
    return sd.ScimDirectory(TENANT, max_page=max_page)


def payload(**over):
    p = {
        "externalId": "ext-1",
        "userName": "alice@corp.example",
        "displayName": "Alice",
        "emails": ["alice@corp.example"],
        "password": "Secret123!",
    }
    p.update(over)
    return p


def test_create_returns_versioned_resource():
    rec = directory().provision(payload(), "key-1", now=0)
    assert rec["replayed"] is False
    assert rec["version"] == 1
    assert rec["active"] is True
    assert rec["id"].startswith("u-")
    assert rec["resource"]["tenantId"] == TENANT
    assert "password" not in rec["resource"]


def test_get_user_returns_detached_snapshot():
    d = directory()
    rec = d.provision(payload(), "key-1", now=0)
    got = d.get_user(rec["id"])
    assert "password" not in got
    got["userName"] = "mallory@corp.example"
    assert d.get_user(rec["id"])["userName"] == "alice@corp.example"


def test_same_idempotency_key_replays_original():
    d = directory()
    first = d.provision(payload(), "key-1", now=0)
    again = d.provision(payload(displayName="Changed"), "key-1", now=1)
    assert again["id"] == first["id"]
    assert again["replayed"] is True
    assert again["version"] == 1
    assert d.list_users()["totalResults"] == 1


def test_same_external_id_with_new_key_updates():
    d = directory()
    first = d.provision(payload(), "key-1", now=0)
    second = d.provision(payload(displayName="Alice B"), "key-2", now=1)
    assert second["id"] == first["id"]
    assert second["replayed"] is False
    assert second["version"] == 2
    assert d.get_user(first["id"])["displayName"] == "Alice B"
    assert d.list_users()["totalResults"] == 1


def test_missing_external_id_is_rejected():
    p = payload()
    del p["externalId"]
    with pytest.raises(ValueError):
        directory().provision(p, "key-1", now=0)


def test_empty_user_name_is_rejected():
    with pytest.raises(ValueError):
        directory().provision(payload(userName=""), "key-1", now=0)


def test_user_name_collision_is_rejected():
    d = directory()
    d.provision(payload(), "key-1", now=0)
    with pytest.raises(sd.ScimConflict) as exc:
        d.provision(payload(externalId="ext-2"), "key-2", now=1)
    assert exc.value.code == "user_name_conflict"


def test_payload_tenant_mismatch_is_rejected():
    with pytest.raises(sd.ScimConflict) as exc:
        directory().provision(payload(tenantId="t2"), "key-1", now=0)
    assert exc.value.code == "tenant_mismatch"


def test_stale_patch_version_is_rejected():
    d = directory()
    rec = d.provision(payload(), "key-1", now=0)
    with pytest.raises(sd.ScimConflict) as exc:
        d.patch(rec["id"], [{"op": "replace", "path": "displayName", "value": "X"}], 0, now=1)
    assert exc.value.code == "version_conflict"
    assert d.get_user(rec["id"])["displayName"] == "Alice"


def test_unknown_patch_operation_is_rejected():
    d = directory()
    rec = d.provision(payload(), "key-1", now=0)
    with pytest.raises(sd.ScimConflict) as exc:
        d.patch(rec["id"], [{"op": "move", "path": "displayName", "value": "X"}], 1, now=1)
    assert exc.value.code == "unsupported_op"


def test_removing_required_attribute_is_rejected():
    d = directory()
    rec = d.provision(payload(), "key-1", now=0)
    with pytest.raises(sd.ScimConflict) as exc:
        d.patch(rec["id"], [{"op": "remove", "path": "userName"}], 1, now=1)
    assert exc.value.code == "required_attribute"


def test_replacing_user_name_is_rejected():
    d = directory()
    rec = d.provision(payload(), "key-1", now=0)
    with pytest.raises(sd.ScimConflict) as exc:
        d.patch(rec["id"], [{"op": "replace", "path": "userName", "value": "bob@corp.example"}], 1, now=1)
    assert exc.value.code == "immutable_attribute"


def test_duplicate_multivalue_is_rejected_then_patch_succeeds():
    d = directory()
    rec = d.provision(payload(), "key-1", now=0)
    with pytest.raises(sd.ScimConflict) as exc:
        d.patch(rec["id"], [{"op": "add", "path": "emails", "value": "alice@corp.example"}], 1, now=1)
    assert exc.value.code == "duplicate_value"
    out = d.patch(rec["id"], [{"op": "replace", "path": "displayName", "value": "Alice C"}], 1, now=2)
    assert out["version"] == 2
    assert d.get_user(rec["id"])["displayName"] == "Alice C"


def test_pagination_is_bounded_and_validated():
    d = directory(max_page=2)
    for i in range(3):
        d.provision(payload(externalId="ext-" + str(i), userName="user" + str(i) + "@corp.example"), "key-" + str(i), now=0)
    with pytest.raises(ValueError):
        d.list_users(start_index=0)
    page = d.list_users(start_index=1, count=1000)
    assert page["itemsPerPage"] == 2
    assert page["totalResults"] == 3
    assert len(page["resources"]) == 2
    second = d.list_users(start_index=2, count=1)
    assert len(second["resources"]) == 1


def test_deprovision_is_soft_idempotent_and_recoverable():
    d = directory()
    rec = d.provision(payload(), "key-1", now=0)
    out = d.deprovision(rec["id"], 1, now=1)
    assert out["active"] is False
    assert out["version"] == 2
    assert out["already"] is False
    again = d.deprovision(rec["id"], 2, now=2)
    assert again["already"] is True
    assert d.list_users()["totalResults"] == 0
    assert d.get_user(rec["id"])["active"] is False
    back = d.provision(payload(), "key-3", now=3)
    assert back["id"] == rec["id"]
    assert back["active"] is True
    assert back["version"] == 3
