import copy


class ScimConflict(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


_REQUIRED_ATTRIBUTES = {"id", "tenantid", "externalid", "username"}
_IMMUTABLE_ATTRIBUTES = {"id", "tenantid", "externalid", "username"}
_MULTI_VALUED_ATTRIBUTES = {
    "emails",
    "phonenumbers",
    "ims",
    "addresses",
    "groups",
    "roles",
    "entitlements",
    "x509certificates",
}


def _clean(value):
    """Return a detached copy with credential fields removed."""
    if isinstance(value, dict):
        return {
            key: _clean(item)
            for key, item in value.items()
            if str(key).lower() != "password"
        }
    if isinstance(value, list):
        return [_clean(item) for item in value]
    return copy.deepcopy(value)


def _has_value(values, candidate):
    return any(existing == candidate for existing in values)


def _has_duplicates(values):
    seen = []
    for value in values:
        if _has_value(seen, value):
            return True
        seen.append(value)
    return False


class ScimDirectory:
    def __init__(self, tenant_id, max_page=100):
        if isinstance(max_page, bool) or not isinstance(max_page, int) or max_page < 1:
            raise ValueError("max_page must be a positive integer")
        self._tenant_id = tenant_id
        self._max_page = max_page
        self._users = {}
        self._order = []
        self._external_ids = {}
        self._idempotency = {}
        self._next_user_number = 1

    def provision(self, payload, idempotency_key, now):
        if not isinstance(idempotency_key, str) or not idempotency_key:
            raise ValueError("idempotency_key is required")

        if idempotency_key in self._idempotency:
            result = copy.deepcopy(self._idempotency[idempotency_key])
            result["replayed"] = True
            return result

        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")

        external_id = payload.get("externalId")
        user_name = payload.get("userName")
        if not isinstance(external_id, str) or not external_id.strip():
            raise ValueError("externalId is required")
        if not isinstance(user_name, str) or not user_name.strip():
            raise ValueError("userName is required")

        if "tenantId" in payload and payload["tenantId"] != self._tenant_id:
            raise ScimConflict("tenant_mismatch")
        if "tenant_id" in payload and payload["tenant_id"] != self._tenant_id:
            raise ScimConflict("tenant_mismatch")

        existing_id = self._external_ids.get(external_id)
        if existing_id is None:
            existing_id = self._user_name_owner(user_name)
            if existing_id is not None:
                raise ScimConflict("user_name_conflict")

            user_id = self._allocate_user_id()
            record = {
                "id": user_id,
                "version": 1,
                "active": True,
                "resource": self._resource_from_payload(
                    payload, user_id, active=True
                ),
            }
            self._users[user_id] = record
            self._order.append(user_id)
            self._external_ids[external_id] = user_id
        else:
            record = self._users[existing_id]
            current = record["resource"]
            if user_name != current.get("userName"):
                raise ScimConflict("immutable_attribute")

            user_name_owner = self._user_name_owner(user_name)
            if user_name_owner is not None and user_name_owner != existing_id:
                raise ScimConflict("user_name_conflict")

            resource = self._resource_from_payload(
                payload, existing_id, active=True
            )
            record["resource"] = resource
            record["active"] = True
            record["version"] += 1

        result = self._response(record)
        self._idempotency[idempotency_key] = copy.deepcopy(result)
        return copy.deepcopy(result)

    def patch(self, user_id, operations, version, now):
        record = self._users.get(user_id)
        if record is None:
            raise ValueError("user_not_found")
        if version != record["version"]:
            raise ScimConflict("version_conflict")
        if not isinstance(operations, list):
            raise ValueError("operations must be a list")

        resource = copy.deepcopy(record["resource"])
        for operation in operations:
            if not isinstance(operation, dict):
                raise ValueError("operation must be an object")

            op = operation.get("op")
            if not isinstance(op, str) or op.lower() not in {"add", "replace", "remove"}:
                raise ScimConflict("unsupported_op")
            op = op.lower()

            path = operation.get("path")
            if not isinstance(path, str) or not path.strip():
                raise ScimConflict("invalid_path")
            path = path.strip()
            root = path.split(".", 1)[0]
            normalized_root = root.lower()

            if op == "remove":
                if normalized_root in _REQUIRED_ATTRIBUTES:
                    raise ScimConflict("required_attribute")
                self._apply_remove(resource, path, operation.get("value"))
                continue

            if normalized_root in _IMMUTABLE_ATTRIBUTES:
                raise ScimConflict("immutable_attribute")

            if "value" not in operation:
                raise ScimConflict("invalid_value")
            value = operation["value"]

            if op == "replace":
                if normalized_root in _REQUIRED_ATTRIBUTES and not self._is_present(value):
                    raise ScimConflict("required_attribute")
                if (
                    normalized_root in _MULTI_VALUED_ATTRIBUTES
                    and isinstance(value, list)
                    and _has_duplicates(value)
                ):
                    raise ScimConflict("duplicate_value")
                self._assign_path(resource, path, copy.deepcopy(value))
            else:
                self._apply_add(resource, path, root, copy.deepcopy(value))

        record["resource"] = resource
        record["version"] += 1
        return self._response(record)

    def deprovision(self, user_id, version, now):
        record = self._users.get(user_id)
        if record is None:
            raise ValueError("user_not_found")

        if not record["active"]:
            return self._response(record, already=True)

        if version != record["version"]:
            raise ScimConflict("version_conflict")

        record["active"] = False
        record["resource"]["active"] = False
        record["version"] += 1
        return self._response(record, already=False)

    def list_users(self, start_index=1, count=50):
        if (
            isinstance(start_index, bool)
            or not isinstance(start_index, int)
            or start_index < 1
        ):
            raise ValueError("start_index must be at least 1")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ValueError("count must be a positive integer")

        active_ids = [
            user_id
            for user_id in self._order
            if self._users[user_id]["active"]
        ]
        page_size = min(count, self._max_page)
        offset = start_index - 1
        selected = active_ids[offset : offset + page_size]

        return {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(active_ids),
            "startIndex": start_index,
            "itemsPerPage": len(selected),
            "resources": [
                _clean(self._users[user_id]["resource"]) for user_id in selected
            ],
        }

    def get_user(self, user_id):
        record = self._users.get(user_id)
        if record is None:
            raise ValueError("user_not_found")
        return _clean(record["resource"])

    def _allocate_user_id(self):
        while True:
            user_id = "u-{}".format(self._next_user_number)
            self._next_user_number += 1
            if user_id not in self._users:
                return user_id

    def _user_name_owner(self, user_name):
        for user_id, record in self._users.items():
            if record["resource"].get("userName") == user_name:
                return user_id
        return None

    def _resource_from_payload(self, payload, user_id, active):
        resource = _clean(payload)
        for attribute in _MULTI_VALUED_ATTRIBUTES:
            value = resource.get(attribute)
            if isinstance(value, list) and _has_duplicates(value):
                raise ScimConflict("duplicate_value")
        resource["id"] = user_id
        resource["tenantId"] = self._tenant_id
        resource["active"] = active
        return resource

    def _response(self, record, replayed=False, already=None):
        result = {
            "id": record["id"],
            "version": record["version"],
            "active": record["active"],
            "replayed": replayed,
            "resource": _clean(record["resource"]),
        }
        if already is not None:
            result["already"] = already
        return result

    @staticmethod
    def _is_present(value):
        if value is None:
            return False
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, (list, dict)):
            return bool(value)
        return True

    @staticmethod
    def _assign_path(resource, path, value):
        parts = path.split(".")
        target = resource
        for part in parts[:-1]:
            child = target.get(part)
            if not isinstance(child, dict):
                child = {}
                target[part] = child
            target = child
        target[parts[-1]] = value

    @staticmethod
    def _apply_remove(resource, path, value):
        parts = path.split(".")
        target = resource
        for part in parts[:-1]:
            target = target.get(part)
            if not isinstance(target, dict):
                return

        key = parts[-1]
        if value is None:
            target.pop(key, None)
            return

        current = target.get(key)
        if isinstance(current, list):
            target[key] = [item for item in current if item != value]
        elif current == value:
            target.pop(key, None)

    @staticmethod
    def _apply_add(resource, path, root, value):
        parts = path.split(".")
        target = resource
        for part in parts[:-1]:
            child = target.get(part)
            if not isinstance(child, dict):
                child = {}
                target[part] = child
            target = child

        key = parts[-1]
        current = target.get(key)
        normalized_root = root.lower()
        incoming = value if isinstance(value, list) else [value]

        if normalized_root in _MULTI_VALUED_ATTRIBUTES or isinstance(current, list):
            if isinstance(current, list):
                existing = current
            elif current is None:
                existing = []
            else:
                existing = [current]
            added = []
            for item in incoming:
                if _has_value(existing, item) or _has_value(added, item):
                    raise ScimConflict("duplicate_value")
                added.append(item)
            target[key] = copy.deepcopy(existing) + copy.deepcopy(added)
            return

        target[key] = copy.deepcopy(value)
