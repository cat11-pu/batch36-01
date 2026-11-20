class IacGateError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


_OPS = {"eq", "ne", "in", "not_in", "contains", "not_contains", "exists", "missing"}

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class PlanSentinel:
    def __init__(self, rules, waivers=None, now=0):
        if not isinstance(rules, (list, tuple)):
            raise IacGateError("bad_rule")
        self._rules = []
        seen_ids = set()
        for rule in rules:
            self._rules.append(self._validate_rule(rule, seen_ids))
        self._waivers = []
        for waiver in waivers or []:
            self._waivers.append(self._validate_waiver(waiver))
        self._now = now

    def scan(self, plan):
        if not isinstance(plan, dict):
            raise IacGateError("bad_plan")
        changes = plan.get("resource_changes")
        if not isinstance(changes, list):
            raise IacGateError("bad_plan")

        active_waivers = {
            (w["rule_id"], w["address"])
            for w in self._waivers
            if self._now < w["expires_at"]
        }

        violations = []
        waived = []
        seen_addresses = set()
        for change in changes:
            if not isinstance(change, dict):
                raise IacGateError("bad_change")
            address = change.get("address")
            parts = address.split(".") if isinstance(address, str) else []
            if len(parts) != 2 or not all(parts):
                raise IacGateError("bad_address")
            if address in seen_addresses:
                raise IacGateError("duplicate_address")
            seen_addresses.add(address)

            body = change.get("change")
            if not isinstance(body, dict):
                raise IacGateError("bad_change")
            actions = body.get("actions")
            if not isinstance(actions, list):
                raise IacGateError("bad_change")
            if actions and all(action == "delete" for action in actions):
                continue
            after = body.get("after")
            if not isinstance(after, dict):
                raise IacGateError("bad_change")
            unknown = self._unknown_paths(body.get("after_unknown"))
            resource_type = change.get("type")

            for rule in self._rules:
                if rule["resource_type"] != "*" and rule["resource_type"] != resource_type:
                    continue
                hit, code = self._evaluate(rule, after, unknown)
                if not hit:
                    continue
                key = (rule["id"], address)
                if key in active_waivers:
                    waived.append({"rule_id": rule["id"], "address": address})
                else:
                    violations.append(
                        {
                            "rule_id": rule["id"],
                            "address": address,
                            "code": code,
                            "severity": rule["severity"],
                        }
                    )

        violations.sort(
            key=lambda v: (v["address"], _SEVERITY_RANK.get(v["severity"], 4), v["rule_id"])
        )
        waived.sort(key=lambda w: (w["address"], w["rule_id"]))
        return {"ok": not violations, "violations": violations, "waived": waived}

    @staticmethod
    def _validate_rule(rule, seen_ids):
        if not isinstance(rule, dict):
            raise IacGateError("bad_rule")
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise IacGateError("bad_rule")
        if rule_id in seen_ids:
            raise IacGateError("duplicate_rule")
        seen_ids.add(rule_id)
        op = rule.get("op")
        if op not in _OPS:
            raise IacGateError("unknown_op")
        resource_type = rule.get("resource_type")
        if not isinstance(resource_type, str) or not resource_type:
            raise IacGateError("bad_rule")
        path = rule.get("path", "")
        if not isinstance(path, str):
            raise IacGateError("bad_rule")
        value = rule.get("value")
        if op in ("in", "not_in") and not isinstance(value, list):
            raise IacGateError("bad_rule")
        if path == "" and op not in ("exists", "missing"):
            raise IacGateError("bad_rule")
        return {
            "id": rule_id,
            "resource_type": resource_type,
            "path": path,
            "op": op,
            "value": value,
            "severity": rule.get("severity", ""),
        }

    @staticmethod
    def _validate_waiver(waiver):
        if not isinstance(waiver, dict):
            raise IacGateError("bad_waiver")
        ticket = waiver.get("ticket")
        expires_at = waiver.get("expires_at")
        if ticket is None or expires_at is None:
            raise IacGateError("bad_waiver")
        if not isinstance(ticket, str) or not ticket.strip():
            raise IacGateError("bad_waiver")
        if not isinstance(expires_at, (int, float)) or isinstance(expires_at, bool) or expires_at <= 0:
            raise IacGateError("bad_waiver")
        rule_id = waiver.get("rule_id")
        address = waiver.get("address")
        if not isinstance(rule_id, str) or not rule_id:
            raise IacGateError("bad_waiver")
        if not isinstance(address, str) or not address:
            raise IacGateError("bad_waiver")
        return {"rule_id": rule_id, "address": address, "expires_at": expires_at}

    @staticmethod
    def _unknown_paths(after_unknown):
        paths = set()

        def walk(node, prefix):
            if isinstance(node, dict):
                for key, value in node.items():
                    walk(value, "{}.{}".format(prefix, key) if prefix else str(key))
            elif isinstance(node, list):
                for index, item in enumerate(node):
                    walk(item, "{}.{}".format(prefix, index))
            elif node is True and prefix:
                paths.add(prefix)

        if isinstance(after_unknown, dict):
            walk(after_unknown, "")
        return paths

    @staticmethod
    def _resolve(obj, path):
        current = obj
        for part in path.split("."):
            if isinstance(current, dict):
                if part not in current:
                    return False, None
                current = current[part]
            elif isinstance(current, list):
                if not part.isdigit() or int(part) >= len(current):
                    return False, None
                current = current[int(part)]
            else:
                return False, None
        return True, current

    def _evaluate(self, rule, after, unknown):
        path = rule["path"]
        op = rule["op"]
        if path and path in unknown:
            return True, "unknown_value"
        if not path:
            return (op == "exists"), "rule_matched"
        found, actual = self._resolve(after, path)
        if not found:
            if op == "missing":
                return True, "missing_attribute"
            return False, None
        if op == "exists":
            return True, "rule_matched"
        if op == "missing":
            return False, None
        value = rule["value"]
        if op == "eq":
            return actual == value, "rule_matched"
        if op == "ne":
            return actual != value, "rule_matched"
        if op == "in":
            return actual in value, "rule_matched"
        if op == "not_in":
            return actual not in value, "rule_matched"
        if op == "contains":
            if isinstance(actual, (list, str)):
                return value in actual, "rule_matched"
            return False, None
        if op == "not_contains":
            if isinstance(actual, (list, str)):
                return value not in actual, "rule_matched"
            return False, None
        return False, None
