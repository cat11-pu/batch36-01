import copy
import ipaddress
import numbers
import re


class AttributeGateError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


_MISSING = object()
_ROOTS = ("subject", "resource", "context")

_OPERATORS = {
    "eq": "eq",
    "==": "eq",
    "ne": "ne",
    "neq": "ne",
    "!=": "ne",
    "in": "in",
    "in_set": "in",
    "notin": "not_in",
    "not_in": "not_in",
    "not-in": "not_in",
    "nin": "not_in",
    "lt": "lt",
    "<": "lt",
    "lte": "lte",
    "<=": "lte",
    "gt": "gt",
    ">": "gt",
    "gte": "gte",
    ">=": "gte",
    "exists": "exists",
    "cidr": "cidr",
    "in_cidr": "cidr",
}

_COMBINATORS = ("allOf", "anyOf", "noneOf")


def _glob_regex(pattern, block_colon):
    parts = []
    for char in pattern:
        if char == "*":
            parts.append("[^:]*" if block_colon else ".*")
        else:
            parts.append(re.escape(char))
    return re.compile("^" + "".join(parts) + r"\Z")


def _compile_resource(pattern):
    if not isinstance(pattern, str) or not pattern:
        raise AttributeGateError("bad_rule")
    return tuple(_glob_regex(part, True) for part in pattern.split(":"))


def _compile_action(pattern):
    if not isinstance(pattern, str) or not pattern:
        raise AttributeGateError("bad_rule")
    return _glob_regex(pattern, False)


def _canonical_operator(op):
    if not isinstance(op, str):
        raise AttributeGateError("unknown_operator")
    canonical = _OPERATORS.get(op.lower())
    if canonical is None:
        raise AttributeGateError("unknown_operator")
    return canonical


def _validate_condition(node):
    if not isinstance(node, dict):
        raise AttributeGateError("bad_rule")

    combinators = [name for name in _COMBINATORS if name in node]
    if combinators:
        if len(combinators) != 1:
            raise AttributeGateError("bad_rule")
        if any(key in node for key in ("attr", "op", "value")):
            raise AttributeGateError("bad_rule")
        children = node[combinators[0]]
        if not isinstance(children, (list, tuple)):
            raise AttributeGateError("bad_rule")
        for child in children:
            _validate_condition(child)
        return

    attr = node.get("attr")
    if not isinstance(attr, str) or not attr:
        raise AttributeGateError("bad_rule")
    op = _canonical_operator(node.get("op"))
    if op != "exists" and "value" not in node:
        raise AttributeGateError("bad_rule")


def _resolve_attribute(request, path):
    parts = path.split(".")
    if not parts or parts[0] not in _ROOTS:
        return _MISSING

    value = request
    for part in parts:
        if not isinstance(value, dict) or part not in value:
            return _MISSING
        value = value[part]
    return value


def _is_number(value):
    return (
        isinstance(value, numbers.Number)
        and not isinstance(value, (bool, complex))
    )


def _numeric_operand(value):
    if not _is_number(value):
        raise AttributeGateError("bad_operand")
    return value


def _evaluate_leaf(node, request):
    actual = _resolve_attribute(request, node["attr"])
    op = _canonical_operator(node.get("op"))

    if op == "exists":
        return actual is not _MISSING
    if actual is _MISSING:
        return False

    expected = node.get("value")

    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    if op in ("in", "not_in"):
        if not isinstance(expected, (list, tuple, set, frozenset)):
            raise AttributeGateError("bad_operand")
        try:
            contained = actual in expected
        except TypeError:
            raise AttributeGateError("bad_operand")
        return contained if op == "in" else not contained
    if op in ("lt", "lte", "gt", "gte"):
        left = _numeric_operand(actual)
        right = _numeric_operand(expected)
        try:
            if op == "lt":
                return left < right
            if op == "lte":
                return left <= right
            if op == "gt":
                return left > right
            return left >= right
        except TypeError:
            raise AttributeGateError("bad_operand")
    if op == "cidr":
        if not isinstance(actual, str) or not isinstance(expected, str):
            raise AttributeGateError("bad_operand")
        try:
            address = ipaddress.ip_address(actual)
            network = ipaddress.ip_network(expected, strict=False)
        except ValueError:
            raise AttributeGateError("bad_operand")
        if address.version != network.version:
            return False
        return address in network

    raise AttributeGateError("unknown_operator")


def _evaluate_condition(node, request):
    for name in _COMBINATORS:
        if name in node:
            children = node[name]
            if name == "allOf":
                return all(_evaluate_condition(child, request) for child in children)
            if name == "anyOf":
                return any(_evaluate_condition(child, request) for child in children)
            return not any(_evaluate_condition(child, request) for child in children)
    return _evaluate_leaf(node, request)


class AttributeGate:
    def __init__(self, policy):
        rules = policy.get("rules") if isinstance(policy, dict) else policy
        if not isinstance(rules, (list, tuple)):
            raise AttributeGateError("bad_rule")

        self._rules = []
        seen = set()

        for rule in rules:
            if not isinstance(rule, dict):
                raise AttributeGateError("bad_rule")

            rule_id = rule.get("id")
            if not isinstance(rule_id, str) or not rule_id:
                raise AttributeGateError("bad_rule")
            if rule_id in seen:
                raise AttributeGateError("duplicate_rule")
            seen.add(rule_id)

            effect = rule.get("effect")
            if effect not in ("allow", "deny"):
                raise AttributeGateError("bad_rule")

            action_re = _compile_action(rule.get("action"))
            resource_res = _compile_resource(rule.get("resource"))

            condition = rule.get("condition")
            _validate_condition(condition)

            obligations = rule.get("obligations", [])
            if not isinstance(obligations, (list, tuple)):
                raise AttributeGateError("bad_rule")

            self._rules.append(
                {
                    "id": rule_id,
                    "effect": effect,
                    "action_re": action_re,
                    "resource_res": resource_res,
                    "condition": copy.deepcopy(condition),
                    "obligations": copy.deepcopy(list(obligations)),
                }
            )

    def evaluate(self, request):
        if not isinstance(request, dict):
            raise AttributeGateError("bad_request")

        action = request.get("action")
        if not isinstance(action, str) or not action:
            raise AttributeGateError("bad_request")

        resource = request.get("resource")
        resource_type = None
        resource_name = None
        if isinstance(resource, dict):
            resource_type = resource.get("type")
            resource_name = resource.get("name")

        resource_matches = (
            isinstance(resource_type, str) and isinstance(resource_name, str)
        )

        matched = []
        allowed_rules = []
        denied = False

        for rule in self._rules:
            if rule["action_re"].match(action) is None:
                continue
            if not resource_matches:
                continue
            if len(rule["resource_res"]) != 2:
                continue
            if rule["resource_res"][0].match(resource_type) is None:
                continue
            if rule["resource_res"][1].match(resource_name) is None:
                continue
            if not _evaluate_condition(rule["condition"], request):
                continue

            matched.append(rule["id"])
            if rule["effect"] == "deny":
                denied = True
            else:
                allowed_rules.append(rule)

        if denied:
            return {
                "allowed": False,
                "reason": "deny",
                "matched": matched,
                "obligations": [],
            }

        if allowed_rules:
            obligations = []
            for rule in allowed_rules:
                obligations.extend(copy.deepcopy(rule["obligations"]))
            return {
                "allowed": True,
                "reason": "allow",
                "matched": matched,
                "obligations": obligations,
            }

        return {
            "allowed": False,
            "reason": "no_match",
            "matched": [],
            "obligations": [],
        }
