import copy


class RoleTreeError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class RoleTreeGuard:
    def __init__(self, policy):
        policy = copy.deepcopy(policy)
        self._policy = policy

        roles_cfg = policy.get("roles", {})
        nodes_cfg = policy.get("nodes", {})
        self._actions = list(policy.get("actions", []))
        self._action_set = set(self._actions)

        self._boundaries = {}
        for role_name, cfg in roles_cfg.items():
            boundary = cfg.get("boundary")
            if boundary is not None:
                for action in boundary:
                    if action not in self._action_set:
                        raise RoleTreeError("unknown_action")
                self._boundaries[role_name] = tuple(boundary)

        self._parents = {}
        for role_name, cfg in roles_cfg.items():
            parents = list(cfg.get("parents", []))
            for parent in parents:
                if parent not in roles_cfg:
                    raise RoleTreeError("unknown_role")
            self._parents[role_name] = parents

        self._closures = {}
        self._build_closures()

        self._parent_of = {}
        self._deleted = set()
        for node_name, cfg in nodes_cfg.items():
            parent = cfg.get("parent")
            if parent is not None and parent not in nodes_cfg:
                raise RoleTreeError("unknown_node")
            self._parent_of[node_name] = parent
            if cfg.get("deleted"):
                self._deleted.add(node_name)

        self._paths = {}
        for node_name in nodes_cfg:
            self._paths[node_name] = self._build_path(node_name)

        self._grants = set()
        self._denies = set()
        for entry in policy.get("grants", []):
            self._index_entry(entry, roles_cfg, nodes_cfg, self._grants)
        for entry in policy.get("denies", []):
            self._index_entry(entry, roles_cfg, nodes_cfg, self._denies)

    def _build_closures(self):
        state = {name: 0 for name in self._parents}

        def visit(role_name):
            state[role_name] = 1
            closure = [role_name]
            seen = {role_name}
            for parent in self._parents[role_name]:
                if state[parent] == 1:
                    raise RoleTreeError("role_cycle")
                if state[parent] == 0:
                    visit(parent)
                for inherited in self._closures[parent]:
                    if inherited not in seen:
                        seen.add(inherited)
                        closure.append(inherited)
            state[role_name] = 2
            self._closures[role_name] = closure

        for role_name in self._parents:
            if state[role_name] == 0:
                visit(role_name)

    def _build_path(self, start):
        path = []
        seen = set()
        current = start
        while current is not None:
            if current in seen:
                raise RoleTreeError("node_cycle")
            seen.add(current)
            path.append(current)
            current = self._parent_of[current]
        return tuple(path)

    def _index_entry(self, entry, roles_cfg, nodes_cfg, target):
        role_name = entry["role"]
        action = entry["action"]
        node = entry["node"]
        if role_name not in roles_cfg:
            raise RoleTreeError("unknown_role")
        if action != "*" and action not in self._action_set:
            raise RoleTreeError("unknown_action")
        if node not in nodes_cfg:
            raise RoleTreeError("unknown_node")
        target.add((role_name, action, node))

    @staticmethod
    def _result(allowed, reason, role, node):
        return {
            "allowed": allowed,
            "reason": reason,
            "role": role,
            "node": node,
        }

    def _match_rule(self, identity_role, action, path, rules):
        for current in path:
            for rule_role in self._closures[identity_role]:
                if (rule_role, action, current) in rules:
                    return rule_role, current
                if rule_role == "admin" and (rule_role, "*", current) in rules:
                    return rule_role, current
        return None

    def _validate(self, roles, node):
        if node not in self._paths:
            raise RoleTreeError("unknown_node")
        for identity_role in roles:
            if identity_role not in self._closures:
                raise RoleTreeError("unknown_role")

    def check(self, roles, action, node):
        if not roles:
            return self._result(False, "no_roles", None, node)
        if action not in self._action_set:
            raise RoleTreeError("unknown_action")
        self._validate(roles, node)

        path = self._paths[node]

        for current in path:
            if current in self._deleted:
                return self._result(False, "deleted", roles[0], current)

        for identity_role in roles:
            hit = self._match_rule(identity_role, action, path, self._denies)
            if hit is not None:
                deny_role, deny_node = hit
                return self._result(False, "deny", deny_role, deny_node)

        boundary_role = None
        for identity_role in roles:
            grant = self._match_rule(identity_role, action, path, self._grants)
            if grant is None:
                continue
            boundary = self._boundaries.get(identity_role)
            if boundary is not None and action not in boundary:
                if boundary_role is None:
                    boundary_role = identity_role
                continue
            grant_role, grant_node = grant
            return self._result(True, "grant", grant_role, node)

        if boundary_role is not None:
            return self._result(False, "boundary", boundary_role, node)
        return self._result(False, "no_grant", roles[0], node)

    def effective(self, roles, node):
        if not roles:
            return []
        self._validate(roles, node)
        allowed = set()
        for action in self._actions:
            if self.check(roles, action, node)["allowed"]:
                allowed.add(action)
        return sorted(allowed)

    def state(self):
        return copy.deepcopy(self._policy)
