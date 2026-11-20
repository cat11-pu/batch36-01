class RoleTreeError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class RoleTreeGuard:
    def __init__(self, policy):
        pass

    def check(self, roles, action, node):
        return None

    def effective(self, roles, node):
        return None

    def state(self):
        return {}
