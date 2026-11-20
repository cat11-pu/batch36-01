class TenantScopeError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class TenantScopePlanner:
    def __init__(self, tables, shared_tables=()):
        pass

    def plan(self, tenant, query):
        return None
