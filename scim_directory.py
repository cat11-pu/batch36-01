class ScimConflict(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class ScimDirectory:
    def __init__(self, tenant_id, max_page=100):
        pass

    def provision(self, payload, idempotency_key, now):
        return None

    def patch(self, user_id, operations, version, now):
        return None

    def deprovision(self, user_id, version, now):
        return None

    def list_users(self, start_index=1, count=50):
        return None

    def get_user(self, user_id):
        return None
