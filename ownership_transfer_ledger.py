class OwnershipError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class OwnershipLedger:
    def __init__(self, objects, users):
        pass

    def share(self, object_id, actor, grantee, level):
        return None

    def request_transfer(self, object_id, actor, target, now, ttl=3600):
        return None

    def accept_transfer(self, transfer_id, actor, now):
        return None

    def check(self, object_id, actor, action, ticket=None):
        return None
