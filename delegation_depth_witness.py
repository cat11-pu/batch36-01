class DelegationError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class DelegationWitness:
    def __init__(self, secret, max_depth=3, clock_skew=0):
        pass

    def issue(self, subject, audience, scopes, ttl, now, allow_redelegate=True):
        return None

    def redelegate(self, token, subject, audience, scopes, ttl, now, allow_redelegate=True):
        return None

    def verify(self, token, audience, required_scope, now, revoked=()):
        return None

    def chain(self, token):
        return None
