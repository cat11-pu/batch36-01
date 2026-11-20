class IntrospectionError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class IntrospectionBroker:
    def __init__(self, issuer, audiences, verify_token, client_secrets, cache_ttl=60):
        pass

    def introspect(self, token, client_id, client_secret, token_type_hint=None, now=0):
        return None

    def revoke(self, token, now=0):
        return None

    def snapshot(self):
        return None
