class ParError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class PushedRequestRegistry:
    def __init__(self, clients, response_types, scopes, max_ttl=90):
        pass

    def push(self, client_id, params, now, ttl=60):
        return None

    def consume(self, request_uri, client_id, now):
        return None
