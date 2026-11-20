class MagicLinkError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class MagicLinkDispenser:
    def __init__(self, base_url, redirect_allowlist, ttl=900, max_attempts=5):
        pass

    def issue(self, email, redirect_uri, binding, now=0):
        return None

    def consume(self, token, binding, now=0):
        return None

    def invalidate(self, email):
        return None

    def snapshot(self):
        return None
