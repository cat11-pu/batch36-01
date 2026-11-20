class SamlWrapError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class AssertionWrappingGuard:
    def __init__(self, audience, acs_url, issuers, max_skew=120):
        pass

    def verify(self, envelope, now):
        return None
