class WafCanonError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class WafPayloadCanonicalizer:
    def __init__(self, max_depth=3, max_len=8192, mode="text"):
        pass

    def canonicalize(self, payload, now=0):
        return None

    def snapshot(self):
        return None
