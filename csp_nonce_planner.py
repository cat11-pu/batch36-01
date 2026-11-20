class CspPlanError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class CspNoncePlanner:
    def __init__(self, nonce_source, min_len=16, max_len=64, reuse_window=300):
        pass

    def build(self, policy, now=0):
        return None

    def report(self, payload, now=0):
        return None

    def snapshot(self):
        return None
