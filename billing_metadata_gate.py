class MetadataError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class BillingMetadataGate:
    def __init__(self, callers, clock_skew=30, max_metadata_bytes=4096, max_timeout_ms=5000):
        pass

    def check(self, invocation, now):
        return None

    def snapshot(self):
        return None
