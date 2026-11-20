class AuditSealError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class AuditSealLedger:
    def __init__(self, chain_key, algorithm="sha256"):
        pass

    def append(self, entry, now=0):
        return None

    def verify(self, records, checkpoint=None):
        return None

    def checkpoint(self):
        return None

    def snapshot(self):
        return None
