class BackupCodeError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class BackupCodeVault:
    def __init__(self, max_failures=5, ttl=3600, lock_seconds=300, max_codes=20):
        pass

    def generate(self, user, count=10, now=0):
        return None

    def consume(self, user, code, now):
        return None

    def remaining(self, user):
        return None

    def export_state(self):
        return None
