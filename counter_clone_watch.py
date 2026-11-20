class CounterWatchError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class CounterCloneWatch:
    def __init__(self, jump_threshold=1000):
        pass

    def register(self, credential_id, device_id, counter=0, now=0):
        return None

    def observe(self, credential_id, device_id, counter, signature_ok, now=0):
        return None

    def status(self, credential_id):
        return None

    def recover(self, credential_id, device_id, counter, now=0):
        return None

    def snapshot(self):
        return None
