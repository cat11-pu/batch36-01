class HostKeyError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class HostKeyRolloverLedger:
    def __init__(self, max_keys_per_host=3, overlap=3600):
        pass

    def publish(self, host, generation, keys, now=0):
        return None

    def assess(self, host, client_keys, now=0):
        return None

    def merge_update(self, host, client_keys, proposed, now=0):
        return None

    def revoke(self, host, fingerprint, now=0):
        return None

    def snapshot(self):
        return None
