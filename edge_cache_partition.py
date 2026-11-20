class CacheKeyError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class EdgeCachePartition:
    def __init__(self, trusted_hosts, max_key_len=512):
        pass

    def derive(self, request, policy, now=0):
        return None

    def snapshot(self):
        return None
