class DualKeyError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class DualKeyRing:
    def __init__(self, crypto, max_grace=3600, min_interval=60):
        pass

    def install(self, version, key_id, now=0):
        return None

    def promote(self, version, now=0):
        return None

    def encrypt(self, plaintext, now=0):
        return None

    def decrypt(self, blob, now=0):
        return None

    def retire(self, version, now=0):
        return None

    def compromise(self, version, now=0):
        return None

    def snapshot(self):
        return None
