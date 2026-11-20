class EnvelopeError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class EnvelopeCipher:
    def __init__(self, keys, crypto, max_dek_uses=100):
        pass

    def encrypt(self, key_id, plaintext, context, now=0):
        return None

    def decrypt(self, blob, context, now=0):
        return None

    def rewrap(self, blob, new_key_id, now=0):
        return None

    def revoke_key(self, key_id, now=0):
        return None

    def snapshot(self):
        return None
