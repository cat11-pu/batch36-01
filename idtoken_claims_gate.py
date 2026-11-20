class IdTokenError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class IdTokenGate:
    def __init__(self, issuer, client_id, verify_signature, key_ids, allowed_algs=("RS256", "ES256"), clock_skew=60):
        pass

    def validate(self, token, nonce, now):
        return None
