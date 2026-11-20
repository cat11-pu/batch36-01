class DpopError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class DpopBoundTokenService:
    def __init__(self, clients, thumbprint, nonce_ttl=60, proof_skew=60, jti_window=300):
        pass

    def challenge(self, now):
        return None

    def issue(self, client_id, subject, proof, now):
        return None

    def refresh(self, refresh_token, proof, now):
        return None
