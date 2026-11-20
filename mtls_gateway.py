class MtlsError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class MutualTlsAuthenticator:
    def __init__(self, trusted_issuers, accounts, revoked=None, max_chain_depth=1):
        pass

    def authenticate(self, cert, request, now):
        return None
