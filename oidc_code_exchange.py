class ExchangeError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class AuthorizationCodeBroker:
    def __init__(self, issuer, clients, keys, required_acr="urn:mfa", max_age=300):
        pass

    def begin(self, client_id, redirect_uri, now, ttl=120):
        return None

    def redeem(self, client_id, redirect_uri, code, verifier, response, now):
        return None

    def sessions(self):
        return None
