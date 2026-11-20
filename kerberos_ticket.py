class KerberosError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class KerberosTicketGuard:
    def __init__(self, realm, services, max_skew=300, replay_window=600):
        pass

    def validate(self, ticket, authenticator, now):
        return None

    def renew(self, ticket, now, lifetime=600):
        return None
