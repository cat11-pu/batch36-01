class SshCertError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class SshUserCertAuthority:
    def __init__(self, trusted_cas, allowed_principals, verify_signature=None, allow_wildcard=False):
        pass

    def verify(self, cert, client_ip, now):
        return None
