class RefreshError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class RefreshRotationStore:
    def __init__(self, token_ttl=3600, max_family_len=10):
        pass

    def issue(self, client_id, subject, scopes, now=0):
        return None

    def rotate(self, token, client_id, scopes=None, now=0):
        return None

    def revoke_family(self, family_id):
        return None

    def inspect(self, token):
        return None

    def snapshot(self):
        return None
