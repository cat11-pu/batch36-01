class SignatureError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class SignatureMultimatch:
    def __init__(self, rules, max_hits=100, max_payload=65536):
        pass

    def scan(self, payload, now=0):
        return None

    def snapshot(self):
        return None
