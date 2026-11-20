class StapleError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class OcspStapler:
    def __init__(self, max_age=300, clock_skew=60, require_nonce=True):
        pass

    def validate(self, staple, cert, issuer, now, nonce=None):
        return None

    def snapshot(self):
        return None
