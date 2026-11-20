class EmailOtpError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class EmailOtpService:
    def __init__(self, ttl=600, max_attempts=5, resend_cooldown=60):
        pass

    def send(self, email, now=0):
        return None

    def verify(self, email, code, now=0):
        return None

    def revoke(self, email):
        return None

    def snapshot(self):
        return None
