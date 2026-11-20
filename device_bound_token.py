class BindingError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class DeviceBindingAuthority:
    def __init__(self, audience, verify_proof=None, max_age=60, ttl=600):
        pass

    def enroll(self, device_public_key, now):
        return None

    def issue(self, device_id, subject, now):
        return None

    def verify(self, token, proof, now, method="POST", url="https://api.example.com/orders"):
        return None

    def revoke_device(self, device_id, now):
        return None
