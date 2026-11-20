class PasskeySyncError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class PasskeySyncLedger:
    def __init__(self, rp_id, verify_signature=None, max_holders=3):
        pass

    def enroll_device(self, device_id, proof, now):
        return None

    def apply_bundle(self, device_id, bundle, now):
        return None

    def resolve(self, credential_id, now):
        return None

    def revoke_device(self, device_id, now):
        return None

    def snapshot(self):
        return None
