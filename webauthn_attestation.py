class AttestationVerifier:
    def __init__(self, rp_id, origins, anchors, verify_signature=None, allow_none=False):
        pass

    def issue(self, user_handle, now, ttl=120):
        return None

    def verify(self, user_handle, response, now):
        return None

    def credentials(self):
        return None
