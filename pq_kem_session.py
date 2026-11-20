class KemError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class HybridKemBroker:
    def __init__(self, policy, kem, mac, require_hybrid=True, max_sessions=8):
        pass

    def negotiate(self, client_suites, now=0):
        return None

    def respond(self, negotiation, client_public, transcript, now=0):
        return None

    def confirm(self, session_id, tag, transcript, now=0):
        return None

    def snapshot(self):
        return None
