class HandshakeError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class AgentConsoleHandshake:
    def __init__(self, origins_by_tenant, tickets):
        pass

    def accept(self, tenant, request, now=0):
        return None

    def snapshot(self):
        return None
