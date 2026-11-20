class RouteTribunalError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class ContinueRouteTribunal:
    def __init__(self, allowed_hosts, fallback="/home", max_hops=3):
        pass

    def resolve(self, value, now=0):
        return None

    def audit(self):
        return None
