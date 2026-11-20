class HostRouteError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class VirtualHostRouter:
    def __init__(self, sites, default_site=None, trusted_proxies=()):
        pass

    def resolve(self, request, now=0):
        return None

    def snapshot(self):
        return None
