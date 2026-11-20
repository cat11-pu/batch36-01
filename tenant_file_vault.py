class VaultError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class TenantFileVault:
    def __init__(self, roots, index):
        pass

    def open_read(self, tenant, key, now=0):
        return None

    def issue_handle(self, tenant, key, ttl=60, now=0):
        return None

    def redeem(self, handle, tenant, now):
        return None

    def snapshot(self):
        return None
