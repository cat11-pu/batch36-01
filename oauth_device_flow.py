class DeviceFlowError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class DeviceAuthorization:
    def __init__(self, clients, scopes, interval=5, ttl=600):
        pass

    def start(self, client_id, scope, now):
        return None

    def approve(self, user_code, subject, now):
        return None

    def poll(self, device_code, now):
        return None
