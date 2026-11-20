class LogoutError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class FrontChannelLogoutHub:
    def __init__(self, issuer, clients):
        pass

    def open_session(self, session_id, subject, client_ids, now, ttl=600):
        return None

    def build_frames(self, session_id, now):
        return None

    def handle_frame(self, params, referer, now):
        return None

    def logout_session(self, session_id, now):
        return None
