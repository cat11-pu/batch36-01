class BreakglassError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class BreakglassLease:
    def __init__(self, max_minutes=60, max_renewals=1):
        pass

    def request(self, user, ticket, minutes, justification, now):
        return None

    def approve(self, request_id, approver, now):
        return None

    def check(self, user, now, action="read"):
        return None

    def renew(self, request_id, approver, minutes, now):
        return None

    def close_ticket(self, ticket, now):
        return None

    def revoke(self, request_id, now):
        return None
