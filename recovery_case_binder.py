class RecoveryError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class RecoveryCaseBinder:
    def __init__(self, ttl=86400, required_approvals=2):
        pass

    def open_case(self, account_id, requester, evidence, now=0):
        return None

    def approve(self, case_id, approver, now=0):
        return None

    def deny(self, case_id, approver, now=0):
        return None

    def issue_token(self, case_id, now=0):
        return None

    def complete(self, case_id, token, now=0):
        return None

    def snapshot(self):
        return None
