class CeremonyError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class HsmKeyCeremony:
    def __init__(self, threshold, total_shares, ceremony_ttl=600):
        pass

    def open(self, ceremony_id, holders, now=0):
        return None

    def submit_share(self, ceremony_id, holder, share_id, now=0):
        return None

    def seal(self, ceremony_id, now=0):
        return None

    def abort(self, ceremony_id, reason, now=0):
        return None

    def audit(self, ceremony_id):
        return None
