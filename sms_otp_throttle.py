class SmsThrottleError(ValueError):
    def __init__(self, code, retry_after=0):
        super().__init__(code)
        self.code = code
        self.retry_after = retry_after


class SmsOtpThrottle:
    def __init__(self, per_phone=3, per_ip=10, global_limit=100, window=3600, cooldown=60, daily_cap=10, blocked_prefixes=()):
        pass

    def request(self, phone, ip, now=0):
        return None

    def snapshot(self):
        return None
