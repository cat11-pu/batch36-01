class IacGateError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class PlanSentinel:
    def __init__(self, rules, waivers=None, now=0):
        pass

    def scan(self, plan):
        return None
