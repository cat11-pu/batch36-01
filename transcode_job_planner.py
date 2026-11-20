class PlanError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class TranscodeJobPlanner:
    def __init__(self, workdir, allowed_filters, presets=("fast", "medium", "slow"), runner=None):
        pass

    def plan(self, job, now=0):
        return None

    def run(self, plan, now=0):
        return None

    def snapshot(self):
        return None
