class PolicyCacheError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class PolicyDecisionCache:
    def __init__(self, evaluator, ttl=30):
        pass

    def publish(self, tenant, version, policy, now=0):
        return None

    def decide(self, tenant, subject, action, resource, now=0):
        return None

    def invalidate(self, tenant, subject=None):
        return None

    def stats(self):
        return {}
