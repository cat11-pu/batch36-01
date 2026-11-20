class BudgetError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class PartnerQueryBudget:
    def __init__(self, max_depth=8, max_cost=1000, max_aliases=20, page_factor=10, partner_quota=5000):
        pass

    def measure(self, document):
        return None

    def charge(self, partner, document, now=0):
        return None

    def snapshot(self):
        return None
