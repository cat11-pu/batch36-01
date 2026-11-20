class StageError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class MaterialBundleStager:
    def __init__(self, max_entries=500, max_total=50000000, max_entry=5000000, max_ratio=100):
        pass

    def plan(self, members, target_root, now=0):
        return None

    def commit(self, plan):
        return None

    def snapshot(self):
        return None
