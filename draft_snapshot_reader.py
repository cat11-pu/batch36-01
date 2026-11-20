class SnapshotError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class DraftSnapshotReader:
    def __init__(self, types, secret, max_depth=6, max_items=1000, max_text=4096, max_bytes=4096):
        pass

    def read(self, envelope, now=0):
        return None

    def snapshot(self):
        return None
