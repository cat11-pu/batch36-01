class ChainError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class ChainBuilder:
    def __init__(self, anchors, max_depth=4, verify_link=None):
        pass

    def build(self, leaf, intermediates, now, purpose="serverAuth"):
        return None

    def audit(self):
        return None
