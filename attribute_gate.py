class AttributeGateError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class AttributeGate:
    def __init__(self, policy):
        pass

    def evaluate(self, request):
        return None
