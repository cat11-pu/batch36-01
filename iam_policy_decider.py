class IamPolicyError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class IamDecider:
    def __init__(self, identity, resource, boundary=None, session=None):
        pass

    def decide(self, request):
        return None
