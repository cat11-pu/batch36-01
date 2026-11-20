class FramingError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class HttpFrameArbiter:
    def __init__(self, max_body=1048576):
        pass

    def frame(self, request, now=0):
        return None

    def journal(self):
        return None
