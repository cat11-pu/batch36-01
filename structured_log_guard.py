class LogFieldError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class StructuredLogGuard:
    def __init__(self, max_value_len=256, max_fields=16,
                 levels=("DEBUG", "INFO", "WARN", "ERROR")):
        pass

    def render(self, record, now=0):
        return None

    def snapshot(self):
        return None
