class HeaderComposerError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class SmtpHeaderComposer:
    def __init__(self, max_recipients=20, max_body=10000):
        pass

    def assemble(self, message, now=0):
        return None

    def audit(self):
        return None
