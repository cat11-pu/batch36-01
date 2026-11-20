class XmlIntakeError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class StatementXmlIntake:
    def __init__(self, max_bytes=65536, max_items=50):
        pass

    def parse(self, raw):
        return None

    def snapshot(self):
        return None
