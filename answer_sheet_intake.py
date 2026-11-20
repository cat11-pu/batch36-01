class IntakeError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class AnswerSheetIntake:
    def __init__(self, kinds, max_bytes=1048576):
        pass

    def admit(self, upload, now=0):
        return None

    def snapshot(self):
        return None
