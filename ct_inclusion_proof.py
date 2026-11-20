class CtProofError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class CtInclusionAudit:
    def __init__(self, logs, verify_signature=None, max_sct_age=7776000):
        pass

    def verify(self, sct, sth, proof, leaf_cert, now=0):
        return None
