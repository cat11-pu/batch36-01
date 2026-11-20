class DigestSentinelError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class AssetDigestSentinel:
    def __init__(self, algorithms=("sha256", "sha384", "sha512")):
        pass

    def verify(self, tag, content, now=0):
        return None

    def snapshot(self):
        return None
