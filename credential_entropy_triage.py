class SecretScanError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class CredentialEntropyTriage:
    def __init__(self, min_len=20, max_len=512, entropy_threshold=4.0,
                 allow_prefixes=(), placeholder_markers=("example", "changeme"),
                 known_prefixes=("sk_live_", "ghp_", "AKIA")):
        pass

    def scan(self, text, path="app.py", now=0):
        return None

    def snapshot(self):
        return None
