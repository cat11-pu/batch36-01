class BackupContextError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class BackupContextBinder:
    def __init__(self, required_keys, signer=None, verifier=None, ttl=86400):
        pass

    def seal_manifest(self, backup_id, context, chunks, now=0):
        return None

    def open_manifest(self, manifest, expected_context, chunks, now=0):
        return None

    def snapshot(self):
        return None
