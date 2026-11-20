class CodesignError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class ReleaseManifestVerifier:
    def __init__(self, trusted_signers, revoked_serials=(), verify_signature=None,
                 verify_timestamp=None, digest_of=None, max_manifest_age=86400,
                 known_logs=()):
        pass

    def verify(self, manifest, artifacts, now=0):
        return None

    def snapshot(self):
        return None
