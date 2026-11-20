class SamlArtifactError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class ArtifactVault:
    def __init__(self, entity_id, source_id, ttl=120):
        pass

    def issue(self, sp_entity_id, assertion_ref, endpoint_index=0, now=0):
        return None

    def resolve(self, artifact, sp_entity_id, endpoint_index=0, now=0):
        return None

    def discard(self, artifact):
        return None

    def snapshot(self):
        return None
