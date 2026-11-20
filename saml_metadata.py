class MetadataTrustStore:
    def __init__(self, entity_id, anchors, max_validity=604800):
        pass

    def validate(self, document, signature, now):
        return None

    def trusted_keys(self, now):
        return None
