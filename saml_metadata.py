class MetadataTrustStore:
    def __init__(self, entity_id, anchors, max_validity=604800):
        if entity_id is None or not str(entity_id).strip():
            raise ValueError("entity_id is required")
        self._entity_id = str(entity_id).strip()
        self._max_validity = max_validity
        self._anchors = {}
        for anchor in anchors or []:
            key_id = anchor.get("key_id")
            if not key_id:
                raise ValueError("anchor missing key_id")
            if key_id in self._anchors:
                raise ValueError(f"duplicate key_id: {key_id}")
            if not anchor.get("fingerprint"):
                raise ValueError(f"anchor {key_id} missing fingerprint")
            if anchor.get("not_before") is None or anchor.get("not_after") is None:
                raise ValueError(f"anchor {key_id} missing validity window")
            self._anchors[key_id] = dict(anchor)

    def validate(self, document, signature, now):
        if not isinstance(document, dict):
            raise ValueError("metadata document is required")
        entity_id = document.get("entity_id")
        if entity_id is None:
            raise ValueError("entity_id missing from metadata")
        if str(entity_id).strip() != self._entity_id:
            raise ValueError("entity_id mismatch")

        if not signature:
            raise ValueError("signature is required")
        if signature.get("reference") != "EntityDescriptor":
            raise ValueError("signature must reference the EntityDescriptor")
        digest = signature.get("digest") or ""
        if len(digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in digest):
            raise ValueError("digest must be 64 hex characters")

        anchor = self._anchors.get(signature.get("key_id"))
        if anchor is None:
            raise ValueError("unknown signing key")
        if anchor.get("usage") != "signing":
            raise ValueError("key is not designated for signing")
        if not (anchor["not_before"] <= now <= anchor["not_after"]):
            raise ValueError("signing key is outside its validity window")

        if document.get("signing_cert") != anchor["fingerprint"]:
            raise ValueError("signing certificate fingerprint does not match trust anchor")

        valid_until = document.get("valid_until")
        if valid_until is None:
            raise ValueError("valid_until missing from metadata")
        if valid_until < now:
            raise ValueError("metadata has expired")
        if valid_until > now + self._max_validity:
            raise ValueError("metadata validity exceeds maximum cache duration")

        return {
            "entity_id": self._entity_id,
            "key_id": anchor["key_id"],
            "fingerprint": anchor["fingerprint"],
            "expires_at": valid_until,
        }

    def trusted_keys(self, now):
        return [
            anchor["key_id"]
            for anchor in self._anchors.values()
            if anchor.get("usage") == "signing"
            and anchor["not_before"] <= now <= anchor["not_after"]
        ]
