import base64
import binascii
import copy
import hashlib
import secrets
import threading


ARTIFACT_TYPE = b"\x00\x04"
ARTIFACT_LENGTH = 44
SOURCE_ID_OFFSET = 4
SOURCE_ID_LENGTH = 20
HANDLE_LENGTH = 20


class SamlArtifactError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class ArtifactVault:
    def __init__(self, entity_id, source_id, ttl=120):
        if not isinstance(source_id, (bytes, bytearray)) or len(source_id) != SOURCE_ID_LENGTH:
            raise ValueError("source_id must be exactly 20 bytes")
        self.entity_id = entity_id
        self.source_id = bytes(source_id)
        self.ttl = ttl
        self._pending = {}
        self._consumed = set()
        self._lock = threading.Lock()

    def issue(self, sp_entity_id, assertion_ref, endpoint_index=0, now=0):
        if not sp_entity_id or not isinstance(sp_entity_id, str):
            raise ValueError("sp_entity_id must be a non-empty string")
        if not assertion_ref or not isinstance(assertion_ref, str):
            raise ValueError("assertion_ref must be a non-empty string")
        if isinstance(endpoint_index, bool) or not isinstance(endpoint_index, int):
            raise ValueError("endpoint_index must be a non-negative integer")
        if endpoint_index < 0 or endpoint_index > 0xFFFF:
            raise ValueError("endpoint_index must be a non-negative integer in 0..65535")

        with self._lock:
            handle = secrets.token_bytes(HANDLE_LENGTH)
            while handle in self._pending or handle in self._consumed:
                handle = secrets.token_bytes(HANDLE_LENGTH)
            raw = (
                ARTIFACT_TYPE
                + endpoint_index.to_bytes(2, "big")
                + self.source_id
                + handle
            )
            self._pending[handle] = {
                "sp_entity_id": sp_entity_id,
                "assertion_ref": assertion_ref,
                "endpoint_index": endpoint_index,
                "issued_at": now,
            }
            return base64.b64encode(raw).decode("ascii")

    def resolve(self, artifact, sp_entity_id, endpoint_index=0, now=0):
        raw = self._decode_artifact(artifact)

        if len(raw) != ARTIFACT_LENGTH:
            raise SamlArtifactError("bad_artifact_length")
        if raw[:2] != ARTIFACT_TYPE:
            raise SamlArtifactError("bad_artifact_type")

        artifact_endpoint_index = int.from_bytes(raw[2:4], "big")
        if raw[SOURCE_ID_OFFSET:SOURCE_ID_OFFSET + SOURCE_ID_LENGTH] != self.source_id:
            raise SamlArtifactError("source_mismatch")
        if artifact_endpoint_index != endpoint_index:
            raise SamlArtifactError("endpoint_mismatch")

        handle = raw[SOURCE_ID_OFFSET + SOURCE_ID_LENGTH:]

        with self._lock:
            if handle in self._consumed:
                raise SamlArtifactError("artifact_reused")
            record = self._pending.get(handle)
            if record is None:
                raise SamlArtifactError("unknown_artifact")
            if record["sp_entity_id"] != sp_entity_id:
                raise SamlArtifactError("sp_mismatch")
            if now - record["issued_at"] > self.ttl:
                raise SamlArtifactError("artifact_expired")

            del self._pending[handle]
            self._consumed.add(handle)
            return {
                "sp_entity_id": record["sp_entity_id"],
                "assertion_ref": record["assertion_ref"],
            }

    def discard(self, artifact):
        raw = self._decode_artifact(artifact)
        handle = raw[SOURCE_ID_OFFSET + SOURCE_ID_LENGTH:]
        with self._lock:
            removed = self._pending.pop(handle, None) is not None
            self._consumed.discard(handle)
            return removed

    def snapshot(self):
        with self._lock:
            pending = {}
            for handle, record in self._pending.items():
                handle_ref = hashlib.sha256(handle).hexdigest()
                pending[handle_ref] = {
                    "sp_entity_id": record["sp_entity_id"],
                    "assertion_ref": record["assertion_ref"],
                    "endpoint_index": record["endpoint_index"],
                    "issued_at": record["issued_at"],
                    "expires_at": record["issued_at"] + self.ttl,
                }
            return {"pending": copy.deepcopy(pending)}

    @staticmethod
    def _decode_artifact(artifact):
        if not isinstance(artifact, str):
            raise SamlArtifactError("bad_artifact_encoding")
        trimmed = artifact.strip()
        if any(ch.isspace() for ch in trimmed):
            raise SamlArtifactError("bad_artifact_encoding")
        try:
            return base64.b64decode(trimmed, validate=True)
        except (binascii.Error, ValueError):
            raise SamlArtifactError("bad_artifact_encoding")
