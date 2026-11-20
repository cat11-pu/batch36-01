import hashlib
import json
import threading


class BackupContextError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class BackupContextBinder:
    def __init__(self, required_keys, signer=None, verifier=None, ttl=86400):
        self._required_keys = frozenset(required_keys)
        self._signer = signer
        self._verifier = verifier
        self._ttl = ttl
        self._lock = threading.Lock()
        self._sealed = 0
        self._opened = 0

    def _normalize_context(self, context):
        if not isinstance(context, dict):
            raise BackupContextError("bad_context")
        keys = set(context)
        missing = self._required_keys - keys
        if missing:
            raise BackupContextError("missing_context_key")
        extra = keys - self._required_keys
        if extra:
            raise BackupContextError("unexpected_context_key")
        normalized = {}
        for key, value in context.items():
            if not isinstance(value, str) or not value.strip():
                raise BackupContextError("bad_context_value")
            normalized[key] = value.strip()
        return normalized

    @staticmethod
    def _context_digest(context):
        return _sha256(_canonical(context))

    @staticmethod
    def _chunk_seal(context_digest, chunk_id, index, data_digest):
        return _sha256("|".join([context_digest, chunk_id, str(index), data_digest]))

    def _validate_chunks(self, chunks):
        if not chunks:
            raise BackupContextError("empty_chunk_list")
        seen = set()
        for chunk in chunks:
            chunk_id = chunk.get("id") if isinstance(chunk, dict) else None
            if not isinstance(chunk_id, str) or not chunk_id.strip():
                raise BackupContextError("bad_chunk_id")
            if chunk_id in seen:
                raise BackupContextError("duplicate_chunk")
            seen.add(chunk_id)
            if not isinstance(chunk.get("data"), str):
                raise BackupContextError("bad_chunk_data")

    def seal_manifest(self, backup_id, context, chunks, now=0):
        normalized = self._normalize_context(context)
        if backup_id != normalized.get("backup_id"):
            raise BackupContextError("backup_id_mismatch")
        self._validate_chunks(chunks)
        context_digest = self._context_digest(normalized)
        manifest_chunks = []
        for index, chunk in enumerate(chunks):
            data_digest = _sha256(chunk["data"])
            manifest_chunks.append(
                {
                    "id": chunk["id"],
                    "index": index,
                    "digest": data_digest,
                    "seal": self._chunk_seal(context_digest, chunk["id"], index, data_digest),
                }
            )
        body = {
            "backup_id": backup_id,
            "context": normalized,
            "context_digest": context_digest,
            "chunks": manifest_chunks,
            "created_at": now,
            "ttl": self._ttl,
        }
        signature = None
        if self._signer is not None:
            try:
                signature = self._signer(_canonical(body))
            except BackupContextError:
                raise
            except Exception as exc:
                raise BackupContextError("signer_error") from exc
        manifest = dict(body)
        manifest["signature"] = signature
        with self._lock:
            self._sealed += 1
        return manifest

    def open_manifest(self, manifest, expected_context, chunks, now=0):
        if not isinstance(manifest, dict):
            raise BackupContextError("bad_manifest")
        signature = manifest.get("signature")
        if self._verifier is not None:
            try:
                verified = self._verifier(
                    {k: v for k, v in manifest.items() if k != "signature"}, signature
                )
            except BackupContextError:
                raise
            except Exception as exc:
                raise BackupContextError("bad_manifest_signature") from exc
            if not verified:
                raise BackupContextError("bad_manifest_signature")
        stored_context = manifest.get("context")
        if not isinstance(stored_context, dict):
            raise BackupContextError("bad_manifest")
        if self._context_digest(stored_context) != manifest.get("context_digest"):
            raise BackupContextError("context_digest_mismatch")
        created_at = manifest.get("created_at", 0)
        ttl = manifest.get("ttl", self._ttl)
        if now - created_at > ttl:
            raise BackupContextError("manifest_expired")
        expected = self._normalize_context(expected_context)
        if (
            "tenant" in expected
            and stored_context.get("tenant") != expected["tenant"]
        ):
            raise BackupContextError("tenant_mismatch")
        if stored_context != expected:
            raise BackupContextError("context_mismatch")
        if manifest.get("backup_id") != expected.get("backup_id"):
            raise BackupContextError("backup_id_mismatch")
        if manifest.get("backup_id") != stored_context.get("backup_id"):
            raise BackupContextError("backup_id_mismatch")

        manifest_chunks = manifest.get("chunks") or []
        provided = list(chunks or [])
        provided_ids = [c.get("id") for c in provided if isinstance(c, dict)]
        manifest_ids = [c.get("id") for c in manifest_chunks]
        if set(manifest_ids) - set(provided_ids):
            raise BackupContextError("missing_chunk")
        if set(provided_ids) - set(manifest_ids):
            raise BackupContextError("unexpected_chunk")
        if len(provided_ids) != len(set(provided_ids)):
            raise BackupContextError("duplicate_chunk")
        context_digest = manifest["context_digest"]
        for index, manifest_chunk in enumerate(manifest_chunks):
            provided_chunk = provided[index]
            if provided_chunk.get("id") != manifest_chunk.get("id"):
                raise BackupContextError("chunk_context_mismatch")
            data = provided_chunk.get("data")
            if not isinstance(data, str):
                raise BackupContextError("bad_chunk_data")
            data_digest = _sha256(data)
            if data_digest != manifest_chunk.get("digest"):
                raise BackupContextError("chunk_corrupt")
            expected_seal = self._chunk_seal(
                context_digest, manifest_chunk["id"], index, data_digest
            )
            if expected_seal != manifest_chunk.get("seal"):
                raise BackupContextError("chunk_context_mismatch")

        with self._lock:
            self._opened += 1
        return {
            "backup_id": manifest["backup_id"],
            "tenant": stored_context.get("tenant"),
            "context": dict(stored_context),
            "chunks": list(manifest_ids),
        }

    def snapshot(self):
        with self._lock:
            return {"sealed": self._sealed, "opened": self._opened}
