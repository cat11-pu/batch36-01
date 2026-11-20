import copy
import hashlib
import json
import threading


class EnvelopeError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class EnvelopeCipher:
    def __init__(self, keys, crypto, max_dek_uses=100):
        self._keys = copy.deepcopy(keys)
        self._crypto = crypto
        self._max_dek_uses = max_dek_uses
        self._uses = {}
        self._dek_seq = 0
        self._context_keys = None
        self._lock = threading.RLock()

    @staticmethod
    def _digest_context(context):
        canon = json.dumps(context, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canon.encode("utf-8")).hexdigest()

    def _validate_context(self, context):
        if not isinstance(context, dict) or not context:
            raise EnvelopeError("bad_context")
        for name, value in context.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise EnvelopeError("bad_context")
        key_set = frozenset(context)
        if self._context_keys is None:
            self._context_keys = key_set
        elif key_set != self._context_keys:
            raise EnvelopeError("bad_context")

    def _require_usable_key(self, key_id, now):
        meta = self._keys.get(key_id)
        if meta is None:
            raise EnvelopeError("unknown_key")
        state = meta.get("state")
        if state == "destroyed":
            raise EnvelopeError("key_destroyed")
        if state != "enabled":
            raise EnvelopeError("key_disabled")
        created_at = meta.get("created_at", 0)
        if created_at is not None and now < created_at:
            raise EnvelopeError("key_not_yet_active")
        retire_at = meta.get("retire_at")
        if retire_at is not None and now >= retire_at:
            raise EnvelopeError("key_retired")
        return meta

    @staticmethod
    def _check_blob(blob):
        for field in ("key_id", "dek_id", "wrapped_dek", "sealed", "context_digest"):
            if field not in blob:
                raise EnvelopeError("bad_blob")

    def encrypt(self, key_id, plaintext, context, now=0):
        if not isinstance(plaintext, str) or not plaintext:
            raise EnvelopeError("bad_plaintext")
        with self._lock:
            self._require_usable_key(key_id, now)
            self._validate_context(context)
            self._dek_seq += 1
            dek_id = "dek-%d" % self._dek_seq
            dek = self._crypto.generate()
            token = self._crypto.wrap(key_id, dek)
            digest = self._digest_context(context)
            sealed = self._crypto.seal(dek, plaintext, digest)
            self._uses[dek_id] = 1
            return {
                "key_id": key_id,
                "dek_id": dek_id,
                "wrapped_dek": token,
                "sealed": sealed,
                "context_digest": digest,
            }

    def decrypt(self, blob, context, now=0):
        self._check_blob(blob)
        with self._lock:
            meta = self._keys.get(blob["key_id"])
            if meta is None:
                raise EnvelopeError("unknown_key")
            if meta.get("state") == "destroyed":
                raise EnvelopeError("key_destroyed")
            self._validate_context(context)
            if self._digest_context(context) != blob["context_digest"]:
                raise EnvelopeError("context_mismatch")
            dek = self._crypto.unwrap(blob["wrapped_dek"])
            if not dek:
                raise EnvelopeError("bad_wrapped_dek")
            plaintext = self._crypto.open(dek, blob["sealed"], blob["context_digest"])
            if plaintext is None:
                raise EnvelopeError("integrity_failed")
            dek_id = blob["dek_id"]
            uses = self._uses.get(dek_id)
            if uses is None:
                raise EnvelopeError("unknown_dek")
            if uses > self._max_dek_uses:
                raise EnvelopeError("dek_exhausted")
            self._uses[dek_id] = uses + 1
            return plaintext

    def rewrap(self, blob, new_key_id, now=0):
        self._check_blob(blob)
        with self._lock:
            old = self._keys.get(blob["key_id"])
            if old is None:
                raise EnvelopeError("unknown_key")
            if old.get("state") == "destroyed":
                raise EnvelopeError("key_destroyed")
            self._require_usable_key(new_key_id, now)
            dek = self._crypto.unwrap(blob["wrapped_dek"])
            if not dek:
                raise EnvelopeError("bad_wrapped_dek")
            token = self._crypto.wrap(new_key_id, dek)
            moved = dict(blob)
            moved["key_id"] = new_key_id
            moved["wrapped_dek"] = token
            return moved

    def revoke_key(self, key_id, now=0):
        with self._lock:
            meta = self._keys.get(key_id)
            if meta is None:
                raise EnvelopeError("unknown_key")
            meta["state"] = "destroyed"

    def snapshot(self):
        with self._lock:
            keys = {}
            for key_id, meta in self._keys.items():
                canon = json.dumps(meta, sort_keys=True, separators=(",", ":"))
                keys[key_id] = {
                    "state": meta.get("state"),
                    "digest": hashlib.sha256(canon.encode("utf-8")).hexdigest(),
                }
            return copy.deepcopy({"keys": keys, "uses": dict(self._uses)})
