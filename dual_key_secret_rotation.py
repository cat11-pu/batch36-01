import copy
import math
import threading


class DualKeyError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


_STANDBY = "standby"
_ACTIVE = "active"
_PREVIOUS = "previous"
_RETIRED = "retired"
_REVOKED = "revoked"


def _is_valid_version(version):
    return isinstance(version, int) and not isinstance(version, bool)


def _is_valid_interval(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    )


class DualKeyRing:
    def __init__(self, crypto, max_grace=3600, min_interval=60):
        if not _is_valid_interval(max_grace):
            raise DualKeyError("invalid_grace")
        if not _is_valid_interval(min_interval):
            raise DualKeyError("invalid_interval")
        self._crypto = crypto
        self._max_grace = max_grace
        self._min_interval = min_interval
        self._keys = {}
        self._key_ids = {}
        self._active = None
        self._standby = None
        self._last_promotion_at = None
        self._lock = threading.Lock()

    def install(self, version, key_id, now=0):
        if not _is_valid_version(version):
            raise DualKeyError("invalid_version")
        if not isinstance(key_id, str) or not key_id:
            raise DualKeyError("invalid_key_id")
        with self._lock:
            if self._keys and version <= max(self._keys):
                raise DualKeyError("version_order")
            if key_id in self._key_ids:
                raise DualKeyError("duplicate_key_id")
            if self._standby is not None:
                raise DualKeyError("standby_exists")
            self._keys[version] = {
                "version": version,
                "key_id": key_id,
                "state": _STANDBY,
                "installed_at": now,
                "grace_until": None,
            }
            self._key_ids[key_id] = version
            self._standby = version
            return {"version": version, "key_id": key_id, "state": _STANDBY}

    def promote(self, version, now=0):
        if not _is_valid_version(version):
            raise DualKeyError("invalid_version")
        with self._lock:
            record = self._keys.get(version)
            if record is not None and record["state"] == _REVOKED:
                raise DualKeyError("key_revoked")
            if self._standby is None or version != self._standby:
                raise DualKeyError("no_standby_key")
            if (
                self._last_promotion_at is not None
                and now - self._last_promotion_at < self._min_interval
            ):
                raise DualKeyError("promotion_too_soon")
            previous = self._active
            grace_until = None
            if previous is not None:
                prev_record = self._keys[previous]
                prev_record["state"] = _PREVIOUS
                grace_until = now + self._max_grace
                prev_record["grace_until"] = grace_until
            record["state"] = _ACTIVE
            self._active = version
            self._standby = None
            self._last_promotion_at = now
            return {"active": version, "previous": previous, "grace_until": grace_until}

    def encrypt(self, plaintext, now=0):
        with self._lock:
            if self._active is None:
                raise DualKeyError("no_active_key")
            record = self._keys[self._active]
            if record["state"] != _ACTIVE:
                raise DualKeyError("no_active_key")
            ciphertext = self._crypto.seal(record["key_id"], plaintext)
            return {
                "version": record["version"],
                "key_id": record["key_id"],
                "ciphertext": ciphertext,
            }

    def decrypt(self, blob, now=0):
        try:
            version = blob["version"]
        except (TypeError, KeyError):
            raise DualKeyError("unknown_version")
        with self._lock:
            record = self._keys.get(version)
            if record is None:
                raise DualKeyError("unknown_version")
            state = record["state"]
            if state == _REVOKED:
                raise DualKeyError("key_revoked")
            if state == _RETIRED:
                raise DualKeyError("key_retired")
            if state == _PREVIOUS:
                grace_until = record["grace_until"]
                if grace_until is None or now > grace_until:
                    raise DualKeyError("key_retired")
            elif state != _ACTIVE:
                raise DualKeyError("key_not_active")
            plaintext = self._crypto.open(record["key_id"], blob.get("ciphertext"))
            if plaintext is None:
                raise DualKeyError("decrypt_failed")
            return plaintext

    def retire(self, version, now=0):
        with self._lock:
            record = self._keys.get(version)
            if record is None:
                raise DualKeyError("unknown_version")
            state = record["state"]
            if state == _ACTIVE:
                raise DualKeyError("active_key")
            if state == _RETIRED:
                raise DualKeyError("already_retired")
            if state == _REVOKED:
                raise DualKeyError("key_revoked")
            record["state"] = _RETIRED
            record["grace_until"] = None
            if self._standby == version:
                self._standby = None
            return {"version": version, "state": _RETIRED}

    def compromise(self, version, now=0):
        with self._lock:
            record = self._keys.get(version)
            if record is None:
                raise DualKeyError("unknown_version")
            if record["state"] == _REVOKED:
                raise DualKeyError("key_revoked")
            record["state"] = _REVOKED
            record["grace_until"] = None
            if self._active == version:
                self._active = None
            if self._standby == version:
                self._standby = None
            return {"version": version, "state": _REVOKED}

    def snapshot(self):
        with self._lock:
            return copy.deepcopy(
                {
                    "keys": {
                        version: {
                            "version": rec["version"],
                            "state": rec["state"],
                            "installed_at": rec["installed_at"],
                            "grace_until": rec["grace_until"],
                        }
                        for version, rec in self._keys.items()
                    },
                    "active": self._active,
                    "standby": self._standby,
                    "last_promotion_at": self._last_promotion_at,
                    "max_grace": self._max_grace,
                    "min_interval": self._min_interval,
                }
            )
