class BackupCodeError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


class BackupCodeVault:
    def __init__(self, max_failures=5, ttl=3600, lock_seconds=300, max_codes=20):
        import threading

        self.max_failures = max_failures
        self.ttl = ttl
        self.lock_seconds = lock_seconds
        self.max_codes = max_codes
        self._users = {}
        self._lock = threading.Lock()

    @staticmethod
    def _normalize(code):
        if not isinstance(code, str):
            raise ValueError("code must be a string")
        return code.upper().replace("-", "").replace(" ", "").strip()

    @staticmethod
    def _hash(salt, normalized):
        import hashlib

        return hashlib.sha256((salt + normalized).encode("utf-8")).hexdigest()

    @staticmethod
    def _new_code():
        import secrets

        chars = "".join(secrets.choice(_ALPHABET) for _ in range(16))
        return "-".join(chars[i : i + 4] for i in range(0, 16, 4))

    def generate(self, user, count=10, now=0):
        import secrets

        if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= self.max_codes:
            raise ValueError("count must be between 1 and %d" % self.max_codes)
        codes = []
        entries = []
        seen = set()
        while len(codes) < count:
            plain = self._new_code()
            if plain in seen:
                continue
            seen.add(plain)
            salt = secrets.token_hex(16)
            entries.append(
                {
                    "salt": salt,
                    "hash": self._hash(salt, self._normalize(plain)),
                    "used": False,
                }
            )
            codes.append(plain)
        expires_at = now + self.ttl
        with self._lock:
            self._users[user] = {
                "entries": entries,
                "expires_at": expires_at,
                "failures": 0,
                "locked_until": None,
            }
        return {"codes": codes, "expires_at": expires_at}

    def consume(self, user, code, now):
        normalized = self._normalize(code)
        if not normalized:
            raise ValueError("code must not be empty")
        with self._lock:
            record = self._users.get(user)
            if record is None:
                raise BackupCodeError("unknown_user")
            locked_until = record["locked_until"]
            if locked_until is not None:
                if now < locked_until:
                    raise BackupCodeError("locked")
                record["locked_until"] = None
                record["failures"] = 0
            if now > record["expires_at"]:
                raise BackupCodeError("expired")
            entries = record["entries"]
            if all(entry["used"] for entry in entries):
                raise BackupCodeError("exhausted")
            matched = None
            for entry in entries:
                if entry["hash"] == self._hash(entry["salt"], normalized):
                    matched = entry
                    break
            if matched is None:
                record["failures"] += 1
                if record["failures"] >= self.max_failures:
                    record["locked_until"] = now + self.lock_seconds
                raise BackupCodeError("invalid_code")
            if matched["used"]:
                raise BackupCodeError("already_used")
            matched["used"] = True
            record["failures"] = 0
            remaining = sum(1 for entry in entries if not entry["used"])
            return {"remaining": remaining}

    def remaining(self, user):
        with self._lock:
            record = self._users.get(user)
            if record is None:
                return 0
            return sum(1 for entry in record["entries"] if not entry["used"])

    def export_state(self):
        with self._lock:
            return {
                user: {
                    "codes": [
                        {"hash": entry["hash"], "used": entry["used"]}
                        for entry in record["entries"]
                    ],
                    "expires_at": record["expires_at"],
                    "failures": record["failures"],
                    "locked_until": record["locked_until"],
                }
                for user, record in self._users.items()
            }
