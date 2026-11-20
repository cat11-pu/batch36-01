class EmailOtpError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


import hashlib
import hmac
import secrets
import threading


class EmailOtpService:
    def __init__(self, ttl=600, max_attempts=5, resend_cooldown=60):
        self._ttl = ttl
        self._max_attempts = max_attempts
        self._resend_cooldown = resend_cooldown
        self._secret = secrets.token_bytes(32)
        self._challenges = {}
        self._last_sent_at = {}
        self._locked = set()
        self._superseded = {}
        self._used = {}
        self._lock = threading.Lock()

    @staticmethod
    def _normalize(email):
        return email.strip().lower()

    def _hash(self, email, code):
        return hmac.new(
            self._secret, f"{email}:{code}".encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def send(self, email, now=0):
        email = self._normalize(email)
        with self._lock:
            if email in self._locked:
                raise EmailOtpError("locked")
            last = self._last_sent_at.get(email)
            if last is not None and now - last < self._resend_cooldown:
                raise EmailOtpError("resend_too_soon")
            old = self._challenges.get(email)
            if old is not None:
                self._superseded.setdefault(email, set()).add(old["code_hash"])
            code = f"{secrets.randbelow(1000000):06d}"
            self._challenges[email] = {
                "code_hash": self._hash(email, code),
                "created_at": now,
                "expires_at": now + self._ttl,
                "attempts": 0,
            }
            self._last_sent_at[email] = now
            return {"code": code, "expires_at": now + self._ttl}

    def verify(self, email, code, now=0):
        email = self._normalize(email)
        if not isinstance(code, str) or len(code) != 6 or not code.isdigit():
            raise ValueError("malformed code")
        candidate = self._hash(email, code)
        with self._lock:
            if email in self._locked:
                raise EmailOtpError("locked")
            challenge = self._challenges.get(email)
            if challenge is None:
                if candidate in self._used.get(email, ()):
                    raise EmailOtpError("code_used")
                raise EmailOtpError("no_challenge")
            if now > challenge["expires_at"]:
                raise EmailOtpError("code_expired")
            if hmac.compare_digest(candidate, challenge["code_hash"]):
                del self._challenges[email]
                self._used.setdefault(email, set()).add(candidate)
                return {"ok": True}
            if candidate in self._superseded.get(email, ()):
                raise EmailOtpError("code_superseded")
            challenge["attempts"] += 1
            if challenge["attempts"] >= self._max_attempts:
                self._locked.add(email)
            raise EmailOtpError("bad_code")

    def revoke(self, email):
        email = self._normalize(email)
        with self._lock:
            self._challenges.pop(email, None)
            self._last_sent_at.pop(email, None)
            self._locked.discard(email)
            self._superseded.pop(email, None)
            self._used.pop(email, None)

    def snapshot(self):
        with self._lock:
            return {
                "challenges": {
                    email: dict(record)
                    for email, record in self._challenges.items()
                }
            }
