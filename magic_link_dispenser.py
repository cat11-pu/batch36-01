class MagicLinkError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


import copy
import hashlib
import secrets
import threading
from urllib.parse import urlencode, urlsplit, urlunsplit


def _normalize_email(email):
    return (email or "").strip().lower()


def _comparison_form(uri):
    parts = urlsplit(uri)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class MagicLinkDispenser:
    def __init__(self, base_url, redirect_allowlist, ttl=900, max_attempts=5):
        self._base_url = base_url
        self._allowlist = {_comparison_form(uri) for uri in redirect_allowlist}
        self._ttl = ttl
        self._max_attempts = max_attempts
        self._links = {}
        self._attempts = {}
        self._lock = threading.Lock()

    def issue(self, email, redirect_uri, binding, now=0):
        email = _normalize_email(email)
        if not email:
            raise ValueError("email must not be empty")
        if not (binding or "").strip():
            raise ValueError("binding must not be empty")
        if _comparison_form(redirect_uri) not in self._allowlist:
            raise MagicLinkError("redirect_not_allowed")
        with self._lock:
            if self._attempts.get(email, 0) >= self._max_attempts:
                raise MagicLinkError("locked")
            for record in self._links.values():
                if record["email"] == email and not record["used"]:
                    record["used"] = True
            token = secrets.token_urlsafe(32)
            self._links[_digest(token)] = {
                "email": email,
                "redirect_uri": redirect_uri,
                "binding": binding,
                "expires_at": now + self._ttl,
                "used": False,
            }
            url = self._base_url + ("&" if "?" in self._base_url else "?") + urlencode({"token": token})
            return {"url": url, "email": email, "expires_at": now + self._ttl}

    def consume(self, token, binding, now=0):
        if not token:
            raise MagicLinkError("invalid_token")
        with self._lock:
            record = self._links.get(_digest(token))
            if record is None:
                raise MagicLinkError("invalid_token")
            if record["used"]:
                raise MagicLinkError("token_used")
            if now >= record["expires_at"]:
                raise MagicLinkError("token_expired")
            email = record["email"]
            if self._attempts.get(email, 0) >= self._max_attempts:
                raise MagicLinkError("locked")
            if record["binding"] != binding:
                self._attempts[email] = self._attempts.get(email, 0) + 1
                raise MagicLinkError("binding_mismatch")
            record["used"] = True
            return {"email": email, "redirect_uri": record["redirect_uri"]}

    def invalidate(self, email):
        email = _normalize_email(email)
        with self._lock:
            for record in self._links.values():
                if record["email"] == email:
                    record["used"] = True

    def snapshot(self):
        with self._lock:
            return copy.deepcopy(
                {
                    "links": [
                        {
                            "digest": digest,
                            "email": record["email"],
                            "redirect_uri": record["redirect_uri"],
                            "expires_at": record["expires_at"],
                            "used": record["used"],
                        }
                        for digest, record in self._links.items()
                    ]
                }
            )
