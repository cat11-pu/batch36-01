class IntrospectionError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


import copy
import hashlib
import hmac
import threading

_KNOWN_HINTS = frozenset({"access_token", "refresh_token"})


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class IntrospectionBroker:
    def __init__(self, issuer, audiences, verify_token, client_secrets, cache_ttl=60):
        if not issuer or not isinstance(issuer, str):
            raise ValueError("issuer must be a non-empty string")
        if not audiences:
            raise ValueError("audiences must be a non-empty collection")
        self._issuer = issuer
        self._audiences = set(audiences)
        self._verify_token = verify_token
        self._client_secret_digests = {
            client_id: _digest(secret)
            for client_id, secret in client_secrets.items()
        }
        self._cache_ttl = cache_ttl
        self._cache = {}
        self._revoked = set()
        self._lock = threading.Lock()

    def introspect(self, token, client_id, client_secret, token_type_hint=None, now=0):
        self._authenticate_client(client_id, client_secret)
        if token_type_hint is not None and token_type_hint not in _KNOWN_HINTS:
            raise ValueError("unknown token_type_hint: %r" % (token_type_hint,))

        token_digest = _digest(token)
        with self._lock:
            if token_digest in self._revoked:
                return {"active": False}
            cached = self._cache.get(token_digest)
            if cached is not None and now - cached[0] < self._cache_ttl:
                return copy.deepcopy(cached[1])

        result = self._build_active_response(token, now)
        if result["active"]:
            with self._lock:
                if token_digest not in self._revoked:
                    self._cache[token_digest] = (now, copy.deepcopy(result))
        return copy.deepcopy(result)

    def revoke(self, token, now=0):
        token_digest = _digest(token)
        with self._lock:
            self._revoked.add(token_digest)
            self._cache.pop(token_digest, None)

    def snapshot(self):
        with self._lock:
            return {
                "revoked": sorted(self._revoked),
                "tokens": {
                    digest: {"cached_at": cached_at}
                    for digest, (cached_at, _result) in self._cache.items()
                },
            }

    def _authenticate_client(self, client_id, client_secret):
        expected = self._client_secret_digests.get(client_id)
        if expected is None:
            raise IntrospectionError("invalid_client")
        if not client_secret:
            raise IntrospectionError("client_auth_required")
        if not hmac.compare_digest(expected, _digest(client_secret)):
            raise IntrospectionError("invalid_client")

    def _build_active_response(self, token, now):
        inactive = {"active": False}
        try:
            claims = self._verify_token(token)
        except Exception:
            return inactive
        if not isinstance(claims, dict):
            return inactive

        iss = claims.get("iss")
        if not iss or iss != self._issuer:
            return inactive

        aud = claims.get("aud")
        token_audiences = set(aud) if isinstance(aud, (list, tuple, set)) else {aud}
        if not token_audiences & self._audiences:
            return inactive

        exp = claims.get("exp")
        nbf = claims.get("nbf")
        iat = claims.get("iat")
        if not isinstance(exp, (int, float)) or now >= exp:
            return inactive
        if isinstance(nbf, (int, float)) and now < nbf:
            return inactive
        if isinstance(iat, (int, float)):
            if iat > now or exp < iat:
                return inactive

        if claims.get("token_type") != "access_token":
            return inactive

        scope = claims.get("scope")
        if scope is not None and not isinstance(scope, list):
            return inactive

        result = {"active": True}
        for key, value in claims.items():
            result[key] = copy.deepcopy(value)
        return result
