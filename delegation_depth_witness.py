class DelegationError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


import hashlib
import hmac
import json
import threading
import uuid


_TOKEN_FIELDS = (
    "token_id",
    "subject",
    "audience",
    "scopes",
    "expiry",
    "depth",
    "allow_redelegate",
    "ancestors",
    "signature",
)


class DelegationWitness:
    def __init__(self, secret, max_depth=3, clock_skew=0):
        if not secret:
            raise DelegationError("invalid_request")
        self._key = str(secret).encode("utf-8")
        self._max_depth = int(max_depth)
        self._clock_skew = int(clock_skew)
        self._lock = threading.Lock()
        self._counter = 0

    def issue(self, subject, audience, scopes, ttl, now, allow_redelegate=True):
        self._validate_request(subject, audience, scopes, ttl)
        if 0 > self._max_depth:
            raise DelegationError("depth_exceeded")
        return self._mint(
            subject=subject,
            audience=audience,
            scopes=list(scopes),
            expiry=now + ttl,
            depth=0,
            allow_redelegate=bool(allow_redelegate),
            ancestors=[],
        )

    def redelegate(self, token, subject, audience, scopes, ttl, now, allow_redelegate=True):
        parent = self._checked_token(token)
        self._validate_request(subject, audience, scopes, ttl)
        depth = parent["depth"] + 1
        if depth > self._max_depth:
            raise DelegationError("depth_exceeded")
        if not set(scopes).issubset(set(parent["scopes"])):
            raise DelegationError("scope_escalation")
        expiry = now + ttl
        if expiry > parent["expiry"]:
            raise DelegationError("expiry_exceeds_parent")
        if not parent["allow_redelegate"]:
            raise DelegationError("redelegation_forbidden")
        ancestors = parent["ancestors"] + [
            {"token_id": parent["token_id"], "subject": parent["subject"]}
        ]
        return self._mint(
            subject=subject,
            audience=audience,
            scopes=list(scopes),
            expiry=expiry,
            depth=depth,
            allow_redelegate=bool(allow_redelegate),
            ancestors=ancestors,
        )

    def verify(self, token, audience, required_scope, now, revoked=()):
        claims = self._checked_token(token)
        revoked_ids = set(revoked or ())
        ancestor_ids = {a["token_id"] for a in claims["ancestors"]}
        if claims["token_id"] in revoked_ids or ancestor_ids & revoked_ids:
            raise DelegationError("revoked")
        if claims["audience"] != audience:
            raise DelegationError("audience_mismatch")
        if required_scope not in claims["scopes"]:
            raise DelegationError("scope_missing")
        if now > claims["expiry"] + self._clock_skew:
            raise DelegationError("expired")
        return {
            "token_id": claims["token_id"],
            "subject": claims["subject"],
            "audience": claims["audience"],
            "scopes": list(claims["scopes"]),
            "expiry": claims["expiry"],
            "depth": claims["depth"],
            "allow_redelegate": claims["allow_redelegate"],
            "subjects": [a["subject"] for a in claims["ancestors"]]
            + [claims["subject"]],
        }

    def chain(self, token):
        claims = self._checked_token(token)
        return {
            "subjects": [a["subject"] for a in claims["ancestors"]]
            + [claims["subject"]],
            "depth": claims["depth"],
        }

    def _validate_request(self, subject, audience, scopes, ttl):
        if not subject or not isinstance(subject, str):
            raise DelegationError("invalid_request")
        if not audience or not isinstance(audience, str):
            raise DelegationError("invalid_request")
        if not scopes or not all(isinstance(s, str) and s for s in scopes):
            raise DelegationError("invalid_request")
        if not isinstance(ttl, (int, float)) or isinstance(ttl, bool) or ttl <= 0:
            raise DelegationError("invalid_request")

    def _next_token_id(self):
        with self._lock:
            self._counter += 1
            counter = self._counter
        return f"tok-{counter}-{uuid.uuid4().hex}"

    def _canonical(self, fields):
        return json.dumps(
            fields, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def _sign(self, fields):
        return hmac.new(
            self._key, self._canonical(fields), hashlib.sha256
        ).hexdigest()

    def _mint(self, subject, audience, scopes, expiry, depth,
              allow_redelegate, ancestors):
        fields = {
            "token_id": self._next_token_id(),
            "subject": subject,
            "audience": audience,
            "scopes": list(scopes),
            "expiry": expiry,
            "depth": depth,
            "allow_redelegate": allow_redelegate,
            "ancestors": [dict(a) for a in ancestors],
        }
        token = dict(fields)
        token["signature"] = self._sign(fields)
        return token

    def _checked_token(self, token):
        if not isinstance(token, dict):
            raise DelegationError("malformed_token")
        for field in _TOKEN_FIELDS:
            if field not in token:
                raise DelegationError("malformed_token")
        if not isinstance(token["token_id"], str) or not token["token_id"]:
            raise DelegationError("malformed_token")
        if not isinstance(token["subject"], str) or not token["subject"]:
            raise DelegationError("malformed_token")
        if not isinstance(token["audience"], str) or not token["audience"]:
            raise DelegationError("malformed_token")
        scopes = token["scopes"]
        if (
            not isinstance(scopes, list)
            or not scopes
            or not all(isinstance(s, str) and s for s in scopes)
        ):
            raise DelegationError("malformed_token")
        if not isinstance(token["expiry"], (int, float)) or isinstance(
            token["expiry"], bool
        ):
            raise DelegationError("malformed_token")
        if not isinstance(token["depth"], int) or isinstance(
            token["depth"], bool
        ) or token["depth"] < 0:
            raise DelegationError("malformed_token")
        if not isinstance(token["allow_redelegate"], bool):
            raise DelegationError("malformed_token")
        ancestors = token["ancestors"]
        if not isinstance(ancestors, list) or not all(
            isinstance(a, dict)
            and isinstance(a.get("token_id"), str)
            and isinstance(a.get("subject"), str)
            for a in ancestors
        ):
            raise DelegationError("malformed_token")
        if not isinstance(token["signature"], str) or not token["signature"]:
            raise DelegationError("malformed_token")
        if len(ancestors) != token["depth"]:
            raise DelegationError("malformed_token")
        fields = {k: token[k] for k in _TOKEN_FIELDS if k != "signature"}
        expected = self._sign(fields)
        if not hmac.compare_digest(expected, token["signature"]):
            raise DelegationError("signature_mismatch")
        return token
