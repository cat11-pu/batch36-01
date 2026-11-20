import copy
import hashlib
import secrets
import threading


class RefreshError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _normalize_scopes(scopes):
    if not isinstance(scopes, list) or not scopes:
        raise ValueError("invalid_scopes")
    seen = set()
    normalized = []
    for scope in scopes:
        if scope not in seen:
            seen.add(scope)
            normalized.append(scope)
    return normalized


class RefreshRotationStore:
    def __init__(self, token_ttl=3600, max_family_len=10):
        self._token_ttl = token_ttl
        self._max_family_len = max_family_len
        self._tokens = {}
        self._families = {}
        self._lock = threading.Lock()

    def _new_token(self):
        while True:
            token = secrets.token_hex(16)
            if token not in self._tokens:
                return token

    def _new_family_id(self):
        while True:
            family_id = secrets.token_hex(8)
            if family_id not in self._families:
                return family_id

    def issue(self, client_id, subject, scopes, now=0):
        if not client_id or not subject:
            raise ValueError("invalid_principal")
        normalized = _normalize_scopes(scopes)
        with self._lock:
            token = self._new_token()
            family_id = self._new_family_id()
            record = {
                "token": token,
                "family_id": family_id,
                "client_id": client_id,
                "subject": subject,
                "scopes": list(normalized),
                "issued_at": now,
                "expires_at": now + self._token_ttl,
                "used": False,
            }
            self._tokens[token] = record
            self._families[family_id] = {
                "client_id": client_id,
                "subject": subject,
                "scopes": list(normalized),
                "length": 1,
                "revoked": False,
            }
            return copy.deepcopy(record)

    def rotate(self, token, client_id, scopes=None, now=0):
        with self._lock:
            record = self._tokens.get(token)
            if record is None:
                raise RefreshError("unknown_token")
            family = self._families[record["family_id"]]
            if record["used"]:
                family["revoked"] = True
                raise RefreshError("token_reuse")
            if family["revoked"]:
                raise RefreshError("family_revoked")
            if now > record["expires_at"]:
                raise RefreshError("expired")
            if client_id != record["client_id"]:
                raise RefreshError("client_mismatch")
            if family["length"] >= self._max_family_len:
                raise RefreshError("family_exhausted")
            if scopes is None:
                new_scopes = list(family["scopes"])
            else:
                new_scopes = _normalize_scopes(scopes)
                if not set(new_scopes) <= set(family["scopes"]):
                    raise RefreshError("scope_escalation")
            record["used"] = True
            new_token = self._new_token()
            new_record = {
                "token": new_token,
                "family_id": record["family_id"],
                "client_id": record["client_id"],
                "subject": record["subject"],
                "scopes": list(new_scopes),
                "issued_at": now,
                "expires_at": now + self._token_ttl,
                "used": False,
            }
            self._tokens[new_token] = new_record
            family["scopes"] = list(new_scopes)
            family["length"] += 1
            return copy.deepcopy(new_record)

    def revoke_family(self, family_id):
        with self._lock:
            family = self._families.get(family_id)
            if family is not None:
                family["revoked"] = True

    def inspect(self, token):
        with self._lock:
            record = self._tokens.get(token)
            if record is None:
                raise RefreshError("unknown_token")
            family = self._families[record["family_id"]]
            return {
                "family_id": record["family_id"],
                "client_id": record["client_id"],
                "subject": record["subject"],
                "scopes": list(record["scopes"]),
                "issued_at": record["issued_at"],
                "expires_at": record["expires_at"],
                "used": record["used"],
                "family_revoked": family["revoked"],
            }

    def snapshot(self):
        with self._lock:
            tokens = {}
            for token, record in self._tokens.items():
                digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
                masked = {k: copy.deepcopy(v) for k, v in record.items() if k != "token"}
                tokens[digest] = masked
            return {
                "tokens": tokens,
                "families": copy.deepcopy(self._families),
            }
