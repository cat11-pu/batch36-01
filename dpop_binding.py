import secrets

TOKEN_URL = "https://as.example.com/token"

ALLOWED_ALGORITHMS = frozenset(
    {
        "ES256",
        "ES384",
        "ES512",
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "EdDSA",
    }
)

PRIVATE_KEY_PARAMS = frozenset({"d", "p", "q", "dp", "dq", "qi", "k"})

DPOP_PROOF_TYPE = "dpop+jwt"
TOKEN_TYPE = "DPoP"
HTTP_METHOD = "POST"
ACCESS_TOKEN_TTL = 300


class DpopError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class DpopBoundTokenService:
    def __init__(self, clients, thumbprint, nonce_ttl=60, proof_skew=60, jti_window=300):
        self._clients = clients
        self._thumbprint = thumbprint
        self._nonce_ttl = nonce_ttl
        self._proof_skew = proof_skew
        self._jti_window = jti_window
        self._nonces = {}
        self._seen_jtis = {}
        self._access_tokens = {}
        self._refresh_tokens = {}

    def challenge(self, now):
        nonce = secrets.token_hex(16)
        expires_at = now + self._nonce_ttl
        self._nonces[nonce] = expires_at
        return {"nonce": nonce, "expires_at": expires_at}

    def issue(self, client_id, subject, proof, now):
        claims = self._validate_proof(proof, now)
        if client_id not in self._clients:
            raise DpopError("invalid_client")
        jkt = self._thumbprint(claims["jwk"])
        return self._mint(client_id, subject, jkt, now)

    def refresh(self, refresh_token, proof, now):
        claims = self._validate_proof(proof, now)
        record = self._refresh_tokens.get(refresh_token)
        if record is None or record["used"]:
            raise DpopError("refresh_reused")
        jkt = self._thumbprint(claims["jwk"])
        if jkt != record["jkt"]:
            raise DpopError("binding_mismatch")
        record["used"] = True
        del self._refresh_tokens[refresh_token]
        return self._mint(record["client_id"], record["subject"], record["jkt"], now)

    def _validate_proof(self, proof, now):
        if not isinstance(proof, dict):
            raise DpopError("invalid_proof")

        if proof.get("typ") != DPOP_PROOF_TYPE:
            raise DpopError("invalid_proof_type")

        if proof.get("alg") not in ALLOWED_ALGORITHMS:
            raise DpopError("invalid_algorithm")

        jwk = proof.get("jwk")
        if not isinstance(jwk, dict):
            raise DpopError("invalid_proof")
        if any(param in jwk for param in PRIVATE_KEY_PARAMS):
            raise DpopError("private_key_exposed")

        if proof.get("htm") != HTTP_METHOD:
            raise DpopError("invalid_method")

        if proof.get("htu") != TOKEN_URL:
            raise DpopError("invalid_target")

        iat = proof.get("iat")
        if not isinstance(iat, int) or isinstance(iat, bool) or abs(now - iat) > self._proof_skew:
            raise DpopError("invalid_proof_time")

        nonce = proof.get("nonce")
        if not isinstance(nonce, str) or not nonce or nonce not in self._nonces:
            raise DpopError("invalid_nonce")
        if now >= self._nonces[nonce]:
            raise DpopError("invalid_nonce")

        jti = proof.get("jti")
        if not isinstance(jti, str) or not jti:
            raise DpopError("invalid_proof")
        seen_at = self._seen_jtis.get(jti)
        if seen_at is not None and now - seen_at < self._jti_window:
            raise DpopError("replay_detected")
        self._seen_jtis[jti] = now

        return proof

    def _mint(self, client_id, subject, jkt, now):
        access_token = secrets.token_hex(32)
        refresh_token = secrets.token_hex(32)
        expires_at = now + ACCESS_TOKEN_TTL
        record = {
            "client_id": client_id,
            "subject": subject,
            "jkt": jkt,
            "expires_at": expires_at,
            "used": False,
        }
        self._access_tokens[access_token] = dict(record)
        self._refresh_tokens[refresh_token] = record
        return {
            "token_type": TOKEN_TYPE,
            "jkt": jkt,
            "expires_in": ACCESS_TOKEN_TTL,
            "access_token": access_token,
            "refresh_token": refresh_token,
        }
