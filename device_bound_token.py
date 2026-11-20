import copy
import hashlib
import secrets


class BindingError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class DeviceBindingAuthority:
    def __init__(self, audience, verify_proof=None, max_age=60, ttl=600):
        self.audience = audience
        self.verify_proof = verify_proof
        self.max_age = max_age
        self.ttl = ttl
        self._devices = {}
        self._key_index = {}
        self._tokens = {}
        self._used_jtis = {}

    def enroll(self, device_public_key, now):
        if not device_public_key:
            raise ValueError("device_public_key is required")
        existing_id = self._key_index.get(device_public_key)
        if existing_id is not None:
            existing = self._devices[existing_id]
            if existing["status"] != "active":
                raise BindingError("device_revoked")
            return copy.deepcopy(existing)
        device_id = secrets.token_hex(32)
        record = {
            "device_id": device_id,
            "public_key": device_public_key,
            "status": "active",
            "enrolled_at": now,
        }
        self._devices[device_id] = record
        self._key_index[device_public_key] = device_id
        return copy.deepcopy(record)

    def issue(self, device_id, subject, now):
        device = self._devices.get(device_id)
        if device is None:
            raise BindingError("unknown_device")
        if device["status"] != "active":
            raise BindingError("device_revoked")
        if not subject:
            raise ValueError("subject is required")
        token = secrets.token_hex(32)
        record = {
            "token": token,
            "device_id": device_id,
            "subject": subject,
            "audience": self.audience,
            "issued_at": now,
            "expires_at": now + self.ttl,
        }
        self._tokens[token] = record
        return copy.deepcopy(record)

    def verify(self, token, proof, now, method="POST", url="https://api.example.com/orders"):
        if not proof:
            raise ValueError("proof is required")
        token_string = token.get("token") if isinstance(token, dict) else None
        record = self._tokens.get(token_string)
        if record is None:
            raise BindingError("unknown_token")
        if now >= record["expires_at"]:
            raise BindingError("expired_token")
        device = self._devices.get(record["device_id"])
        if device is None or device["status"] != "active":
            raise BindingError("device_revoked")
        signature = proof.get("signature")
        if not self.verify_proof or not self.verify_proof(
            device["public_key"], proof, signature
        ):
            raise BindingError("bad_proof")
        if proof.get("htm") != method:
            raise BindingError("method_mismatch")
        if proof.get("htu") != url:
            raise BindingError("url_mismatch")
        proof_iat = proof.get("iat")
        if proof_iat is None or abs(now - proof_iat) > self.max_age:
            raise BindingError("stale_proof")
        proof_device = proof.get("device_id")
        if proof_device != record["device_id"]:
            raise BindingError("device_mismatch")
        digest = hashlib.sha256(token_string.encode()).hexdigest()
        if proof.get("ath") != digest:
            raise BindingError("token_hash_mismatch")
        jti = proof.get("jti")
        cutoff = now - self.max_age
        for used_jti in [key for key, seen_at in self._used_jtis.items() if seen_at < cutoff]:
            del self._used_jtis[used_jti]
        if jti in self._used_jtis:
            raise BindingError("replayed_proof")
        self._used_jtis[jti] = now
        return {
            "subject": record["subject"],
            "device_id": record["device_id"],
            "remaining": record["expires_at"] - now,
        }

    def revoke_device(self, device_id, now):
        device = self._devices.get(device_id)
        if device is None:
            raise BindingError("unknown_device")
        device["status"] = "revoked"
        device["revoked_at"] = now
        return copy.deepcopy(device)
