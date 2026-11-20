import copy
import threading
import uuid


class KemError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


# Suite registry: canonical (upper-case) name -> per-suite length
# constraints for the client public key, KEM ciphertext and shared secret.
SUITE_SPECS = {
    "X25519MLKEM768": {
        "public_key_len": 1216,
        "ciphertext_len": 1120,
        "shared_secret_len": 32,
        "hybrid": True,
    },
    "P256MLKEM768": {
        "public_key_len": 1216,
        "ciphertext_len": 1120,
        "shared_secret_len": 32,
        "hybrid": True,
    },
    "X25519": {
        "public_key_len": 32,
        "ciphertext_len": 32,
        "shared_secret_len": 32,
        "hybrid": False,
    },
}

NEGOTIATION_TTL = 300
SESSION_TTL = 300


def _canonical(name):
    if not isinstance(name, str):
        raise KemError("unknown_suite")
    return name.upper()


class HybridKemBroker:
    def __init__(self, policy, kem, mac, require_hybrid=True, max_sessions=8):
        self._policy = []
        for suite in policy:
            canonical = _canonical(suite)
            if canonical not in SUITE_SPECS:
                raise KemError("unknown_suite")
            if canonical not in self._policy:
                self._policy.append(canonical)
        self._policy_set = set(self._policy)
        self._kem = kem
        self._mac = mac
        self._require_hybrid = require_hybrid
        self._max_sessions = max_sessions
        self._negotiations = {}
        self._sessions = {}
        self._lock = threading.RLock()

    def negotiate(self, client_suites, now=0):
        normalized = []
        for suite in client_suites:
            canonical = _canonical(suite)
            if canonical in normalized:
                raise KemError("duplicate_suite")
            if canonical not in SUITE_SPECS:
                raise KemError("unknown_suite")
            normalized.append(canonical)

        selected = None
        for suite in normalized:
            if suite in self._policy_set:
                selected = suite
                break
        if selected is None:
            raise KemError("no_common_suite")
        if self._require_hybrid and not SUITE_SPECS[selected]["hybrid"]:
            raise KemError("downgrade_blocked")

        negotiation_id = uuid.uuid4().hex
        with self._lock:
            self._purge_expired(now)
            self._negotiations[negotiation_id] = {
                "negotiation_id": negotiation_id,
                "suite": selected,
                "expires_at": now + NEGOTIATION_TTL,
                "responded": False,
            }
        return {
            "negotiation_id": negotiation_id,
            "suite": selected,
            "expires_at": now + NEGOTIATION_TTL,
        }

    def respond(self, negotiation, client_public, transcript, now=0):
        if not isinstance(negotiation, dict):
            raise KemError("bad_negotiation")
        negotiation_id = negotiation.get("negotiation_id")
        if not negotiation_id or not isinstance(negotiation_id, str):
            raise KemError("bad_negotiation")

        with self._lock:
            record = self._negotiations.get(negotiation_id)
            if record is None:
                raise KemError("unknown_negotiation")
            if now >= record["expires_at"]:
                raise KemError("negotiation_expired")
            if record["responded"]:
                raise KemError("negotiation_replayed")
            self._purge_expired(now)

            suite = record["suite"]
            if suite not in self._policy_set:
                raise KemError("suite_no_longer_allowed")
            spec = SUITE_SPECS[suite]

            if not isinstance(client_public, bytes):
                raise KemError("bad_public_key")
            if len(client_public) != spec["public_key_len"]:
                raise KemError("bad_public_key")

            if not isinstance(transcript, bytes) or len(transcript) == 0:
                raise KemError("bad_transcript")

            if self._pending_session_count(now) >= self._max_sessions:
                raise KemError("too_many_sessions")

            try:
                ciphertext, shared_secret = self._kem.encapsulate(
                    suite, client_public
                )
            except KemError:
                raise
            except Exception as exc:
                raise KemError("encapsulation_failed") from exc

            if not isinstance(ciphertext, bytes) or len(ciphertext) != (
                spec["ciphertext_len"]
            ):
                raise KemError("bad_ciphertext")
            if not isinstance(shared_secret, bytes) or len(shared_secret) != (
                spec["shared_secret_len"]
            ):
                raise KemError("bad_shared_secret")

            session_id = uuid.uuid4().hex
            self._sessions[session_id] = {
                "session_id": session_id,
                "suite": suite,
                "transcript": transcript,
                "shared_secret": shared_secret,
                "expires_at": now + SESSION_TTL,
                "state": "pending",
            }
            record["responded"] = True

        return {
            "session_id": session_id,
            "suite": suite,
            "ciphertext": ciphertext,
            "expires_at": now + SESSION_TTL,
        }

    def confirm(self, session_id, tag, transcript, now=0):
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise KemError("unknown_session")
            if session["state"] != "pending":
                raise KemError("session_replayed")
            if now >= session["expires_at"]:
                raise KemError("session_expired")

            if transcript != session["transcript"]:
                raise KemError("transcript_mismatch")

            expected_tag = self._mac(
                session["shared_secret"],
                session["transcript"] + b"|" + session_id.encode("ascii"),
            )
            if not isinstance(tag, str) or tag != expected_tag:
                raise KemError("bad_confirm_tag")

            session["state"] = "established"
            result = {
                "established": True,
                "session_id": session_id,
                "suite": session["suite"],
                "expires_at": session["expires_at"],
            }
        return result

    def snapshot(self):
        with self._lock:
            negotiations = [
                {
                    "negotiation_id": record["negotiation_id"],
                    "suite": record["suite"],
                    "expires_at": record["expires_at"],
                    "responded": record["responded"],
                }
                for record in self._negotiations.values()
            ]
            sessions = [
                {
                    "session_id": session["session_id"],
                    "suite": session["suite"],
                    "expires_at": session["expires_at"],
                    "state": session["state"],
                }
                for session in self._sessions.values()
            ]
            return {
                "policy": copy.deepcopy(self._policy),
                "require_hybrid": self._require_hybrid,
                "max_sessions": self._max_sessions,
                "negotiations": negotiations,
                "sessions": sessions,
            }

    def _pending_session_count(self, now):
        return sum(
            1
            for session in self._sessions.values()
            if session["state"] == "pending" and now < session["expires_at"]
        )

    def _purge_expired(self, now):
        for negotiation_id in [
            negotiation_id
            for negotiation_id, record in self._negotiations.items()
            if now >= record["expires_at"] and not record["responded"]
        ]:
            del self._negotiations[negotiation_id]

        for session_id in [
            session_id
            for session_id, session in self._sessions.items()
            if now >= session["expires_at"]
        ]:
            del self._sessions[session_id]
