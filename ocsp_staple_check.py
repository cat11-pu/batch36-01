import copy
import threading


class StapleError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class OcspStapler:
    def __init__(self, max_age=300, clock_skew=60, require_nonce=True):
        self.max_age = max_age
        self.clock_skew = clock_skew
        self.require_nonce = require_nonce
        self._lock = threading.Lock()
        self._checks = 0
        self._last_conclusion = None

    def validate(self, staple, cert, issuer, now, nonce=None):
        conclusion = None
        try:
            result = self._validate(staple, cert, issuer, now, nonce)
            conclusion = {
                "ok": True,
                "serial": result["serial"],
                "status": result["status"],
                "responder": result["responder"],
                "next_update": result["next_update"],
            }
            return result
        except StapleError as exc:
            conclusion = {"ok": False, "code": exc.code}
            raise
        finally:
            with self._lock:
                self._checks += 1
                self._last_conclusion = conclusion

    def _validate(self, staple, cert, issuer, now, nonce):
        if not isinstance(staple, dict):
            raise StapleError("malformed")

        response_status = staple.get("response_status")
        if response_status != "successful":
            if response_status == "tryLater":
                raise StapleError("try_later")
            raise StapleError("response_error")

        if staple.get("response_type") != "basic":
            raise StapleError("unsupported_response")

        if "version" in staple and staple["version"] != 0:
            raise StapleError("malformed")

        if self.require_nonce:
            staple_nonce = staple.get("nonce")
            if nonce is None:
                raise StapleError("nonce_missing")
            if staple_nonce is None:
                raise StapleError("nonce_missing")
            if staple_nonce != nonce:
                raise StapleError("nonce_mismatch")

        entries = staple.get("entries")
        if not isinstance(entries, list) or not entries:
            raise StapleError("malformed")
        if not all(isinstance(entry, dict) for entry in entries):
            raise StapleError("malformed")

        serial = cert.get("serial")
        matched = [entry for entry in entries if entry.get("serial") == serial]
        if len(matched) == 1:
            target = matched[0]
        elif len(matched) > 1:
            raise StapleError("duplicate_entry")
        else:
            raise StapleError("serial_mismatch")

        status = target.get("status")
        if status == "revoked":
            raise StapleError("cert_revoked")
        if status == "unknown":
            raise StapleError("cert_unknown")
        if status != "good":
            raise StapleError("malformed")

        produced_at = staple.get("produced_at")
        this_update = target.get("this_update")
        next_update = target.get("next_update")
        if not (
            self._is_int(produced_at)
            and self._is_int(this_update)
            and self._is_int(next_update)
        ):
            raise StapleError("malformed")

        if next_update <= this_update:
            raise StapleError("malformed")

        if now < this_update - self.clock_skew:
            raise StapleError("not_yet_valid")
        if now > next_update + self.clock_skew:
            raise StapleError("stale")

        if produced_at > now + self.clock_skew:
            raise StapleError("future_response")
        if now - produced_at > self.max_age + self.clock_skew:
            raise StapleError("stale")

        responder = staple.get("responder")
        if not isinstance(responder, dict):
            raise StapleError("malformed")
        self._authorize_responder(responder, issuer, produced_at)

        signature = staple.get("signature_ok")
        if callable(signature):
            signature_ok = signature()
        else:
            signature_ok = signature
        if not signature_ok:
            raise StapleError("bad_signature")

        return {
            "serial": serial,
            "status": status,
            "responder": responder.get("fingerprint"),
            "next_update": next_update,
        }

    @staticmethod
    def _is_int(value):
        return isinstance(value, int) and not isinstance(value, bool)

    def _authorize_responder(self, responder, issuer, produced_at):
        same_identity = (
            responder.get("fingerprint") == issuer.get("fingerprint")
            or (
                responder.get("subject") == issuer.get("subject")
                and responder.get("issued_by") == issuer.get("subject")
            )
        )
        if same_identity:
            return

        if responder.get("issued_by") != issuer.get("subject"):
            raise StapleError("unauthorized_responder")
        if "OCSPSigning" not in responder.get("eku", []):
            raise StapleError("unauthorized_responder")

        not_before = responder.get("not_before")
        not_after = responder.get("not_after")
        if not (self._is_int(not_before) and self._is_int(not_after)):
            raise StapleError("unauthorized_responder")
        if not (
            not_before - self.clock_skew
            <= produced_at
            <= not_after + self.clock_skew
        ):
            raise StapleError("unauthorized_responder")

    def snapshot(self):
        with self._lock:
            return {
                "checks": self._checks,
                "last_conclusion": copy.deepcopy(self._last_conclusion),
            }
