class CodesignError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


import re
import threading

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _num(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


class ReleaseManifestVerifier:
    def __init__(self, trusted_signers, revoked_serials=(), verify_signature=None,
                 verify_timestamp=None, digest_of=None, max_manifest_age=86400,
                 known_logs=()):
        self._signers = dict(trusted_signers)
        self._revoked = set(revoked_serials)
        self._verify_signature = verify_signature
        self._verify_timestamp = verify_timestamp
        self._digest_of = digest_of
        self._max_manifest_age = max_manifest_age
        self._known_logs = set(known_logs)
        self._lock = threading.Lock()
        self._channels = {}

    def verify(self, manifest, artifacts, now=0):
        m = manifest or {}

        channel = m.get("channel")
        if not isinstance(channel, str) or not channel:
            raise CodesignError("bad_channel")
        version = m.get("version")
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise CodesignError("bad_version")

        sig = m.get("signature")
        if not isinstance(sig, dict):
            raise CodesignError("unsigned")

        signer = sig.get("signer")
        trusted = self._signers.get(signer)
        if trusted is None:
            raise CodesignError("unknown_signer")
        if sig.get("key_id") != trusted.get("key_id"):
            raise CodesignError("key_mismatch")
        if channel not in trusted.get("channels", ()):
            raise CodesignError("channel_denied")

        if sig.get("serial") in self._revoked:
            raise CodesignError("revoked")

        not_before = _num(sig.get("cert_not_before"))
        not_after = _num(sig.get("cert_not_after"))
        signed_at = _num(sig.get("signed_at"))
        if not_before is None or not_after is None or signed_at is None \
                or not (not_before <= signed_at <= not_after):
            raise CodesignError("cert_not_valid_at_signing")

        timestamp = sig.get("timestamp")
        cert_currently_valid = not_before <= now <= not_after
        if timestamp is not None or not cert_currently_valid:
            if not isinstance(timestamp, dict):
                raise CodesignError("bad_timestamp")
            ts_time = _num(timestamp.get("time"))
            ts_not_before = _num(timestamp.get("cert_not_before"))
            ts_not_after = _num(timestamp.get("cert_not_after"))
            if ts_time is None or not (not_before <= ts_time <= not_after):
                raise CodesignError("bad_timestamp")
            if ts_time > now:
                raise CodesignError("bad_timestamp")
            if ts_not_before is None or ts_not_after is None \
                    or not (ts_not_before <= ts_time <= ts_not_after):
                raise CodesignError("bad_timestamp")
            ts_serial = timestamp.get("serial")
            if ts_serial in self._revoked:
                raise CodesignError("revoked")
            if self._verify_timestamp is not None:
                try:
                    ts_ok = self._verify_timestamp(
                        signer, ts_serial, timestamp.get("signature"))
                except Exception as exc:
                    raise CodesignError("timestamp_hook_error") from exc
                if not ts_ok:
                    raise CodesignError("bad_timestamp")

        if self._verify_signature is not None:
            try:
                sig_ok = self._verify_signature(
                    signer, sig.get("key_id"), sig.get("value"))
            except Exception as exc:
                raise CodesignError("signature_hook_error") from exc
            if not sig_ok:
                raise CodesignError("bad_signature")
        elif not sig.get("value"):
            raise CodesignError("bad_signature")

        if now - signed_at > self._max_manifest_age:
            raise CodesignError("stale_manifest")

        if self._known_logs:
            inclusion = m.get("log_inclusion")
            if not isinstance(inclusion, dict) or not inclusion.get("verified") \
                    or inclusion.get("log_id") not in self._known_logs:
                raise CodesignError("log_inclusion")

        entries = m.get("artifacts")
        if not isinstance(entries, list):
            raise CodesignError("bad_artifacts")
        seen = set()
        for entry in entries:
            name = entry.get("name") if isinstance(entry, dict) else None
            if not isinstance(name, str) or not name or "/" in name or "\\" in name:
                raise CodesignError("invalid_artifact_name")
            if name in seen:
                raise CodesignError("duplicate_artifact")
            seen.add(name)
            digest = entry.get("digest")
            if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
                raise CodesignError("invalid_digest")

        provided = artifacts or {}
        for name in seen:
            if name not in provided:
                raise CodesignError("missing_artifact")
        for name in provided:
            if name not in seen:
                raise CodesignError("unexpected_artifact")

        for entry in entries:
            name = entry["name"]
            local = self._digest_of(name) if self._digest_of is not None \
                else provided.get(name)
            if entry["digest"] != local or provided.get(name) != local:
                raise CodesignError("digest_mismatch")

        with self._lock:
            current = self._channels.get(channel)
            if current is not None and version <= current:
                raise CodesignError("rollback")
            self._channels[channel] = version

        return {
            "channel": channel,
            "version": version,
            "artifacts": sorted(seen),
        }

    def snapshot(self):
        with self._lock:
            return {"channels": dict(self._channels)}
