import json
import re
import threading
from urllib.parse import urlsplit

NONCE_PATTERN = re.compile(r"[A-Za-z0-9_-]+")


class MessageReceiverError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class PostMessageReceiver:
    DANGEROUS_KEYS = frozenset(("__proto__", "constructor", "prototype"))
    INT32_MAX = 2_147_483_647
    MAX_NESTING_DEPTH = 8
    MAX_ARRAY_LENGTH = 100
    MIN_NONCE_LENGTH = 8
    MAX_NONCE_LENGTH = 128

    def __init__(self, allowed_origins, allowed_sources,
                 allowed_types=("ping", "resize"), max_bytes=4096,
                 reuse_window=60, max_sequence_gap=1, channels=None):
        self.allowed_origins = frozenset(allowed_origins)
        self.allowed_sources = frozenset(allowed_sources)
        self.allowed_types = frozenset(allowed_types)
        self.max_bytes = max_bytes
        self.reuse_window = reuse_window
        self.max_sequence_gap = max_sequence_gap
        self.channels = dict(channels or {})
        self._last_sequence = {}
        self._seen_nonces = {}
        self._counts = {
            "accepted": 0,
            "rejected": 0,
            "replay": 0,
            "format_errors": 0,
        }
        self._lock = threading.RLock()

    def accept(self, event, now=0):
        with self._lock:
            if not isinstance(event, dict):
                self._fail("bad_event")

            origin = event.get("origin")
            self._validate_origin(origin)

            if event.get("target_origin") == "*":
                self._fail("target_wildcard")

            source = event.get("source")
            if source not in self.allowed_sources:
                self._fail("unknown_source")

            payload = event.get("data")
            if not isinstance(payload, dict):
                self._fail("bad_payload")

            self._validate_payload(payload)

            encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            if len(encoded) > self.max_bytes:
                self._fail("payload_too_large")

            message_type = event.get("type")
            if message_type not in self.allowed_types:
                self._fail("bad_type")

            channel = event.get("channel")
            if channel != self.channels.get(source):
                self._fail("channel_mismatch")

            nonce = event.get("nonce")
            self._validate_nonce(nonce, now)

            sequence = event.get("sequence")
            self._validate_sequence(sequence, source)

            self._last_sequence[source] = sequence
            self._seen_nonces[nonce] = now
            self._counts["accepted"] += 1

            return {
                "type": message_type,
                "sequence": sequence,
                "source": source,
            }

    def snapshot(self):
        with self._lock:
            return dict(self._counts)

    def _fail(self, code):
        self._counts["rejected"] += 1
        if code == "replay":
            self._counts["replay"] += 1
        else:
            self._counts["format_errors"] += 1
        raise MessageReceiverError(code)

    def _validate_origin(self, origin):
        if origin is None:
            self._fail("origin_missing")
        if not isinstance(origin, str):
            self._fail("origin_malformed")
        if origin == "" or origin == "null":
            self._fail("null_origin")

        parts = urlsplit(origin)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            self._fail("origin_malformed")
        if parts.path or parts.query or parts.fragment:
            self._fail("origin_malformed")
        if "{}://{}".format(parts.scheme, parts.netloc) != origin:
            self._fail("origin_malformed")

        if origin not in self.allowed_origins:
            self._fail("origin_not_allowed")

    def _validate_payload(self, payload):
        try:
            self._walk_payload(payload, depth=1)
        except MessageReceiverError:
            raise
        except (TypeError, ValueError, RecursionError):
            self._fail("bad_payload")

    def _walk_payload(self, node, depth):
        if depth > self.MAX_NESTING_DEPTH:
            self._fail("nested_too_deep")

        if isinstance(node, dict):
            for key, value in node.items():
                if not isinstance(key, str):
                    self._fail("non_string_key")
                if key in self.DANGEROUS_KEYS:
                    self._fail("dangerous_key")
                self._walk_payload(value, depth + 1)
            return

        if isinstance(node, list):
            if len(node) > self.MAX_ARRAY_LENGTH:
                self._fail("array_too_large")
            for value in node:
                self._walk_payload(value, depth + 1)
            return

        if isinstance(node, str):
            for char in node:
                code = ord(char)
                if code < 0x20 or code == 0x7F:
                    self._fail("control_character")

    def _validate_nonce(self, nonce, now):
        if not nonce:
            self._fail("nonce_missing")
        if not isinstance(nonce, str):
            self._fail("bad_nonce")

        valid_length = self.MIN_NONCE_LENGTH <= len(nonce) <= self.MAX_NONCE_LENGTH
        if not valid_length or not NONCE_PATTERN.fullmatch(nonce):
            self._fail("bad_nonce")

        self._purge_nonces(now)
        if nonce in self._seen_nonces:
            self._fail("replay")

    def _purge_nonces(self, now):
        expired = [
            nonce
            for nonce, seen_at in self._seen_nonces.items()
            if now - seen_at > self.reuse_window
        ]
        for nonce in expired:
            del self._seen_nonces[nonce]

    def _validate_sequence(self, sequence, source):
        if isinstance(sequence, bool) or not isinstance(sequence, int):
            self._fail("bad_sequence")
        if sequence <= 0:
            self._fail("bad_sequence")
        if sequence > self.INT32_MAX:
            self._fail("sequence_overflow")

        previous = self._last_sequence.get(source)
        if previous is None:
            return
        if sequence == previous:
            self._fail("sequence_repeated")
        if sequence < previous:
            self._fail("sequence_regression")
        if sequence - previous > self.max_sequence_gap:
            self._fail("sequence_gap")
