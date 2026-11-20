import base64
import binascii
import hashlib
import hmac
import re
import threading
from urllib.parse import urlsplit


class DigestSentinelError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class AssetDigestSentinel:
    _DIGEST_SIZES = {
        "sha256": 32,
        "sha384": 48,
        "sha512": 64,
    }
    _ALLOWED_CROSSORIGIN = ("anonymous", "use-credentials")
    _FORBIDDEN_CHARS = (",", ";", '"', "'", "\\")
    _FORMAT_CODES = frozenset(
        ("missing_integrity", "bad_integrity", "bad_digest", "unsupported_algorithm")
    )

    def __init__(self, algorithms=("sha256", "sha384", "sha512")):
        if isinstance(algorithms, str):
            candidates = [algorithms]
        else:
            candidates = list(algorithms)
        chosen = []
        for name in candidates:
            normalized = str(name).lower()
            if normalized not in self._DIGEST_SIZES:
                continue
            if normalized not in chosen:
                chosen.append(normalized)
        if not chosen:
            raise DigestSentinelError("unsupported_algorithm")
        chosen.sort(key=lambda alg: self._DIGEST_SIZES[alg])
        self.algorithms = tuple(chosen)
        self._lock = threading.Lock()
        self._stats = {
            "verified": 0,
            "format_failures": 0,
            "digest_mismatches": 0,
            "policy_failures": 0,
            "failures": 0,
        }

    def verify(self, tag, content, now=0):
        if not isinstance(content, bytes):
            self._record_failure("non_bytes_content")
            raise DigestSentinelError("non_bytes_content")

        integrity = tag.get("integrity")
        if not isinstance(integrity, str) or not integrity:
            self._record_failure("missing_integrity")
            raise DigestSentinelError("missing_integrity")

        if (
            any(char in integrity for char in self._FORBIDDEN_CHARS)
            or "\n" in integrity
            or "\r" in integrity
            or integrity[0].isspace()
            or integrity[-1].isspace()
        ):
            self._record_failure("bad_integrity")
            raise DigestSentinelError("bad_integrity")

        pieces = re.split(r"\s+", integrity)
        tokens = []
        for piece in pieces:
            if "-" not in piece:
                self._record_failure("bad_integrity")
                raise DigestSentinelError("bad_integrity")
            algorithm, encoded = piece.split("-", 1)
            algorithm = algorithm.lower()
            if algorithm not in self._DIGEST_SIZES:
                continue
            if not self._is_standard_base64(encoded):
                self._record_failure("bad_digest")
                raise DigestSentinelError("bad_digest")
            raw = base64.b64decode(encoded)
            if len(raw) != self._DIGEST_SIZES[algorithm]:
                self._record_failure("bad_digest")
                raise DigestSentinelError("bad_digest")
            tokens.append((algorithm, raw))

        if not tokens:
            self._record_failure("unsupported_algorithm")
            raise DigestSentinelError("unsupported_algorithm")

        if tag.get("crossorigin") not in self._ALLOWED_CROSSORIGIN:
            self._record_failure("missing_crossorigin")
            raise DigestSentinelError("missing_crossorigin")

        if not self._is_secure_source(tag.get("src")):
            self._record_failure("insecure_source")
            raise DigestSentinelError("insecure_source")

        strongest = max(
            (alg for alg, _ in tokens),
            key=lambda alg: self._DIGEST_SIZES[alg],
        )
        strongest_tokens = [
            (index, alg, raw)
            for index, (alg, raw) in enumerate(tokens)
            if alg == strongest
        ]
        expected = hashlib.new(strongest, content).digest()
        matched_index = None
        for index, _alg, raw in strongest_tokens:
            if hmac.compare_digest(raw, expected):
                if matched_index is None:
                    matched_index = index
        if matched_index is None:
            self._record_failure("digest_mismatch")
            raise DigestSentinelError("digest_mismatch")

        with self._lock:
            self._stats["verified"] += 1
        return {
            "ok": True,
            "algorithm": strongest,
            "index": matched_index,
        }

    def snapshot(self):
        with self._lock:
            return dict(self._stats)

    @staticmethod
    def _is_standard_base64(encoded):
        if not encoded or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", encoded):
            return False
        if len(encoded) % 4 != 0:
            return False
        try:
            base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            return False
        return True

    def _is_secure_source(self, src):
        if not isinstance(src, str) or not src:
            return False
        if src.startswith("//"):
            return False
        if src.startswith("/"):
            return True
        try:
            parts = urlsplit(src)
        except ValueError:
            return False
        if parts.scheme.lower() != "https":
            return False
        if parts.username is not None or parts.password is not None:
            return False
        if parts.port is not None and parts.port != 443:
            return False
        return True

    def _record_failure(self, code):
        with self._lock:
            self._stats["failures"] += 1
            if code == "digest_mismatch":
                self._stats["digest_mismatches"] += 1
            elif code in self._FORMAT_CODES:
                self._stats["format_failures"] += 1
            else:
                self._stats["policy_failures"] += 1
