import io
import math
import re
import threading
from collections import Counter


TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_]+")


class SecretScanError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class CredentialEntropyTriage:
    def __init__(self, min_len=20, max_len=512, entropy_threshold=4.0,
                 allow_prefixes=(), placeholder_markers=("example", "changeme"),
                 known_prefixes=("sk_live_", "ghp_", "AKIA")):
        self.min_len = min_len
        self.max_len = max_len
        self.entropy_threshold = entropy_threshold
        self.allow_prefixes = tuple(allow_prefixes)
        self.placeholder_markers = tuple(placeholder_markers)
        self.known_prefixes = tuple(known_prefixes)
        self._lock = threading.Lock()
        self._stats = {
            "scanned": 0,
            "findings": 0,
            "suppressed": 0,
            "skipped": 0,
            "rejected": 0,
        }

    def scan(self, text, path="app.py", now=0):
        if not self._is_safe_path(path):
            with self._lock:
                self._stats["rejected"] += 1
            raise SecretScanError("bad_path")

        if any(path.startswith(prefix) for prefix in self.allow_prefixes):
            with self._lock:
                self._stats["scanned"] += 1
                self._stats["skipped"] += 1
            return {
                "path": path,
                "skipped": True,
                "reason": "allowlisted",
                "findings": [],
            }

        if "\x00" in text:
            with self._lock:
                self._stats["rejected"] += 1
            raise SecretScanError("binary_input")

        findings = []
        suppressed = 0
        seen = set()

        stream = io.StringIO(text)
        for line_no, line in enumerate(stream, start=1):
            for match in TOKEN_RE.finditer(line):
                candidate = match.group(0)
                if len(candidate) < self.min_len or len(candidate) > self.max_len:
                    continue

                if self._is_suppressed(candidate):
                    suppressed += 1
                    continue

                if candidate in seen:
                    suppressed += 1
                    continue

                entropy = self._entropy(candidate)
                known = next(
                    (prefix for prefix in self.known_prefixes
                     if candidate.startswith(prefix)),
                    None,
                )
                if known is not None:
                    kind = "known_prefix"
                elif entropy >= self.entropy_threshold:
                    kind = "high_entropy"
                else:
                    continue

                seen.add(candidate)
                findings.append({
                    "path": path,
                    "line": line_no,
                    "column": match.start() + 1,
                    "length": len(candidate),
                    "kind": kind,
                    "entropy": entropy,
                    "preview": self._preview(candidate),
                })

        findings.sort(key=lambda item: (item["line"], item["column"]))

        with self._lock:
            self._stats["scanned"] += 1
            self._stats["findings"] += len(findings)
            self._stats["suppressed"] += suppressed

        return {
            "path": path,
            "skipped": False,
            "findings": findings,
        }

    def snapshot(self):
        with self._lock:
            return dict(self._stats)

    @staticmethod
    def _is_safe_path(path):
        if path.startswith("\\"):
            return False
        parts = re.split(r"[\\/]+", path)
        if ".." in parts:
            return False
        if re.match(r"^[A-Za-z]:", path):
            return False
        return True

    def _is_suppressed(self, candidate):
        for marker in self.placeholder_markers:
            if marker and marker in candidate:
                return True
        if len(set(candidate)) == 1:
            return True
        return self._is_obvious_sequence(candidate)

    @staticmethod
    def _is_obvious_sequence(candidate):
        if len(candidate) < 2:
            return False
        steps = {ord(candidate[index + 1]) - ord(candidate[index])
                 for index in range(len(candidate) - 1)}
        return steps == {1} or steps == {-1}

    @staticmethod
    def _entropy(candidate):
        length = len(candidate)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in Counter(candidate).values()
        )

    @staticmethod
    def _preview(candidate):
        if len(candidate) <= 6:
            return "..."
        return "%s...%s" % (candidate[:4], candidate[-2:])
