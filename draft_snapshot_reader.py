import hashlib
import hmac
import json
import math

_INT_MIN = -(2 ** 63)
_INT_MAX = 2 ** 63 - 1
_HEX_LOWER = frozenset("0123456789abcdef")


class SnapshotError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class DraftSnapshotReader:
    def __init__(self, types, secret, max_depth=6, max_items=1000, max_text=4096, max_bytes=4096):
        self._types = dict(types)
        self._secret = bytes(secret)
        self._max_depth = max_depth
        self._max_items = max_items
        self._max_text = max_text
        self._max_bytes = max_bytes
        self._reads = 0
        self._rejected = 0
        self._last_error = None

    def read(self, envelope, now=0):
        try:
            return self._read(envelope)
        except SnapshotError as exc:
            self._rejected += 1
            self._last_error = exc.code
            raise

    def _read(self, envelope):
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "mac"}:
            raise SnapshotError("bad_envelope")
        payload = envelope["payload"]
        mac = envelope["mac"]
        if not isinstance(payload, str):
            raise SnapshotError("bad_envelope")
        if (
            not isinstance(mac, str)
            or len(mac) != 64
            or any(ch not in _HEX_LOWER for ch in mac)
        ):
            raise SnapshotError("bad_envelope")

        expected = hmac.new(self._secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, mac):
            raise SnapshotError("bad_signature")

        if len(payload.encode("utf-8")) > self._max_bytes:
            raise SnapshotError("payload_too_large")

        try:
            data = json.loads(
                payload,
                object_pairs_hook=self._object_pairs,
                parse_int=self._parse_int,
                parse_float=self._parse_float,
                parse_constant=self._parse_constant,
            )
        except SnapshotError:
            raise
        except RecursionError:
            raise SnapshotError("too_deep")
        except ValueError:
            raise SnapshotError("bad_json")

        kinds = []
        value = self._restore(data, 1, kinds)
        self._reads += 1
        return {"value": value, "kinds": kinds}

    @staticmethod
    def _object_pairs(pairs):
        obj = {}
        for key, val in pairs:
            if key in obj:
                raise SnapshotError("duplicate_key")
            obj[key] = val
        return obj

    @staticmethod
    def _parse_int(text):
        num = int(text)
        if num < _INT_MIN or num > _INT_MAX:
            raise SnapshotError("number_out_of_range")
        return num

    @staticmethod
    def _parse_float(text):
        num = float(text)
        if not math.isfinite(num):
            raise SnapshotError("non_finite")
        return num

    @staticmethod
    def _parse_constant(text):
        raise SnapshotError("non_finite")

    def _restore(self, node, depth, kinds):
        if isinstance(node, dict):
            if depth > self._max_depth:
                raise SnapshotError("too_deep")
            if len(node) > self._max_items:
                raise SnapshotError("too_many_items")
            for key in node:
                if not isinstance(key, str):
                    raise SnapshotError("bad_key")
                if key.startswith("_"):
                    raise SnapshotError("forbidden_key")
                if len(key) > self._max_text:
                    raise SnapshotError("text_too_long")
            if "kind" in node:
                if set(node) != {"kind", "value"}:
                    raise SnapshotError("bad_tag")
                kind = node["kind"]
                if not isinstance(kind, str) or kind not in self._types:
                    raise SnapshotError("unknown_type")
                value = self._restore(node["value"], depth + 1, kinds)
                if not self._types[kind](value):
                    raise SnapshotError("invalid_value")
                kinds.append(kind)
                return (kind, value)
            return {key: self._restore(val, depth + 1, kinds) for key, val in node.items()}
        if isinstance(node, list):
            if depth > self._max_depth:
                raise SnapshotError("too_deep")
            if len(node) > self._max_items:
                raise SnapshotError("too_many_items")
            return [self._restore(item, depth + 1, kinds) for item in node]
        if isinstance(node, str):
            if len(node) > self._max_text:
                raise SnapshotError("text_too_long")
            return node
        if isinstance(node, (int, float, bool)) or node is None:
            return node
        raise SnapshotError("bad_value")

    def snapshot(self):
        return {
            "reads": self._reads,
            "rejected": self._rejected,
            "last_error": self._last_error,
        }
