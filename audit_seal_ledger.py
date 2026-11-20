import copy
import hashlib
import hmac
import json
import threading


_ALGORITHMS = frozenset(("sha256", "sha384", "sha512"))
_MAX_DEPTH = 4


class AuditSealError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class AuditSealLedger:
    def __init__(self, chain_key, algorithm="sha256"):
        if isinstance(chain_key, str):
            try:
                key = chain_key.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise AuditSealError("bad_key") from exc
        elif isinstance(chain_key, (bytes, bytearray)):
            key = bytes(chain_key)
        else:
            raise AuditSealError("bad_key")

        if not key:
            raise AuditSealError("bad_key")
        if not isinstance(algorithm, str) or algorithm not in _ALGORITHMS:
            raise AuditSealError("bad_algorithm")

        self._key = key
        self._algorithm = algorithm
        self._zero = "0" * (hashlib.new(algorithm).digest_size * 2)
        self._seq = 0
        self._head = self._zero
        self._appended = 0
        self._verified = 0
        self._lock = threading.Lock()

    def append(self, entry, now=0):
        with self._lock:
            self._validate_entry(entry)
            event = copy.deepcopy(entry)
            seq = self._seq + 1
            digest = self._digest(event)
            record = {
                "seq": seq,
                "prev": self._head,
                "event": event,
                "digest": digest,
            }
            record["mac"] = self._mac(record)
            self._seq = seq
            self._head = record["mac"]
            self._appended += 1
            return copy.deepcopy(record)

    def verify(self, records, checkpoint=None):
        with self._lock:
            self._verified += 1

        if not isinstance(records, (list, tuple)):
            return self._result(False, 0, None, "bad_records")

        length = len(records)
        if length == 0:
            return self._result(False, 0, None, "empty_chain")

        checkpoint_seq = None
        checkpoint_head = None
        if checkpoint is not None:
            if not isinstance(checkpoint, dict):
                return self._result(False, length, None, "checkpoint_mismatch")
            checkpoint_seq = checkpoint.get("seq")
            checkpoint_head = checkpoint.get("head")
            if (
                type(checkpoint_seq) is not int
                or checkpoint_seq < 0
                or not isinstance(checkpoint_head, str)
            ):
                return self._result(False, length, None, "checkpoint_mismatch")
            if length < checkpoint_seq:
                return self._result(False, length, None, "truncated")

        previous = self._zero
        for position, record in enumerate(records, 1):
            if not isinstance(record, dict):
                return self._result(False, length, position, "bad_record")

            seq = record.get("seq")
            if type(seq) is not int or seq != position:
                broken_at = seq if type(seq) is int else position
                return self._result(False, length, broken_at, "seq_mismatch")

            prev = record.get("prev")
            if not self._secure_equal(prev, previous):
                return self._result(False, length, seq, "prev_mismatch")

            event = record.get("event")
            try:
                self._validate_entry(event)
                digest = self._digest(event)
            except (
                AuditSealError,
                TypeError,
                ValueError,
                UnicodeError,
                RecursionError,
            ):
                return self._result(False, length, seq, "digest_mismatch")

            stored_digest = record.get("digest")
            if not self._secure_equal(stored_digest, digest):
                return self._result(False, length, seq, "digest_mismatch")

            payload = {key: value for key, value in record.items() if key != "mac"}
            try:
                expected_mac = self._mac(payload)
            except (
                AuditSealError,
                TypeError,
                ValueError,
                UnicodeError,
                RecursionError,
            ):
                return self._result(False, length, seq, "mac_mismatch")

            mac = record.get("mac")
            if not self._secure_equal(mac, expected_mac):
                return self._result(False, length, seq, "mac_mismatch")

            previous = mac

        if checkpoint is not None:
            if checkpoint_seq == 0:
                expected_head = self._zero
            else:
                expected_head = records[checkpoint_seq - 1]["mac"]
            if not self._secure_equal(expected_head, checkpoint_head):
                broken_at = checkpoint_seq if checkpoint_seq else None
                return self._result(
                    False, length, broken_at, "checkpoint_mismatch"
                )

        return self._result(True, length, None, None)

    def checkpoint(self):
        with self._lock:
            return {"seq": self._seq, "head": self._head}

    def snapshot(self):
        with self._lock:
            return {"appended": self._appended, "verified": self._verified}

    @staticmethod
    def _result(ok, length, broken_at, reason):
        return {
            "ok": ok,
            "length": length,
            "broken_at": broken_at,
            "reason": reason,
        }

    @classmethod
    def _validate_entry(cls, entry):
        if not isinstance(entry, dict) or not entry:
            raise AuditSealError("bad_entry")
        cls._validate_value(entry, 0)

    @classmethod
    def _validate_value(cls, value, depth):
        if isinstance(value, float):
            raise AuditSealError("bad_value")
        if depth > _MAX_DEPTH:
            raise AuditSealError("bad_value")

        if isinstance(value, dict):
            for key, child in value.items():
                if not isinstance(key, str):
                    raise AuditSealError("bad_value")
                cls._validate_value(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                cls._validate_value(child, depth + 1)
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise AuditSealError("bad_value") from exc
        elif value is None or isinstance(value, (bool, int)):
            return
        else:
            raise AuditSealError("bad_value")

    def _digest(self, event):
        return hashlib.new(
            self._algorithm, self._canonical_bytes(event)
        ).hexdigest()

    def _mac(self, payload):
        return hmac.new(
            self._key, self._canonical_bytes(payload), self._algorithm
        ).hexdigest()

    @staticmethod
    def _secure_equal(left, right):
        if not isinstance(left, str) or not isinstance(right, str):
            return False
        try:
            left = left.encode("utf-8")
            right = right.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return hmac.compare_digest(left, right)

    @staticmethod
    def _canonical_bytes(value):
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
