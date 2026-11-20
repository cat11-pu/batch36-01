class SignatureError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


import re
import threading
from collections import deque

_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
_KNOWN_FLAGS = frozenset({"nocase", "word"})
_RULE_ID_RE = re.compile(r"^[a-z0-9-]{1,32}$")


def _is_word_char(ch):
    return ch.isalnum() or ch == "_"


class _Automaton:
    """Aho-Corasick automaton over exact strings."""

    def __init__(self):
        self._goto = [{}]
        self._fail = [0]
        self._out = [[]]

    def add(self, pattern, tag):
        state = 0
        for ch in pattern:
            nxt = self._goto[state].get(ch)
            if nxt is None:
                nxt = len(self._goto)
                self._goto[state][ch] = nxt
                self._goto.append({})
                self._fail.append(0)
                self._out.append([])
            state = nxt
        self._out[state].append(tag)

    def build(self):
        queue = deque()
        for nxt in self._goto[0].values():
            queue.append(nxt)
        while queue:
            state = queue.popleft()
            for ch, nxt in self._goto[state].items():
                queue.append(nxt)
                fail = self._fail[state]
                while fail and ch not in self._goto[fail]:
                    fail = self._fail[fail]
                self._fail[nxt] = self._goto[fail].get(ch, 0)
                self._out[nxt].extend(self._out[self._fail[nxt]])

    def scan(self, text, emit):
        state = 0
        for pos, ch in enumerate(text):
            while state and ch not in self._goto[state]:
                state = self._fail[state]
            state = self._goto[state].get(ch, 0)
            for tag in self._out[state]:
                emit(pos, tag)


class SignatureMultimatch:
    def __init__(self, rules, max_hits=100, max_payload=65536):
        if not isinstance(rules, list):
            raise SignatureError("bad_rules")
        if not isinstance(max_hits, int) or isinstance(max_hits, bool) or max_hits < 1:
            raise SignatureError("bad_max_hits")
        if not isinstance(max_payload, int) or isinstance(max_payload, bool) or max_payload < 1:
            raise SignatureError("bad_max_payload")

        self._max_hits = max_hits
        self._max_payload = max_payload
        self._rules = []
        seen_ids = set()
        exact_auto = _Automaton()
        nocase_auto = _Automaton()
        self._has_exact = False
        self._has_nocase = False

        for rule in rules:
            if not isinstance(rule, dict):
                raise SignatureError("bad_rule")
            rule_id = rule.get("id")
            if not isinstance(rule_id, str) or not _RULE_ID_RE.match(rule_id):
                raise SignatureError("bad_id")
            if rule_id in seen_ids:
                raise SignatureError("duplicate_rule")
            seen_ids.add(rule_id)

            pattern = rule.get("pattern")
            if not isinstance(pattern, str):
                raise SignatureError("bad_pattern")
            if pattern == "":
                raise SignatureError("empty_pattern")
            if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in pattern):
                raise SignatureError("bad_pattern")

            severity = rule.get("severity")
            if severity not in _SEVERITIES:
                raise SignatureError("bad_severity")

            raw_flags = rule.get("flags", [])
            if isinstance(raw_flags, str) or not isinstance(raw_flags, (list, tuple, set, frozenset)):
                raise SignatureError("bad_flag")
            flags = set()
            for flag in raw_flags:
                if flag not in _KNOWN_FLAGS:
                    raise SignatureError("bad_flag")
                flags.add(flag)

            index = len(self._rules)
            self._rules.append({
                "id": rule_id,
                "severity": severity,
                "word": "word" in flags,
                "length": len(pattern),
            })
            tag = (index, len(pattern))
            if "nocase" in flags:
                nocase_auto.add(pattern.lower(), tag)
                self._has_nocase = True
            else:
                exact_auto.add(pattern, tag)
                self._has_exact = True

        self._exact_auto = exact_auto
        self._nocase_auto = nocase_auto
        exact_auto.build()
        nocase_auto.build()

        self._lock = threading.Lock()
        self._scanned = 0
        self._hits = 0
        self._failures = 0

    def _record_failure(self):
        with self._lock:
            self._failures += 1

    def scan(self, payload, now=0):
        if not isinstance(payload, str):
            self._record_failure()
            raise SignatureError("bad_payload")
        if len(payload) > self._max_payload:
            self._record_failure()
            raise SignatureError("payload_too_large")

        raw = []
        if self._has_exact:
            self._exact_auto.scan(payload, lambda pos, tag: raw.append((pos, tag)))
        if self._has_nocase:
            lowered = payload.lower()
            self._nocase_auto.scan(lowered, lambda pos, tag: raw.append((pos, tag)))

        hits = []
        for end_pos, (index, length) in raw:
            offset = end_pos - length + 1
            rule = self._rules[index]
            if rule["word"]:
                before = payload[offset - 1] if offset > 0 else ""
                after_pos = offset + length
                after = payload[after_pos] if after_pos < len(payload) else ""
                if (before and _is_word_char(before)) or (after and _is_word_char(after)):
                    continue
            hits.append({
                "rule": rule["id"],
                "offset": offset,
                "length": length,
                "severity": rule["severity"],
                "matched": payload[offset:offset + length],
            })

        hits.sort(key=lambda hit: (hit["offset"], hit["rule"]))
        truncated = len(hits) > self._max_hits
        hits = hits[:self._max_hits]

        with self._lock:
            self._scanned += 1
            self._hits += len(hits)

        return {"hits": hits, "truncated": truncated}

    def snapshot(self):
        with self._lock:
            return {
                "scanned": self._scanned,
                "hits": self._hits,
                "failures": self._failures,
            }
