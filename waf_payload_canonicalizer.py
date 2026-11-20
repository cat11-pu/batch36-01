import re
import threading
import unicodedata


class WafCanonError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class WafPayloadCanonicalizer:
    _MODES = ("text", "query", "json")

    _HEX = frozenset("0123456789abcdefABCDEF")

    _JSON_ESCAPES = {
        '"': '"',
        "\\": "\\",
        "/": "/",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
    }

    _INVISIBLE_RANGES = (
        (0x200B, 0x200D),
        (0x200E, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x2064),
        (0x2066, 0x2069),
        (0xFEFF, 0xFEFF),
        (0xFFF9, 0xFFFB),
        (0x115F, 0x115F),
        (0x180E, 0x180E),
        (0x00AD, 0x00AD),
    )

    def __init__(self, max_depth=3, max_len=8192, mode="text"):
        if mode not in self._MODES:
            raise WafCanonError("bad_mode")
        self.max_depth = max_depth
        self.max_len = max_len
        self.mode = mode
        self._lock = threading.Lock()
        self._canonicalized = 0
        self._rejected = 0

    def canonicalize(self, payload, now=0):
        try:
            if not isinstance(payload, str):
                raise WafCanonError("bad_payload")
            if len(payload) > self.max_len:
                raise WafCanonError("payload_too_large")

            stages = ["percent", "unicode", "comment", "whitespace"]
            text = payload

            if self.mode == "query":
                stages = ["plus"] + stages
                text = text.replace("+", " ")

            text, layers = self._decode_percent(text)

            if self.mode == "json":
                stages = ["percent", "json", "unicode", "comment", "whitespace"]
                text = self._unescape_json(text)

            text = self._normalize_unicode(text)
            text = self._replace_comments(text)
            text = self._collapse_whitespace(text)

            if len(text) > self.max_len:
                raise WafCanonError("payload_too_large")

            result = {"canonical": text, "layers": layers, "stages": stages}
            with self._lock:
                self._canonicalized += 1
            return result
        except WafCanonError:
            with self._lock:
                self._rejected += 1
            raise

    def snapshot(self):
        with self._lock:
            return {
                "canonicalized": self._canonicalized,
                "rejected": self._rejected,
            }

    def _decode_percent(self, text):
        layers = 0
        while self._has_valid_triplet(text):
            if layers >= self.max_depth:
                raise WafCanonError("decode_depth")
            text = self._decode_one_layer(text)
            layers += 1
            if "\x00" in text:
                raise WafCanonError("nul_byte")
            if len(text) > self.max_len:
                raise WafCanonError("payload_too_large")
        return text, layers

    def _has_valid_triplet(self, text):
        idx = text.find("%")
        while idx != -1:
            if (
                idx + 2 < len(text)
                and text[idx + 1] in self._HEX
                and text[idx + 2] in self._HEX
            ):
                return True
            idx = text.find("%", idx + 1)
        return False

    def _decode_one_layer(self, text):
        out = []
        byte_buffer = bytearray()
        idx = 0
        length = len(text)

        def flush():
            if byte_buffer:
                out.append(bytes(byte_buffer).decode("utf-8", errors="replace"))
                byte_buffer.clear()

        while idx < length:
            char = text[idx]
            if (
                char == "%"
                and idx + 2 < length
                and text[idx + 1] in self._HEX
                and text[idx + 2] in self._HEX
            ):
                byte_buffer.append(int(text[idx + 1 : idx + 3], 16))
                idx += 3
            else:
                flush()
                out.append(char)
                idx += 1
        flush()
        return "".join(out)

    def _unescape_json(self, text):
        out = []
        idx = 0
        length = len(text)
        while idx < length:
            char = text[idx]
            if char != "\\":
                out.append(char)
                idx += 1
                continue
            if idx + 1 >= length:
                raise WafCanonError("bad_json_escape")
            nxt = text[idx + 1]
            if nxt == "u":
                if idx + 5 >= length:
                    raise WafCanonError("bad_json_escape")
                hexpart = text[idx + 2 : idx + 6]
                if any(ch not in self._HEX for ch in hexpart):
                    raise WafCanonError("bad_json_escape")
                code = int(hexpart, 16)
                if 0xD800 <= code <= 0xDBFF:
                    tail = text[idx + 6 : idx + 12]
                    if (
                        len(tail) != 6
                        or tail[0] != "\\"
                        or tail[1] != "u"
                        or any(ch not in self._HEX for ch in tail[2:])
                    ):
                        raise WafCanonError("bad_json_escape")
                    low = int(tail[2:], 16)
                    if not 0xDC00 <= low <= 0xDFFF:
                        raise WafCanonError("bad_json_escape")
                    code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                    idx += 12
                elif 0xDC00 <= code <= 0xDFFF:
                    raise WafCanonError("bad_json_escape")
                else:
                    idx += 6
                out.append(chr(code))
            elif nxt in self._JSON_ESCAPES:
                out.append(self._JSON_ESCAPES[nxt])
                idx += 2
            else:
                raise WafCanonError("bad_json_escape")
        return "".join(out)

    def _normalize_unicode(self, text):
        for char in text:
            if self._is_invisible(ord(char)):
                raise WafCanonError("invisible_char")
        normalized = unicodedata.normalize("NFKD", text)
        for char in normalized:
            if self._is_invisible(ord(char)):
                raise WafCanonError("invisible_char")
        if len(normalized) > self.max_len:
            raise WafCanonError("payload_too_large")
        return normalized

    def _is_invisible(self, code):
        for start, end in self._INVISIBLE_RANGES:
            if start <= code <= end:
                return True
        return False

    def _replace_comments(self, text):
        out = []
        idx = 0
        length = len(text)
        while idx < length:
            if text[idx : idx + 2] == "/*":
                close = text.find("*/", idx + 2)
                if close == -1:
                    raise WafCanonError("bad_comment")
                out.append(" ")
                idx = close + 2
            else:
                out.append(text[idx])
                idx += 1
        return "".join(out)

    def _collapse_whitespace(self, text):
        return re.sub(r"\s+", " ", text).strip(" ")
