import re
import threading
import unicodedata


class CorsPolicyError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class CorsPreflightArbiter:
    _ORIGIN_RE = re.compile(
        r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*)://"
        r"(?P<host>[^:/?#]+)"
        r"(?::(?P<port>[0-9]+))?$"
    )

    def __init__(self, allowed_origins, allowed_methods=("GET", "POST"),
                 allowed_headers=("content-type",), max_age=600,
                 credentials=True, allow_private_network=False):
        if not isinstance(allowed_origins, (list, tuple, set, frozenset)):
            raise CorsPolicyError("invalid_allowed_origins")

        if not isinstance(max_age, int) or isinstance(max_age, bool) or max_age < 0:
            raise CorsPolicyError("invalid_max_age")

        wildcard = False
        normalized = []
        seen = set()
        for entry in allowed_origins:
            if not isinstance(entry, str) or entry == "":
                raise CorsPolicyError("invalid_allowed_origins")
            if entry == "*":
                wildcard = True
                continue
            if entry.startswith("*.") or "*" in entry:
                raise CorsPolicyError("wildcard_subdomain_not_allowed")
            if not self._ORIGIN_RE.match(entry):
                raise CorsPolicyError("invalid_origin_entry")
            if entry in seen:
                raise CorsPolicyError("duplicate_origin")
            seen.add(entry)
            normalized.append(entry)

        if wildcard and credentials:
            raise CorsPolicyError("wildcard_credentials_conflict")

        self._wildcard = wildcard
        self._allowed_origins = tuple(normalized)
        self._allowed_methods = tuple(allowed_methods)
        self._allowed_headers = tuple(allowed_headers)
        self._allowed_headers_lc = {
            header.lower() for header in allowed_headers if isinstance(header, str)
        }
        self._max_age = max_age
        self._credentials = bool(credentials)
        self._allow_private_network = bool(allow_private_network)

        self._lock = threading.Lock()
        self._decisions = 0
        self._preflight_decisions = 0
        self._actual_decisions = 0
        self._errors = 0

    def decide(self, request, now=0):
        is_preflight = bool(request.get("preflight"))
        try:
            if not is_preflight:
                self._reject_preflight_fields_on_actual(request)

            origin = self._validate_origin(request.get("origin"))

            if request.get("private_network") and not self._allow_private_network:
                raise CorsPolicyError("private_network_denied")

            if self._wildcard:
                headers = {"Access-Control-Allow-Origin": "*", "Vary": "Origin"}
            else:
                if origin not in self._allowed_origins:
                    raise CorsPolicyError("origin_not_allowed")
                headers = {
                    "Access-Control-Allow-Origin": origin,
                    "Vary": "Origin",
                }
                if self._credentials:
                    headers["Access-Control-Allow-Credentials"] = "true"

            if is_preflight:
                headers.update(self._decide_preflight(request))

            ordered = {key: headers[key] for key in self._header_order(headers)}

            with self._lock:
                self._decisions += 1
                if is_preflight:
                    self._preflight_decisions += 1
                else:
                    self._actual_decisions += 1

            return {"headers": ordered}
        except CorsPolicyError:
            with self._lock:
                self._errors += 1
            raise

    def render_error(self):
        return {"headers": {}}

    def snapshot(self):
        with self._lock:
            return {
                "decisions": self._decisions,
                "preflight_decisions": self._preflight_decisions,
                "actual_decisions": self._actual_decisions,
                "errors": self._errors,
            }

    @classmethod
    def _validate_origin(cls, raw):
        if raw is None:
            raise CorsPolicyError("origin_missing")
        if not isinstance(raw, str):
            raise CorsPolicyError("bad_origin")
        origin = raw.strip()
        if origin == "":
            raise CorsPolicyError("origin_missing")
        if origin == "null":
            raise CorsPolicyError("null_origin")
        if any(ch.isspace() for ch in origin):
            raise CorsPolicyError("bad_origin")
        if any(unicodedata.category(ch) == "Cf" for ch in origin):
            raise CorsPolicyError("bad_origin")
        if "," in origin:
            raise CorsPolicyError("bad_origin")
        match = cls._ORIGIN_RE.match(origin)
        if match is None:
            raise CorsPolicyError("bad_origin")
        port = match.group("port")
        if port is not None and not (1 <= int(port) <= 65535):
            raise CorsPolicyError("bad_origin")
        return origin

    @staticmethod
    def _reject_preflight_fields_on_actual(request):
        if "requested_headers" in request or "max_age" in request:
            raise CorsPolicyError("unexpected_preflight_field")

    def _decide_preflight(self, request):
        method = request.get("method")
        if not method or not isinstance(method, str):
            raise CorsPolicyError("method_missing")
        if method not in self._allowed_methods:
            raise CorsPolicyError("method_not_allowed")

        normalized_headers = []
        seen = set()
        for header in request.get("requested_headers", ()) or ():
            if not isinstance(header, str):
                raise CorsPolicyError("header_not_allowed")
            name = header.strip().lower()
            if name == "" or name in seen:
                continue
            seen.add(name)
            normalized_headers.append(name)
        for name in normalized_headers:
            if name not in self._allowed_headers_lc:
                raise CorsPolicyError("header_not_allowed")

        requested_max_age = request.get("max_age", self._max_age)
        if not isinstance(requested_max_age, int) or isinstance(requested_max_age, bool):
            requested_max_age = self._max_age
        max_age = max(0, min(requested_max_age, self._max_age))

        return {
            "Access-Control-Allow-Methods": ", ".join(self._allowed_methods),
            "Access-Control-Allow-Headers": ", ".join(self._allowed_headers),
            "Access-Control-Max-Age": str(max_age),
        }

    @staticmethod
    def _header_order(headers):
        preferred = (
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Credentials",
            "Vary",
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers",
            "Access-Control-Max-Age",
        )
        ordered = [key for key in preferred if key in headers]
        ordered.extend(sorted(key for key in headers if key not in preferred))
        return ordered
