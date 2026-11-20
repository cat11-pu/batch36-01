import base64
import binascii
import hmac
import threading
from urllib.parse import urlsplit


class HandshakeError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class AgentConsoleHandshake:
    PATH = "/ws/agent"
    VERSION = "13"
    ORIGIN_HEADER = "origin"
    HOST_HEADER = "host"
    UPGRADE_HEADER = "upgrade"
    CONNECTION_HEADER = "connection"
    VERSION_HEADER = "sec-websocket-version"
    KEY_HEADER = "sec-websocket-key"
    TICKET_HEADER = "x-console-ticket"
    DEFAULT_HTTPS_PORT = 443

    def __init__(self, origins_by_tenant, tickets):
        self._tenants = {}
        for tenant, config in origins_by_tenant.items():
            allowed_origins = set()
            for origin in config.get("origins", ()):
                try:
                    canonical, _, _ = self._canonical_origin(origin)
                except HandshakeError:
                    continue
                allowed_origins.add(canonical)
            self._tenants[tenant] = {
                "origins": frozenset(allowed_origins),
                "protocols": tuple(config.get("protocols", ())),
            }

        self._tickets = []
        for ticket in tickets:
            value = ticket.get("value")
            if isinstance(value, str):
                value_bytes = value.encode("utf-8")
            elif isinstance(value, bytes):
                value_bytes = value
            else:
                value_bytes = None
            self._tickets.append(
                {
                    "tenant": ticket.get("tenant"),
                    "value_bytes": value_bytes,
                    "expires": ticket.get("expires"),
                    "used": bool(ticket.get("used", False)),
                }
            )

        self._counts = {"accepted": 0, "rejected": 0}
        self._lock = threading.Lock()

    def accept(self, tenant, request, now=0):
        with self._lock:
            try:
                result = self._accept_locked(tenant, request, now)
            except HandshakeError:
                self._counts["rejected"] += 1
                raise
            self._counts["accepted"] += 1
            return result

    def snapshot(self):
        with self._lock:
            return dict(self._counts)

    def _accept_locked(self, tenant, request, now):
        tenant_config = self._tenants.get(tenant)
        if tenant_config is None:
            raise HandshakeError("unknown_tenant")
        if not isinstance(request, dict):
            raise HandshakeError("bad_request")

        headers = request.get("headers")
        if headers is None:
            headers = {}

        raw_origin = self._one_header(
            headers,
            self.ORIGIN_HEADER,
            "origin_missing",
            "duplicate_origin",
        )
        origin, origin_host, origin_port = self._canonical_origin(raw_origin)
        if origin not in tenant_config["origins"]:
            raise HandshakeError("origin_not_allowed")

        raw_host = self._one_header(
            headers,
            self.HOST_HEADER,
            "missing_host",
            "duplicate_host",
        )
        host, host_port = self._canonical_host(raw_host)
        if host != origin_host or host_port != origin_port:
            raise HandshakeError("host_mismatch")

        if request.get("path") != self.PATH:
            raise HandshakeError("bad_path")

        upgrade_values = self._header_values(headers, self.UPGRADE_HEADER)
        if not upgrade_values:
            raise HandshakeError("upgrade_missing")
        connection_values = self._header_values(headers, self.CONNECTION_HEADER)
        if not connection_values:
            raise HandshakeError("connection_missing")
        if (
            "websocket" not in self._header_tokens(upgrade_values)
            or "upgrade" not in self._header_tokens(connection_values)
        ):
            raise HandshakeError("bad_upgrade")

        version = self._one_header(
            headers,
            self.VERSION_HEADER,
            "version_missing",
            "bad_version",
        )
        if not isinstance(version, str) or version.strip() != self.VERSION:
            raise HandshakeError("bad_version")

        key = self._one_header(
            headers,
            self.KEY_HEADER,
            "key_missing",
            "bad_key",
        )
        self._validate_connection_key(key)

        protocol = self._select_protocol(
            request.get("subprotocols"),
            tenant_config["protocols"],
        )

        ticket_value = self._one_header(
            headers,
            self.TICKET_HEADER,
            "ticket_missing",
            "bad_ticket",
        )
        ticket = self._find_ticket(ticket_value)
        if ticket is None or ticket["tenant"] != tenant:
            raise HandshakeError("ticket_unknown")
        if ticket["used"]:
            raise HandshakeError("ticket_replayed")
        expires = ticket["expires"]
        if expires is not None and now >= expires:
            raise HandshakeError("ticket_expired")

        ticket["used"] = True
        return {
            "tenant": tenant,
            "origin": origin,
            "protocol": protocol,
        }

    @staticmethod
    def _header_items(headers):
        if isinstance(headers, dict):
            return headers.items()
        if isinstance(headers, (list, tuple)):
            return headers
        raise HandshakeError("bad_request")

    @classmethod
    def _header_values(cls, headers, wanted):
        values = []
        for name, value in cls._header_items(headers):
            if not isinstance(name, str) or name.lower() != wanted:
                continue
            if isinstance(value, (list, tuple)):
                values.extend(value)
            else:
                values.append(value)
        return values

    @classmethod
    def _one_header(cls, headers, wanted, missing_code, duplicate_code):
        values = cls._header_values(headers, wanted)
        if not values:
            raise HandshakeError(missing_code)
        if len(values) != 1:
            raise HandshakeError(duplicate_code)
        return values[0]

    @classmethod
    def _header_tokens(cls, values):
        tokens = set()
        for value in values:
            if not isinstance(value, str):
                raise HandshakeError("bad_upgrade")
            for token in value.split(","):
                token = token.strip().lower()
                if token:
                    tokens.add(token)
        return tokens

    @classmethod
    def _canonical_origin(cls, raw):
        if not isinstance(raw, str):
            raise HandshakeError("bad_origin")
        raw = raw.strip()
        if not raw or raw == "null" or raw == "*":
            raise HandshakeError("origin_not_allowed")
        if cls._has_control_or_space(raw) or "\\" in raw:
            raise HandshakeError("bad_origin")
        if "?" in raw or "#" in raw:
            raise HandshakeError("bad_origin")
        if raw.endswith(":"):
            raise HandshakeError("bad_origin")

        parts = urlsplit(raw)
        if parts.scheme.lower() != "https":
            raise HandshakeError("bad_origin")
        if not parts.netloc or parts.hostname is None:
            raise HandshakeError("bad_origin")
        if parts.username is not None or parts.password is not None:
            raise HandshakeError("bad_origin")
        if parts.path or parts.query or parts.fragment:
            raise HandshakeError("bad_origin")

        try:
            port = parts.port
        except ValueError:
            raise HandshakeError("bad_origin")
        if port is None:
            port = cls.DEFAULT_HTTPS_PORT
        if port != cls.DEFAULT_HTTPS_PORT:
            raise HandshakeError("bad_origin")

        host = parts.hostname.lower().rstrip(".")
        if not host or "*" in host:
            raise HandshakeError("bad_origin")
        canonical = "https://" + cls._format_host(host)
        return canonical, host, port

    @classmethod
    def _canonical_host(cls, raw):
        if not isinstance(raw, str):
            raise HandshakeError("bad_host")
        raw = raw.strip()
        if not raw or cls._has_control_or_space(raw):
            raise HandshakeError("bad_host")
        if any(char in raw for char in "/\\?#@,*"):
            raise HandshakeError("bad_host")
        if raw.endswith(":"):
            raise HandshakeError("bad_host")

        try:
            parts = urlsplit("https://" + raw)
        except ValueError:
            raise HandshakeError("bad_host")
        if (
            not parts.netloc
            or parts.hostname is None
            or parts.username is not None
            or parts.password is not None
            or parts.path
            or parts.query
            or parts.fragment
        ):
            raise HandshakeError("bad_host")

        try:
            port = parts.port
        except ValueError:
            raise HandshakeError("bad_host")
        if port is None:
            port = cls.DEFAULT_HTTPS_PORT

        host = parts.hostname.lower().rstrip(".")
        if not host or "*" in host:
            raise HandshakeError("bad_host")
        return host, port

    @staticmethod
    def _has_control_or_space(value):
        return any(ord(char) <= 0x20 or ord(char) == 0x7F for char in value)

    @staticmethod
    def _format_host(host):
        if ":" in host and not host.startswith("["):
            return "[%s]" % host
        return host

    @classmethod
    def _validate_connection_key(cls, raw):
        if not isinstance(raw, str):
            raise HandshakeError("bad_key")
        raw = raw.strip()
        try:
            decoded = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            raise HandshakeError("bad_key")
        if len(decoded) != 16:
            raise HandshakeError("bad_key")
        if base64.b64encode(decoded).decode("ascii") != raw:
            raise HandshakeError("bad_key")

    @staticmethod
    def _select_protocol(offered, allowed):
        if offered is None:
            offered = ()
        elif isinstance(offered, str):
            offered = (offered,)
        elif not isinstance(offered, (list, tuple)):
            raise HandshakeError("bad_subprotocol")

        if not offered:
            raise HandshakeError("subprotocol_required")
        if any(not isinstance(protocol, str) for protocol in offered):
            raise HandshakeError("bad_subprotocol")

        allowed = set(allowed)
        for protocol in offered:
            if protocol in allowed:
                return protocol
        raise HandshakeError("subprotocol_not_allowed")

    @staticmethod
    def _as_ticket_bytes(value):
        if isinstance(value, str):
            return value.encode("utf-8")
        if isinstance(value, bytes):
            return value
        return None

    def _find_ticket(self, candidate):
        candidate_bytes = self._as_ticket_bytes(candidate)
        match = None
        for ticket in self._tickets:
            expected = ticket["value_bytes"]
            same = False
            if candidate_bytes is not None and expected is not None:
                try:
                    same = hmac.compare_digest(candidate_bytes, expected)
                except TypeError:
                    same = False
            if same and match is None:
                match = ticket
        return match
