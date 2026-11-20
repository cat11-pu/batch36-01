class PreviewError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


import ipaddress
import re
import threading
from urllib.parse import urljoin, urlsplit

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
LABEL_RE = re.compile(r"^[A-Za-z0-9-]+$")


class LinkPreviewWarden:
    def __init__(self, resolver, fetcher, allowed_ports=(443,), max_hops=3, max_bytes=2000000):
        self._resolver = resolver
        self._fetcher = fetcher
        self._allowed_ports = frozenset(allowed_ports)
        self._max_hops = max_hops
        self._max_bytes = max_bytes
        self._lock = threading.Lock()
        self._inspected = 0
        self._blocked = 0
        self._last_code = None

    def inspect(self, url, now=0):
        try:
            result = self._follow(url)
        except PreviewError as exc:
            with self._lock:
                self._blocked += 1
                self._last_code = exc.code
            raise
        with self._lock:
            self._inspected += 1
            self._last_code = None
        return result

    def snapshot(self):
        with self._lock:
            return {
                "inspected": self._inspected,
                "blocked": self._blocked,
                "last_code": self._last_code,
            }

    def _validate(self, url):
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise PreviewError("scheme_not_allowed")
        if parts.username is not None or parts.password is not None:
            raise PreviewError("userinfo_not_allowed")
        if parts.fragment:
            raise PreviewError("fragment_not_allowed")
        try:
            port = parts.port
        except ValueError:
            raise PreviewError("port_not_allowed")
        effective_port = port if port is not None else 443
        if effective_port not in self._allowed_ports:
            raise PreviewError("port_not_allowed")
        host = parts.hostname
        if not host:
            raise PreviewError("invalid_host")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise PreviewError("ip_literal")
        labels = host.split(".")
        if any(not label or not LABEL_RE.match(label) for label in labels):
            raise PreviewError("invalid_host")
        return host

    def _check_addresses(self, addresses):
        if not addresses:
            raise PreviewError("unresolvable")
        for addr in addresses:
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                raise PreviewError("invalid_address")
            if (
                ip.is_loopback
                or ip.is_private
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                raise PreviewError("private_address")

    def _follow(self, url):
        current = url
        visited = set()
        resolutions = {}
        hops = 0
        while True:
            host = self._validate(current)
            if current in visited:
                raise PreviewError("redirect_loop")
            visited.add(current)
            addresses = list(self._resolver(host))
            if host in resolutions:
                if set(resolutions[host]) != set(addresses):
                    raise PreviewError("dns_rebind")
            else:
                resolutions[host] = addresses
            self._check_addresses(addresses)
            address = addresses[0]
            response = self._fetcher(current, address)
            status = response.get("status")
            if status is not None and 200 <= status < 300:
                if response.get("size", 0) > self._max_bytes:
                    raise PreviewError("payload_too_large")
                return {
                    "final_url": current,
                    "hops": hops,
                    "address": address,
                    "digest": response.get("digest"),
                }
            if status in REDIRECT_STATUSES:
                location = response.get("location")
                if not location:
                    raise PreviewError("missing_location")
                if hops + 1 > self._max_hops:
                    raise PreviewError("too_many_hops")
                hops += 1
                current = urljoin(current, location)
                continue
            raise PreviewError("unexpected_status")
