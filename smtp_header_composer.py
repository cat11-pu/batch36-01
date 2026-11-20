import re
import threading
import unicodedata


class HeaderComposerError(ValueError):
    def __init__(self, code, source=None):
        super().__init__(code)
        self.code = code
        self.source = source


_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")
_LOCAL_CHARS = frozenset(
    "!#$%&'*+-/=?^_`{|}~"
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "."
)
_DISPLAY_FORBIDDEN = frozenset('<>",;\\')
_RESERVED_HEADERS = frozenset(
    {
        "from",
        "to",
        "cc",
        "bcc",
        "subject",
        "date",
        "reply-to",
        "sender",
        "return-path",
        "received",
        "message-id",
        "in-reply-to",
        "references",
        "mime-version",
        "content-type",
        "content-transfer-encoding",
        "content-disposition",
        "content-id",
    }
)


class SmtpHeaderComposer:
    def __init__(
        self,
        max_recipients=20,
        max_body=10000,
        max_subject=998,
        max_headers=50,
        **aliases,
    ):
        max_subject = aliases.pop("max_subject_length", max_subject)
        max_headers = aliases.pop("max_header_count", max_headers)
        if aliases:
            unexpected = next(iter(aliases))
            raise TypeError("unexpected argument: " + unexpected)
        if max_recipients < 0 or max_body < 0 or max_subject < 0 or max_headers < 0:
            raise ValueError("limits must be non-negative")
        self.max_recipients = max_recipients
        self.max_body = max_body
        self.max_subject = max_subject
        self.max_headers = max_headers
        self._lock = threading.Lock()
        self._stats = {
            "assembled": 0,
            "rejected": 0,
            "rejected_address": 0,
            "rejected_header_name": 0,
            "rejected_header_value": 0,
            "rejected_body": 0,
        }

    def assemble(self, message, now=0):
        try:
            return self._assemble(message, now)
        except HeaderComposerError as exc:
            source = exc.source or {
                "bad_address": "address",
                "duplicate_recipient": "address",
                "too_many_recipients": "address",
                "bad_header_name": "header_name",
                "reserved_header": "header_name",
                "duplicate_header": "header_name",
                "too_many_headers": "header_name",
                "bad_body": "body",
            }.get(exc.code, "header_value")
            with self._lock:
                self._stats["rejected"] += 1
                self._stats["rejected_" + source] += 1
            raise

    def audit(self):
        with self._lock:
            return dict(self._stats)

    def _assemble(self, message, now):
        if not isinstance(message, dict):
            raise HeaderComposerError("bad_message")

        sender = self._parse_mailbox(message.get("from"), "address")
        to = self._parse_mailboxes(message.get("to"))
        cc = self._parse_mailboxes(message.get("cc"))
        bcc = self._parse_mailboxes(message.get("bcc"))

        recipients = []
        seen = set()
        for entry in to + cc + bcc:
            key = entry["address"].lower()
            if key in seen:
                raise HeaderComposerError("duplicate_recipient", "address")
            seen.add(key)
            recipients.append(entry)

        if len(recipients) > self.max_recipients:
            raise HeaderComposerError("too_many_recipients", "address")

        subject = self._parse_subject(message.get("subject"))
        custom_headers = self._parse_headers(message.get("headers"))
        body = self._parse_body(message.get("body"))

        lines = ["From: " + self._render_mailbox(sender)]
        if to:
            lines.append("To: " + ", ".join(self._render_mailbox(item) for item in to))
        if cc:
            lines.append("Cc: " + ", ".join(self._render_mailbox(item) for item in cc))
        lines.append("Subject: " + subject)
        lines.extend(name + ": " + value for name, value in custom_headers)

        rendered = "\r\n".join(lines) + "\r\n\r\n" + body
        if not rendered.endswith("\r\n\r\n"):
            rendered += "\r\n"
            if not rendered.endswith("\r\n\r\n"):
                rendered += "\r\n"

        with self._lock:
            self._stats["assembled"] += 1

        return {
            "rendered": rendered,
            "envelope_rcpt": [entry["address"] for entry in recipients],
            "bcc_omitted": True,
        }

    def _parse_mailboxes(self, value):
        if value is None:
            return []
        if isinstance(value, (str, dict)):
            value = [value]
        if not isinstance(value, (list, tuple)):
            raise HeaderComposerError("bad_address", "address")
        return [self._parse_mailbox(item, "address") for item in value]

    def _parse_mailbox(self, value, source):
        if isinstance(value, str):
            address = value
            name = ""
        elif isinstance(value, dict):
            address = value.get("address")
            name = value.get("name", "")
        else:
            raise HeaderComposerError("bad_address", source)

        if not isinstance(name, str):
            raise HeaderComposerError("bad_display_name", "header_value")
        self._check_field_value(name, "header_value")
        self._check_display_name(name)

        if not isinstance(address, str):
            raise HeaderComposerError("bad_address", source)
        self._check_field_value(address, source)

        local, domain = self._split_address(address)
        self._check_local(local)
        self._check_domain(domain)
        return {"address": address, "name": name, "local": local, "domain": domain}

    def _split_address(self, address):
        if any(ch.isspace() for ch in address):
            raise HeaderComposerError("bad_address", "address")
        if address.count("@") != 1:
            raise HeaderComposerError("bad_address", "address")
        local, domain = address.split("@", 1)
        if not local or not domain:
            raise HeaderComposerError("bad_address", "address")
        return local, domain

    def _check_local(self, local):
        if local.startswith(".") or local.endswith(".") or ".." in local:
            raise HeaderComposerError("bad_address", "address")
        if any(ch not in _LOCAL_CHARS for ch in local):
            raise HeaderComposerError("bad_address", "address")

    def _check_domain(self, domain):
        if len(domain) > 253:
            raise HeaderComposerError("bad_address", "address")
        for label in domain.split("."):
            if not label or len(label) > 63:
                raise HeaderComposerError("bad_address", "address")
            if not _DOMAIN_LABEL_RE.fullmatch(label):
                raise HeaderComposerError("bad_address", "address")

    def _check_field_value(self, value, source):
        for ch in value:
            if ch in "\r\n\x00\u2028\u2029":
                raise HeaderComposerError("header_injection", source)
            if unicodedata.category(ch) == "Cc" and ch != "\t":
                raise HeaderComposerError("header_injection", source)

    def _check_display_name(self, name):
        for ch in name:
            if ch == "\t" or unicodedata.category(ch) == "Cf":
                raise HeaderComposerError("bad_display_name", "header_value")
            if ch in _DISPLAY_FORBIDDEN:
                raise HeaderComposerError("bad_display_name", "header_value")

    def _parse_subject(self, value):
        if not isinstance(value, str):
            raise HeaderComposerError("empty_subject", "header_value")
        self._check_field_value(value, "header_value")
        subject = value.strip()
        if not subject:
            raise HeaderComposerError("empty_subject", "header_value")
        if len(subject) > self.max_subject:
            raise HeaderComposerError("subject_too_long", "header_value")
        return subject

    def _parse_headers(self, value):
        if value is None:
            return []
        if isinstance(value, dict):
            entries = list(value.items())
        elif isinstance(value, (list, tuple)):
            entries = list(value)
        else:
            raise HeaderComposerError("bad_header_name", "header_name")

        if len(entries) > self.max_headers:
            raise HeaderComposerError("too_many_headers", "header_name")

        result = []
        seen = set()
        for entry in entries:
            if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                raise HeaderComposerError("bad_header_name", "header_name")
            name, header_value = entry
            if not isinstance(name, str):
                raise HeaderComposerError("bad_header_name", "header_name")
            self._check_field_value(name, "header_name")
            if not _TOKEN_RE.fullmatch(name):
                raise HeaderComposerError("bad_header_name", "header_name")
            lowered = name.lower()
            if lowered in _RESERVED_HEADERS:
                raise HeaderComposerError("reserved_header", "header_name")
            if lowered in seen:
                raise HeaderComposerError("duplicate_header", "header_name")
            seen.add(lowered)
            if not isinstance(header_value, str):
                raise HeaderComposerError("bad_header_value", "header_value")
            self._check_field_value(header_value, "header_value")
            result.append((name, header_value))
        return result

    def _parse_body(self, value):
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise HeaderComposerError("bad_body", "body")
        if "\x00" in value:
            raise HeaderComposerError("bad_body", "body")
        if re.search(r"\r(?!\n)", value):
            raise HeaderComposerError("bad_body", "body")
        if len(value) > self.max_body:
            raise HeaderComposerError("bad_body", "body")
        for ch in value:
            if ch in "\t\n\r":
                continue
            if unicodedata.category(ch) == "Cc":
                raise HeaderComposerError("bad_body", "body")
        return value.replace("\r\n", "\n").replace("\n", "\r\n")

    @staticmethod
    def _render_mailbox(entry):
        name = entry["name"].strip()
        if name:
            return name + " <" + entry["address"] + ">"
        return entry["address"]
