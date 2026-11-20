import ipaddress


class SshCertError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class SshUserCertAuthority:
    KNOWN_CRITICAL_OPTIONS = frozenset(
        ("force-command", "source-address", "verify-required")
    )

    def __init__(self, trusted_cas, allowed_principals, verify_signature=None, allow_wildcard=False):
        self._cas = {}
        for ca in trusted_cas:
            key_id = ca.get("key_id")
            if not key_id:
                raise SshCertError("invalid_ca")
            if key_id in self._cas:
                raise SshCertError("duplicate_ca")
            if not ca.get("public_key"):
                raise SshCertError("ca_missing_key")
            if ca.get("not_before") > ca.get("not_after"):
                raise SshCertError("ca_bad_validity")
            self._cas[key_id] = ca

        if not allowed_principals:
            raise SshCertError("empty_allowed_principals")
        self._allowed_principals = set(allowed_principals)
        self._verify_signature = verify_signature
        self._allow_wildcard = allow_wildcard

    def verify(self, cert, client_ip, now):
        if cert.get("cert_type") != "user":
            raise SshCertError("bad_cert_type")

        ca = self._cas.get(cert.get("ca_key_id"))
        if ca is None:
            raise SshCertError("unknown_ca")
        if not ca["not_before"] <= now <= ca["not_after"]:
            raise SshCertError("ca_inactive")

        if not cert.get("valid_after") <= now <= cert.get("valid_before"):
            raise SshCertError("cert_inactive")

        if not self._verify_signature or not self._verify_signature(ca, cert, cert.get("signature")):
            raise SshCertError("bad_signature")

        principals = cert.get("principals")
        if not principals:
            raise SshCertError("principal_denied")
        for principal in principals:
            if not isinstance(principal, str) or not principal:
                raise SshCertError("principal_denied")
            if principal == "*" and not self._allow_wildcard:
                raise SshCertError("principal_denied")
            if principal != "*" and principal not in self._allowed_principals:
                raise SshCertError("principal_denied")

        force_command = None
        source_networks = None
        critical_options = cert.get("critical_options") or {}
        for name, value in critical_options.items():
            if name not in self.KNOWN_CRITICAL_OPTIONS:
                raise SshCertError("bad_critical_option")
            if name == "force-command":
                if not isinstance(value, str) or not value:
                    raise SshCertError("bad_critical_option")
                force_command = value
            elif name == "source-address":
                source_networks = self._parse_source_addresses(value)

        if source_networks is not None:
            self._check_source_address(client_ip, source_networks)

        return {
            "key_id": cert.get("key_id"),
            "ca_key_id": ca["key_id"],
            "principals": list(principals),
            "force_command": force_command,
        }

    @staticmethod
    def _parse_source_addresses(value):
        if not isinstance(value, str) or not value.strip():
            raise SshCertError("source_address_denied")
        networks = []
        for entry in value.split(","):
            entry = entry.strip()
            if not entry:
                raise SshCertError("source_address_denied")
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                raise SshCertError("source_address_denied")
        return networks

    @staticmethod
    def _check_source_address(client_ip, networks):
        try:
            address = ipaddress.ip_address(client_ip)
        except (ValueError, TypeError):
            raise SshCertError("source_address_denied")
        for network in networks:
            if network.version == address.version and address in network:
                return
        raise SshCertError("source_address_denied")
