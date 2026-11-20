class MtlsError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class MutualTlsAuthenticator:
    def __init__(self, trusted_issuers, accounts, revoked=None, max_chain_depth=1):
        self.trusted_issuers = {str(fp).strip() for fp in (trusted_issuers or set())}
        self.accounts = {
            str(name).strip(): dict(info) for name, info in (accounts or {}).items()
        }
        self.revoked = {str(s).strip().lower() for s in (revoked or set())}
        self.max_chain_depth = max_chain_depth

    def authenticate(self, cert, request, now):
        if not cert:
            raise MtlsError("no_certificate")

        issuer = cert.get("issuer_fingerprint")
        if not issuer or str(issuer).strip() not in self.trusted_issuers:
            raise MtlsError("untrusted_issuer")

        eku = cert.get("eku") or []
        if "clientAuth" not in eku:
            raise MtlsError("wrong_eku")

        key_usage = cert.get("key_usage") or []
        if "digitalSignature" not in key_usage:
            raise MtlsError("bad_key_usage")

        not_before = cert.get("not_before")
        not_after = cert.get("not_after")
        if (
            not_before is None
            or not_after is None
            or not_before > not_after
            or now < not_before
            or now > not_after
        ):
            raise MtlsError("cert_inactive")

        chain_depth = cert.get("chain_depth")
        if chain_depth is None or chain_depth > self.max_chain_depth:
            raise MtlsError("chain_too_deep")

        serial = cert.get("serial")
        if not serial or not str(serial).strip():
            raise MtlsError("bad_serial")
        serial = str(serial).strip()
        if serial.lower() in self.revoked:
            raise MtlsError("revoked")

        request = request or {}
        conn_serial = request.get("tls_cert_serial")
        if conn_serial is None or str(conn_serial).strip() != serial:
            raise MtlsError("session_mismatch")

        subject_cn = cert.get("subject_cn")
        if not subject_cn or str(subject_cn).strip() not in self.accounts:
            raise MtlsError("unknown_account")
        account_name = str(subject_cn).strip()
        account = self.accounts[account_name]

        if not account.get("enabled"):
            raise MtlsError("account_disabled")

        registered_uri = str(account.get("uri") or "").strip()
        if cert.get("san_uri") != registered_uri:
            raise MtlsError("identity_mismatch")

        return {
            "account": account_name,
            "uri": registered_uri,
            "serial": serial,
        }
