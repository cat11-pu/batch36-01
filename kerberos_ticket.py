class KerberosError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


KNOWN_FLAGS = {
    "reserved",
    "forwardable",
    "forwarded",
    "proxiable",
    "proxy",
    "may_postdate",
    "postdated",
    "invalid",
    "renewable",
    "initial",
    "pre_authent",
    "hw_authent",
    "transited_policy_checked",
    "ok_as_delegate",
    "anonymous",
    "disable_transited_check",
    "enc_pa_rep",
}


def _split_principal(principal):
    if not isinstance(principal, str) or "@" not in principal:
        raise KerberosError("invalid_principal")
    name, realm = principal.rsplit("@", 1)
    if not name or not realm:
        raise KerberosError("invalid_principal")
    return name, realm


def _normalize_service(principal):
    name, realm = _split_principal(principal)
    parts = [p.strip() for p in name.split("/") if p.strip()]
    if not parts:
        raise KerberosError("invalid_principal")
    service = parts[0]
    instance = "/".join(p.lower() for p in parts[1:])
    normalized = service + ("/" + instance if instance else "")
    return normalized + "@" + realm.upper()


class KerberosTicketGuard:
    def __init__(self, realm, services, max_skew=300, replay_window=600):
        self.realm = realm
        self.services = {_normalize_service(s) for s in services}
        self.max_skew = max_skew
        self.replay_window = replay_window
        self._replay_cache = {}

    def validate(self, ticket, authenticator, now):
        client = ticket.get("client")
        server = ticket.get("server")

        _, client_realm = _split_principal(client)
        if client_realm != self.realm:
            raise KerberosError("wrong_realm")

        normalized_server = _normalize_service(server)
        _, server_realm = _split_principal(server)
        if server_realm != self.realm:
            raise KerberosError("wrong_realm")
        if normalized_server not in self.services:
            raise KerberosError("unknown_service")

        flags = ticket.get("flags") or []
        unknown = [f for f in flags if f not in KNOWN_FLAGS]
        if unknown:
            raise KerberosError("unknown_flag")

        if not ticket.get("session_key"):
            raise KerberosError("empty_session_key")

        start = ticket.get("start")
        end = ticket.get("end")
        if start is not None and now < start - self.max_skew:
            raise KerberosError("not_yet_valid")
        if end is not None and now > end + self.max_skew:
            raise KerberosError("expired")

        ctime = authenticator.get("ctime")
        if ctime is None or abs(ctime - now) > self.max_skew:
            raise KerberosError("clock_skew")

        if authenticator.get("client") != client:
            raise KerberosError("client_mismatch")

        if not authenticator.get("checksum"):
            raise KerberosError("bad_checksum")

        self._evict_replay_cache(now)
        replay_key = (client, normalized_server, ctime, authenticator.get("cusec", 0))
        if replay_key in self._replay_cache:
            raise KerberosError("replay_detected")
        self._replay_cache[replay_key] = ctime

        return {
            "client": client,
            "server": normalized_server,
            "remaining": end - now if end is not None else None,
            "session_key": ticket.get("session_key"),
        }

    def renew(self, ticket, now, lifetime=600):
        flags = ticket.get("flags") or []
        if "renewable" not in flags:
            raise KerberosError("not_renewable")
        renew_till = ticket.get("renew_till")
        if renew_till is None or now > renew_till:
            raise KerberosError("renew_window_expired")
        return {"start": now, "end": now + lifetime}

    def _evict_replay_cache(self, now):
        cutoff = now - self.replay_window
        stale = [key for key, ctime in self._replay_cache.items() if ctime < cutoff]
        for key in stale:
            del self._replay_cache[key]
