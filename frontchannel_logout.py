import secrets
from urllib.parse import parse_qsl, urlencode, urlparse


class LogoutError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class FrontChannelLogoutHub:
    def __init__(self, issuer, clients):
        if not issuer:
            raise ValueError("issuer is required")
        self.issuer = issuer
        self.clients = {}
        for client in clients:
            self._register_client(client)
        self.sessions = {}

    def _register_client(self, client):
        client_id = client.get("client_id")
        if not client_id:
            raise ValueError("client_id is required")
        if client_id in self.clients:
            raise ValueError("duplicate client_id: %s" % client_id)

        logout_uri = client.get("logout_uri", "")
        parsed = urlparse(logout_uri)
        hostname = parsed.hostname
        if parsed.scheme != "https":
            raise ValueError("logout_uri must use https")
        if not hostname or "*" in hostname:
            raise ValueError("logout_uri must point to a valid https host")
        if parsed.fragment:
            raise ValueError("logout_uri must not contain a fragment")

        origins = client.get("origins") or []
        for origin in origins:
            if not origin or "*" in origin:
                raise ValueError("wildcard origins are not allowed")

        self.clients[client_id] = {
            "client_id": client_id,
            "logout_uri": logout_uri,
            "origins": list(origins),
        }

    def open_session(self, session_id, subject, client_ids, now, ttl=600):
        if not session_id:
            raise ValueError("session_id is required")
        if not subject:
            raise ValueError("subject is required")
        if not client_ids:
            raise ValueError("client_ids is required")
        for client_id in client_ids:
            if client_id not in self.clients:
                raise ValueError("unknown client_id: %s" % client_id)

        bindings = []
        issued = set()
        for client_id in client_ids:
            sid = secrets.token_hex(16)
            while sid in issued:
                sid = secrets.token_hex(16)
            issued.add(sid)
            bindings.append({
                "client_id": client_id,
                "sid": sid,
                "consumed": False,
            })

        session = {
            "session_id": session_id,
            "subject": subject,
            "expires_at": now + ttl,
            "bindings": bindings,
        }
        self.sessions[session_id] = session
        return session

    def build_frames(self, session_id, now):
        session = self._require_active_session(session_id, now)
        frames = []
        for binding in session["bindings"]:
            client = self.clients[binding["client_id"]]
            frames.append({
                "client_id": client["client_id"],
                "url": self._build_frame_url(client, binding["sid"]),
            })
        return {"issuer": self.issuer, "frames": frames}

    def _build_frame_url(self, client, sid):
        parsed = urlparse(client["logout_uri"])
        query = parse_qsl(parsed.query, keep_blank_values=True)
        query.append(("iss", self.issuer))
        query.append(("sid", sid))
        query.append(("nonce", secrets.token_hex(16)))
        query.sort(key=lambda item: item[0])
        return parsed._replace(query=urlencode(query), fragment="").geturl()

    def _require_active_session(self, session_id, now):
        session = self.sessions.get(session_id)
        if session is None:
            raise LogoutError("unknown_session")
        if now >= session["expires_at"]:
            raise LogoutError("expired")
        return session

    def _find_binding(self, sid):
        for session in self.sessions.values():
            for binding in session["bindings"]:
                if binding["sid"] == sid:
                    return session, binding
        return None

    @staticmethod
    def _remaining(session):
        return sum(1 for binding in session["bindings"] if not binding["consumed"])

    def _referer_allowed(self, referer, client):
        if not referer:
            return False
        host = urlparse(referer).hostname
        return bool(host) and host in client["origins"]

    def handle_frame(self, params, referer, now):
        params = params or {}
        sid = params.get("sid")
        if not sid:
            raise ValueError("sid is required")

        found = self._find_binding(sid)
        if found is None:
            raise LogoutError("unknown_session")
        session, binding = found
        if now >= session["expires_at"]:
            raise LogoutError("expired")
        if params.get("iss") != self.issuer:
            raise LogoutError("bad_issuer")

        client = self.clients[binding["client_id"]]
        if not self._referer_allowed(referer, client):
            raise LogoutError("bad_referer")

        if binding["consumed"]:
            return {
                "client_id": client["client_id"],
                "status": "already_logged_out",
                "remaining": self._remaining(session),
            }

        binding["consumed"] = True
        return {
            "client_id": client["client_id"],
            "status": "logged_out",
            "remaining": self._remaining(session),
        }

    def logout_session(self, session_id, now):
        session = self.sessions.get(session_id)
        if session is None:
            raise LogoutError("unknown_session")
        cleared = len(session["bindings"])
        del self.sessions[session_id]
        return {"cleared": cleared}
