import copy
import secrets


REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"


class ParError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class PushedRequestRegistry:
    def __init__(self, clients, response_types, scopes, max_ttl=90):
        self.clients = clients
        self.response_types = set(response_types)
        self.scopes = set(scopes)
        self.max_ttl = max_ttl
        self.requests = {}

    def push(self, client_id, params, now, ttl=60):
        if not isinstance(params, dict):
            raise ParError("invalid_request")

        client = self.clients.get(client_id)
        if client is None:
            raise ParError("invalid_client")
        if params.get("client_id") != client_id:
            raise ParError("invalid_client")

        response_type = params.get("response_type")
        if not isinstance(response_type, str) or response_type not in self.response_types:
            raise ParError("unsupported_response_type")

        scope_value = params.get("scope", "")
        if not isinstance(scope_value, str):
            raise ParError("invalid_scope")
        scope = list(dict.fromkeys(scope_value.split()))
        if any(item not in self.scopes for item in scope):
            raise ParError("invalid_scope")

        redirect_uri = params.get("redirect_uri")
        if redirect_uri not in client.get("redirect_uris", ()):
            raise ParError("invalid_redirect")

        state = params.get("state")
        if not isinstance(state, str) or not state.strip():
            raise ParError("missing_state")

        if client.get("public"):
            challenge = params.get("code_challenge")
            method = params.get("code_challenge_method")
            if not isinstance(challenge, str) or not challenge:
                raise ParError("pkce_required")
            if method != "S256":
                raise ParError("invalid_challenge_method")

        if "request" in params or "request_uri" in params:
            raise ParError("nested_request")

        if not isinstance(ttl, (int, float)) or isinstance(ttl, bool) or ttl < 0:
            raise ParError("invalid_request")
        expires_in = min(ttl, self.max_ttl)
        request_uri = REQUEST_URI_PREFIX + secrets.token_hex(16)
        stored = copy.deepcopy(params)
        stored["scope"] = scope
        self.requests[request_uri] = {
            "client_id": client_id,
            "expires_at": now + expires_in,
            "params": stored,
            "used": False,
        }
        return {
            "request_uri": request_uri,
            "expires_in": expires_in,
            "expires_at": now + expires_in,
        }

    def consume(self, request_uri, client_id, now):
        if not isinstance(request_uri, str):
            raise ParError("invalid_request_uri")
        record = self.requests.get(request_uri)
        if record is None:
            raise ParError("invalid_request_uri")
        if record["client_id"] != client_id:
            raise ParError("invalid_client")
        if record["used"]:
            raise ParError("request_uri_used")
        if now >= record["expires_at"]:
            raise ParError("expired_request_uri")

        record["used"] = True
        return copy.deepcopy(record["params"])
