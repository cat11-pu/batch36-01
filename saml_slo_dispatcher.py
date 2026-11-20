import copy
import threading


STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"


class SamlSloError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class SamlSloDispatcher:
    def __init__(self, entity_id, idp_entity_id, verify_signature, clock_skew=0):
        self.entity_id = entity_id
        self.idp_entity_id = idp_entity_id
        self._verify_signature = verify_signature
        self.clock_skew = clock_skew
        self._sessions = {}
        self._requests = {}
        self._lock = threading.Lock()

    def register_session(self, session_index, subject, client_id):
        with self._lock:
            self._sessions[session_index] = {
                "subject": subject,
                "client_id": client_id,
            }

    def handle_request(self, request, now):
        request_id = request.get("id")
        if not request_id:
            raise SamlSloError("empty_request_id")
        if request.get("issuer") != self.idp_entity_id:
            raise SamlSloError("bad_issuer")
        if request.get("destination") != self.entity_id:
            raise SamlSloError("bad_destination")
        not_on_or_after = request.get("not_on_or_after")
        if isinstance(not_on_or_after, bool) or not isinstance(not_on_or_after, int):
            raise SamlSloError("invalid_not_on_or_after")
        if not_on_or_after <= now - self.clock_skew:
            raise SamlSloError("request_expired")
        if not request.get("signature"):
            raise SamlSloError("bad_signature")
        if not self._verify_signature(request):
            raise SamlSloError("bad_signature")
        name_id = request.get("name_id")
        if not isinstance(name_id, str) or not name_id.strip():
            raise SamlSloError("invalid_name_id")
        name_id = name_id.strip()
        indexes = request.get("session_indexes")
        if not indexes:
            raise SamlSloError("empty_session_indexes")
        indexes = list(dict.fromkeys(indexes))

        with self._lock:
            if request_id in self._requests:
                raise SamlSloError("request_replayed")
            subjects = set()
            for index in indexes:
                session = self._sessions.get(index)
                if session is None:
                    raise SamlSloError("unknown_session_index")
                subjects.add(session["subject"])
            if len(subjects) != 1:
                raise SamlSloError("subject_mismatch")
            subject = subjects.pop()
            if subject != name_id:
                raise SamlSloError("subject_mismatch")

            removed = []
            for index in indexes:
                del self._sessions[index]
                removed.append(index)
            kept = [
                {"session_index": index, "client_id": session["client_id"]}
                for index, session in self._sessions.items()
                if session["subject"] == subject
            ]
            self._requests[request_id] = {
                "issuer": request["issuer"],
                "status": "success",
            }
        return {"status": "success", "removed": removed, "kept": kept}

    def build_response(self, request_id, status=None):
        with self._lock:
            record = self._requests.get(request_id)
            if record is None:
                raise SamlSloError("unknown_request")
            return {
                "id": "resp-%s" % request_id,
                "in_response_to": request_id,
                "destination": record["issuer"],
                "status": status or STATUS_SUCCESS,
            }

    def state(self):
        with self._lock:
            return {"sessions": copy.deepcopy(self._sessions)}
