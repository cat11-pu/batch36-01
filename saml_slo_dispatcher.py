class SamlSloError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class SamlSloDispatcher:
    def __init__(self, entity_id, idp_entity_id, verify_signature, clock_skew=0):
        pass

    def register_session(self, session_index, subject, client_id):
        return None

    def handle_request(self, request, now):
        return None

    def build_response(self, request_id, status="urn:oasis:names:tc:SAML:2.0:status:Success"):
        return None

    def state(self):
        return None
