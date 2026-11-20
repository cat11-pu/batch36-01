class CorsPolicyError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class CorsPreflightArbiter:
    def __init__(self, allowed_origins, allowed_methods=("GET", "POST"),
                 allowed_headers=("content-type",), max_age=600,
                 credentials=True, allow_private_network=False):
        pass

    def decide(self, request, now=0):
        return None

    def render_error(self):
        return None

    def snapshot(self):
        return None
