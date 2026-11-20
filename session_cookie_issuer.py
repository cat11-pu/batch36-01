class CookieIssueError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class SessionCookieIssuer:
    def __init__(self, site_domain="example.com", require_secure=True):
        pass

    def issue(self, name, value, attrs, now=0):
        return None

    def parse(self, headers, now=0):
        return None

    def snapshot(self):
        return None
