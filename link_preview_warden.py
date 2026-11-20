class PreviewError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class LinkPreviewWarden:
    def __init__(self, resolver, fetcher, allowed_ports=(443,), max_hops=3, max_bytes=2000000):
        pass

    def inspect(self, url, now=0):
        return None

    def snapshot(self):
        return None
