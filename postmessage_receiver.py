class MessageReceiverError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class PostMessageReceiver:
    def __init__(self, allowed_origins, allowed_sources,
                 allowed_types=("ping", "resize"), max_bytes=4096,
                 reuse_window=60, max_sequence_gap=1, channels=None):
        pass

    def accept(self, event, now=0):
        return None

    def snapshot(self):
        return None
