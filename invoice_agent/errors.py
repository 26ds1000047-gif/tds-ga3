class ApiError(Exception):
    """Raised anywhere; main.py turns it into a generic JSON error body.

    Messages are deliberately generic: never put task IDs or other users' data in them.
    """

    def __init__(self, status: int, code: str, message: str = "The request could not be processed."):
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message
