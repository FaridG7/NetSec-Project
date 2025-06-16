class ConflictError(Exception):
    def __init__(self, message="Conflict: Resource already exists or state conflict."):
        super().__init__(message)
        self.status_code = 409

