class ConflictError(Exception):
    def __init__(self, message="Conflict: Resource already exists or state conflict."):
        super().__init__(message)
        self.code = 409

class LoginFailed(Exception):
    def __init__(self, message="Unauthorized: Username or Password incorrect."):
        super().__init__(message)
        self.code = 401

