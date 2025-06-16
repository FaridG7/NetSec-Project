class ServiceUnavailable(Exception):
    def __init__(self, message="Service Unavailable: An error occured during process."):
        super().__init__(message)
        self.code = 503

class OptionsNotFound(ServiceUnavailable):
    def __init__(self, message="Options Not Found: Could not find the options 'files/options.json'"):
        super().__init__(message)

class BadOptionsFormat(ServiceUnavailable):
    def __init__(self, message="Bad Options Format: 'files/options.json' doesn't have the correct format."):
        super().__init__(message)

class LoginFailed(Exception):
    def __init__(self, message="Unauthorized: Username or password incorrect."):
        super().__init__(message)
        self.code = 401

class ConflictError(Exception):
    def __init__(self, message="Conflict: Resource already exists or state conflict."):
        super().__init__(message)
        self.code = 409

class BadInput(Exception):
    def __init__(self, message="Bad Input: Bad input entered."):
        super().__init__(message)
        self.code = 400

