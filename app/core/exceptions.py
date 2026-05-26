"""Custom exceptions for the Cyber Threat Intelligence Analysis Platform."""

class CTIException(Exception):
    """Base exception for all CTI platform errors."""
    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class InvalidIOCException(CTIException):
    """Raised when an IOC format is invalid or cannot be parsed."""
    pass


class SSRFSecurityException(CTIException):
    """Raised when an outbound network request targets a private or forbidden IP/host."""
    pass


class ProviderAPIException(CTIException):
    """Raised when an external threat provider fails or errors."""
    def __init__(self, provider: str, message: str, status_code: int = None, details: dict = None):
        super().__init__(f"[{provider}] {message}", details)
        self.provider = provider
        self.status_code = status_code


class RateLimitExceededException(CTIException):
    """Raised when an intelligence provider's rate limit is hit."""
    def __init__(self, provider: str, wait_seconds: float = 60.0):
        super().__init__(f"Rate limit exceeded for {provider}. Retry in {wait_seconds:.1f}s.")
        self.provider = provider
        self.wait_seconds = wait_seconds


class ReportGenerationException(CTIException):
    """Raised when threat report rendering fails."""
    pass
