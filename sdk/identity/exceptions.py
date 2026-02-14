"""AgentHub Identity SDK exceptions."""
from __future__ import annotations


class AgentHubError(Exception):
    """Base exception for AgentHub SDK."""

    def __init__(self, message: str, status_code: int | None = None, detail: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail


class AuthenticationError(AgentHubError):
    """Raised when authentication fails (401)."""


class AuthorizationError(AgentHubError):
    """Raised when authorization fails (403)."""


class NotFoundError(AgentHubError):
    """Raised when a resource is not found (404)."""


class ValidationError(AgentHubError):
    """Raised when request validation fails (400/422)."""


class RateLimitError(AgentHubError):
    """Raised when rate limit is exceeded (429)."""


class ServerError(AgentHubError):
    """Raised for server-side errors (5xx)."""
