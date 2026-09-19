# src/task_api/core/exceptions.py


class DomainError(Exception):
    """Base exception for all core application domain failures."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class InvalidTokenError(DomainError):
    """Raised when an access, action or refresh token is invalid or expired."""


class RecordNotFoundError(DomainError):
    """Raised when a requested resource is missing in PostgreSQL."""


class DuplicateRecordError(DomainError):
    """Raised when a duplicate resource is inserted in PostgreSQL."""


class InvalidCredentialsError(DomainError):
    """Raised when supplied credentials do not match the user."""


class EmailAlreadyVerifiedError(DomainError):
    """Raised when an email verification is requested for an already verified user."""


class TokenCooldownError(DomainError):
    """Raised when an action token is requested before the cooldown period has elapsed."""
