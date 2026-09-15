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
