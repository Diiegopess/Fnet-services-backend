"""
Módulo de Excepciones Base del Core.
"""

from typing import Any
from fastapi import status


class AppException(Exception):
    """Excepción base para todos los errores controlados de la aplicación."""

    def __init__(
        self,
        message: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        error_code: str = "BAD_REQUEST",
        details: Any | None = None,
    ):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details
        super().__init__(self.message)


class UnauthorizedError(AppException):
    """Lanzada cuando la autenticación falla, expira o no es válida."""

    def __init__(
        self,
        message: str = "No autenticado o credenciales inválidas.",
        details: Any | None = None,
    ):
        super().__init__(
            message=message,
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code="UNAUTHORIZED",
            details=details,
        )


class ForbiddenError(AppException):
    """Lanzada cuando el usuario no tiene los permisos suficientes."""

    def __init__(
        self,
        message: str = "Acceso denegado. Permisos insuficientes.",
        details: Any | None = None,
    ):
        super().__init__(
            message=message,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="FORBIDDEN",
            details=details,
        )


class NotFoundError(AppException):
    """Lanzada cuando el recurso solicitado no existe."""

    def __init__(
        self,
        message: str = "El recurso solicitado no fue encontrado.",
        details: Any | None = None,
    ):
        super().__init__(
            message=message,
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="NOT_FOUND",
            details=details,
        )