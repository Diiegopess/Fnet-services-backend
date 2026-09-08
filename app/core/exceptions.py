"""Módulo de Excepciones Base del Core.

Define la excepción raíz y las especializaciones de protocolo HTTP transversales.
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
    """Lanzada cuando falla la autenticación (HTTP 401)."""

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
    """Lanzada cuando se deniega el acceso por permisos o contexto (HTTP 403)."""

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
    """Lanzada cuando un recurso no existe (HTTP 404)."""

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


class ConflictError(AppException):
    """Lanzada cuando un recurso ya existe o hay conflicto de estado (HTTP 409)."""

    def __init__(
        self,
        message: str = "El recurso ya existe o genera un conflicto.",
        details: Any | None = None,
    ):
        super().__init__(
            message=message,
            status_code=status.HTTP_409_CONFLICT,
            error_code="CONFLICT",
            details=details,
        )


class BadGatewayError(AppException):
    """Lanzada cuando falla la comunicación con una API externa o dispositivo (HTTP 502)."""

    def __init__(
        self,
        message: str = "Error de comunicación con el servicio externo.",
        details: Any | None = None,
    ):
        super().__init__(
            message=message,
            status_code=status.HTTP_502_BAD_GATEWAY,
            error_code="BAD_GATEWAY",
            details=details,
        )