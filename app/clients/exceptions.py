"""Excepciones de Dominio para el Módulo de Clientes."""

from typing import Any
from app.core.exceptions import AppException, ConflictError, NotFoundError


class ClientNotFoundError(NotFoundError):
    def __init__(self, message: str = "Cliente no encontrado.", details: Any | None = None):
        super().__init__(message=message, details=details)
        self.error_code = "CLIENT_NOT_FOUND"


class ClientAlreadyExistsError(ConflictError):
    def __init__(
        self,
        message: str = "Ya existe un cliente con ese nombre o identificación fiscal.",
        details: Any | None = None,
    ):
        super().__init__(message=message, details=details)
        self.error_code = "CLIENT_ALREADY_EXISTS"


class InvalidTechnicianAssignmentError(AppException):
    """Fallo en regla de validación de negocio al asignar técnicos (HTTP 400)."""

    def __init__(
        self,
        message: str = "Uno o más identificadores de técnicos no son válidos o están inactivos.",
        details: Any | None = None,
    ):
        super().__init__(
            message=message,
            status_code=400,
            error_code="INVALID_TECHNICIAN_ASSIGNMENT",
            details=details,
        )