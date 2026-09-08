"""Módulo de Excepciones del Dominio de Usuarios."""

from typing import Any
from app.core.exceptions import ConflictError, NotFoundError


class UserNotFoundError(NotFoundError):
    """Lanzada cuando un usuario no existe en la base de datos."""

    def __init__(
        self,
        message: str = "El usuario solicitado no fue encontrado.",
        details: Any | None = None,
    ):
        super().__init__(message=message, details=details)
        self.error_code = "USER_NOT_FOUND"


class UserAlreadyExistsError(ConflictError):
    """Lanzada cuando se intenta registrar un correo duplicado."""

    def __init__(
        self,
        message: str = "Ya existe un usuario registrado con este correo electrónico.",
        details: Any | None = None,
    ):
        super().__init__(message=message, details=details)
        self.error_code = "USER_ALREADY_EXISTS"