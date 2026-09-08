"""Módulo de Excepciones del Dominio de Autenticación.

Define las excepciones específicas para los flujos de login local, JWT y Google OAuth.
"""

from typing import Any
from app.core.exceptions import ForbiddenError, UnauthorizedError


class InvalidCredentialsError(UnauthorizedError):
    """Lanzada cuando las credenciales ingresadas son incorrectas."""

    def __init__(
        self,
        message: str = "Correo electrónico o contraseña incorrectos.",
        details: Any | None = None,
    ):
        super().__init__(message=message, details=details)
        self.error_code = "INVALID_CREDENTIALS"


class InactiveUserError(ForbiddenError):
    """Lanzada cuando el usuario intenta autenticarse pero su cuenta está deshabilitada."""

    def __init__(
        self,
        message: str = "La cuenta se encuentra inactiva o suspendida.",
        details: Any | None = None,
    ):
        super().__init__(message=message, details=details)
        self.error_code = "USER_INACTIVE"


class InvalidTokenError(UnauthorizedError):
    """Lanzada cuando el JWT de la aplicación es inválido, malformado o expiró."""

    def __init__(
        self,
        message: str = "El token de autenticación es inválido o ha expirado.",
        details: Any | None = None,
    ):
        super().__init__(message=message, details=details)
        self.error_code = "INVALID_TOKEN"


class InvalidGoogleTokenError(UnauthorizedError):
    """Lanzada cuando el ID Token de Google no es válido o expiró."""

    def __init__(
        self,
        message: str = (
            "El token de Google es inválido, ha expirado o no se pudo verificar."
        ),
        details: Any | None = None,
    ):
        super().__init__(message=message, details=details)
        self.error_code = "INVALID_GOOGLE_TOKEN"