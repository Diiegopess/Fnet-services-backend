"""
Excepciones específicas para el Módulo de VDOMs.
"""

from typing import Any
from app.core.exceptions import (
    AppException,
    ForbiddenError,
    NotFoundError,
    ConflictError,
    BadGatewayError,
)


class VDOMNotFoundError(NotFoundError):
    def __init__(self, message: str = "El VDOM solicitado no existe o está inactivo.", details: Any | None = None):
        super().__init__(message=message, details=details)


class VDOMAccessDeniedError(ForbiddenError):
    def __init__(self, message: str = "No tiene permisos para acceder a este VDOM.", details: Any | None = None):
        super().__init__(message=message, details=details)


class VDOMAlreadyExistsError(ConflictError):
    def __init__(self, message: str = "El VDOM ya se encuentra registrado para este dispositivo.", details: Any | None = None):
        super().__init__(message=message, details=details)


class VDOMIntegrationError(BadGatewayError):
    def __init__(self, message: str = "Error de comunicación con el dispositivo al operar sobre el VDOM.", details: Any | None = None):
        super().__init__(message=message, details=details)