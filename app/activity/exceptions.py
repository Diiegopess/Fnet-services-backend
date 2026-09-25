"""
Módulo de Excepciones del Dominio de Actividad (Activity Logs).

Define las excepciones asociadas a la trazabilidad, consulta y acceso
a las bitácoras de eventos del sistema.
"""

from typing import Any
from app.core.exceptions import AppException, ForbiddenError, NotFoundError


class ActivityAccessDeniedError(ForbiddenError):
    """Lanzada cuando un usuario intenta consultar la bitácora sin los permisos adecuados."""

    def __init__(
        self,
        message: str = "No posee los permisos suficientes para acceder a la bitácora de actividad del sistema.",
        details: Any | None = None,
    ):
        super().__init__(message=message, details=details)
        self.error_code = "ACTIVITY_ACCESS_DENIED"


class ActivityLogNotFoundError(NotFoundError):
    """Lanzada cuando se busca un registro de actividad específico y no existe."""

    def __init__(
        self,
        message: str = "El registro de actividad solicitado no fue encontrado.",
        details: Any | None = None,
    ):
        super().__init__(message=message, details=details)
        self.error_code = "ACTIVITY_LOG_NOT_FOUND"


class ActivityLogWriteError(AppException):
    """Lanzada en caso de un fallo crítico al intentar escribir una traza de actividad."""

    def __init__(
        self,
        message: str = "No se pudo registrar el evento de actividad en la base de datos.",
        details: Any | None = None,
    ):
        super().__init__(
            message=message,
            status_code=500,
            error_code="ACTIVITY_LOG_WRITE_FAILED",
            details=details,
        )