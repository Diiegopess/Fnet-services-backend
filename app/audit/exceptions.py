"""Módulo de Excepciones del Dominio de Auditoría (Audit Logs).

Define las excepciones asociadas a la trazabilidad, consulta y acceso
a las bitácoras de eventos del sistema.
"""

from typing import Any
from app.core.exceptions import AppException, ForbiddenError, NotFoundError


class AuditAccessDeniedError(ForbiddenError):
    """Lanzada cuando un usuario intenta consultar la bitácora sin los permisos adecuados."""

    def __init__(
        self,
        message: str = "No posee los permisos suficientes para acceder a la auditoría del sistema.",
        details: Any | None = None,
    ):
        super().__init__(message=message, details=details)
        self.error_code = "AUDIT_ACCESS_DENIED"


class AuditLogNotFoundError(NotFoundError):
    """Lanzada cuando se busca un registro de bitácora específico y no existe."""

    def __init__(
        self,
        message: str = "El registro de auditoría solicitado no fue encontrado.",
        details: Any | None = None,
    ):
        super().__init__(message=message, details=details)
        self.error_code = "AUDIT_LOG_NOT_FOUND"


class AuditLogWriteError(AppException):
    """Lanzada en caso de un fallo crítico al intentar escribir una traza de auditoría."""

    def __init__(
        self,
        message: str = "No se pudo registrar el evento de auditoría en la base de datos.",
        details: Any | None = None,
    ):
        super().__init__(
            message=message,
            status_code=500,
            error_code="AUDIT_LOG_WRITE_FAILED",
            details=details,
        )