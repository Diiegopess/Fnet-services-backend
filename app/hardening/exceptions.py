from typing import Any
from fastapi import status

from app.core.exceptions import AppException, NotFoundError


class HardeningException(AppException):
    """Excepción base para errores específicos del dominio de Hardening."""

    def __init__(
        self,
        message: str = "Error en el servicio de Hardening.",
        status_code: int = status.HTTP_400_BAD_REQUEST,
        error_code: str = "HARDENING_ERROR",
        details: Any | None = None,
    ):
        super().__init__(
            message=message,
            status_code=status_code,
            error_code=error_code,
            details=details,
        )


class ProfileNotFoundException(NotFoundError):
    """Lanzada cuando un perfil de hardening no existe (HTTP 404)."""

    def __init__(self, profile_id: str):
        super().__init__(
            message=f"El perfil de hardening con ID '{profile_id}' no fue encontrado.",
            details={"profile_id": profile_id},
        )


class RuleNotFoundException(NotFoundError):
    """Lanzada cuando una regla del catálogo no existe (HTTP 404)."""

    def __init__(self, rule_id: str):
        super().__init__(
            message=f"La regla '{rule_id}' no existe en el catálogo maestro.",
            details={"rule_id": rule_id},
        )


class InvalidExecutionPayloadException(HardeningException):
    """Lanzada cuando el payload para una auditoría es inválido (HTTP 400)."""

    def __init__(self, message: str, details: Any | None = None):
        super().__init__(
            message=message,
            status_code=status.HTTP_400_BAD_REQUEST,
            error_code="INVALID_AUDIT_PAYLOAD",
            details=details,
        )


class RuleEvaluationError(HardeningException):
    """Lanzada cuando ocurre un fallo inesperado al procesar una regla específica."""

    def __init__(self, rule_id: str, reason: str):
        super().__init__(
            message=f"Error durante la evaluación de la regla '{rule_id}': {reason}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code="RULE_EVALUATION_FAILED",
            details={"rule_id": rule_id, "reason": reason},
        )

class ReportNotFoundException(NotFoundError):
    """Lanzada cuando un reporte de auditoría no existe (HTTP 404)."""

    def __init__(self, report_id: str):
        super().__init__(
            message=f"El reporte de auditoría con ID '{report_id}' no fue encontrado.",
            details={"report_id": report_id},
        )


class ConfigParsingError(HardeningException):
    """Lanzada cuando la configuración CLI del equipo no se puede parsear o está corrupta."""

    def __init__(self, reason: str):
        super().__init__(
            message=f"Error al procesar el archivo de configuración: {reason}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error_code="CONFIG_PARSING_FAILED",
            details={"reason": reason},
        )