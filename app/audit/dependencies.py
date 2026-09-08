"""Módulo de Dependencias para el Dominio de Auditoría."""

from fastapi import Depends

from app.auth.api import get_current_user
from app.core.rbac.context import AuthenticatedUser
from app.audit.exceptions import AuditAccessDeniedError


async def require_audit_access(
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> AuthenticatedUser:
    """
    Garantiza que solo administradores o usuarios con privilegios elevados
    puedan consultar la bitácora de auditoría del sistema.
    """
    if not current_user.is_superuser:
        raise AuditAccessDeniedError(
            message="No posee los permisos suficientes para acceder a la auditoría del sistema."
        )

    return current_user