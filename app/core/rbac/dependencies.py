"""
Lógica pura de validación de permisos RBAC en el Core.
Totalmente desacoplada de subdominios específicos.
"""

from typing import Union
from enum import Enum
from fastapi import HTTPException, status

from app.core.rbac.context import AuthenticatedUser


class PermissionChecker:
    """Verificador puro eagnóstico de permisos sobre el contexto de usuario."""

    def __init__(self, *required_permissions: Union[Enum, str]):
        self.required_permissions: set[str] = {
            p.value if isinstance(p, Enum) else str(p)
            for p in required_permissions
        }

    def verify(self, current_user: AuthenticatedUser) -> AuthenticatedUser:
        if current_user.is_superuser:
            return current_user

        if not self.required_permissions.issubset(current_user.permissions):
            missing = self.required_permissions - current_user.permissions
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permisos insuficientes. Se requiere: {', '.join(sorted(missing))}",
            )

        return current_user