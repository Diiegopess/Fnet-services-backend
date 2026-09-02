"""
Lógica pura de validación de permisos RBAC en el Core.
No contiene dependencias hacia ningún subdominio específico.
"""

from fastapi import HTTPException, status

from app.core.rbac.context import AuthenticatedUser
from app.core.rbac.permissions import PermissionEnum


class PermissionChecker:
    """Verificador puro de permisos sobre el contexto de usuario."""

    def __init__(self, *required_permissions: PermissionEnum | str):
        self.required_permissions: set[str] = {
            p.value if isinstance(p, PermissionEnum) else p
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