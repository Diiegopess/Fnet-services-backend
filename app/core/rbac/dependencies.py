"""
Dependencias para la autorización basada en permisos (RBAC).
"""
from fastapi import Depends, HTTPException, status

from app.core.rbac.permissions import PermissionEnum
from app.users.dependencies import get_current_user
from app.users.models import User


class RequirePermissions:
    """
    Guardián de autorización granular.
    Verifica que el usuario actual posea todos los permisos solicitados.
    Los usuarios con is_superuser=True omiten la validación automáticamente.
    """

    def __init__(self, *required_permissions: PermissionEnum | str):
        self.required_permissions = {
            p.value if isinstance(p, PermissionEnum) else p
            for p in required_permissions
        }

    def __call__(self, current_user: User = Depends(get_current_user)) -> User:
        if current_user.is_superuser:
            return current_user

        # Obtener los códigos de permisos de todos los roles asignados
        user_permissions = {
            perm.code
            for role in current_user.roles
            for perm in role.permissions
        }

        if not self.required_permissions.issubset(user_permissions):
            missing = self.required_permissions - user_permissions
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permisos insuficientes. Se requiere: {', '.join(sorted(missing))}",
            )

        return current_user