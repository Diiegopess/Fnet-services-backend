"""
Módulo de Dependencias para el Dominio de Usuarios.
"""

from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.api import get_current_user
from app.core.rbac.context import AuthenticatedUser
from app.infrastructure.db.database import get_db
from app.users import service as user_service
from app.users.models import User


async def get_current_user_entity(
    db: AsyncSession = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> User:
    """
    Obtiene la entidad ORM interna 'User' a partir del usuario autenticado
    resuelto por Auth (uso exclusivo para endpoints/servicios internos de app.users).
    """
    user = await user_service.get_by_id_or_fail(db, user_id=current_user.id)
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="El perfil de usuario se encuentra inactivo.",
        )
    return user


async def get_current_superuser(
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> AuthenticatedUser:
    """Verifica privilegios de superusuario sobre el AuthenticatedUser provisto por Auth."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No posee privilegios suficientes para realizar esta acción.",
        )
    return current_user