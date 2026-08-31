"""
Módulo de Dependencias para el Dominio de Usuarios.
"""

import uuid
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_token
from app.infrastructure.db.database import get_db
from app.users import service as user_service
from app.users.models import User

security_bearer = HTTPBearer(auto_error=True)


async def get_current_user_id(
    auth: HTTPAuthorizationCredentials = Depends(security_bearer),
) -> uuid.UUID:
    """Decodifica el JWT y extrae el UUID del usuario del claim 'sub'."""
    token = auth.credentials
    try:
        payload = decode_token(token)
        user_id_str: str | None = payload.get("sub")
        if not user_id_str:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token no contiene un identificador de usuario válido.",
            )
        return uuid.UUID(user_id_str)
    except (jwt.PyJWTError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales de autenticación inválidas o expiradas.",
        )


async def get_current_user(
    db: AsyncSession = Depends(get_db),
    user_id: uuid.UUID = Depends(get_current_user_id),
) -> User:
    """Obtiene el usuario cargando sus roles y permisos validados."""
    user = await user_service.get_by_id_or_fail(db, user_id=user_id)
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="El perfil de usuario se encuentra inactivo.",
        )
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Alias para resolución en dependencias de políticas RBAC."""
    return current_user


async def get_current_superuser(
    current_user: User = Depends(get_current_user),
) -> User:
    """Verifica directamente privilegios de superusuario raíz."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No posee privilegios suficientes para realizar esta acción.",
        )
    return current_user