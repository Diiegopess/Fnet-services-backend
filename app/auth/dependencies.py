"""
Módulo de Dependencias para el Dominio de Autenticación y Control de Acceso.
"""

import uuid
from typing import Callable
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.service import AuthService
from app.core.events.base import EventMetadata
from app.core.events.interfaces import IEventPublisher
from app.core.rbac.context import AuthenticatedUser
from app.core.rbac.dependencies import PermissionChecker
from app.core.rbac.permissions import PermissionEnum
from app.core.security import decode_token
from app.infrastructure.brokers.factory import get_event_publisher
from app.infrastructure.db.database import get_db
from app.users.api import UsersAPI

security_bearer = HTTPBearer(auto_error=True)


def get_event_metadata(request: Request) -> EventMetadata:
    """Extrae la IP real y el User-Agent desde las cabeceras HTTP."""
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    elif request.client and request.client.host:
        client_ip = request.client.host
    else:
        client_ip = "unknown"

    user_agent = request.headers.get("user-agent", "unknown")

    return EventMetadata(
        ip_address=client_ip,
        user_agent=user_agent
    )


def get_auth_service(
    db: AsyncSession = Depends(get_db),
    publisher: IEventPublisher = Depends(get_event_publisher),
) -> AuthService:
    return AuthService(db=db, publisher=publisher)


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
) -> AuthenticatedUser:
    """Resuelve la identidad usando EXCLUSIVAMENTE la fachada UsersAPI."""
    users_api = UsersAPI(db)
    user_context = await users_api.get_authenticated_user_context(user_id)
    if not user_context:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no encontrado o perfil inactivo.",
        )
    return user_context


def RequirePermissions(*permissions: PermissionEnum | str) -> Callable[..., AuthenticatedUser]:
    """
    Inyector de dependencia para endpoints protegidos por RBAC.
    Resuelve el AuthenticatedUser y valida sus permisos con el checker del Core.
    """
    checker = PermissionChecker(*permissions)

    async def dependency(
        current_user: AuthenticatedUser = Depends(get_current_user),
    ) -> AuthenticatedUser:
        return checker.verify(current_user)

    return dependency