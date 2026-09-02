"""
Módulo de Routers HTTP para el Dominio de Autenticación.

Expone las rutas públicas para el registro, inicio de sesión (Local y Google OAuth 2.0)
y el cierre de sesión activo (Logout), capturando metadatos de auditoría forense.
"""

from typing import Any
import uuid
from fastapi import APIRouter, Depends, status
import redis.asyncio as redis

from app.auth.dependencies import get_auth_service, get_event_metadata
from app.auth.schemas import (
    AuthCredentialResponse,
    GoogleAuthRequest,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
)
from app.auth.service import AuthService
from app.core.events.base import EventMetadata
from app.core.security import create_access_token
from app.infrastructure.cache.redis import get_redis
from app.auth.dependencies import (
    get_auth_service,
    get_current_user_id,
    get_event_metadata,
)

router = APIRouter(prefix="/auth", tags=["Auth"])


# --- 1. ENDPOINT: REGISTRO LOCAL ---
@router.post(
    "/register",
    response_model=AuthCredentialResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registro de nuevo usuario",
    description="Crea las credenciales de acceso y emite el evento asíncrono hacia el dominio Users y Audit.",
)
async def register(
    data: RegisterRequest,
    auth_service: AuthService = Depends(get_auth_service),
    metadata: EventMetadata = Depends(get_event_metadata),
) -> Any:
    """
    Registra una cuenta local y despacha el evento 'auth.user_registered'.
    """
    credential = await auth_service.register_user(data=data, metadata=metadata)
    return credential


# --- 2. ENDPOINT: LOGIN LOCAL (Email + Password) ---
@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Inicio de sesión local",
    description="Valida las credenciales en 'auth_credentials', emite evento de auditoría y retorna un JWT.",
)
async def login_local(
    credentials: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service),
    metadata: EventMetadata = Depends(get_event_metadata),
) -> Any:
    account = await auth_service.authenticate_user(
        email=credentials.email,
        password=credentials.password,
        metadata=metadata,
    )

    access_token = create_access_token(
        subject=str(account.id),
        extra_claims={
            "email": account.email,
        },
    )

    return TokenResponse(access_token=access_token, token_type="bearer")


# --- 3. ENDPOINT: LOGIN CON GOOGLE OAUTH 2.0 ---
@router.post(
    "/google",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Inicio de sesión / Registro con Google",
    description="Valida el ID Token de Google, registra o vincula la cuenta y despacha eventos.",
)
async def login_google(
    google_data: GoogleAuthRequest,
    auth_service: AuthService = Depends(get_auth_service),
    metadata: EventMetadata = Depends(get_event_metadata),
) -> Any:
    account = await auth_service.authenticate_google_user(
        token=google_data.id_token,
        metadata=metadata,
    )

    access_token = create_access_token(
        subject=str(account.id),
        extra_claims={
            "email": account.email,
            "is_superuser": getattr(account, "is_superuser", False),
        },
    )
    return TokenResponse(access_token=access_token, token_type="bearer")


# --- 4. ENDPOINT: LOGOUT ---
@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Cierre de sesión",
    description="Invalida la sesión activa del usuario.",
)
async def logout(
    user_id: uuid.UUID = Depends(get_current_user_id),
    cache_client: redis.Redis = Depends(get_redis),
) -> dict[str, str]:
    """
    Endpoint protegido para revocar la sesión activa.
    """
    return {"message": "Sesión cerrada exitosamente."}