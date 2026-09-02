"""
Módulo de Routers HTTP para el Dominio de Autenticación.
"""

from typing import Any
import uuid
from fastapi import APIRouter, Depends, status
import redis.asyncio as redis

from app.auth.dependencies import (
    get_auth_service,
    get_current_user_id,
    get_event_metadata,
)
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

router = APIRouter(prefix="/auth", tags=["Auth"])


# --- 1. ENDPOINT: REGISTRO LOCAL ---
@router.post(
    "/register",
    response_model=AuthCredentialResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registro de nuevo usuario",
)
async def register(
    data: RegisterRequest,
    auth_service: AuthService = Depends(get_auth_service),
    metadata: EventMetadata = Depends(get_event_metadata),
) -> Any:
    return await auth_service.register_user(data=data, metadata=metadata)


# --- 2. ENDPOINT: LOGIN LOCAL ---
@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Inicio de sesión local",
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
        extra_claims={"email": account.email},
    )

    return TokenResponse(access_token=access_token, token_type="bearer")


# --- 3. ENDPOINT: LOGIN CON GOOGLE OAUTH 2.0 ---
@router.post(
    "/google",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Inicio de sesión / Registro con Google",
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
)
async def logout(
    user_id: uuid.UUID = Depends(get_current_user_id),
    auth_service: AuthService = Depends(get_auth_service),
    metadata: EventMetadata = Depends(get_event_metadata),
    cache_client: redis.Redis = Depends(get_redis),
) -> dict[str, str]:
    await auth_service.logout_user(user_id=str(user_id), metadata=metadata)
    return {"message": "Sesión cerrada exitosamente."}