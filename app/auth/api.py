# app/auth/api.py
"""
API Pública del Módulo de Autenticación.

Punto único de contacto interno para otros módulos del backend.
"""

import uuid
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import (
    RequirePermissions,
    get_current_user,
    get_current_user_id,
)
from app.auth.repository import AuthRepository
from app.core.security import hash_password

# Re-exportamos las dependencias HTTP de autenticación para uso de otros módulos
__all__ = [
    "AuthAPI",
    "get_current_user_id",
    "get_current_user",
    "RequirePermissions",
]


class AuthAPI:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.repo = AuthRepository(db)

    async def credential_exists(self, email: str) -> bool:
        """Verifica si ya existe un registro de credenciales."""
        cred = await self.repo.get_by_email(email)
        return cred is not None

    async def is_credential_active(self, user_id: uuid.UUID) -> bool:
        """Verifica si las credenciales de un usuario están activas."""
        cred = await self.repo.get_by_id(user_id)
        return bool(cred and cred.is_active)

    async def create_user_credentials(
        self,
        user_id: uuid.UUID,
        email: str,
        plain_password: str,
        is_active: bool = True,
        is_email_verified: bool = True,
    ) -> uuid.UUID:
        """Crea las credenciales y retorna el UUID asignado sin fugar el modelo ORM."""
        hashed_pwd = hash_password(plain_password)
        cred = await self.repo.create_credential(
            credential_id=user_id,
            email=email,
            password_hash=hashed_pwd,
            is_active=is_active,
            is_email_verified=is_email_verified,
        )
        return cred.id