"""
API Pública del Módulo de Usuarios.

Punto único de contacto interno para otros módulos del sistema.
"""

import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.users import service as user_service
from app.users.schemas import UserProfileCreate, UserResponse


class UsersAPI:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_user_by_id(self, user_id: uuid.UUID) -> Optional[UserResponse]:
        """Obtiene el DTO del usuario por su UUID."""
        user = await user_service.get_by_id(self.db, user_id)
        return UserResponse.model_validate(user) if user else None

    async def get_user_by_email(self, email: str) -> Optional[UserResponse]:
        """Busca un usuario por su email retornando un DTO."""
        user = await user_service.get_by_email(self.db, email)
        return UserResponse.model_validate(user) if user else None

    async def is_user_active(self, user_id: uuid.UUID) -> bool:
        """Verifica si el usuario existe y está habilitado."""
        user = await user_service.get_by_id(self.db, user_id)
        return bool(user and user.is_active)

    async def user_has_role(self, user_id: uuid.UUID, role_name: str) -> bool:
        """Verifica si el usuario tiene asignado un rol específico."""
        user = await user_service.get_by_id(self.db, user_id)
        if not user:
            return False
        return any(role.name == role_name for role in user.roles)

    async def create_profile(
        self,
        user_id: uuid.UUID,
        email: str,
        full_name: str | None = None,
        is_active: bool = True,
        is_superuser: bool = False,
        role_names: list[str] | None = None,
    ) -> UserResponse:
        """
        Crea el perfil de usuario encapsulando el schema internamente.
        Otros módulos no necesitan importar schemas de 'users'.
        """
        profile_in = UserProfileCreate(
            id=user_id,
            email=email,
            full_name=full_name,
            is_active=is_active,
            is_superuser=is_superuser,
            role_names=role_names or ["USER"],
        )
        user = await user_service.create_profile(self.db, profile_in)
        return UserResponse.model_validate(user)