"""
Módulo de Repositorio para el Dominio de Usuarios y RBAC.

Maneja el acceso a datos y las consultas SQLAlchemy de las tablas:
- users
- roles
- permissions
"""

import uuid
from typing import Optional, Sequence
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.infrastructure.repositories.base import BaseRepository
from app.users.models import Permission, Role, User
from app.users.schemas import UserProfileCreate, UserUpdateAdmin


class UserRepository(BaseRepository[User, UserProfileCreate, UserUpdateAdmin]):
    def __init__(self, db: AsyncSession):
        super().__init__(model=User, db=db)

    # --- CONSULTAS DE USUARIOS CON RBAC ---

    async def get_by_id(self, user_id: uuid.UUID) -> Optional[User]:
        stmt = (
            select(User)
            .options(selectinload(User.roles).selectinload(Role.permissions))
            .where(User.id == user_id)
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_by_email(self, email: str) -> Optional[User]:
        stmt = (
            select(User)
            .options(selectinload(User.roles).selectinload(Role.permissions))
            .where(User.email == email)
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_multi(self, skip: int = 0, limit: int = 100) -> Sequence[User]:
        stmt = (
            select(User)
            .options(selectinload(User.roles).selectinload(Role.permissions))
            .offset(skip)
            .limit(limit)
        )
        result = await self.db.execute(stmt)
        return result.scalars().all()

    # --- CONSULTAS Y GESTIÓN DE ROLES Y PERMISOS ---

    async def get_role_by_name(self, role_name: str) -> Optional[Role]:
        stmt = (
            select(Role)
            .options(selectinload(Role.permissions))
            .where(Role.name == role_name)
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_roles_by_names(self, role_names: list[str]) -> Sequence[Role]:
        stmt = (
            select(Role)
            .options(selectinload(Role.permissions))
            .where(Role.name.in_(role_names))
        )
        result = await self.db.execute(stmt)
        return result.scalars().all()

    async def get_permission_by_code(self, code: str) -> Optional[Permission]:
        stmt = select(Permission).where(Permission.code == code)
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_permissions_by_codes(self, codes: list[str]) -> Sequence[Permission]:
        stmt = select(Permission).where(Permission.code.in_(codes))
        result = await self.db.execute(stmt)
        return result.scalars().all()

    async def list_all_roles(self) -> Sequence[Role]:
        stmt = select(Role).options(selectinload(Role.permissions))
        result = await self.db.execute(stmt)
        return result.scalars().all()

    async def list_all_permissions(self) -> Sequence[Permission]:
        stmt = select(Permission)
        result = await self.db.execute(stmt)
        return result.scalars().all()

    async def create_permission(self, code: str, description: str) -> Permission:
        permission = Permission(code=code, description=description)
        self.db.add(permission)
        await self.db.flush()
        return permission

    async def create_role(
        self,
        name: str,
        description: Optional[str] = None,
        permissions: Optional[list[Permission]] = None,
    ) -> Role:
        role = Role(name=name, description=description)
        if permissions:
            role.permissions = permissions
        self.db.add(role)
        await self.db.flush()
        return role

    async def assign_roles_to_user(self, user: User, roles: list[Role]) -> User:
        user.roles = roles
        self.db.add(user)
        await self.db.flush()
        await self.db.refresh(user)
        return user