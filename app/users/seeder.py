# app/users/seeder.py
"""
Seeder del Dominio de Usuarios / RBAC.
Maneja exclusivamente el ciclo de vida de usuarios, roles y permisos.
"""

import logging
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.rbac.permissions import PermissionEnum
from app.infrastructure.db.seeder_registry import SeederRegistry
from app.users.models import Permission, Role, User

logger = logging.getLogger(__name__)

BASE_ROLES_PERMISSIONS: dict[str, list[PermissionEnum]] = {
    "ADMIN": [
        PermissionEnum.USERS_READ,
        PermissionEnum.USERS_CREATE,
        PermissionEnum.USERS_UPDATE,
        PermissionEnum.USERS_DELETE,
        PermissionEnum.USERS_ASSIGN_ROLE,
        PermissionEnum.AUDIT_READ,
        PermissionEnum.AUDIT_EXPORT,
        PermissionEnum.CLIENTS_READ,
        PermissionEnum.CLIENTS_CREATE,
        PermissionEnum.CLIENTS_UPDATE,
        PermissionEnum.CLIENTS_DELETE,
        PermissionEnum.CLIENTS_ASSIGN_TECHNICIAN,
    ],
    "TECHNICIAN": [
        PermissionEnum.USERS_READ,
        PermissionEnum.CLIENTS_READ,
        PermissionEnum.CLIENTS_UPDATE,
    ],
    "AUDITOR": [
        PermissionEnum.AUDIT_READ,
        PermissionEnum.AUDIT_EXPORT,
        PermissionEnum.USERS_READ,
        PermissionEnum.CLIENTS_READ,
    ],
    "USER": [
        PermissionEnum.USERS_READ,
        PermissionEnum.CLIENTS_READ,
    ],
}


async def _seed_rbac(session) -> dict[str, Role]:
    """Sincroniza el catálogo de permisos y roles en BD."""
    res_perm = await session.execute(select(Permission))
    existing_perms = {p.code: p for p in res_perm.scalars().all()}

    for perm_enum in PermissionEnum:
        if perm_enum.value not in existing_perms:
            perm = Permission(
                code=perm_enum.value,
                description=f"Permiso para la acción {perm_enum.value}",
            )
            session.add(perm)
            existing_perms[perm_enum.value] = perm
            logger.info(f"[SEED_USERS] Permiso creado: {perm_enum.value}")

    await session.flush()

    res_role = await session.execute(
        select(Role).options(selectinload(Role.permissions))
    )
    existing_roles = {r.name: r for r in res_role.scalars().all()}

    db_roles: dict[str, Role] = {}
    for role_name, perm_enums in BASE_ROLES_PERMISSIONS.items():
        target_permissions = [
            existing_perms[p.value]
            for p in perm_enums
            if p.value in existing_perms
        ]

        if role_name not in existing_roles:
            role = Role(
                name=role_name,
                description=f"Rol del sistema {role_name}",
                permissions=target_permissions,
            )
            session.add(role)
            logger.info(f"[SEED_USERS] Rol creado: {role_name}")
        else:
            role = existing_roles[role_name]
            role.permissions = target_permissions
            session.add(role)

        db_roles[role_name] = role

    await session.flush()
    return db_roles


async def _seed_superuser_profile(session, admin_role: Role | None) -> None:
    """Crea el perfil de usuario del Administrador si no existe."""
    stmt_user = select(User).where(User.email == settings.FIRST_SUPERUSER_EMAIL)
    res_user = await session.execute(stmt_user)
    if res_user.scalar_one_or_none():
        logger.info(f"[SEED_USERS] Perfil superusuario ya existe: {settings.FIRST_SUPERUSER_EMAIL}")
        return

    user_profile = User(
        email=settings.FIRST_SUPERUSER_EMAIL,
        full_name=settings.FIRST_SUPERUSER_FULL_NAME,
        is_active=True,
        is_superuser=True,
        roles=[admin_role] if admin_role else [],
    )
    session.add(user_profile)
    logger.info(f"[SEED_USERS] Perfil superusuario creado: {settings.FIRST_SUPERUSER_EMAIL}")


@SeederRegistry.register
async def seed_users_domain(session) -> None:
    """Punto de entrada de seeding exclusivo para el Dominio de Usuarios."""
    db_roles = await _seed_rbac(session)
    await _seed_superuser_profile(session, db_roles.get("ADMIN"))