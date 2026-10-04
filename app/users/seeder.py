"""
Seeder del Dominio de Usuarios / RBAC.
Sincroniza permisos globales y crea el perfil inicial del superadministrador.
"""

import logging
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.rbac.permissions import get_all_system_permissions
from app.infrastructure.db.seeder_registry import SeederRegistry
from app.users.models import Permission, Role, User

logger = logging.getLogger(__name__)


async def _seed_rbac(session) -> Role:
    """Sincroniza el catálogo de permisos en BD y asegura el rol ADMIN."""
    system_permissions = get_all_system_permissions()

    res_perm = await session.execute(select(Permission))
    existing_perms = {p.code: p for p in res_perm.scalars().all()}

    # Insertar únicamente los permisos no registrados en la tabla
    for code, desc in system_permissions.items():
        if code not in existing_perms:
            new_perm = Permission(code=code, description=desc)
            session.add(new_perm)
            existing_perms[code] = new_perm
            logger.info(f"[SEED_USERS] Permiso creado: {code}")

    await session.flush()

    # Asegurar la existencia del rol ADMIN con todos los permisos disponibles
    res_role = await session.execute(
        select(Role).options(selectinload(Role.permissions)).where(Role.name == "ADMIN")
    )
    admin_role = res_role.scalar_one_or_none()
    all_permissions = list(existing_perms.values())

    if not admin_role:
        admin_role = Role(
            name="ADMIN",
            description="Administrador del sistema con acceso total",
            permissions=all_permissions,
        )
        session.add(admin_role)
        logger.info("[SEED_USERS] Rol ADMIN creado.")
    else:
        admin_role.permissions = all_permissions
        session.add(admin_role)

    await session.flush()
    return admin_role


async def _seed_superuser_user(session, admin_role: Role) -> None:
    """Crea la fila raíz User para el superadministrador."""
    stmt_user = select(User).where(User.email == settings.FIRST_SUPERUSER_EMAIL)
    res_user = await session.execute(stmt_user)
    if res_user.scalar_one_or_none():
        logger.info(f"[SEED_USERS] Usuario {settings.FIRST_SUPERUSER_EMAIL} ya existe.")
        return

    admin_user = User(
        email=settings.FIRST_SUPERUSER_EMAIL,
        full_name=settings.FIRST_SUPERUSER_FULL_NAME,
        is_active=True,
        is_superuser=True,
        roles=[admin_role],
    )
    session.add(admin_user)
    await session.flush()
    logger.info(f"[SEED_USERS] Perfil de superusuario creado: {settings.FIRST_SUPERUSER_EMAIL}")


@SeederRegistry.register
async def seed_users_domain(session) -> None:
    """Punto de entrada de seeding para el dominio de Usuarios."""
    admin_role = await _seed_rbac(session)
    await _seed_superuser_user(session, admin_role)