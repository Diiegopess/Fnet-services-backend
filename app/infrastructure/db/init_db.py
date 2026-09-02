"""
Módulo de Inicialización de la Base de Datos y Seeding del Catálogo RBAC.
"""

import logging
import uuid
from sqlalchemy import select
from sqlalchemy.orm import selectinload

# Importación de modelos para el registro global de metadatos SQLAlchemy
from app.audit.models import AuditLog  # noqa: F401
from app.auth.models import AuthCredential
from app.core.config import settings
from app.core.rbac.permissions import PermissionEnum
from app.core.security import hash_password
from app.infrastructure.db.database import AsyncSessionLocal, Base, engine
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


async def _create_tables() -> None:
    """Verifica y crea las tablas si no existen (ideal para entornos de desarrollo)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("[INIT_DB] Estructura de tablas verificada/creada.")


async def _seed_rbac(session) -> dict[str, Role]:
    """Sincroniza permisos y roles optimizando las consultas SQL."""
    # 1. Cargar todos los permisos existentes en 1 sola consulta
    res_perm = await session.execute(select(Permission))
    existing_perms = {p.code: p for p in res_perm.scalars().all()}

    # 2. Registrar permisos faltantes
    for perm_enum in PermissionEnum:
        if perm_enum.value not in existing_perms:
            perm = Permission(
                code=perm_enum.value,
                description=f"Permiso para la acción {perm_enum.value}",
            )
            session.add(perm)
            existing_perms[perm_enum.value] = perm
            logger.info(f"[SEED_RBAC] Permiso creado: {perm_enum.value}")

    await session.flush()

    # 3. Cargar todos los roles existentes con sus permisos
    res_role = await session.execute(
        select(Role).options(selectinload(Role.permissions))
    )
    existing_roles = {r.name: r for r in res_role.scalars().all()}

    # 4. Sincronizar roles y sus asociaciones
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
            logger.info(f"[SEED_RBAC] Rol creado: {role_name}")
        else:
            role = existing_roles[role_name]
            role.permissions = target_permissions
            session.add(role)

        db_roles[role_name] = role

    await session.flush()
    return db_roles


async def _seed_superuser(session, admin_role: Role | None) -> None:
    """Genera el superusuario e inicializa sus credenciales si no existe."""
    stmt_cred = select(AuthCredential).where(
        AuthCredential.email == settings.FIRST_SUPERUSER_EMAIL
    )
    res_cred = await session.execute(stmt_cred)
    if res_cred.scalar_one_or_none():
        logger.info(f"[SEED_SUPERUSER] Superusuario ya existe: {settings.FIRST_SUPERUSER_EMAIL}")
        return

    user_id = uuid.uuid4()

    cred = AuthCredential(
        id=user_id,
        email=settings.FIRST_SUPERUSER_EMAIL,
        password_hash=hash_password(settings.FIRST_SUPERUSER_PASSWORD),
        is_active=True,
        is_email_verified=True,
    )
    session.add(cred)

    user_profile = User(
        id=user_id,
        email=settings.FIRST_SUPERUSER_EMAIL,
        full_name=settings.FIRST_SUPERUSER_FULL_NAME,
        is_active=True,
        is_superuser=True,
        roles=[admin_role] if admin_role else [],
    )
    session.add(user_profile)

    logger.info(f"[SEED_SUPERUSER] Superusuario creado: {settings.FIRST_SUPERUSER_EMAIL}")


async def init_db() -> None:
    """Función orquestadora principal para la inicialización de la BD."""
    await _create_tables()

    async with AsyncSessionLocal() as session:
        try:
            db_roles = await _seed_rbac(session)
            await _seed_superuser(session, db_roles.get("ADMIN"))
            await session.commit()
            logger.info("[INIT_DB] Inicialización de BD completada exitosamente.")
        except Exception as e:
            await session.rollback()
            logger.error(f"[INIT_DB_ERROR] Fallo en la inicialización de la BD: {e}", exc_info=True)
            raise