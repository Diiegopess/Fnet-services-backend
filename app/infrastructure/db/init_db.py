import logging
import uuid
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.audit.models import AuditLog  # noqa: F401 - Registra la tabla 'audit_logs'
from app.auth.models import AuthCredential
from app.core.config import settings
from app.core.rbac.permissions import PermissionEnum
from app.core.security import hash_password
from app.infrastructure.db.database import AsyncSessionLocal, Base, engine
from app.users.models import Permission, Role, User

logger = logging.getLogger(__name__)

# Mapeo de roles base y sus permisos asignados
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


async def init_db() -> None:
    """
    Crea tablas DDL, sincroniza el catálogo RBAC (permisos y roles)
    y genera el superusuario inicial.
    """
    # 1. Crear tablas si no existen
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Tablas de la base de datos verificadas/creadas exitosamente.")

    async with AsyncSessionLocal() as session:
        try:
            # 2. Seeding del catálogo de Permisos
            db_permissions: dict[str, Permission] = {}
            for perm_enum in PermissionEnum:
                stmt_perm = select(Permission).where(Permission.code == perm_enum.value)
                res_perm = await session.execute(stmt_perm)
                permission = res_perm.scalar_one_or_none()

                if not permission:
                    permission = Permission(
                        code=perm_enum.value,
                        description=f"Permiso para la acción {perm_enum.value}",
                    )
                    session.add(permission)
                    await session.flush()
                    logger.info(f"Permiso registrado: {perm_enum.value}")

                db_permissions[perm_enum.value] = permission

            # 3. Seeding del catálogo de Roles y asignación de permisos
            db_roles: dict[str, Role] = {}
            for role_name, perm_enums in BASE_ROLES_PERMISSIONS.items():
                stmt_role = (
                    select(Role)
                    .options(selectinload(Role.permissions))
                    .where(Role.name == role_name)
                )
                res_role = await session.execute(stmt_role)
                role = res_role.scalar_one_or_none()

                target_permissions = [
                    db_permissions[p.value]
                    for p in perm_enums
                    if p.value in db_permissions
                ]

                if not role:
                    role = Role(
                        name=role_name,
                        description=f"Rol del sistema {role_name}",
                        permissions=target_permissions,
                    )
                    session.add(role)
                    await session.flush()
                    logger.info(f"Rol registrado: {role_name}")
                else:
                    role.permissions = target_permissions
                    session.add(role)

                db_roles[role_name] = role

            # 4. Seeding de Superusuario Inicial
            stmt_cred = select(AuthCredential).where(
                AuthCredential.email == settings.FIRST_SUPERUSER_EMAIL
            )
            res_cred = await session.execute(stmt_cred)
            existing_cred = res_cred.scalar_one_or_none()

            if existing_cred:
                logger.info(
                    f"Superusuario inicial ya registrado: {settings.FIRST_SUPERUSER_EMAIL}"
                )
                await session.commit()
                return

            user_id = uuid.uuid4()

            # Credenciales de autenticación
            cred = AuthCredential(
                id=user_id,
                email=settings.FIRST_SUPERUSER_EMAIL,
                password_hash=hash_password(settings.FIRST_SUPERUSER_PASSWORD),
                is_active=True,
                is_email_verified=True,
            )
            session.add(cred)

            # Perfil con rol ADMIN asociado
            user_profile = User(
                id=user_id,
                email=settings.FIRST_SUPERUSER_EMAIL,
                full_name=settings.FIRST_SUPERUSER_FULL_NAME,
                is_active=True,
                is_superuser=True,
                roles=[db_roles["ADMIN"]] if "ADMIN" in db_roles else [],
            )
            session.add(user_profile)

            await session.commit()
            logger.info(
                f"Superusuario inicial y asignación RBAC creados: {settings.FIRST_SUPERUSER_EMAIL}"
            )

        except Exception as e:
            await session.rollback()
            logger.error(f"Error al inicializar datos y RBAC: {e}")
            raise