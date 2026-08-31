"""
Módulo de Servicios para el Dominio de Usuarios y RBAC.

Contiene las operaciones de base de datos y reglas de negocio
para perfiles de usuario (tabla 'users') y gestión de roles.
"""

import uuid
from typing import Sequence
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.events.base import DomainEvent, EventMetadata
from app.core.events.interfaces import IEventPublisher
from app.core.security import hash_password
from app.users.exceptions import UserAlreadyExistsError, UserNotFoundError
from app.users.models import Role, User
from app.users.repository import UserRepository
from app.users.schemas import (
    UserCreateAdmin,
    UserProfileCreate,
    UserUpdate,
    UserUpdateAdmin,
)


# ==============================================================================
# 1. CONSULTAS DE LECTURA (Usando UserRepository con carga de RBAC)
# ==============================================================================

async def get_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    """Busca un usuario por su UUID primario cargando roles y permisos."""
    repo = UserRepository(db)
    return await repo.get_by_id(user_id=user_id)


async def get_by_id_or_fail(db: AsyncSession, user_id: uuid.UUID) -> User:
    """Busca un usuario por UUID. Si no existe, lanza UserNotFoundError."""
    user = await get_by_id(db, user_id=user_id)
    if not user:
        raise UserNotFoundError()
    return user


async def get_by_email(db: AsyncSession, email: str) -> User | None:
    """Busca un usuario por su correo electrónico con roles y permisos."""
    repo = UserRepository(db)
    return await repo.get_by_email(email=email)


async def get_multi(
    db: AsyncSession, skip: int = 0, limit: int = 100
) -> Sequence[User]:
    """Retorna una lista paginada de usuarios con sus roles y permisos."""
    repo = UserRepository(db)
    return await repo.get_multi(skip=skip, limit=limit)


# ==============================================================================
# 2. CREACIÓN Y APROVISIONAMIENTO DE PERFILES
# ==============================================================================

async def create_profile(db: AsyncSession, profile_in: UserProfileCreate) -> User:
    """Crea un perfil de usuario asignándole el UUID recibido desde Auth."""
    repo = UserRepository(db)
    existing_user = await repo.get_by_email(email=profile_in.email)
    if existing_user:
        raise UserAlreadyExistsError()

    db_user = User(
        id=profile_in.id,
        email=profile_in.email,
        full_name=profile_in.full_name,
        is_active=profile_in.is_active,
        is_superuser=profile_in.is_superuser,
    )

    if profile_in.role_names:
        roles = await repo.get_roles_by_names(profile_in.role_names)
        db_user.roles = list(roles)

    db.add(db_user)
    await db.commit()
    return await get_by_id_or_fail(db, db_user.id)


async def admin_create_user(
    db: AsyncSession,
    user_in: UserCreateAdmin,
    metadata: EventMetadata,
    publisher: IEventPublisher,
) -> User:
    """
    Crea el usuario administrativamente con sus roles iniciales y publica el
    evento para que Auth provisione las credenciales.
    """
    repo = UserRepository(db)
    existing_user = await repo.get_by_email(email=user_in.email)
    if existing_user:
        raise UserAlreadyExistsError()

    user_id = uuid.uuid4()

    # Construir nombre completo a partir de nombres y apellidos
    names = [n for n in [user_in.first_name, user_in.last_name] if n]
    full_name = " ".join(names) if names else None

    # 1. Crear el usuario en la tabla 'users'
    db_user = User(
        id=user_id,
        email=user_in.email,
        full_name=full_name,
        is_active=user_in.is_active,
        is_superuser=user_in.is_superuser,
    )

    # Asignar roles iniciales si se indicaron
    if user_in.role_names:
        roles = await repo.get_roles_by_names(user_in.role_names)
        db_user.roles = list(roles)

    db.add(db_user)
    await db.commit()

    # 2. Publicar evento a Redis Streams para sincronizar Auth y registrar Auditoría
    event = DomainEvent(
        event_type="user.created_by_admin",
        metadata=metadata,
        payload={
            "user_id": str(db_user.id),
            "email": db_user.email,
            "password_hash": hash_password(user_in.password),
            "is_active": db_user.is_active,
        },
    )
    await publisher.publish(stream_or_topic=settings.AUTH_STREAM_NAME, event=event)

    return await get_by_id_or_fail(db, db_user.id)


# ==============================================================================
# 3. ACTUALIZACIÓN DE PERFILES Y GESTIÓN DE ROLES
# ==============================================================================

async def update_user(
    db: AsyncSession,
    user_id: uuid.UUID,
    user_in: UserUpdate | UserUpdateAdmin,
) -> User:
    """Actualiza los datos del perfil de un usuario validando unicidad de email."""
    repo = UserRepository(db)
    db_user = await get_by_id_or_fail(db, user_id)

    if user_in.email and user_in.email != db_user.email:
        existing_email = await repo.get_by_email(email=user_in.email)
        if existing_email:
            raise UserAlreadyExistsError()

    update_data = user_in.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        setattr(db_user, field, value)

    db.add(db_user)
    await db.commit()
    return await get_by_id_or_fail(db, db_user.id)


async def assign_roles_to_user(
    db: AsyncSession,
    user_id: uuid.UUID,
    role_names: list[str],
) -> User:
    """Asigna una lista de roles a un usuario reemplazando los anteriores."""
    repo = UserRepository(db)
    db_user = await get_by_id_or_fail(db, user_id)
    roles = await repo.get_roles_by_names(role_names)

    await repo.assign_roles_to_user(user=db_user, roles=list(roles))
    await db.commit()
    return await get_by_id_or_fail(db, user_id)


async def list_roles(db: AsyncSession) -> Sequence[Role]:
    """Retorna todo el catálogo de roles disponibles."""
    repo = UserRepository(db)
    return await repo.list_all_roles()

async def get_multi_by_ids(db: AsyncSession, user_ids: list[uuid.UUID]) -> Sequence[User]:
    """Retorna los usuarios existentes para una lista de UUIDs."""
    if not user_ids:
        return []
    repo = UserRepository(db)
    return await repo.get_by_ids(user_ids)