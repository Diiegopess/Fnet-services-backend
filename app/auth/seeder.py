"""
Seeder del Dominio de Autenticación.
Crea las credenciales de acceso vinculadas al perfil de usuario existente.
"""

import logging
from sqlalchemy import select

from app.auth.models import AuthCredential
from app.core.config import settings
from app.core.security import hash_password
from app.infrastructure.db.seeder_registry import SeederRegistry
from app.users.api import UsersAPI

logger = logging.getLogger(__name__)


@SeederRegistry.register
async def seed_auth_domain(session) -> None:
    """Crea la credencial inicial del superusuario."""
    stmt_cred = select(AuthCredential).where(
        AuthCredential.email == settings.FIRST_SUPERUSER_EMAIL
    )
    res_cred = await session.execute(stmt_cred)
    if res_cred.scalar_one_or_none():
        logger.info(f"[SEED_AUTH] Credenciales ya existentes: {settings.FIRST_SUPERUSER_EMAIL}")
        return

    # Usar la fachada UsersAPI para obtener el ID sin acoplamiento ORM
    users_api = UsersAPI(session)
    user_dto = await users_api.get_user_by_email(settings.FIRST_SUPERUSER_EMAIL)

    if not user_dto:
        logger.error(
            f"[SEED_AUTH] No se puede crear credencial: el usuario {settings.FIRST_SUPERUSER_EMAIL} no existe."
        )
        return

    cred = AuthCredential(
        id=user_dto.id,
        email=settings.FIRST_SUPERUSER_EMAIL,
        password_hash=hash_password(settings.FIRST_SUPERUSER_PASSWORD),
        is_active=True,
        is_email_verified=True,
    )
    session.add(cred)
    logger.info(f"[SEED_AUTH] Credenciales de superusuario creadas para ID: {user_dto.id}")