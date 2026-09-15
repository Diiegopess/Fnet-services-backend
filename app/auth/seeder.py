# app/auth/seeder.py
"""
Seeder del Dominio de Autenticación.
Maneja exclusivamente las credenciales y mecanismos de acceso.
"""

import logging
from sqlalchemy import select

from app.auth.models import AuthCredential
from app.core.config import settings
from app.core.security import hash_password
from app.infrastructure.db.seeder_registry import SeederRegistry

logger = logging.getLogger(__name__)


@SeederRegistry.register
async def seed_auth_domain(session) -> None:
    """Crea la credencial inicial del superusuario si no existe."""
    stmt_cred = select(AuthCredential).where(
        AuthCredential.email == settings.FIRST_SUPERUSER_EMAIL
    )
    res_cred = await session.execute(stmt_cred)
    if res_cred.scalar_one_or_none():
        logger.info(f"[SEED_AUTH] Credenciales ya existentes: {settings.FIRST_SUPERUSER_EMAIL}")
        return

    cred = AuthCredential(
        email=settings.FIRST_SUPERUSER_EMAIL,
        password_hash=hash_password(settings.FIRST_SUPERUSER_PASSWORD),
        is_active=True,
        is_email_verified=True,
    )
    session.add(cred)
    logger.info(f"[SEED_AUTH] Credenciales de superusuario creadas: {settings.FIRST_SUPERUSER_EMAIL}")