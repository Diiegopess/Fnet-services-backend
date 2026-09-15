# app/infrastructure/db/init_db.py
"""
Módulo de Infraestructura de Base de Datos.
Cero imports de dominios (Users, Auth, Hardening).
"""

import logging
from app.infrastructure.db.database import AsyncSessionLocal, Base, engine
from app.infrastructure.db.seeder_registry import SeederRegistry

logger = logging.getLogger(__name__)


async def _create_tables() -> None:
    """Crea la estructura física de tablas."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def init_db() -> None:
    """Ejecuta la inicialización de tablas y dispara los seeders registrados."""
    await _create_tables()

    async with AsyncSessionLocal() as session:
        try:
            # Corre lo que se haya registrado pasivamente en el arranque
            await SeederRegistry.run_all_seeders(session)
            await session.commit()
            logger.info("[INIT_DB] Base de datos e inicializadores completados.")
        except Exception as e:
            await session.rollback()
            logger.error(f"[INIT_DB_ERROR] Fallo en la inicialización: {e}", exc_info=True)
            raise