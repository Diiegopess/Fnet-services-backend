import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# 1. Importar la configuración de la app y la Base declarativa
from app.core.config import settings
from app.infrastructure.db.database import Base

# 2. IMPORTANTE: Importar TODOS los modelos para que Alembic los detecte
from app.auth.models import AuthCredential  # noqa: F401
from app.users.models import User  # noqa: F401
from app.audit.models import AuditLog  # noqa: F401
from app.clients.models import Client, client_technicians  # noqa: F401
from app.devices.models import FortigateDevice  # noqa: F401
from app.devices.vdoms.models import DeviceVDOM  # noqa: F401

# Objeto de configuración de Alembic
config = context.config

# Sobrescribir la URL de sqlalchemy con la de nuestro .env
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Configurar logging si existe el archivo de configuración
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Asignar la metadata donde están registradas todas nuestras tablas
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Ejecuta migraciones en modo 'offline' (genera solo sentencias SQL)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,  # Detecta cambios de tipos de columnas (ej. VARCHAR a TEXT)
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Crea un AsyncEngine y ejecuta las migraciones de forma asíncrona."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Ejecuta migraciones en modo 'online' (conectándose a PostgreSQL)."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()