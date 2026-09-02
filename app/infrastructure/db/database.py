"""
Módulo de conexión y gestión de sesiones para la base de datos relacional (PostgreSQL).

Utilizamos el motor asíncrono de SQLAlchemy (2.0+) junto con el driver `asyncpg`
para evitar bloquear el hilo de ejecución principal de FastAPI mientras se esperan 
respuestas de la base de datos.
"""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import declarative_base

from app.core.config import settings

# 1. Crear el Motor Asíncrono (AsyncEngine)
# El 'engine' es la fuente central de conexiones a la base de datos.
# - settings.DATABASE_URL: Lee la cadena de conexión (ej. postgresql+asyncpg://user:pass@host:5432/db).
# - echo=True: Imprime en la consola todas las sentencias SQL reales que genera SQLAlchemy.
#   Es fundamental durante la etapa de desarrollo/aprendizaje para entender qué consultas se están ejecutando.
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=True,
)

# 2. Fábrica de Sesiones Asíncronas (AsyncSessionLocal)
# Funciona como una 'fábrica' que genera instancias de sesión individuales para interactuar con la BD.
# - bind=engine: Asocia cada sesión creada con nuestro motor de conexión.
# - class_=AsyncSession: Le indica a SQLAlchemy que gestione operaciones con la sintaxis async/await.
# - expire_on_commit=False: Evita que los objetos en memoria se vuelvan 'inválidos' después de hacer un commit,
#   permitiendo seguir accediendo a sus atributos sin tener que hacer una re-consulta a la BD.
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)

# 3. Clase Base Declarativa para los Modelos SQL
# Todos los modelos de la aplicación (ej. la tabla 'users' en app/users/models.py) 
# heredarán de esta clase 'Base'. Sirve como registro central para que SQLAlchemy 
# reconozca qué tablas existen en el sistema.
Base = declarative_base()


# 4. Inyector de Dependencia de la Base de Datos (get_db)
# Esta función generadora se usa con `Depends(get_db)` en las rutas de FastAPI.
# - Abre una sesión limpia al recibir una petición HTTP.
# - 'yield session': Entrega la sesión al endpoint para ejecutar consultas.
# - Bloque 'finally': Garantiza que la sesión se cierre SIEMPRE al terminar la petición 
#   (incluso si ocurre un error), evitando fugas de conexiones en el pool de PostgreSQL.
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()