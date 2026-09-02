"""
Punto de Entrada Principal de la Aplicación (FastAPI).
"""

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.api_router import api_router
from app.audit.subscribers import setup_audit_subscribers
from app.auth.subscribers import setup_auth_subscribers
from app.core.config import settings
from app.core.handlers import register_exception_handlers
from app.core.schemas import HealthCheckResponse
from app.infrastructure.brokers.redis_consumer import RedisStreamConsumer
from app.infrastructure.cache.redis import close_redis_pool
from app.infrastructure.db.init_db import init_db
from app.users.subscribers import setup_users_subscribers


def _register_event_subscribers() -> None:
    """Registra los suscriptores de eventos de todos los subdominios en el EventRouter."""
    setup_audit_subscribers()
    setup_auth_subscribers()
    setup_users_subscribers()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Startup: Tablas, seeder RBAC y superusuario
    await init_db()

    # Startup: Registro de Handlers de Eventos
    _register_event_subscribers()

    # Startup: Consumidor en segundo plano
    consumer = RedisStreamConsumer()
    consumer_task = asyncio.create_task(consumer.start())

    yield

    # Shutdown: Apagado coordinado del consumidor
    await consumer.stop()
    consumer_task.cancel()
    try:
        await consumer_task
    except asyncio.CancelledError:
        pass

    # Liberar pool de Redis
    await close_redis_pool()


app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

register_exception_handlers(app)

# Rutas versión 1
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get(
    "/health",
    response_model=HealthCheckResponse,
    tags=["Health"],
    summary="Verificar salud de la API",
)
async def health_check():
    return HealthCheckResponse(
        status="ok",
        environment=settings.ENVIRONMENT,
        version="1.0.0",
    )