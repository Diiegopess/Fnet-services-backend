#app.main.py

"""Punto de entrada principal de la aplicación FastAPI.

Configura el ciclo de vida (startup/shutdown), middlewares, manejadores
globales de excepciones y monta las rutas de la API.
"""

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

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
    """Registra los manejadores de eventos en memoria de los módulos del sistema."""
    setup_audit_subscribers()
    setup_auth_subscribers()
    setup_users_subscribers()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Gestiona el ciclo de vida de arranque y apagado del servicio."""
    # --- Startup ---
    await init_db()
    _register_event_subscribers()

    # Inicia el consumidor de colas en segundo plano sin bloquear el arranque HTTP
    consumer = RedisStreamConsumer()
    consumer_task = asyncio.create_task(consumer.start())

    yield

    # --- Shutdown ---
    await consumer.stop()
    consumer_task.cancel()
    try:
        # Espera que la tarea reconozca la cancelación para no dejarla colgada
        await consumer_task
    except asyncio.CancelledError:
        pass

    await close_redis_pool()


app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)

# Configuración permisiva de CORS para clientes web/móviles
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

register_exception_handlers(app)

app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get(
    "/health",
    response_model=HealthCheckResponse,
    tags=["Health"],
    summary="Verificar salud de la API",
)
async def health_check() -> HealthCheckResponse:
    """Comprueba la disponibilidad del servicio para balanceadores de carga o Kubernetes."""
    return HealthCheckResponse(
        status="ok",
        environment=settings.ENVIRONMENT,
        version="1.0.0",
    )