"""
Registro central desacoplado para enrutamiento de eventos de dominio (Event Router).
Aplica el patrón Observer / Dispatcher para desacoplar el broker de Redis de los handlers de negocio.
"""

import logging
from typing import Awaitable, Callable
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events.base import DomainEvent

logger = logging.getLogger(__name__)

# Definición de tipo para las funciones handler
EventHandler = Callable[[DomainEvent, AsyncSession], Awaitable[None]]


class EventRouter:
    """Enrutador central de eventos de dominio."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = {}

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """
        Registra un handler para un tipo de evento específico.
        Permite usar '*' para suscribirse a TODOS los eventos del sistema (ej. Auditoría).
        """
        if event_type not in self._handlers:
            self._handlers[event_type] = []

        if handler not in self._handlers[event_type]:
            self._handlers[event_type].append(handler)
            logger.info(f"[EVENT_ROUTER] Handler '{handler.__name__}' suscrito a '{event_type}'")

    async def dispatch(self, event: DomainEvent, db: AsyncSession) -> None:
        """
        Despacha un evento a todos los handlers suscritos a su event_type,
        así como a los handlers globales suscritos a '*'.
        """
        # Obtenemos handlers específicos y globales
        specific_handlers = self._handlers.get(event.event_type, [])
        global_handlers = self._handlers.get("*", [])

        # Evitamos duplicados manteniendo el orden
        all_handlers: list[EventHandler] = []
        for h in global_handlers + specific_handlers:
            if h not in all_handlers:
                all_handlers.append(h)

        if not all_handlers:
            logger.warning(
                f"[EVENT_ROUTER] No hay handlers registrados para el evento '{event.event_type}'"
            )
            return

        for handler in all_handlers:
            try:
                await handler(event, db)
            except Exception as e:
                logger.error(
                    f"[EVENT_ROUTER_ERROR] Fallo en handler '{handler.__name__}' procesando '{event.event_type}': {str(e)}",
                    exc_info=True,
                )
                raise e


# Instancia Singleton Global del Router
event_router = EventRouter()