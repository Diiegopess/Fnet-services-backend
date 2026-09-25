# app/activity/subscribers.py

from app.activity.handlers import handle_activity_event
from app.core.events.router import event_router


def setup_activity_subscribers() -> None:
    # Escucha TODOS los eventos de dominio para registrarlos en la bitácora de actividad
    event_router.subscribe("*", handle_activity_event)