# app/audit/subscribers.py (o dentro de app/audit/__init__.py)

from app.audit.handlers import handle_audit_event
from app.core.events.router import event_router

def setup_audit_subscribers() -> None:
    # Escucha TODOS los eventos de dominio
    event_router.subscribe("*", handle_audit_event)