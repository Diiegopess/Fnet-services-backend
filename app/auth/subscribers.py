"""
Módulo de Suscriptores de Eventos para el Dominio de Autenticación.
"""

from app.auth.handlers import handle_user_created_by_admin_event
from app.core.events.router import event_router


def setup_auth_subscribers() -> None:
    """Registra los suscriptores para eventos consumidos por el dominio de Autenticación."""
    event_router.subscribe("user.created_by_admin", handle_user_created_by_admin_event)