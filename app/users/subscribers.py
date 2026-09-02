"""
Módulo de Suscriptores de Eventos del Dominio de Usuarios.
"""

from app.core.events.router import event_router
from app.users.handlers import handle_user_registered_event


def setup_users_subscribers() -> None:
    """
    Registra los suscriptores a eventos de otros dominios que impactan a Usuarios.
    """
    # Escucha cuando Auth registra un usuario para crear su perfil en DB
    event_router.subscribe("auth.user_registered", handle_user_registered_event)