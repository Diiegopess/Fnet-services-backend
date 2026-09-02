# app/users/subscribers.py

from app.core.events.router import event_router
from app.users.handlers import handle_user_registered_event

def setup_users_subscribers() -> None:
    event_router.subscribe("auth.user_registered", handle_user_registered_event)