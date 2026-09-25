"""
Agregador Central de Rutas de la API (v1).
"""

from fastapi import APIRouter
from app.auth.router import router as auth_router
from app.users.router import router as users_router
from app.activity.router import router as activity_router
from app.clients.router import router as clients_router
from app.devices.router import router as devices_router
from app.vdoms.router import router as vdoms_router
from app.services.hardening.router import router as hardening_router

api_router = APIRouter()

# Inclusión de routers de dominio
api_router.include_router(auth_router)
api_router.include_router(users_router)
api_router.include_router(activity_router)
api_router.include_router(clients_router)
api_router.include_router(devices_router)
api_router.include_router(vdoms_router)
api_router.include_router(hardening_router)