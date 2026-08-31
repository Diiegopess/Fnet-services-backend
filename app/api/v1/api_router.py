"""
Agregador Central de Rutas de la API (v1).
"""

from fastapi import APIRouter
from app.auth.router import router as auth_router
from app.users.router import router as users_router
from app.audit.router import router as audit_router

api_router = APIRouter()

# Inclusión de routers de dominio
api_router.include_router(auth_router)
api_router.include_router(users_router)
api_router.include_router(audit_router)