"""
Registro Central para Handlers de Seeding (Inverted Registry Pattern).
Permite a los dominios registrar sus inicializadores sin acoplar la infraestructura.
"""

import logging
from typing import Awaitable, Callable, List
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

SeederFunc = Callable[[AsyncSession], Awaitable[None]]


class SeederRegistry:
    """Registro global desacoplado de seeders por dominio."""

    _seeders: List[SeederFunc] = []

    @classmethod
    def register(cls, func: SeederFunc) -> SeederFunc:
        """Decorador para registrar una función de seeding de dominio."""
        cls._seeders.append(func)
        return func

    @classmethod
    async def run_all_seeders(cls, session: AsyncSession) -> None:
        """Ejecuta secuencialmente todos los seeders registrados."""
        for seeder in cls._seeders:
            logger.info(f"[SEEDER] Ejecutando {seeder.__name__}...")
            await seeder(session)