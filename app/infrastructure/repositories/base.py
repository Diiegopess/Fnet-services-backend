"""
Módulo del Repositorio Base Genérico.
"""

from typing import Any, Generic, List, Optional, Sequence, Type, TypeVar
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.infrastructure.db.database import Base

ModelType = TypeVar("ModelType", bound=Base)
CreateSchemaType = TypeVar("CreateSchemaType", bound=BaseModel)
UpdateSchemaType = TypeVar("UpdateSchemaType", bound=BaseModel)


class BaseRepository(Generic[ModelType, CreateSchemaType, UpdateSchemaType]):
    """Repositorio base con operaciones CRUD desacopladas del control transaccional directos."""

    def __init__(self, model: Type[ModelType], db: AsyncSession):
        self.model = model
        self.db = db

    async def get_by_id(self, id: Any) -> Optional[ModelType]:
        """Obtiene un registro por su clave primaria."""
        stmt = select(self.model).where(self.model.id == id)
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_all(self, skip: int = 0, limit: int = 100) -> Sequence[ModelType]:
        """Obtiene una lista paginada de registros."""
        stmt = select(self.model).offset(skip).limit(limit)
        result = await self.db.execute(stmt)
        return result.scalars().all()

    async def create(self, schema: CreateSchemaType | dict) -> ModelType:
        """Crea un nuevo objeto en la sesión sin realizar commit explícito."""
        if isinstance(schema, dict):
            data = schema
        elif hasattr(schema, "model_dump"):
            data = schema.model_dump(exclude_unset=True)
        else:
            data = schema.dict(exclude_unset=True)

        db_obj = self.model(**data)
        self.db.add(db_obj)
        # flush envía los cambios a la BD para generar IDs sin cerrar la transacción
        await self.db.flush()
        await self.db.refresh(db_obj)
        return db_obj

    async def update(self, id: Any, schema: UpdateSchemaType | dict) -> Optional[ModelType]:
        """Actualiza un objeto existente a través del ciclo de vida del ORM."""
        db_obj = await self.get_by_id(id)
        if not db_obj:
            return None

        if isinstance(schema, dict):
            data = schema
        elif hasattr(schema, "model_dump"):
            data = schema.model_dump(exclude_unset=True)
        else:
            data = schema.dict(exclude_unset=True)

        for field, value in data.items():
            if hasattr(db_obj, field):
                setattr(db_obj, field, value)

        self.db.add(db_obj)
        await self.db.flush()
        await self.db.refresh(db_obj)
        return db_obj

    async def delete(self, id: Any) -> bool:
        """Elimina un registro por su ID."""
        db_obj = await self.get_by_id(id)
        if not db_obj:
            return False

        await self.db.delete(db_obj)
        await self.db.flush()
        return True