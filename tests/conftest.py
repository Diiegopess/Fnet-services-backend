import os
import sys
from pathlib import Path

# Añade la raíz del proyecto (Fnet-services-backend) al sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

import pytest

# Importar la Base compartida y los módulos que contienen las entidades ORM
import app.infrastructure.db.database  # noqa: F401
import app.users.models  # noqa: F401
import app.auth.models  # noqa: F401

# Importa el modelo/módulo que contiene la relación 'client_technicians'
# Por ejemplo (ajusta la ruta según la estructura de tu proyecto):
import app.clients.models  # noqa: F401


# Variables de entorno para el entorno de test
os.environ["SECRET_KEY"] = "test_super_secret_key_for_unit_testing_32bytes!"
os.environ["DATABASE_URL"] = "postgresql+asyncpg://user:pass@localhost:5432/test_db"
os.environ["ENVIRONMENT"] = "testing"

from app.core.config import settings


@pytest.fixture(scope="session")
def test_settings():
    """Retorna la configuración global cargada para el entorno de prueba."""
    return settings